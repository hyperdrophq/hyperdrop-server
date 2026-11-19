package housekeep

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"hyperdrop/server/internal/metadb"
)

// missingChunk bounds how many of one share's rows the integrity scan holds
// before it checks them on disk, so a share of many files costs bounded
// memory and the scan's context is checked between its pieces. A variable so
// a test can shorten it.
var missingChunk = 10000

// IntegrityResult is what one integrity scan did: how many stored files it
// checked, how many of them are missing from disk, and how long it took.
// Cancelled is whether its context ended first, in which case the counts
// cover only part of the volume and nothing was recorded or published.
// Failed is whether reading the rows failed partway for another reason: the
// counts cover the rows read before it and are published, but not recorded,
// so the next process still owes a scan.
type IntegrityResult struct {
	Files, Missing int
	Took           time.Duration
	Cancelled      bool
	Failed         bool
}

// Line is the one line a finished scan logs.
func (r IntegrityResult) Line() string {
	return fmt.Sprintf("integrity scan: %s (%d files, %d missing)", r.Took.Round(time.Millisecond), r.Files, r.Missing)
}

// LoadIntegrity puts the last recorded scan's count into MissingFiles, so
// the health verdict states it from the start of a process rather than after
// the next scan. A volume with no record leaves it alone.
func (p *Pass) LoadIntegrity() error {
	s, ok, err := p.DB.LastIntegrityScan()
	if err != nil || !ok {
		return err
	}
	if p.MissingFiles != nil {
		p.MissingFiles.Store(int64(s.Missing))
	}
	return nil
}

// IntegrityDue answers whether a scan is owed at now, from the recorded scan
// and this process's own, reading the database alone so a NAS disk stays
// spun down between scans. One is owed when none was recorded, when the
// latest started at least MissingInterval ago, or, until this process has
// finished one, when the recorded one found files missing: an operator who
// restored them and restarts sees the warning clear without waiting a day.
// A start after now (a clock set back since) counts as no scan, so the
// clock's correction never holds scans off until it catches up: a recorded
// one is passed over for this process's own, and when this process's own is
// after now too a scan is owed.
func (p *Pass) IntegrityDue(now time.Time) (bool, error) {
	s, ok, err := p.DB.LastIntegrityScan()
	if err != nil {
		return false, err
	}
	if ok && s.Missing > 0 && p.scannedAt.IsZero() {
		return true, nil
	}
	last := p.scannedAt
	if ok && s.At.After(last) && !now.Before(s.At) {
		last = s.At
	}
	return last.IsZero() || now.Before(last) || now.Sub(last) >= MissingInterval, nil
}

// NotDueLine is the one line a process logs, at its first check, when no scan
// is owed: the last recorded scan's time and counts. It starts with
// "integrity scan not due: ", which is not the finished-scan prefix, and ok is
// false when a scan is owed or none was recorded.
func (p *Pass) NotDueLine(now time.Time) (line string, ok bool, err error) {
	d, err := p.IntegrityDue(now)
	if err != nil || d {
		return "", false, err
	}
	s, found, err := p.DB.LastIntegrityScan()
	if err != nil || !found {
		return "", false, err
	}
	return fmt.Sprintf("integrity scan not due: last finished %s (%d files, %d missing)",
		s.At.UTC().Format(time.RFC3339), s.Files, s.Missing), true, nil
}

// Integrity counts the stored files missing from disk. A scan that finishes
// publishes the count to MissingFiles and records it with the time it
// started (metadb.RecordIntegrityScan); a cancelled one does neither, so the
// earlier count stands and the next IntegrityDue still owes a scan. A scan
// whose row stream fails partway publishes its count and counts as this
// process's scan, so the loop does not read the volume again within the
// interval, but records nothing: a count of part of the volume is not the
// volume's, and the next process owes a scan.
func (p *Pass) Integrity(ctx context.Context) IntegrityResult {
	at := p.now()
	start := time.Now()
	files, missing, done, failed := p.countMissing(ctx)
	r := IntegrityResult{Files: files, Missing: missing, Took: time.Since(start), Cancelled: !done, Failed: failed}
	if !done {
		return r
	}
	p.scannedAt = at
	if p.MissingFiles != nil {
		p.MissingFiles.Store(int64(missing))
	}
	if failed {
		return r
	}
	if err := p.DB.RecordIntegrityScan(metadb.IntegrityScan{At: at, Files: files, Missing: missing}); err != nil {
		log.Printf("integrity scan record: %v", err)
	}
	return r
}

// RecountSidecars reads what every share's tiles and poster occupy from the
// disk, which is how a process learns the count the quota charges them by and
// how it corrects any drift (sharefs.SidecarBytes). The count lives in
// memory, so a process runs it at its start whatever the integrity scan's
// schedule, and again after each later scan. ctx stops it between shares.
func (p *Pass) RecountSidecars(ctx context.Context) {
	err := p.DB.EachShareOwner(func(id, owner string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		p.FS.RecountSidecars(id, owner)
		return nil
	})
	if err != nil && ctx.Err() == nil {
		log.Printf("sidecar recount: %v", err)
	}
}

// countMissing checks every stored file's bytes and answers how many rows it
// checked and how many files are absent. Rows stream in batches in
// (share, path) order and are checked a share at a time, in pieces of at
// most missingChunk, through one listing per directory a piece names
// (sharefs.MissingAmong), so memory does not grow with the volume and a
// directory of more than missingChunk stored files is listed once per
// piece. An absent file counts only once a one-row lookup shows its row
// still stands committed. A check or lookup that fails for any reason but absence says
// nothing about the file and is not counted; the first such failure of a
// scan is logged. ctx is checked at every row, so it stops the scan between
// pieces, and done is false when it did. failed is whether the row stream
// itself failed for another reason, after the rows read before it were
// checked: the counts then cover part of the volume.
func (p *Pass) countMissing(ctx context.Context) (files, missing int, done, failed bool) {
	var checkErr error
	note := func(err error) {
		if checkErr == nil {
			checkErr = err
		}
	}
	share := ""
	var rels []string
	check := func() {
		if len(rels) == 0 {
			return
		}
		if p.beforeCheck != nil {
			p.beforeCheck(share, rels)
		}
		gone, err := p.FS.MissingAmong(share, rels)
		files += len(rels)
		rels = rels[:0]
		if err != nil {
			note(fmt.Errorf("%s/%w", share, err))
		}
		for _, rel := range gone {
			// The rows were read a batch ago: a file whose row has since
			// gone (its share or the file deleted) or gone back to pending
			// (a replace) is not missing.
			f, err := p.DB.File(share, rel)
			if err == nil && !f.Pending {
				missing++
			} else if err != nil && !errors.Is(err, metadb.ErrNotFound) {
				note(fmt.Errorf("%s/%s: %w", share, rel, err))
			}
		}
	}
	each := p.DB.EachStoredFile
	if p.storedFiles != nil {
		each = p.storedFiles
	}
	err := each(func(shareID, rel string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if shareID != share || len(rels) >= missingChunk {
			check()
			share = shareID
		}
		rels = append(rels, rel)
		return nil
	})
	if ctx.Err() == nil {
		check()
	}
	if ctx.Err() != nil {
		return files, missing, false, false
	}
	if err != nil {
		log.Printf("integrity scan failed: %v", err)
	}
	if checkErr != nil {
		log.Printf("integrity scan could not check some files, first: %v", checkErr)
	}
	return files, missing, true, err != nil
}
