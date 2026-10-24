package housekeep

import (
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"sync/atomic"
	"time"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/sharefs"
)

const (
	// Interval is how often a pass runs.
	Interval = 5 * time.Minute
	// EmptyGrace is how long a share with no committed file is left alone
	// before the sweep takes it as abandoned: long enough that a slow first
	// upload, or a client that went offline mid-share, is never mistaken for
	// a crash.
	EmptyGrace = time.Hour
	// DeviceLinkMaxAge is how long a device link's row is kept after its
	// mint, whatever its state: long past its last use, which ends minutes
	// after the mint.
	DeviceLinkMaxAge = 24 * time.Hour
)

const (
	// BackupInterval is how old the newest backup may be before a pass
	// writes another.
	BackupInterval = 24 * time.Hour
	// MissingInterval is how long a count of stored files missing from disk
	// stands before a pass counts again. The first pass of a process always
	// counts.
	MissingInterval = 24 * time.Hour
	// RecoveredMarkerAge is how long the recovered marker (a boot that
	// restored the database from a backup) stays for the health verdict.
	RecoveredMarkerAge = 7 * 24 * time.Hour
)

// Pass is one housekeeping run over a database and its file layer.
type Pass struct {
	DB *metadb.DB
	FS *sharefs.FS
	// DataDir holds backups/ and the recovered marker; empty skips both.
	DataDir string
	Now     func() time.Time
	// Alive answers whether a share's sender has reported preparing one of
	// its files after since (the api's preparing tracker). A share so
	// reported on is as alive to the empty sweep as one whose part grew: the
	// bytes are still being made. Nil means no such reports exist.
	Alive func(shareID string, since time.Time) bool
	// MissingFiles, when set, receives the latest count of stored files
	// missing from disk, for the health verdict to read.
	MissingFiles *atomic.Int64

	lastMissing time.Time
	// beforeStat, when set, runs before the integrity scan stats a file: the
	// tests' seam between reading a batch of rows and the disk.
	beforeStat func(shareID, rel string)
}

// Result is what one pass did. Counts are zero and errors nil on a quiet
// volume, which is the normal case: the caller logs only what happened, so
// an idle server says nothing.
type Result struct {
	Reservations int
	Due          int
	DueErr       error
	Expired      int
	ExpiredErr   error
	StalledParts int
	StalledRows  int
	StalledErr   error
	Empty        int
	EmptyErr     error
	Changes      int
	ChangesErr   error
	// DeviceLinks counts the sign-in links swept a day after their mint.
	DeviceLinks    int
	DeviceLinksErr error
	OptimizeErr    error
	BackedUp       bool
	BackupErr      error
	// MissingChecked is whether this pass counted stored files missing from
	// disk (once a day, and on a process's first pass); MissingFiles is the
	// count.
	MissingChecked bool
	MissingFiles   int
}

// Lines is what the caller logs: one line per thing that happened or
// failed, nothing on a quiet pass.
func (r Result) Lines() []string {
	var out []string
	add := func(n int, err error, did, what string) {
		if err != nil {
			out = append(out, fmt.Sprintf("%s: %v", what, err))
		} else if n > 0 {
			out = append(out, fmt.Sprintf("%s: %s %d", what, did, n))
		}
	}
	add(r.Reservations, nil, "dropped idle holds:", "reservation sweep")
	add(r.Due, r.DueErr, "applied due changes:", "scheduled changes")
	add(r.Expired, r.ExpiredErr, "removed expired shares:", "expiry sweep")
	if r.StalledErr != nil {
		out = append(out, fmt.Sprintf("stalled uploads: %v", r.StalledErr))
	} else if r.StalledParts > 0 || r.StalledRows > 0 {
		out = append(out, fmt.Sprintf("stalled uploads: dropped %d partial(s) and %d pending file(s)", r.StalledParts, r.StalledRows))
	}
	add(r.Empty, r.EmptyErr, "removed abandoned shares:", "empty sweep")
	add(r.Changes, r.ChangesErr, "pruned journal rows:", "change journal")
	add(r.DeviceLinks, r.DeviceLinksErr, "removed old links:", "device links")
	if r.MissingFiles > 0 {
		out = append(out, fmt.Sprintf("integrity: %d stored file(s) missing from disk", r.MissingFiles))
	}
	if r.OptimizeErr != nil {
		out = append(out, fmt.Sprintf("optimize: %v", r.OptimizeErr))
	}
	if r.BackupErr != nil {
		out = append(out, fmt.Sprintf("backup: %v", r.BackupErr))
	} else if r.BackedUp {
		out = append(out, "backup: wrote a copy of the database")
	}
	return out
}

func (p *Pass) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Run performs one pass. Every step asks the database or memory whether it
// has work and reads the disk only for the shares a query or that memory
// named, so a volume with nothing due costs no syscalls under shares/ and a
// NAS disk can stay spun down between requests. Stalled uploads are swept
// with their rows first, and then the parts no pending row leads to, which
// the boot pass would otherwise be the only one to remove. They go before
// empty shares, deliberately: removing a dead pending row is what leaves a
// stalled upload's share with nothing, and the empty sweep then removes it
// in the same pass rather than an hour later.
func (p *Pass) Run() Result {
	var r Result
	now := p.now()
	r.Reservations = p.FS.SweepReservations()
	r.Due, r.DueErr = p.DB.ApplyDue(now)
	r.Expired, r.ExpiredErr = p.sweepExpired(now)
	r.StalledParts, r.StalledRows, r.StalledErr = p.sweepStalled(now)
	r.StalledParts += p.FS.SweepStaleParts()
	r.Empty, r.EmptyErr = p.sweepEmpty(now)
	r.Changes, r.ChangesErr = p.DB.PruneChanges(now.Add(-metadb.ChangesRetention))
	r.DeviceLinks, r.DeviceLinksErr = p.DB.PruneDeviceLinks(now.Add(-DeviceLinkMaxAge))
	r.OptimizeErr = p.DB.Optimize()
	if p.DataDir != "" {
		r.BackedUp, r.BackupErr = p.backup(now)
		p.expireRecovered(now)
	}
	if now.Sub(p.lastMissing) >= MissingInterval {
		p.lastMissing = now
		r.MissingChecked = true
		r.MissingFiles = p.countMissing()
		if p.MissingFiles != nil {
			p.MissingFiles.Store(int64(r.MissingFiles))
		}
	}
	return r
}

// countMissing stats every stored file's bytes and answers how many are
// absent. Rows stream in batches, so memory does not grow with the volume,
// and an absent file counts only once a one-row lookup shows its row still
// stands committed. A stat or lookup that fails for any reason but absence
// says nothing about the file and is not counted; the first such failure of
// a pass is logged.
func (p *Pass) countMissing() int {
	missing := 0
	var statErr error
	err := p.DB.EachStoredFile(func(shareID, rel string) error {
		if p.beforeStat != nil {
			p.beforeStat(shareID, rel)
		}
		gone, err := p.FS.FileMissing(shareID, rel)
		switch {
		case err != nil:
			if statErr == nil {
				statErr = fmt.Errorf("%s/%s: %w", shareID, rel, err)
			}
		case gone:
			// The rows were read a batch ago: a file whose row has since
			// gone (its share or the file deleted) or gone back to pending
			// (a replace) is not missing.
			f, err := p.DB.File(shareID, rel)
			if err == nil && !f.Pending {
				missing++
			} else if err != nil && !errors.Is(err, metadb.ErrNotFound) && statErr == nil {
				statErr = fmt.Errorf("%s/%s: %w", shareID, rel, err)
			}
		}
		return nil
	})
	if err != nil {
		log.Printf("integrity scan: %v", err)
	}
	if statErr != nil {
		log.Printf("integrity scan: some files could not be checked, first: %v", statErr)
	}
	return missing
}

// backup writes a copy when the newest one is older than BackupInterval.
// The newest copy's name carries its time, so no other state is kept.
func (p *Pass) backup(now time.Time) (bool, error) {
	dir := filepath.Join(p.DataDir, "backups")
	if newest := metadb.NewestBackup(dir); newest != "" {
		if at := metadb.BackupTime(newest); !at.IsZero() && now.Sub(at) < BackupInterval {
			return false, nil
		}
	}
	_, err := metadb.Backup(p.DB, dir, now)
	return err == nil, err
}

// expireRecovered drops the recovered marker once it is older than
// RecoveredMarkerAge: a week is long enough for the owner to have seen the
// warning, and a boot never clears it, or a restart could hide it first.
func (p *Pass) expireRecovered(now time.Time) {
	if rec, ok := metadb.ReadRecovered(p.DataDir); ok && now.Sub(rec.At) > RecoveredMarkerAge {
		metadb.ClearRecovered(p.DataDir)
	}
}

// sweepExpired removes shares whose expiry has passed: rows first, under a
// re-check inside the write transaction, then the directory.
func (p *Pass) sweepExpired(now time.Time) (int, error) {
	ids, err := p.DB.Expired(now)
	if err != nil {
		return 0, err
	}
	return p.removeShares(ids, func(id string) (bool, error) { return p.DB.DeleteExpiredShare(id, now) })
}

// removeShares deletes each share's rows through del, which re-tests the
// sweep's condition inside its write transaction and answers false when it no
// longer holds, and only then removes the share's directory. It answers how
// many shares went.
func (p *Pass) removeShares(ids []string, del func(id string) (bool, error)) (int, error) {
	n := 0
	var errs []error
	for _, id := range ids {
		ok, err := del(id)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !ok {
			continue
		}
		if err := p.FS.RemoveShare(id); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", id, err))
			continue
		}
		n++
	}
	return n, errors.Join(errs...)
}

// sweepStalled clears the staging of uploads that stopped: a pending row
// declared more than the window ago loses the file it names, its part and
// its row when its part has not been written for the window, or when a
// final file already stands under files/ for it, which is a commit that
// renamed the part in and then failed to record its row and so leaves
// bytes nothing serves. The share then stops telling visitors a file is
// still uploading when nothing is.
//
// Two rows stay. One whose part is fresh is a live upload. One with
// neither a part nor a file has nothing staged to clear: the client that
// declared it may not have sent a byte yet, its slug may already be in a
// link, and expiry and the empty sweep own it.
//
// The candidates are a snapshot, so the removal re-checks under the path's
// lock that the row is still pending and its part still quiet: an upload
// resumed or committed since (a commit renames and writes its row under
// that lock) keeps its bytes.
func (p *Pass) sweepStalled(now time.Time) (parts, rows int, err error) {
	window := p.FS.AbandonedUploadWindow()
	refs, err := p.DB.PendingFiles(now.Add(-window))
	if err != nil {
		return 0, 0, err
	}
	var errs []error
	for _, ref := range refs {
		staged := false
		if age, ok := p.FS.PartAge(ref.ShareID, ref.Path); ok {
			if age < window {
				continue
			}
			staged = true
		} else if _, err := p.FS.Stat(ref.ShareID, ref.Path); err != nil {
			continue
		}
		// The file goes before the row: a removal that fails leaves the row
		// for the next pass to try again, where dropping the row first would
		// strand the bytes with nothing naming them.
		removed, err := p.FS.RemoveFileIf(ref.ShareID, ref.Path, func() bool {
			if f, err := p.DB.File(ref.ShareID, ref.Path); err != nil || !f.Pending {
				return false
			}
			age, ok := p.FS.PartAge(ref.ShareID, ref.Path)
			return !ok || age >= window
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("%s/%s: %w", ref.ShareID, ref.Path, err))
			continue
		}
		if !removed {
			continue
		}
		if staged {
			parts++
		}
		if err := p.DB.RemovePending(ref.ShareID, ref.Path); err != nil {
			errs = append(errs, fmt.Errorf("%s/%s: %w", ref.ShareID, ref.Path, err))
			continue
		}
		rows++
	}
	return parts, rows, errors.Join(errs...)
}

// sweepEmpty removes shares that never received a file, past the grace: an
// inbox waits empty by design, a linked share holds no uploads by
// construction, a share with folder records is being built, and a share with
// fresh staging is a transfer that may still resume. The database re-tests
// the first three inside the delete; the file layer answers the last.
func (p *Pass) sweepEmpty(now time.Time) (int, error) {
	cutoff := now.Add(-EmptyGrace)
	ids, err := p.DB.EmptyShares(cutoff)
	if err != nil {
		return 0, err
	}
	return p.removeShares(ids, func(id string) (bool, error) {
		if p.FS.HasRecentPart(id, p.FS.AbandonedUploadWindow()) {
			return false, nil
		}
		if p.Alive != nil && p.Alive(id, cutoff) {
			return false, nil
		}
		return p.DB.DeleteEmptyShare(id, cutoff)
	})
}
