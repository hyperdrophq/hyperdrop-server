package housekeep

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"hyperdrop/server/internal/metadb"
)

// scanner is a pass over x whose clock reads *at and whose count lands in
// shared, as a process's integrity loop holds one.
func (x *fixture) scanner(at *time.Time, shared *atomic.Int64) *Pass {
	return &Pass{DB: x.db, FS: x.fs, Now: func() time.Time { return *at }, MissingFiles: shared}
}

func (x *fixture) removeStored(t *testing.T, id, rel string) {
	t.Helper()
	if err := os.Remove(filepath.Join(x.shareDir(id), "files", filepath.FromSlash(rel))); err != nil {
		t.Fatal(err)
	}
}

func due(t *testing.T, p *Pass, at time.Time) bool {
	t.Helper()
	d, err := p.IntegrityDue(at)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestPassCountsStoredFilesMissingFromDisk(t *testing.T) {
	x := setup(t)
	d := x.share(t, metadb.CreateOptions{})
	x.upload(t, d.ID, "a.txt", "a")
	x.upload(t, d.ID, "dir/b.txt", "b")
	x.upload(t, d.ID, "c.txt", "c")
	at := x.now
	if r := x.scanner(&at, nil).Integrity(context.Background()); r.Cancelled || r.Files != 3 || r.Missing != 0 {
		t.Fatalf("intact volume: %+v, want 3 files and 0 missing", r)
	}
	x.removeStored(t, d.ID, "dir/b.txt")
	p := x.scanner(&at, nil)
	if r := p.Integrity(context.Background()); r.Missing != 1 {
		t.Fatalf("one file deleted: %+v, want 1 missing", r)
	}
	// No second scan inside the interval, the count of missing files
	// notwithstanding.
	if due(t, p, at) {
		t.Fatal("a scan is due again within a day")
	}
	at = x.now.Add(MissingInterval)
	if !due(t, p, at) {
		t.Fatal("no scan due a day later")
	}
	if r := p.Integrity(context.Background()); r.Cancelled || r.Missing != 1 {
		t.Fatalf("a day later: %+v, want 1 missing", r)
	}
	if got := (IntegrityResult{Files: 3, Missing: 1, Took: 1500 * time.Microsecond}).Line(); got != "integrity scan: 2ms (3 files, 1 missing)" {
		t.Fatalf("Line() = %q", got)
	}
}

// A share deleted after the scan read its rows is gone on purpose, and its
// files are not counted as missing.
func TestMissingFilesSkipsAShareDeletedDuringTheScan(t *testing.T) {
	x := setup(t)
	kept := x.share(t, metadb.CreateOptions{})
	x.upload(t, kept.ID, "a.txt", "a")
	x.upload(t, kept.ID, "b.txt", "b")
	gone := x.share(t, metadb.CreateOptions{})
	x.upload(t, gone.ID, "c.txt", "c")
	x.upload(t, gone.ID, "d.txt", "d")
	x.removeStored(t, kept.ID, "b.txt")
	at := x.now
	p := x.scanner(&at, nil)
	deleted := false
	p.beforeCheck = func(shareID string, rels []string) {
		if shareID != gone.ID || deleted {
			return
		}
		deleted = true
		if err := x.db.DeleteShare(gone.ID); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(x.shareDir(gone.ID)); err != nil {
			t.Fatal(err)
		}
	}
	if r := p.Integrity(context.Background()); r.Missing != 1 || !deleted {
		t.Fatalf("%+v deleted=%v, want 1 missing (only kept/b.txt) and the share deleted", r, deleted)
	}
}

func TestMissingFilesIgnoresPendingRowsAndPublishesTheCount(t *testing.T) {
	x := setup(t)
	d := x.share(t, metadb.CreateOptions{})
	x.upload(t, d.ID, "a.txt", "a")
	if _, err := x.db.DeclareFile(d.ID, "pending.txt", 5); err != nil {
		t.Fatal(err)
	}
	x.removeStored(t, d.ID, "a.txt")
	var shared atomic.Int64
	at := x.now
	if r := x.scanner(&at, &shared).Integrity(context.Background()); r.Missing != 1 || shared.Load() != 1 {
		t.Fatalf("%+v shared=%d, want 1 1 (the pending row is not counted)", r, shared.Load())
	}
}

// A new process within a day of the recorded scan does not scan, and states
// the recorded count from its start.
func TestARestartWithinADayDoesNotScan(t *testing.T) {
	x := setup(t)
	d := x.share(t, metadb.CreateOptions{})
	x.upload(t, d.ID, "a.txt", "a")
	at := x.now
	if r := x.scanner(&at, nil).Integrity(context.Background()); r.Cancelled || r.Missing != 0 {
		t.Fatalf("%+v", r)
	}
	var shared atomic.Int64
	shared.Store(7)
	later := x.now.Add(MissingInterval - time.Minute)
	p := x.scanner(&later, &shared)
	if err := p.LoadIntegrity(); err != nil {
		t.Fatal(err)
	}
	if shared.Load() != 0 {
		t.Fatalf("LoadIntegrity left %d, want the recorded 0", shared.Load())
	}
	if due(t, p, later) {
		t.Fatal("a scan is due within a day of the recorded one")
	}
}

// A recorded count of missing files is scanned again at the start of the
// next process, so files restored meanwhile clear the warning; that process
// then keeps the daily schedule.
func TestAStoredMissingCountScansAtStart(t *testing.T) {
	x := setup(t)
	d := x.share(t, metadb.CreateOptions{})
	x.upload(t, d.ID, "a.txt", "a")
	x.upload(t, d.ID, "b.txt", "b")
	saved, err := os.ReadFile(filepath.Join(x.shareDir(d.ID), "files", "b.txt"))
	if err != nil {
		t.Fatal(err)
	}
	x.removeStored(t, d.ID, "b.txt")
	at := x.now
	first := x.scanner(&at, nil)
	if r := first.Integrity(context.Background()); r.Missing != 1 {
		t.Fatalf("%+v, want 1 missing", r)
	}
	if due(t, first, at.Add(time.Hour)) {
		t.Fatal("the process that found the file missing scans again within the day")
	}

	if err := os.WriteFile(filepath.Join(x.shareDir(d.ID), "files", "b.txt"), saved, 0o600); err != nil {
		t.Fatal(err)
	}
	var shared atomic.Int64
	restart := at.Add(time.Hour)
	p := x.scanner(&restart, &shared)
	if err := p.LoadIntegrity(); err != nil || shared.Load() != 1 {
		t.Fatalf("LoadIntegrity: %v, count %d, want the recorded 1", err, shared.Load())
	}
	if !due(t, p, restart) {
		t.Fatal("no scan due at the start of a process whose recorded scan found files missing")
	}
	if r := p.Integrity(context.Background()); r.Missing != 0 || shared.Load() != 0 {
		t.Fatalf("%+v shared=%d, want the restored file found", r, shared.Load())
	}
	if due(t, p, restart.Add(time.Hour)) {
		t.Fatal("a scan is due within the day after the start's scan")
	}
}

func TestADayLaterItScans(t *testing.T) {
	x := setup(t)
	d := x.share(t, metadb.CreateOptions{})
	x.upload(t, d.ID, "a.txt", "a")
	at := x.now
	p := x.scanner(&at, nil)
	if !due(t, p, at) {
		t.Fatal("no scan due on a volume with no recorded scan")
	}
	p.Integrity(context.Background())
	fresh := x.scanner(&at, nil)
	if due(t, fresh, at.Add(MissingInterval-time.Nanosecond)) {
		t.Fatal("a scan is due before a day has passed")
	}
	if !due(t, fresh, at.Add(MissingInterval)) {
		t.Fatal("no scan due a day after the recorded one")
	}
	s, ok, err := x.db.LastIntegrityScan()
	if err != nil || !ok || !s.At.Equal(at) || s.Files != 1 || s.Missing != 0 {
		t.Fatalf("recorded %+v, %v, %v; want the scan at %v of 1 file", s, ok, err, at)
	}
}

// A scan whose context ends while it reads the volume stops at its next
// check, and records and publishes nothing: a count of part of the volume is
// not the volume's.
func TestACancelledScanRecordsNothing(t *testing.T) {
	x := setup(t)
	d := x.share(t, metadb.CreateOptions{})
	x.upload(t, d.ID, "a.txt", "a")
	x.upload(t, d.ID, "b.txt", "b")
	x.upload(t, d.ID, "c.txt", "c")
	other := x.share(t, metadb.CreateOptions{})
	x.upload(t, other.ID, "d.txt", "d")
	x.removeStored(t, d.ID, "c.txt")
	var shared atomic.Int64
	shared.Store(42)
	at := x.now
	p := x.scanner(&at, &shared)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	checks := 0
	p.beforeCheck = func(string, []string) {
		checks++
		cancel()
	}
	r := p.Integrity(ctx)
	if !r.Cancelled {
		t.Fatalf("%+v, want Cancelled", r)
	}
	if checks != 1 {
		t.Fatalf("the scan went on to %d shares after its context ended, want 1", checks)
	}
	if shared.Load() != 42 {
		t.Fatalf("shared=%d, want the earlier 42 kept", shared.Load())
	}
	if _, ok, err := x.db.LastIntegrityScan(); ok || err != nil {
		t.Fatalf("a cancelled scan recorded itself (%v, %v)", ok, err)
	}
	if !due(t, p, at) {
		t.Fatal("the cancelled scan is not owed again")
	}
	p.beforeCheck = nil
	if r := p.Integrity(context.Background()); r.Cancelled || r.Files != 4 || r.Missing != 1 || shared.Load() != 1 {
		t.Fatalf("the next scan: %+v shared=%d, want 4 files, 1 missing, published", r, shared.Load())
	}
}

// A share of many files is checked in pieces, and the context stops the scan
// between them.
func TestACancelledScanStopsInsideALargeShare(t *testing.T) {
	defer func(n int) { missingChunk = n }(missingChunk)
	missingChunk = 2
	x := setup(t)
	d := x.share(t, metadb.CreateOptions{})
	for _, rel := range []string{"a", "b", "c", "d", "e"} {
		x.upload(t, d.ID, rel, rel)
	}
	x.removeStored(t, d.ID, "e")
	at := x.now
	var pieces [][]string
	p := x.scanner(&at, nil)
	p.beforeCheck = func(_ string, rels []string) { pieces = append(pieces, append([]string(nil), rels...)) }
	if r := p.Integrity(context.Background()); r.Files != 5 || r.Missing != 1 {
		t.Fatalf("%+v, want 5 files and 1 missing", r)
	}
	if len(pieces) != 3 || strings.Join(pieces[0], ",") != "a,b" || strings.Join(pieces[2], ",") != "e" {
		t.Fatalf("pieces %v, want three of at most two rows", pieces)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	checks := 0
	p.beforeCheck = func(string, []string) {
		checks++
		cancel()
	}
	if r := p.Integrity(ctx); !r.Cancelled || checks != 1 || r.Files != 2 {
		t.Fatalf("%+v after %d pieces, want cancelled after the first piece of 2 files", r, checks)
	}
}

func TestNotDueLineNamesTheLastScanOnlyWhileNoScanIsOwed(t *testing.T) {
	x := setup(t)
	at := x.now
	p := x.scanner(&at, nil)
	if line, ok, err := p.NotDueLine(at); err != nil || ok {
		t.Fatalf("no scan recorded: %q, %v, %v", line, ok, err)
	}
	p.Integrity(context.Background())
	line, ok, err := p.NotDueLine(at.Add(time.Hour))
	if err != nil || !ok {
		t.Fatalf("a scan within a day: %q, %v, %v", line, ok, err)
	}
	want := "integrity scan not due: last finished " + at.UTC().Format(time.RFC3339) + " (0 files, 0 missing)"
	if line != want {
		t.Fatalf("line = %q, want %q", line, want)
	}
	if strings.HasPrefix(line, "integrity scan: ") {
		t.Fatal("the not-due line starts like a finished scan's")
	}
	if line, ok, _ := p.NotDueLine(at.Add(MissingInterval)); ok {
		t.Fatalf("a scan is due, yet the line %q", line)
	}
}

// A row stream that fails partway for a reason other than the context
// publishes what it counted and holds this process off for the interval, but
// leaves the recorded scan as it was, so the next process still owes one.
func TestAFailedRowStreamRecordsNothing(t *testing.T) {
	x := setup(t)
	d := x.share(t, metadb.CreateOptions{})
	for _, rel := range []string{"a", "b", "c"} {
		x.upload(t, d.ID, rel, rel)
	}
	at := x.now
	if r := x.scanner(&at, nil).Integrity(context.Background()); r.Cancelled || r.Failed || r.Files != 3 {
		t.Fatalf("first scan: %+v", r)
	}
	recorded, _, err := x.db.LastIntegrityScan()
	if err != nil {
		t.Fatal(err)
	}

	x.removeStored(t, d.ID, "a")
	var shared atomic.Int64
	later := at.Add(MissingInterval)
	p := x.scanner(&later, &shared)
	p.storedFiles = func(fn func(shareID, relPath string) error) error {
		rows := 0
		err := x.db.EachStoredFile(func(shareID, rel string) error {
			if rows == 2 {
				return errors.New("disk I/O error")
			}
			rows++
			return fn(shareID, rel)
		})
		return err
	}
	r := p.Integrity(context.Background())
	if r.Cancelled || !r.Failed || r.Files != 2 || r.Missing != 1 || shared.Load() != 1 {
		t.Fatalf("failed scan: %+v shared=%d, want 2 files and 1 missing published, failed and not cancelled", r, shared.Load())
	}
	if s, ok, err := x.db.LastIntegrityScan(); err != nil || !ok || s != recorded {
		t.Fatalf("recorded %+v, %v, %v after the failed scan, want %+v unchanged", s, ok, err, recorded)
	}
	if due(t, p, later.Add(time.Hour)) {
		t.Fatal("the process whose scan failed scans again within the interval")
	}
	next := later.Add(time.Hour)
	if !due(t, x.scanner(&next, nil), next) {
		t.Fatal("a new process owes no scan after a failed one")
	}
}

// A recorded scan that started after now (the clock set back since) owes a
// scan rather than holding scans off until the clock catches up; the scan
// it owes settles the schedule.
func TestARecordedScanInTheFutureIsDue(t *testing.T) {
	x := setup(t)
	d := x.share(t, metadb.CreateOptions{})
	x.upload(t, d.ID, "a", "a")
	ahead := x.now.Add(6 * time.Hour)
	if r := x.scanner(&ahead, nil).Integrity(context.Background()); r.Cancelled || r.Failed {
		t.Fatalf("%+v", r)
	}
	at := x.now
	p := x.scanner(&at, nil)
	if !due(t, p, at) {
		t.Fatal("a scan recorded in the future holds the next one off")
	}
	p.Integrity(context.Background())
	if due(t, p, at.Add(time.Hour)) {
		t.Fatal("a scan is due within the day of the one the clock's correction owed")
	}
	fresh := x.scanner(&at, nil)
	if due(t, fresh, at.Add(time.Hour)) {
		t.Fatal("a new process owes a scan within the day of the recorded one")
	}
}
