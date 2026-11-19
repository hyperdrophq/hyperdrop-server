package sharefs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"hyperdrop/server/internal/shareid"
)

// cleanParts removes abandoned upload state from one share's parts/: parts
// nothing has written to for window, with their digest, session and ranges
// sidecars, and any other file there (a sidecar whose part is gone, an
// interrupted sidecar write) once it is as old, or, in the boot sweep,
// once it was written before bootStart, by an earlier process. Fresh parts
// are the resume state of interrupted uploads and survive. A zero bootStart
// is a sweep on a running server, which goes by window alone. It answers
// how many parts went and whether anything is left to look at again. Best
// effort; a share that never staged an upload has no parts/ at all. The
// caller holds the share exclusively, so no part opens or commits
// meanwhile; a chunk's bytes, its sidecar writes and a discard land
// outside that lock, and what they write carries this process's times.
func cleanParts(r *os.Root, window time.Duration, bootStart time.Time) (removed int, left bool) {
	d, err := r.Open(partsDirName)
	if err != nil {
		return 0, false
	}
	entries, err := d.ReadDir(-1)
	d.Close()
	if err != nil {
		return 0, true
	}
	// Directory order is not lexical, so the entries are sorted: a part's
	// name is a prefix of its sidecars' names, and sorting puts the part
	// first, so its sidecars are gone by the time the loop reaches them.
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := filepath.Join(partsDirName, e.Name())
		fi, err := r.Stat(name)
		if err != nil {
			continue // a sidecar of a part removed above
		}
		stale := time.Since(fi.ModTime()) > window
		if strings.HasSuffix(e.Name(), ".part") {
			if !stale {
				left = true
				continue
			}
			r.Remove(name)
			for _, ext := range []string{partHashExt, partSessionExt, partRangesExt} {
				r.Remove(name + ext)
			}
			removed++
			continue
		}
		// What is left is a sidecar or an interrupted sidecar write (.tmp).
		// A sidecar is written before its part exists, and a session sidecar
		// is not rewritten while its part grows, so one goes only when its
		// part is gone and it is as old as an abandoned part, or when an
		// earlier process wrote it, since this one wrote nothing before
		// bootStart; an interrupted write by an earlier process goes whatever
		// its part.
		earlier := !bootStart.IsZero() && fi.ModTime().Before(bootStart)
		part, _, _ := strings.Cut(name, ".part")
		_, partErr := r.Stat(part + ".part")
		keep := partErr == nil && !(earlier && strings.HasSuffix(name, ".tmp"))
		if !keep && (earlier || stale) {
			r.Remove(name)
		} else {
			left = true
		}
	}
	return removed, left
}

// SweepStaleParts runs cleanParts over the shares noted since boot, each held
// exclusively for its pass, so no upload opens a part being removed. A share
// some writer holds (a commit hashing a large part holds it for minutes) is
// skipped and stays noted for the next pass: queueing behind that writer
// would block every new upload into the share until the writer finished. The
// stalled sweep removes an abandoned part together with its pending row;
// this pass takes the parts no pending row leads to (an upload whose row
// went while its part stayed, an overwrite of a committed file abandoned
// midway), which would otherwise hold disk until the next boot. A share
// left with nothing staged is forgotten until it stages again. It answers
// how many parts went.
func (f *FS) SweepStaleParts() int {
	f.stagedMu.Lock()
	ids := make([]string, 0, len(f.staged))
	for id := range f.staged {
		ids = append(ids, id)
	}
	f.stagedMu.Unlock()
	window := f.AbandonedUploadWindow()
	total := 0
	for _, id := range ids {
		release, ok := f.tryLockShare(id)
		if !ok {
			continue
		}
		removed, left := 0, false
		if r, err := f.root(id); err == nil {
			removed, left = cleanParts(r, window, time.Time{})
			r.Close()
		}
		if !left {
			f.stagedMu.Lock()
			delete(f.staged, id)
			f.stagedMu.Unlock()
		}
		release()
		total += removed
	}
	return total
}

// noteStaged records that id holds staging for SweepStaleParts to look at.
func (f *FS) noteStaged(id string) {
	f.stagedMu.Lock()
	f.staged[id] = true
	f.stagedMu.Unlock()
}

// bootProgressEvery is how many entries of shares/ the boot scan visits
// between two progress reports. A variable so a test can shorten it.
var bootProgressEvery = 100000

// bootVisitWorkers is how many share directories the boot scan visits at
// once: each visit is a few metadata reads, which a disk answers faster
// several at a time than one by one. A variable so a test can change it.
var bootVisitWorkers = 4

// bootListBatch is how many entries of shares/ one read of the boot scan's
// listing takes.
const bootListBatch = 4096

// openSharesDir opens shares/ for the boot scan's listing, the one listing
// of shares/ a start makes. A variable so a test can count them.
var openSharesDir = os.Open

// BootPassStats is what the boot scan saw: the entries of shares/, how many
// of them are named like a share id, how many of those no row claims (the
// sweep removes the ones untouched for the abandoned-upload window), and
// how long it took.
type BootPassStats struct {
	Entries, Shares, Rowless int
	Took                     time.Duration
}

// BootWork is what the boot scan leaves for the sweep after the listener
// starts (BootSweep): the shares with a row that hold a parts/ directory,
// and the directories no row claims.
type BootWork struct{ parts, rowless []string }

// Orphans runs the whole boot pass, the scan and then the sweep, without
// progress reports, and answers how many rowless directories it removed.
func (f *FS) Orphans(hasRow func(id string) bool) (removed int, err error) {
	started := time.Now()
	_, w, err := f.BootScan(hasRow, nil)
	if err != nil {
		return 0, err
	}
	removed, _ = f.BootSweep(context.Background(), w, started)
	return removed, nil
}

// BootScan is the part of the boot pass that runs before the listener: one
// listing of shares/, which also removes what an interrupted case probe
// left there, then a visit of every share directory hasRow claims,
// bootVisitWorkers at a time. A visit looks for the share's stage/ and
// parts/ (an Lstat each, through one os.Root on shares/): a stage/ keeps
// only open publishes (cleanStages), each recorded with its owner for the
// per-owner count and the commit journals the boot settles next, before
// any request can open, commit or count a publish; a parts/ is left for
// the sweep. A directory named like a share id that hasRow denies is left
// for the sweep too. Names that are not share ids are an operator's
// business and are left alone. hasRow is called from one goroutine, in
// listing order.
//
// A non-nil progress is called with the entries handed to the visits and
// the entries in all after every bootProgressEvery of them, except the
// last.
func (f *FS) BootScan(hasRow func(id string) bool, progress func(visited, entries int)) (BootPassStats, BootWork, error) {
	start := time.Now()
	var st BootPassStats
	var w BootWork
	sharesDir := filepath.Join(f.dataDir, sharesDirName)
	entries, err := listShares(sharesDir)
	if err != nil {
		return st, w, err
	}
	root, err := os.OpenRoot(sharesDir)
	if err != nil {
		return st, w, err
	}
	defer root.Close()
	st.Entries = len(entries)
	visits := make(chan string)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for range max(bootVisitWorkers, 1) {
		wg.Go(func() {
			for id := range visits {
				if f.visitAtBoot(root, id) {
					mu.Lock()
					w.parts = append(w.parts, id)
					mu.Unlock()
				}
			}
		})
	}
	for i, e := range entries {
		if progress != nil && i > 0 && i%bootProgressEvery == 0 {
			progress(i, len(entries))
		}
		id := e.Name()
		if !e.IsDir() || !shareid.ValidID(id) {
			continue
		}
		st.Shares++
		if hasRow(id) {
			visits <- id
			continue
		}
		st.Rowless++
		w.rowless = append(w.rowless, id)
	}
	close(visits)
	wg.Wait()
	st.Took = time.Since(start)
	return st, w, nil
}

// listShares reads shares/ in directory order, bootListBatch entries at a
// time, and removes on the way every scratch file and directory a case
// probe interrupted by a crash left (probePrefix), which it leaves out of
// the answer. Nothing probes while it runs: the boot scan runs before the
// listener. A probe that cannot be removed now is tried again at the next
// start.
func listShares(dir string) ([]os.DirEntry, error) {
	d, err := openSharesDir(dir)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	var out []os.DirEntry
	for {
		batch, err := d.ReadDir(bootListBatch)
		for _, e := range batch {
			if strings.HasPrefix(e.Name(), probePrefix) {
				os.RemoveAll(filepath.Join(dir, e.Name()))
				continue
			}
			out = append(out, e)
		}
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

// visitAtBoot is the boot scan's visit of share id through sharesRoot: its
// stage/ cleaned and its open publishes recorded, and whether it holds a
// parts/ for the sweep.
func (f *FS) visitAtBoot(sharesRoot *os.Root, id string) (holdsParts bool) {
	if _, err := sharesRoot.Lstat(filepath.Join(id, stageDirName)); err == nil {
		if r, err := f.root(id); err == nil {
			for pid, stage := range cleanStages(r) {
				f.noteStage(id, pid, stage)
			}
			r.Close()
		}
	}
	_, err := sharesRoot.Lstat(filepath.Join(id, partsDirName))
	return err == nil
}

// BootSweep is the part of the boot pass that runs after the listener
// starts, over what BootScan left (w): BootSweepParts, then
// BootSweepOrphans. It answers how many rowless directories it removed and
// in how many shares it removed a stale part.
func (f *FS) BootSweep(ctx context.Context, w BootWork, started time.Time) (removed, cleaned int) {
	cleaned = f.BootSweepParts(ctx, w, started)
	return f.BootSweepOrphans(ctx, w), cleaned
}

// BootSweepParts cleans the parts/ of each share BootScan found holding one
// (cleanParts), taking a file written before started for an earlier
// process's. A share's parts/ is cleaned with the share held exclusively,
// as SweepStaleParts holds it; a share some writer holds is skipped rather
// than waited for and noted, so SweepStaleParts cleans it on a later pass,
// and so is a share still holding a part. It checks ctx before each share
// and stops when it has ended, and answers in how many shares it removed a
// stale part.
func (f *FS) BootSweepParts(ctx context.Context, w BootWork, started time.Time) (cleaned int) {
	window := f.AbandonedUploadWindow()
	for _, id := range w.parts {
		if ctx.Err() != nil {
			return cleaned
		}
		release, ok := f.tryLockShare(id)
		if !ok {
			f.noteStaged(id)
			continue
		}
		if r, err := f.root(id); err == nil {
			removed, left := cleanParts(r, window, started)
			if left {
				f.noteStaged(id)
			}
			r.Close()
			if removed > 0 {
				cleaned++
			}
		}
		release()
	}
	return cleaned
}

// BootSweepOrphans removes each directory BootScan found that no row
// claims, once nothing has written to it for the abandoned-upload window,
// under the share's lock, as RemoveShare takes it. The age guard is what
// makes that safe: a share directory is born by the first upload after its
// row exists, so a rowless directory is a delete that crashed between the
// rows and the directory, or an upload into a share deleted meanwhile, and
// either is safe to remove once nothing has written to it for the window.
// No request reaches a rowless directory, since every route reads the row
// first. It checks ctx before each directory and stops when it has ended,
// and answers how many it removed.
func (f *FS) BootSweepOrphans(ctx context.Context, w BootWork) (removed int) {
	window := f.AbandonedUploadWindow()
	sharesDir := filepath.Join(f.dataDir, sharesDirName)
	for _, id := range w.rowless {
		if ctx.Err() != nil {
			return removed
		}
		dir := filepath.Join(sharesDir, id)
		fi, err := os.Lstat(dir)
		if err != nil || !fi.IsDir() || time.Since(fi.ModTime()) < window {
			continue
		}
		release := f.lockShare(id)
		if os.RemoveAll(dir) == nil {
			removed++
		}
		release()
	}
	return removed
}

// StageJournal is a commit journal found in an open publish.
type StageJournal struct {
	ShareID, PID string
	Journal      Journal
}

// JournalDecision is the database's verdict on a commit journal: Forward
// when the commit is to be finished, with the renames (each staged
// relpath to the relpath its row names) and the removals (each deleted
// path as the share spells it) that finish it. A staged part no rename
// names goes with the stage.
type JournalDecision struct {
	Forward bool
	Renames []Rename
	Removes []string
}

// Journals answers the commit journal of every open publish holding one,
// sorted by share and publish. It takes no lock: at boot it runs after
// BootScan has found the open publishes and before the listener starts, and
// on a running server what it reads is a snapshot the caller judges again
// under the commit's locks (housekeep.RetryPublishes). A journal that
// cannot be read is left where it is, its publish left out, and named in
// the error.
func (f *FS) Journals() ([]StageJournal, error) {
	var out []StageJournal
	var errs []error
	for _, s := range f.openStages() {
		j, ok, err := f.ReadJournal(s.ShareID, s.PID)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s/%s: %w", s.ShareID, s.PID, err))
			continue
		}
		if ok {
			s.Journal = j
			out = append(out, s)
		}
	}
	return out, errors.Join(errs...)
}

// openStages answers every open publish, sorted by share and publish.
func (f *FS) openStages() []StageJournal {
	f.stagesMu.Lock()
	var out []StageJournal
	for id, pids := range f.stages {
		for pid := range pids {
			out = append(out, StageJournal{ShareID: id, PID: pid})
		}
	}
	f.stagesMu.Unlock()
	sort.Slice(out, func(i, k int) bool {
		if out[i].ShareID != out[k].ShareID {
			return out[i].ShareID < out[k].ShareID
		}
		return out[i].PID < out[k].PID
	})
	return out
}

// FinishPublish settles publish pid's commit journal j under the locks a
// commit takes (WithSwap over every path j names, its Rows' included):
// decide reads the rows in the prepare step, and in the swap step a
// Forward verdict performs its renames and removals (SwapIn, which skips
// what is already done) and then retires the stage, with any part the
// verdict left out, which is purged once every lock is released; any other
// verdict removes the journal and leaves the publish open. It answers
// whether the commit was finished. An error from decide or SwapIn leaves
// the journal and the stage for the next attempt: the boot pass, or on a
// running server the housekeeping pass (housekeep.RetryPublishes).
func (f *FS) FinishPublish(id, pid string, j Journal, decide func(Journal) (JournalDecision, error)) (bool, error) {
	if !shareid.ValidPublishID(pid) {
		return false, ErrNoStage
	}
	paths := append(append([]string{}, j.Files...), j.Delete...)
	if j.Rows != nil {
		for _, rn := range j.Rows.Renames {
			paths = append(paths, rn.From, rn.To)
		}
		paths = append(paths, j.Rows.Deleted...)
	}
	var d JournalDecision
	forward := false
	err := f.WithSwap(id, paths, func() error {
		var err error
		d, err = decide(j)
		return err
	}, func() error {
		if !d.Forward {
			return f.RemoveJournal(id, pid)
		}
		if err := f.SwapIn(id, pid, d.Renames, d.Removes); err != nil {
			return err
		}
		forward = true
		return f.retireStage(id, pid)
	})
	if forward {
		if perr := f.PurgeStage(id, pid); perr != nil && err == nil {
			err = perr
		}
	}
	return forward, err
}

// SweepStages removes every open publish nothing has written to for the
// abandoned-upload window (stageQuiet), and every one opened longer ago
// than the stage lifetime (DefaultStageLifetime, FS.StageLifetime) however
// recently it was written, each share held exclusively for its pass and
// skipped, as SweepStaleParts skips it, when some writer holds it. A
// publish holding a commit journal is never removed: its rows may already
// name its staged bytes. The publishes come from memory, so a volume with
// none open costs no disk access. It answers how many went.
func (f *FS) SweepStages() int {
	window := f.AbandonedUploadWindow()
	removed := 0
	for _, s := range f.openStages() {
		release, ok := f.tryLockShare(s.ShareID)
		if !ok {
			continue
		}
		if root, err := f.root(s.ShareID); err == nil {
			sweep := stageQuiet(root, s.PID, window) || (f.stageExpired(s.ShareID, s.PID) && !journalHeld(root, s.PID))
			root.Close()
			if sweep && f.removeStage(s.ShareID, s.PID) == nil {
				removed++
			}
		} else if errors.Is(err, ErrNotFound) {
			f.forgetStage(s.ShareID, s.PID)
		}
		release()
	}
	return removed
}

// stageQuiet reports whether publish pid may be swept: it holds no commit
// journal and neither its directory nor any file in it has been written
// within window.
func stageQuiet(root *os.Root, pid string, window time.Duration) bool {
	if journalHeld(root, pid) {
		return false
	}
	newest, ok := stageWritten(root, pid)
	return ok && time.Since(newest) > window
}

// stageWritten answers the newest modification time of publish pid's
// directory and of every file in it, false when the directory cannot be
// read.
func stageWritten(root *os.Root, pid string) (time.Time, bool) {
	dir := stageRel(pid)
	fi, err := root.Lstat(dir)
	if err != nil {
		return time.Time{}, false
	}
	newest := fi.ModTime()
	d, err := root.Open(dir)
	if err != nil {
		return time.Time{}, false
	}
	entries, err := d.ReadDir(-1)
	d.Close()
	if err != nil {
		return time.Time{}, false
	}
	for _, e := range entries {
		if fi, err := e.Info(); err == nil && fi.ModTime().After(newest) {
			newest = fi.ModTime()
		}
	}
	return newest, true
}

// recentStage reports whether an open publish of the share was written
// within window.
func (f *FS) recentStage(root *os.Root, id string, window time.Duration) bool {
	for _, pid := range f.stagePIDs(id) {
		if newest, ok := stageWritten(root, pid); ok && time.Since(newest) < window {
			return true
		}
	}
	return false
}
