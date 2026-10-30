package sharefs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"hyperdrop/server/internal/shareid"
)

// cleanParts removes abandoned upload state from one share's parts/: parts
// nothing has written to for window, with their digest, session and ranges
// sidecars, and any other file there (a sidecar whose part is gone, an
// interrupted sidecar write) once it is as old, or whatever its age atBoot,
// when nothing writes. Fresh parts are the resume state of interrupted
// uploads and survive. It answers how many parts went and whether anything
// is left to look at again. Best effort; a share that never staged an
// upload has no parts/ at all.
func cleanParts(r *os.Root, window time.Duration, atBoot bool) (removed int, left bool) {
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
		// part is gone and it is as old as an abandoned part, or at boot,
		// when nothing writes; an interrupted write goes at boot whatever
		// its part.
		part, _, _ := strings.Cut(name, ".part")
		_, partErr := r.Stat(part + ".part")
		keep := partErr == nil && !(atBoot && strings.HasSuffix(name, ".tmp"))
		if !keep && (atBoot || stale) {
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
			removed, left = cleanParts(r, window, false)
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

// Orphans is the one pass over shares/, run at boot: a directory named like
// a share id that hasRow denies, untouched for the abandoned-upload window,
// is removed; every other share directory has its stale staging cleaned,
// stage/ keeping only open publishes (cleanStages).
// Names that are not share ids are an operator's business and are left
// alone. The age guard is what makes the pass safe: a share directory is
// born by the first upload after its row exists, so a rowless directory is
// a delete that crashed between the rows and the directory, or an upload
// into a share deleted meanwhile, and either is safe to remove once nothing
// has written to it for the window.
func (f *FS) Orphans(hasRow func(id string) bool) (removed int, err error) {
	sharesDir := filepath.Join(f.dataDir, sharesDirName)
	entries, err := os.ReadDir(sharesDir)
	if err != nil {
		return 0, err
	}
	window := f.AbandonedUploadWindow()
	for _, e := range entries {
		id := e.Name()
		if !e.IsDir() || !shareid.ValidID(id) {
			continue
		}
		if hasRow(id) {
			if r, err := f.root(id); err == nil {
				if _, left := cleanParts(r, window, true); left {
					f.noteStaged(id)
				}
				for pid, st := range cleanStages(r) {
					f.noteStage(id, pid, st)
				}
				r.Close()
			}
			continue
		}
		fi, err := e.Info()
		if err != nil || time.Since(fi.ModTime()) < window {
			continue
		}
		release := f.lockShare(id)
		if os.RemoveAll(filepath.Join(sharesDir, id)) == nil {
			removed++
		}
		release()
	}
	return removed, nil
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
// Orphans has found the open publishes and before the listener starts, and
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
	f.stagesMu.Lock()
	pids := make([]string, 0, len(f.stages[id]))
	for pid := range f.stages[id] {
		pids = append(pids, pid)
	}
	f.stagesMu.Unlock()
	for _, pid := range pids {
		if newest, ok := stageWritten(root, pid); ok && time.Since(newest) < window {
			return true
		}
	}
	return false
}
