package sharefs

import (
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
// is removed; every other share directory has its stale staging cleaned.
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
