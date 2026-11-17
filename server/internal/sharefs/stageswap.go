package sharefs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"hyperdrop/server/internal/shareid"
)

// WithSwap runs a publish's commit in two steps: holding the locks of
// paths exclusively (each folded on a volume that folds case, taken once
// per key, in sorted order, so two commits never deadlock), then the share
// lock shared, it runs prepare; then, prepare having answered nil, it takes
// the share's swap lock exclusively and runs swap. The locks are released
// in reverse after swap, or after prepare when it fails. Under the path
// locks no upload, chunk, finish or removal of those paths runs; under the
// share lock RemoveShare waits; under the swap lock no visitor's read
// straddles swap's renames. prepare holds the reads and syncs that take
// time (StagedFiles, the journal), so visitors wait only for swap: the
// transaction, the renames (SwapIn) and RetireStageLocked. The swap lock
// is apart from the share lock, so readers never queue behind an
// unrelated upload's long hashing. A nil prepare is no step. Neither step
// may call anything that takes one of these locks again.
func (f *FS) WithSwap(id string, paths []string, prepare, swap func() error) error {
	if !shareid.ValidID(id) {
		return ErrNotFound
	}
	keys := make([]string, 0, len(paths))
	for _, rel := range paths {
		if !shareid.ValidRelPath(rel) {
			return ErrBadPath
		}
		keys = append(keys, f.pathKey(rel))
	}
	slices.Sort(keys)
	keys = slices.Compact(keys)
	for _, k := range keys {
		l, done := f.pathLocks.acquire(id + "\x00" + k)
		l.mu.Lock()
		defer func() { l.mu.Unlock(); done() }()
	}
	release := f.rlockShare(id)
	defer release()
	if prepare != nil {
		if err := prepare(); err != nil {
			return err
		}
	}
	l, done := f.swapLocks.acquire(id)
	l.Lock()
	defer func() { l.Unlock(); done() }()
	return swap()
}

// ReadSwapped runs fn holding the share's swap lock shared: a visitor's
// read of a file's row and the open of its bytes, so the two come from the
// same side of a commit. fn must not transfer the bytes (an open
// descriptor keeps the version it opened) and must not take the swap lock
// again.
func (f *FS) ReadSwapped(id string, fn func() error) error {
	if !shareid.ValidID(id) {
		return ErrNotFound
	}
	l, done := f.swapLocks.acquire(id)
	l.RLock()
	defer func() { l.RUnlock(); done() }()
	return fn()
}

// SwapIn moves a committed publish's bytes into place: each removed
// path's stored file goes (its emptied folders pruned), then each staged
// part is renamed over its row's files/<relpath>, parents created and
// bytes no row names cleared from its way (clearWay). Removals
// go first so a path can turn from a file into a folder or back in one
// publish. The rows are already written, so a failure does not stop the
// rest; every failure is returned. It takes no lock: it runs in
// WithSwap's swap step, whose paths name every From, To and removed path. Running it again is safe: a
// part already renamed into place and a file already removed are done.
// Gallery tiles are the caller's (RemoveThumb).
func (f *FS) SwapIn(id, pid string, renames []Rename, removes []string) error {
	if !shareid.ValidPublishID(pid) {
		return ErrNoStage
	}
	for _, rn := range renames {
		if !shareid.ValidRelPath(rn.From) || !shareid.ValidRelPath(rn.To) {
			return ErrBadPath
		}
	}
	for _, rel := range removes {
		if !shareid.ValidRelPath(rel) {
			return ErrBadPath
		}
	}
	root, err := f.root(id)
	if err != nil {
		return err
	}
	defer root.Close()
	var errs []error
	dirs := map[string]bool{}
	for _, rel := range removes {
		if err := root.Remove(fileRel(rel)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, fmt.Errorf("removing %s: %w", rel, err))
			continue
		}
		dirs[filepath.Dir(fileRel(rel))] = true
		dirs[filesDirName] = true
		pruneEmptyParents(root, rel)
	}
	for _, rn := range renames {
		part, final := stagedPartRel(pid, rn.From), fileRel(rn.To)
		if _, err := root.Lstat(part); errors.Is(err, fs.ErrNotExist) {
			if fi, err := root.Lstat(final); err == nil && fi.Mode().IsRegular() {
				continue
			}
			errs = append(errs, fmt.Errorf("%w: %s is neither staged nor stored", ErrNotFound, rn.From))
			continue
		}
		if err := clearWay(root, rn.To); err != nil {
			errs = append(errs, fmt.Errorf("clearing the way to %s: %w", rn.To, err))
			continue
		}
		if err := root.MkdirAll(filepath.Dir(final), 0o700); err != nil {
			errs = append(errs, f.mapDiskErr(pathErr(err)))
			continue
		}
		if err := root.Rename(part, final); err != nil {
			errs = append(errs, f.mapDiskErr(pathErr(err)))
			continue
		}
		dirs[filepath.Dir(final)] = true
	}
	for d := range dirs {
		syncDir(root, d)
	}
	syncDir(root, stageRel(pid))
	return errors.Join(errs...)
}

// clearWay removes, inside the share root, what stands in the way of a
// file renamed to files/<rel> and that no row names: a non-directory at
// one of rel's ancestors, and a directory at rel itself. The rows of a
// committed publish hold a stored file at rel, so they hold none at any
// ancestor and none beneath it; such bytes are left by a removal whose
// rows went and whose bytes stayed.
func clearWay(root *os.Root, rel string) error {
	segs := strings.Split(rel, "/")
	for i := 1; i < len(segs); i++ {
		anc := fileRel(strings.Join(segs[:i], "/"))
		fi, err := root.Lstat(anc)
		if errors.Is(err, fs.ErrNotExist) {
			break
		}
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			if err := root.Remove(anc); err != nil {
				return err
			}
			break
		}
	}
	if fi, err := root.Lstat(fileRel(rel)); err == nil && fi.IsDir() {
		return root.RemoveAll(fileRel(rel))
	}
	return nil
}
