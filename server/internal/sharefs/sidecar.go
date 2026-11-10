package sharefs

import "os"

// sidecarCount is what one share's tiles and poster occupy, and its owner.
type sidecarCount struct {
	owner string
	bytes int64
}

// SidecarBytes answers what owner's tiles and posters occupy across its shares,
// which the quota charges beside the committed bytes (QuotaHeld).
//
// The count lives in memory and comes from the disk: a row would mean a durable
// commit per tile, which a tile's own write skips on purpose (SetThumb), and the
// disk is what a rollback to an older server leaves correct. A process learns it
// from RecountSidecars, so until the first housekeeping pass after a start this
// answers low, and the quota is lenient by that much. A delta landing during a
// share's recount can be lost until the next pass, by at most one tile's size.
func (f *FS) SidecarBytes(owner string) int64 {
	f.sidecarMu.Lock()
	defer f.sidecarMu.Unlock()
	var n int64
	for _, c := range f.sidecars {
		if c.owner == owner {
			n = addSat(n, c.bytes)
		}
	}
	return n
}

// RecountSidecars sets what share id's tiles and poster occupy from the disk. A
// share with no directory holds none.
func (f *FS) RecountSidecars(id, owner string) {
	var n int64
	if entries, err := f.thumbEntries(id); err == nil {
		for _, e := range entries {
			if fi, err := e.Info(); err == nil && fi.Mode().IsRegular() {
				n = addSat(n, fi.Size())
			}
		}
	}
	if root, err := f.root(id); err == nil {
		n = addSat(n, regularSize(root, posterFileName))
		root.Close()
	}
	f.sidecarMu.Lock()
	defer f.sidecarMu.Unlock()
	f.setSidecarLocked(id, owner, n)
}

// admitSidecar asks SidecarRoom for what writing size bytes over rel adds, and
// answers that change for noteSidecar once the write lands.
func (f *FS) admitSidecar(root *os.Root, id, owner, rel string, size int64) (int64, error) {
	delta := size - regularSize(root, rel)
	if delta > 0 && f.SidecarRoom != nil {
		if err := f.SidecarRoom(id, owner, delta); err != nil {
			return 0, err
		}
	}
	return delta, nil
}

// noteSidecar moves share id's count by delta. owner is "" for a removal, which
// does not know it: a share with no count yet has nothing to take from, and its
// recount reads what is left.
func (f *FS) noteSidecar(id, owner string, delta int64) {
	f.sidecarMu.Lock()
	defer f.sidecarMu.Unlock()
	c, ok := f.sidecars[id]
	if owner == "" {
		if !ok {
			return
		}
		owner = c.owner
	}
	f.setSidecarLocked(id, owner, max(c.bytes+delta, 0))
}

func (f *FS) setSidecarLocked(id, owner string, bytes int64) {
	if bytes == 0 {
		delete(f.sidecars, id)
		return
	}
	if f.sidecars == nil {
		f.sidecars = map[string]sidecarCount{}
	}
	f.sidecars[id] = sidecarCount{owner: owner, bytes: bytes}
}

// forgetSidecars drops a deleted share's count.
func (f *FS) forgetSidecars(id string) {
	f.sidecarMu.Lock()
	defer f.sidecarMu.Unlock()
	delete(f.sidecars, id)
}

// regularSize is the size of the regular file at rel, 0 for anything else.
func regularSize(root *os.Root, rel string) int64 {
	fi, err := root.Lstat(rel)
	if err != nil || !fi.Mode().IsRegular() {
		return 0
	}
	return fi.Size()
}
