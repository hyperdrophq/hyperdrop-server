package sharefs

import "time"

// OpenPublishes counts the publishes owner has open across every share.
func (f *FS) OpenPublishes(owner string) int {
	f.stagesMu.Lock()
	defer f.stagesMu.Unlock()
	n := 0
	for _, pids := range f.stages {
		for _, st := range pids {
			if st.owner == owner {
				n++
			}
		}
	}
	return n
}

// StagedBytes answers the bytes owner's uploads hold across every share as
// each declared them, its open publishes' staged paths and its plain ranged
// parts: what the quota charges beside the committed bytes until a stage is
// committed, aborted or swept, or a part committed or discarded. A part no
// chunk reached for the abandoned window is the stalled sweep's and is no
// longer charged, so a removal this ledger was not told of corrects itself. A
// restart forgets the plain parts' charges: a part staged before it is charged
// again only when its upload starts over.
func (f *FS) StagedBytes(owner string) int64 {
	f.stagesMu.Lock()
	defer f.stagesMu.Unlock()
	n, _ := f.stagedLocked(owner)
	return n
}

// stagedLocked is StagedBytes, with what each share's plain ranged parts make of
// it. The caller holds stagesMu.
func (f *FS) stagedLocked(owner string) (int64, map[string]int64) {
	var n int64
	for _, pids := range f.stages {
		for _, st := range pids {
			if st.owner == owner {
				for _, b := range st.declared {
					n = addSat(n, b)
				}
			}
		}
	}
	byShare := map[string]int64{}
	cutoff := time.Now().Add(-f.AbandonedUploadWindow())
	for k, c := range f.parts {
		switch {
		case c.touched.Before(cutoff):
			delete(f.parts, k)
		case c.owner == owner:
			n = addSat(n, c.total)
			byShare[k.id] = addSat(byShare[k.id], c.total)
		}
	}
	return n, byShare
}

// QuotaHeld answers all that owner holds of its quota beyond committed bytes:
// its tiles and posters (SidecarBytes), StagedBytes, and what each share's live
// reservation promises past its parts, which draw on that same promise. The
// reservation of except is left out: the upload asking is the one it was made
// for, and it charges its own bytes.
func (f *FS) QuotaHeld(owner, except string) int64 {
	reserved := map[string]int64{}
	f.resMu.Lock()
	for id, r := range f.reservations {
		if id != except && r.owner == owner && r.live() {
			reserved[id] = r.bytes
		}
	}
	f.resMu.Unlock()
	f.stagesMu.Lock()
	defer f.stagesMu.Unlock()
	n, parts := f.stagedLocked(owner)
	for id, bytes := range reserved {
		n = addSat(n, max(bytes-parts[id], 0))
	}
	return addSat(n, f.SidecarBytes(owner))
}

// ChargePart records that a fresh ranged part of rel holds total bytes of
// owner's quota, replacing what the path's earlier part was charged. An
// anonymous upload is never charged: it stages through Write, its bytes
// discarded with a body that ends early, so a stalled stranger reserves nothing
// of the owner's quota.
func (f *FS) ChargePart(id, rel, owner string, total int64) {
	f.stagesMu.Lock()
	defer f.stagesMu.Unlock()
	if f.parts == nil {
		f.parts = map[partKey]partCharge{}
	}
	f.parts[partKey{id, partName(rel)}] = partCharge{owner: owner, total: total, touched: time.Now()}
}

// PartCharge answers what rel's plain ranged part is charged, 0 when it is not.
func (f *FS) PartCharge(id, rel string) int64 {
	f.stagesMu.Lock()
	defer f.stagesMu.Unlock()
	return f.parts[partKey{id, partName(rel)}].total
}

// touchPartCharge keeps a part a chunk reached out of the abandoned window.
func (f *FS) touchPartCharge(id, rel string) {
	f.stagesMu.Lock()
	defer f.stagesMu.Unlock()
	k := partKey{id, partName(rel)}
	if c, ok := f.parts[k]; ok {
		c.touched = time.Now()
		f.parts[k] = c
	}
}

// releasePartCharge forgets rel's plain ranged part once its bytes left it.
func (f *FS) releasePartCharge(id, rel string) {
	f.stagesMu.Lock()
	defer f.stagesMu.Unlock()
	delete(f.parts, partKey{id, partName(rel)})
}

// releaseShareCharges forgets every plain ranged part of a deleted share.
func (f *FS) releaseShareCharges(id string) {
	f.stagesMu.Lock()
	defer f.stagesMu.Unlock()
	for k := range f.parts {
		if k.id == id {
			delete(f.parts, k)
		}
	}
}

// StagedDeclared answers the bytes rel declared in publish pid, 0 when it
// declared none.
func (f *FS) StagedDeclared(id, pid, rel string) int64 {
	f.stagesMu.Lock()
	defer f.stagesMu.Unlock()
	if st := f.stages[id][pid]; st != nil {
		return st.declared[partName(rel)]
	}
	return 0
}

// declareStaged records bytes for rel in publish pid, before its bytes
// arrive: ErrStageFull when rel is a new path and the publish already
// stages its most, ErrNoStage when the publish is not open. undo forgets a
// path this call added, for a write that then fails.
func (f *FS) declareStaged(id, pid, rel string, bytes int64) (undo func(), err error) {
	f.stagesMu.Lock()
	defer f.stagesMu.Unlock()
	st := f.stages[id][pid]
	if st == nil {
		return nil, ErrNoStage
	}
	name := partName(rel)
	if _, held := st.declared[name]; held {
		st.declared[name] = bytes
		return func() {}, nil
	}
	if len(st.declared) >= f.stageMaxFiles() {
		return nil, ErrStageFull
	}
	st.declared[name] = bytes
	return func() { f.undeclareStaged(id, pid, rel) }, nil
}

// undeclareStaged forgets rel's declared bytes in publish pid.
func (f *FS) undeclareStaged(id, pid, rel string) {
	f.stagesMu.Lock()
	defer f.stagesMu.Unlock()
	if st := f.stages[id][pid]; st != nil {
		delete(st.declared, partName(rel))
	}
}

// stageExpired reports whether publish pid of share id opened longer ago
// than the stage lifetime.
func (f *FS) stageExpired(id, pid string) bool {
	f.stagesMu.Lock()
	defer f.stagesMu.Unlock()
	st := f.stages[id][pid]
	return st != nil && time.Since(st.created) > f.stageLifetime()
}

// noteStage records publish pid open on share id.
func (f *FS) noteStage(id, pid string, st *stageState) {
	f.stagesMu.Lock()
	defer f.stagesMu.Unlock()
	if f.stages == nil {
		f.stages = map[string]map[string]*stageState{}
	}
	if f.stages[id] == nil {
		f.stages[id] = map[string]*stageState{}
	}
	f.stages[id][pid] = st
}

// forgetStage drops publish pid of share id from the open publishes. Every
// removal of a stage directory calls it once the directory is gone.
func (f *FS) forgetStage(id, pid string) {
	f.stagesMu.Lock()
	defer f.stagesMu.Unlock()
	delete(f.stages[id], pid)
	if len(f.stages[id]) == 0 {
		delete(f.stages, id)
	}
}

// forgetShareStages drops every open publish of share id, whose directory
// is gone.
func (f *FS) forgetShareStages(id string) {
	f.stagesMu.Lock()
	defer f.stagesMu.Unlock()
	delete(f.stages, id)
}

// HasOpenPublish reports whether the share has a publish open: its staged
// files are uploads still under way, which a duplicate must wait for.
func (f *FS) HasOpenPublish(id string) bool {
	f.stagesMu.Lock()
	defer f.stagesMu.Unlock()
	return len(f.stages[id]) > 0
}

// stagePIDs answers the ids of the share's open publishes.
func (f *FS) stagePIDs(id string) []string {
	f.stagesMu.Lock()
	defer f.stagesMu.Unlock()
	pids := make([]string, 0, len(f.stages[id]))
	for pid := range f.stages[id] {
		pids = append(pids, pid)
	}
	return pids
}
