package sharefs

import (
	"os"
	"path/filepath"
	"strings"

	"hyperdrop/server/internal/shareid"
)

// cleanStages removes from stage/ everything but open publishes: a
// directory named like a publish id that holds its owner file. A publish
// directory without one is an OpenStage a crash interrupted; any other
// name (a retired stage, a stray file) is nobody's. It answers the
// publishes it keeps, by id, with their owners, opening times and the
// bytes each part declared (its size, or its ranged total when larger).
// It runs at boot, when nothing writes.
func cleanStages(r *os.Root) map[string]*stageState {
	d, err := r.Open(stageDirName)
	if err != nil {
		return nil
	}
	entries, err := d.ReadDir(-1)
	d.Close()
	if err != nil {
		return nil
	}
	kept := map[string]*stageState{}
	for _, e := range entries {
		if e.IsDir() && shareid.ValidPublishID(e.Name()) {
			if o, ok := readStageOwner(r, e.Name()); ok {
				kept[e.Name()] = &stageState{owner: o.Owner, created: o.Created, declared: stagedDeclarations(r, e.Name())}
				continue
			}
		}
		r.RemoveAll(filepath.Join(stageDirName, e.Name()))
	}
	return kept
}

// stagedDeclarations reads the bytes each part of publish pid declares,
// by part name: its size, or the total its ranges record when larger.
func stagedDeclarations(r *os.Root, pid string) map[string]int64 {
	out := map[string]int64{}
	d, err := r.Open(stageRel(pid))
	if err != nil {
		return out
	}
	entries, err := d.ReadDir(-1)
	d.Close()
	if err != nil {
		return out
	}
	for _, e := range entries {
		if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), ".part") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		n := fi.Size()
		if st, ok := readRanges(r, filepath.Join(stageRel(pid), e.Name())); ok && st.Total > n {
			n = st.Total
		}
		out[e.Name()] = n
	}
	return out
}
