package sharefs

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"hyperdrop/server/internal/shareid"
)

// journalHeld reports whether publish pid's commit journal is present,
// readable or not.
func journalHeld(root *os.Root, pid string) bool {
	_, err := root.Lstat(filepath.Join(stageRel(pid), journalName))
	return !errors.Is(err, fs.ErrNotExist)
}

// Journal is a commit's record in stage/<pid>/commit.json: the relpaths it
// makes live, as the commit named them (each staged part is found by its
// relpath's hash, its digest in its .hash sidecar), and the relpaths it
// deletes. It is written and synced before the commit's transaction,
// rewritten with Rows once the transaction has written the rows, and
// removed with the stage after the renames, so one found at boot is a
// commit a crash or a failed rename stopped. A journal with Rows is
// finished path by path; one without is finished only when the rows
// already hold each part's digest, and otherwise dropped, leaving the
// publish open.
type Journal struct {
	Files  []string     `json:"files"`
	Delete []string     `json:"delete"`
	Rows   *JournalRows `json:"rows,omitempty"`
}

// JournalRows marks a journal whose transaction has written its rows: each
// staged relpath with the relpath its row names, and each deleted row's
// relpath, as the transaction spelled them.
type JournalRows struct {
	Renames []Rename `json:"renames"`
	Deleted []string `json:"deleted"`
}

// WriteJournal writes publish pid's commit journal durably, the file and
// its directory synced. It takes no lock: it runs inside WithSwap.
// ErrNoStage when the publish is not open.
func (f *FS) WriteJournal(id, pid string, j Journal) error {
	if !shareid.ValidPublishID(pid) {
		return ErrNoStage
	}
	data, err := json.Marshal(j)
	if err != nil {
		return err
	}
	root, err := f.partRoot(id, partAt{stage: pid})
	if err != nil {
		return err
	}
	defer root.Close()
	if err := replaceFile(root, filepath.Join(stageRel(pid), journalName), data, true); err != nil {
		return f.mapDiskErr(err)
	}
	return nil
}

// ReadJournal reads publish pid's commit journal, false when it has none.
// A journal that does not decode is an error, never an empty commit.
func (f *FS) ReadJournal(id, pid string) (Journal, bool, error) {
	if !shareid.ValidPublishID(pid) {
		return Journal{}, false, ErrNoStage
	}
	root, err := f.root(id)
	if err != nil {
		return Journal{}, false, err
	}
	defer root.Close()
	data, err := root.ReadFile(filepath.Join(stageRel(pid), journalName))
	if errors.Is(err, fs.ErrNotExist) {
		return Journal{}, false, nil
	}
	if err != nil {
		return Journal{}, false, err
	}
	var j Journal
	if err := json.Unmarshal(data, &j); err != nil {
		return Journal{}, false, fmt.Errorf("publish %s: commit journal: %w", pid, err)
	}
	return j, true, nil
}

// RemoveJournal removes publish pid's commit journal, durably; an absent
// one is no error. It takes no lock: it runs inside WithSwap.
func (f *FS) RemoveJournal(id, pid string) error {
	if !shareid.ValidPublishID(pid) {
		return ErrNoStage
	}
	root, err := f.root(id)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.Remove(filepath.Join(stageRel(pid), journalName)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	syncDir(root, stageRel(pid))
	return nil
}

// JournalOverlaps reports whether a commit journal remaining in an open
// publish of the share names a path that one of paths is, sits beneath or
// sits above (compared as the volume compares names): the paths it makes
// live, as sent and as its rows spell them, and the paths it deletes. A
// journal that cannot be read overlaps everything. It takes no lock: a
// caller that must not race a commit's rows runs it in WithSwap's swap
// step.
func (f *FS) JournalOverlaps(id string, paths ...string) bool {
	pids := f.stagePIDs(id)
	keys := make([]string, len(paths))
	for i, p := range paths {
		keys[i] = f.pathKey(p)
	}
	overlaps := func(named string) bool {
		k := f.pathKey(named)
		for _, p := range keys {
			if k == p || strings.HasPrefix(k, p+"/") || strings.HasPrefix(p, k+"/") {
				return true
			}
		}
		return false
	}
	for _, pid := range pids {
		j, held, err := f.ReadJournal(id, pid)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return true
		}
		if !held {
			continue
		}
		named := append(append([]string{}, j.Files...), j.Delete...)
		if j.Rows != nil {
			for _, rn := range j.Rows.Renames {
				named = append(named, rn.To)
			}
			named = append(named, j.Rows.Deleted...)
		}
		for _, n := range named {
			if overlaps(n) {
				return true
			}
		}
	}
	return false
}
