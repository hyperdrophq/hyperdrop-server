package sharefs

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"hyperdrop/server/internal/shareid"
)

// A publish stages its uploads in the share's stage/<pid>/ directory: the
// same hashed part name and sidecars a plain upload keeps in parts/, never
// a row. stage/<pid>/owner marks the publish open; a finished part carries
// .hash (the digest of every byte) and .path (its relpath and type), which
// the commit reads through StagedFiles. The commit renames the parts into
// files/ with SwapIn in WithSwap's swap step, which then retires the stage
// (RetireStageLocked) for PurgeStage to remove once every lock is
// released; RemoveStage does both at once.

// Staged is a finished staged upload: what a publish's commit makes live.
type Staged struct {
	Path   string
	Size   int64
	SHA256 string
	Mime   string
}

// Rename is one staged upload a commit makes live: From is the relpath it
// was staged under, To the relpath its row names (the database's spelling,
// which keeps a stored file's on a volume that folds case).
type Rename struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// ErrNoStage answers a staged write, finish or listing for a publish that
// is not open on the share: never opened, removed, or not a publish id.
var ErrNoStage = errors.New("no such publish")

// ErrStageFull answers a staged write of a new path into a publish that
// already stages its most paths (DefaultStageMaxFiles, FS.StageMaxFiles).
var ErrStageFull = errors.New("the publish holds as many files as it can")

// ErrStageCommitting answers a staged write, finish or discard in a
// publish whose commit journal remains: its rows may already name what is
// staged, so nothing staged changes until the boot pass finishes it.
var ErrStageCommitting = errors.New("the publish is committing")

// stageRel is a publish's directory inside the share root.
func stageRel(pid string) string { return filepath.Join(stageDirName, pid) }

// stagedPartRel is where a relpath's bytes stage inside a publish.
func stagedPartRel(pid, rel string) string { return filepath.Join(stageDirName, pid, partName(rel)) }

// stageOwner is the content of stage/<pid>/owner.
type stageOwner struct {
	Owner   string    `json:"owner"`
	Created time.Time `json:"created"`
}

// stageState is an open publish as the FS keeps it in memory: its owner,
// when it opened, and the bytes each staged path declared, by part name
// (a whole write's size, a ranged upload's total), which the quota counts
// until the stage goes.
type stageState struct {
	owner    string
	created  time.Time
	declared map[string]int64
}

// stagedRecord is the content of a finished part's .path sidecar.
type stagedRecord struct {
	Path string `json:"path"`
	Mime string `json:"mime"`
}

// stageOpen reports whether pid is an open publish in the share: its
// directory holds its owner file.
func stageOpen(root *os.Root, pid string) bool {
	fi, err := root.Lstat(filepath.Join(stageRel(pid), stageOwnerName))
	return err == nil && fi.Mode().IsRegular()
}

// OpenStage opens publish pid on the share: stage/<pid>/ and its owner
// file, holding owner and the time, written durably last, so a directory
// without one is an interrupted open the boot pass removes.
func (f *FS) OpenStage(id, pid, owner string) error {
	if !shareid.ValidPublishID(pid) {
		return ErrBadPath
	}
	if owner == "" {
		return fmt.Errorf("%w: a publish needs an owner", ErrBadRequest)
	}
	release := f.rlockShare(id)
	defer release()
	root, err := f.ensureRoot(id)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.MkdirAll(stageDirName, 0o700); err != nil {
		return f.mapDiskErr(err)
	}
	dir := stageRel(pid)
	if err := root.Mkdir(dir, 0o700); err != nil {
		return f.mapDiskErr(err)
	}
	data, err := json.Marshal(stageOwner{Owner: owner, Created: time.Now().UTC()})
	if err == nil {
		err = replaceFile(root, filepath.Join(dir, stageOwnerName), data, true)
	}
	if err != nil {
		root.RemoveAll(dir)
		return f.mapDiskErr(err)
	}
	syncDir(root, stageDirName)
	f.noteStage(id, pid, &stageState{owner: owner, created: time.Now(), declared: map[string]int64{}})
	return nil
}

// StageOwner answers the username that opened publish pid on the share,
// read from its owner file. ErrNoStage when the publish is not open there.
func (f *FS) StageOwner(id, pid string) (string, error) {
	if !shareid.ValidPublishID(pid) {
		return "", ErrNoStage
	}
	root, err := f.root(id)
	if err != nil {
		return "", ErrNoStage
	}
	defer root.Close()
	o, ok := readStageOwner(root, pid)
	if !ok {
		return "", ErrNoStage
	}
	return o.Owner, nil
}

// readStageOwner reads publish pid's owner file: false unless it is a
// regular file naming an owner.
func readStageOwner(root *os.Root, pid string) (stageOwner, bool) {
	if !stageOpen(root, pid) {
		return stageOwner{}, false
	}
	data, err := root.ReadFile(filepath.Join(stageRel(pid), stageOwnerName))
	if err != nil {
		return stageOwner{}, false
	}
	var o stageOwner
	if json.Unmarshal(data, &o) != nil || o.Owner == "" {
		return stageOwner{}, false
	}
	return o, true
}

// StageExists reports whether pid is an open publish on the share.
func (f *FS) StageExists(id, pid string) bool {
	if !shareid.ValidPublishID(pid) {
		return false
	}
	root, err := f.root(id)
	if err != nil {
		return false
	}
	defer root.Close()
	return stageOpen(root, pid)
}

// RemoveStage removes publish pid and everything staged in it: the stage
// is retired, then purged. A publish that is not there is no error. It
// takes the share lock shared, so it must not run inside WithSwap: there
// RetireStageLocked retires the stage, and PurgeStage removes it after.
func (f *FS) RemoveStage(id, pid string) error {
	if !shareid.ValidPublishID(pid) {
		return ErrBadPath
	}
	release := f.rlockShare(id)
	defer release()
	return f.removeStage(id, pid)
}

// RetireStageLocked closes publish pid in WithSwap's swap step, which
// already holds the share lock shared: it takes no lock (taking that lock a
// second time would deadlock behind a RemoveShare waiting for it). Its
// directory, journal included, is renamed to stage/.<pid>, a name no
// publish id can have, so a staged write racing it finds no stage and
// fails instead of creating a file in it. One rename and one directory
// sync: removing what was staged is PurgeStage's, after every lock is
// released. A publish that is not there is no error.
func (f *FS) RetireStageLocked(id, pid string) error {
	if !shareid.ValidPublishID(pid) {
		return ErrBadPath
	}
	return f.retireStage(id, pid)
}

// PurgeStage removes stage/.<pid>, what retiring publish pid left. It
// takes no lock: no write reaches a retired stage, and the boot pass
// removes one a crash leaves (cleanStages).
func (f *FS) PurgeStage(id, pid string) error {
	if !shareid.ValidPublishID(pid) {
		return ErrBadPath
	}
	root, err := f.root(id)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	defer root.Close()
	return root.RemoveAll(retiredStageRel(pid))
}

// retiredStageRel is where a retired publish waits for its purge.
func retiredStageRel(pid string) string { return filepath.Join(stageDirName, "."+pid) }

// removeStage is RemoveStage's work, under the share lock the caller holds.
func (f *FS) removeStage(id, pid string) error {
	if err := f.retireStage(id, pid); err != nil {
		return err
	}
	return f.PurgeStage(id, pid)
}

// retireStage is RetireStageLocked's work.
func (f *FS) retireStage(id, pid string) error {
	root, err := f.root(id)
	if errors.Is(err, ErrNotFound) {
		f.forgetStage(id, pid)
		return nil
	}
	if err != nil {
		return err
	}
	defer root.Close()
	doomed := retiredStageRel(pid)
	if _, err := root.Lstat(doomed); err == nil {
		if err := root.RemoveAll(doomed); err != nil {
			return err
		}
	}
	if err := root.Rename(stageRel(pid), doomed); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			f.forgetStage(id, pid)
			return nil
		}
		return err
	}
	syncDir(root, stageDirName)
	f.forgetStage(id, pid)
	return nil
}
