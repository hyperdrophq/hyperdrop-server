package sharefs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"hyperdrop/server/internal/mimetype"
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

// partRoot opens the share root a part is written in: created on a plain
// upload's first write, while a publish's part needs the share and its
// stage open already (ErrNoStage).
func (f *FS) partRoot(id string, p partAt) (*os.Root, error) {
	if p.stage == "" {
		return f.ensureRoot(id)
	}
	root, err := f.root(id)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrNoStage
	}
	if err != nil {
		return nil, err
	}
	if !stageOpen(root, p.stage) {
		root.Close()
		return nil, ErrNoStage
	}
	return root, nil
}

// writablePartRoot is partRoot for a write that changes a part: a
// publish's part also needs its stage free of a commit journal
// (ErrStageCommitting). It runs under the part's path lock, which a
// commit holds exclusively while it writes the journal, so no write a
// commit names lands after the journal.
func (f *FS) writablePartRoot(id string, p partAt) (*os.Root, error) {
	root, err := f.partRoot(id, p)
	if err != nil || p.stage == "" {
		return root, err
	}
	if journalHeld(root, p.stage) {
		root.Close()
		return nil, ErrStageCommitting
	}
	return root, nil
}

// journalHeld reports whether publish pid's commit journal is present,
// readable or not.
func journalHeld(root *os.Root, pid string) bool {
	_, err := root.Lstat(filepath.Join(stageRel(pid), journalName))
	return !errors.Is(err, fs.ErrNotExist)
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

// StagedBytes answers the bytes owner's open publishes hold across every
// share, as each staged path declared them: what the quota charges beside
// the committed bytes until a stage is committed, aborted or swept.
func (f *FS) StagedBytes(owner string) int64 {
	f.stagesMu.Lock()
	defer f.stagesMu.Unlock()
	var n int64
	for _, pids := range f.stages {
		for _, st := range pids {
			if st.owner == owner {
				for _, b := range st.declared {
					n += b
				}
			}
		}
	}
	return n
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

// WriteRangeStaged is WriteRange into publish pid: the part and its
// sidecars in stage/<pid>/, and no row declared, so nothing outside the
// publish sees the upload. A chunk of a part FinishStaged has recorded
// writes nothing and answers the upload complete; a chunk under another
// session or total starts the path's part again, as WriteRange does.
// ErrNoStage when the publish is not open.
func (f *FS) WriteRangeStaged(id, pid, rel string, r io.Reader, rg Range, total int64, session string) (RangeState, error) {
	if !shareid.ValidNewRelPath(rel) {
		return RangeState{}, ErrBadPath
	}
	if !shareid.ValidPublishID(pid) {
		return RangeState{}, ErrNoStage
	}
	undo, err := f.declareStaged(id, pid, rel, total)
	if err != nil {
		return RangeState{}, err
	}
	st, err := f.writeRange(id, stagedPart(pid, rel), r, rg, total, session, nil)
	if err != nil && !f.partPresent(id, pid, rel) {
		undo()
	}
	return st, err
}

// partPresent reports whether publish pid holds a part for rel.
func (f *FS) partPresent(id, pid, rel string) bool {
	root, err := f.root(id)
	if err != nil {
		return false
	}
	defer root.Close()
	_, err = root.Lstat(stagedPartRel(pid, rel))
	return err == nil
}

// PartRangesStaged is PartRanges inside publish pid.
func (f *FS) PartRangesStaged(id, pid, rel, session string) (RangeState, bool) {
	if !shareid.ValidRelPath(rel) || !shareid.ValidPublishID(pid) {
		return RangeState{}, false
	}
	return f.partRanges(id, stagedPart(pid, rel), session)
}

// WriteStaged is Write into publish pid, finished as it lands: the body
// replaces anything staged for rel there and is recorded as FinishStaged
// records a ranged part, its size declared once it is in. A failed copy
// discards the part. ErrNoStage when the publish is not open, ErrStageFull
// when rel is a new path past the publish's cap.
func (f *FS) WriteStaged(id, pid, rel string, r io.Reader) (Staged, error) {
	if !shareid.ValidNewRelPath(rel) {
		return Staged{}, ErrBadPath
	}
	if !shareid.ValidPublishID(pid) {
		return Staged{}, ErrNoStage
	}
	unlock := f.lockPath(id, rel)
	defer unlock()
	if _, err := f.declareStaged(id, pid, rel, 0); err != nil {
		return Staged{}, err
	}
	p := stagedPart(pid, rel)
	root, dst, err := f.stagePart(id, p)
	if err != nil {
		f.undeclareStaged(id, pid, rel)
		return Staged{}, err
	}
	defer root.Close()
	h := sha256.New()
	n, err := f.copyToFile(dst, io.TeeReader(f.landing(id, r), h))
	if err == nil {
		var s Staged
		if s, err = f.recordStaged(root, p, h, n); err == nil {
			f.declareStaged(id, pid, rel, n)
			return s, nil
		}
	}
	removePart(root, p.path)
	f.undeclareStaged(id, pid, rel)
	if !stageOpen(root, pid) {
		return Staged{}, ErrNoStage
	}
	return Staged{}, err
}

// FinishStaged records session's ranged upload of rel in publish pid once
// every byte of total is in: one read of the part for its digest, its type
// sniffed as a commit sniffs it, then .hash and .path, each synced. It
// never renames. It runs under the path's lock, so no chunk of the part is
// in flight, and a recorded part takes no further chunk. A part already
// recorded answers its record. ErrNotFound when no ranged part of that
// session and total is staged there; ErrBadRequest while ranges are
// missing.
func (f *FS) FinishStaged(id, pid, rel string, session string, total int64) (Staged, error) {
	if !shareid.ValidRelPath(rel) {
		return Staged{}, ErrBadPath
	}
	if !shareid.ValidPublishID(pid) {
		return Staged{}, ErrNoStage
	}
	unlock := f.lockPath(id, rel)
	defer unlock()
	release := f.rlockShare(id)
	defer release()
	p := stagedPart(pid, rel)
	root, err := f.writablePartRoot(id, p)
	if err != nil {
		return Staged{}, err
	}
	defer root.Close()
	st, ok := readRanges(root, p.path)
	fi, serr := root.Lstat(p.path)
	if serr != nil || !fi.Mode().IsRegular() || !ok || st.Total != total || readPartSession(root, p.path) != session {
		return Staged{}, ErrNotFound
	}
	if m := missingRanges(st.Have, total); len(m) > 0 {
		return Staged{}, fmt.Errorf("%w: %d byte ranges still missing", ErrBadRequest, len(m))
	}
	if s, ok := readStagedRecord(root, pid, p.path); ok {
		return s, nil
	}
	if fi.Size() != total {
		return Staged{}, fmt.Errorf("%w: staged %d bytes, expected %d", ErrBadRequest, fi.Size(), total)
	}
	src, err := root.Open(p.path)
	if err != nil {
		return Staged{}, err
	}
	defer src.Close()
	h := sha256.New()
	if _, err := CopyBuffer(h, src); err != nil {
		return Staged{}, err
	}
	return f.recordStaged(root, p, h, total)
}

// recordStaged sniffs a staged part's type and writes its .hash and then
// its .path, each synced: .path is what makes the part finished, so it
// never names a part whose digest is not on disk.
func (f *FS) recordStaged(root *os.Root, p partAt, h hash.Hash, size int64) (Staged, error) {
	src, err := root.Open(p.path)
	if err != nil {
		return Staged{}, err
	}
	mime := mimetype.Detect(src, path.Base(p.rel))
	src.Close()
	digest, err := encodeDigest(h, size)
	if err != nil {
		return Staged{}, err
	}
	if err := replaceFile(root, p.path+partHashExt, digest, true); err != nil {
		return Staged{}, f.mapDiskErr(err)
	}
	rec, err := json.Marshal(stagedRecord{Path: p.rel, Mime: mime})
	if err != nil {
		return Staged{}, err
	}
	if err := replaceFile(root, p.path+partPathExt, rec, true); err != nil {
		return Staged{}, f.mapDiskErr(err)
	}
	return Staged{Path: p.rel, Size: size, SHA256: hex.EncodeToString(h.Sum(nil)), Mime: mime}, nil
}

// readStagedRecord reads the record of the part at part in publish pid, and
// false unless it is whole: .path names a valid relpath whose part this
// is, the part is a regular file, and .hash covers exactly its bytes.
func readStagedRecord(root *os.Root, pid, part string) (Staged, bool) {
	data, err := root.ReadFile(part + partPathExt)
	if err != nil {
		return Staged{}, false
	}
	var rec stagedRecord
	if json.Unmarshal(data, &rec) != nil || !shareid.ValidRelPath(rec.Path) || stagedPartRel(pid, rec.Path) != part {
		return Staged{}, false
	}
	fi, err := root.Lstat(part)
	if err != nil || !fi.Mode().IsRegular() {
		return Staged{}, false
	}
	digest, err := root.ReadFile(part + partHashExt)
	if err != nil {
		return Staged{}, false
	}
	h := digestState(digest, fi.Size())
	if h == nil {
		return Staged{}, false
	}
	return Staged{Path: rec.Path, Size: fi.Size(), SHA256: hex.EncodeToString(h.Sum(nil)), Mime: rec.Mime}, true
}

// stagedDone reports whether a staged part is recorded as finished.
func stagedDone(root *os.Root, p partAt) bool {
	_, ok := readStagedRecord(root, p.stage, p.path)
	return ok
}

// StagedFile answers the finished upload of rel in publish pid, and false
// when there is none: nothing staged, a part still uploading, or a record
// that does not match its bytes.
func (f *FS) StagedFile(id, pid, rel string) (Staged, bool) {
	if !shareid.ValidRelPath(rel) || !shareid.ValidPublishID(pid) {
		return Staged{}, false
	}
	root, err := f.partRoot(id, partAt{stage: pid})
	if err != nil {
		return Staged{}, false
	}
	defer root.Close()
	return readStagedRecord(root, pid, stagedPartRel(pid, rel))
}

// DiscardStaged removes rel's staged upload from publish pid, part and
// sidecars, under the path's lock. The publish stays open. A publish
// holding a commit journal keeps what is staged.
func (f *FS) DiscardStaged(id, pid, rel string) {
	if !shareid.ValidRelPath(rel) || !shareid.ValidPublishID(pid) {
		return
	}
	unlock := f.lockPath(id, rel)
	defer unlock()
	root, err := f.writablePartRoot(id, stagedPart(pid, rel))
	if err != nil {
		return
	}
	defer root.Close()
	removePart(root, stagedPartRel(pid, rel))
	f.undeclareStaged(id, pid, rel)
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

// StagedFiles answers every finished upload in publish pid, by relpath,
// read from the parts' .path and .hash sidecars. A part still uploading,
// or one whose record does not match its bytes, is not listed.
// ErrNoStage when the publish is not open.
func (f *FS) StagedFiles(id, pid string) (map[string]Staged, error) {
	if !shareid.ValidPublishID(pid) {
		return nil, ErrNoStage
	}
	root, err := f.partRoot(id, partAt{stage: pid})
	if err != nil {
		return nil, err
	}
	defer root.Close()
	d, err := root.Open(stageRel(pid))
	if err != nil {
		return nil, err
	}
	entries, err := d.ReadDir(-1)
	d.Close()
	if err != nil {
		return nil, err
	}
	out := map[string]Staged{}
	for _, e := range entries {
		if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), ".part") {
			continue
		}
		if s, ok := readStagedRecord(root, pid, filepath.Join(stageRel(pid), e.Name())); ok {
			out[s.Path] = s
		}
	}
	return out, nil
}

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

// StagedGone reports whether publish pid holds no part for rel: one a
// commit has renamed into place, or one never staged.
func (f *FS) StagedGone(id, pid, rel string) bool {
	if !shareid.ValidRelPath(rel) || !shareid.ValidPublishID(pid) {
		return false
	}
	root, err := f.root(id)
	if err != nil {
		return false
	}
	defer root.Close()
	_, err = root.Lstat(stagedPartRel(pid, rel))
	return errors.Is(err, fs.ErrNotExist)
}

// JournalOverlaps reports whether a commit journal remaining in an open
// publish of the share names a path that one of paths is, sits beneath or
// sits above (compared as the volume compares names): the paths it makes
// live, as sent and as its rows spell them, and the paths it deletes. A
// journal that cannot be read overlaps everything. It takes no lock: a
// caller that must not race a commit's rows runs it in WithSwap's swap
// step.
func (f *FS) JournalOverlaps(id string, paths ...string) bool {
	f.stagesMu.Lock()
	pids := make([]string, 0, len(f.stages[id]))
	for pid := range f.stages[id] {
		pids = append(pids, pid)
	}
	f.stagesMu.Unlock()
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
