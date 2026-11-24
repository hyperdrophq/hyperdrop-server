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
	"strings"

	"hyperdrop/server/internal/mimetype"
	"hyperdrop/server/internal/shareid"
)

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

// WriteRangeStaged is WriteRange into publish pid: the part and its
// sidecars in stage/<pid>/, and no row declared, so nothing outside the
// publish sees the upload. A chunk of a part FinishStaged has recorded
// writes nothing and answers the upload complete; a chunk under another
// session or total starts the path's part again, as WriteRange does.
// ErrNoStage when the publish is not open.
func (f *FS) WriteRangeStaged(id, pid, rel string, r io.Reader, rg Range, total int64, session string) (RangeState, error) {
	if !uploadable(rel) {
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
	if !uploadable(rel) {
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
	part := stagedPart(pid, rel)
	root, err := f.writablePartRoot(id, part)
	if err != nil {
		return
	}
	defer root.Close()
	removePart(root, part.path)
	f.undeclareStaged(id, pid, rel)
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
