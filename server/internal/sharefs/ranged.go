package sharefs

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"hyperdrop/server/internal/shareid"
)

// ErrPartChanged refuses to record a chunk whose part was replaced while the
// chunk was written (a new session took the path over, or the part was
// swept): its bytes went to a file nobody reads, and the client asks where
// the upload stands and sends again.
var ErrPartChanged = errors.New("the staged upload changed while this chunk was written; ask for the missing ranges")

// errBodyTooLong is a chunk body with bytes past its range.
var errBodyTooLong = fmt.Errorf("%w: body is longer than its Upload-Range", ErrBadRequest)

// MaxRanges bounds the disjoint ranges one ranged upload may hold: every
// chunk rewrites the whole list and the 202 echoes what is missing, so a
// client sending one-byte ranges with gaps between them would cost
// quadratic writes. The reference client's chunks are 8 to 32 MiB, a few
// in flight at once, so it never holds more than a handful. A variable so
// a test can lower it.
var MaxRanges = 4096

// beforeRecord, when set, runs after a chunk's bytes are synced and before
// its range is recorded; an error it returns ends the write there. Tests set
// it to stop a write at the one point where a crash leaves synced bytes the
// sidecar does not name.
var beforeRecord func() error

// WriteRange stages bytes [rg.Start, rg.End) of rel's upload of total bytes
// under session and answers where the upload stands.
//
// Chunks of one upload may arrive in any order and at once: each writes at
// its own offset holding the path's lock SHARED, so they run in parallel,
// and only the step that checks the part and the step that records a range
// take the path's short meta lock. Whole-part operations take the lock
// exclusively and so wait for the chunks in flight.
//
// The part belongs to one session and one total. A chunk under another
// session or another total discards whatever is staged and starts the part
// again, whole-file last-writer-wins; so does a part Write staged, which has
// no ranges sidecar. onCreate runs once
// for a fresh part, before its first byte, under the meta lock: the caller
// declares the file's row there, so a row always precedes the bytes.
//
// A range is recorded only after its bytes are synced. A body that ends
// early records what landed; a body longer than its range records nothing
// and is refused. Complete in the answer tells the caller to commit.
func (f *FS) WriteRange(id, rel string, r io.Reader, rg Range, total int64, session string, onCreate func() error) (RangeState, error) {
	if !shareid.ValidRelPath(rel) {
		return RangeState{}, ErrBadPath
	}
	if total <= 0 || rg.Start < 0 || rg.End > total || rg.Start >= rg.End {
		return RangeState{}, fmt.Errorf("%w: range %d-%d of %d", ErrBadRequest, rg.Start, rg.End, total)
	}
	l, unlock := f.rlockPath(id, rel)
	defer unlock()
	root, dst, ident, err := f.openRangedPart(l, id, rel, total, session, onCreate)
	if err != nil {
		return RangeState{}, err
	}
	defer root.Close()
	// dst stays open until the range is recorded: an open descriptor pins the
	// inode, so a part swapped out meanwhile can never hand its inode number
	// to the fresh part recordRange compares against.
	defer dst.Close()
	// The waiting page counts the chunk's bytes while they arrive; they
	// leave that count just before the range is recorded, so the two never
	// count the same bytes.
	counted := &countingWriter{w: io.NewOffsetWriter(dst, rg.Start), b: &f.inflight, key: inflightKey(id, rel)}
	defer counted.release()
	n, copyErr := CopyBuffer(counted, io.LimitReader(f.touching(id, r), rg.Len()))
	if syncErr := dst.Sync(); syncErr != nil {
		return RangeState{}, f.mapDiskErr(syncErr)
	}
	if copyErr == nil && n == rg.Len() {
		var probe [1]byte
		if m, _ := io.ReadFull(r, probe[:]); m > 0 {
			return RangeState{}, errBodyTooLong
		}
	}
	if beforeRecord != nil {
		if err := beforeRecord(); err != nil {
			return RangeState{}, err
		}
	}
	counted.release()
	st, err := f.recordRange(l, root, rel, ident, session, Range{rg.Start, rg.Start + n})
	if err != nil {
		return RangeState{}, err
	}
	if copyErr != nil {
		return st, f.mapDiskErr(copyErr)
	}
	return st, nil
}

// mapDiskErr turns ENOSPC (no blocks or no inodes left) into ErrDiskFull,
// the error the API words, so every write path answers a full disk with
// 507 no-space rather than a 500. nil stays nil.
func (f *FS) mapDiskErr(err error) error {
	if errors.Is(err, syscall.ENOSPC) {
		return f.diskFullErr()
	}
	return err
}

// openRangedPart keeps a part this session staged for this total, and
// otherwise discards what is staged and starts a fresh one: onCreate, then
// the session and an empty ranges sidecar, then the part. It answers the
// part open for writing and its identity, which recordRange checks.
func (f *FS) openRangedPart(l *pathLock, id, rel string, total int64, session string, onCreate func() error) (*os.Root, *os.File, os.FileInfo, error) {
	l.meta.Lock()
	defer l.meta.Unlock()
	release := f.rlockShare(id)
	defer release()
	root, err := f.ensureRoot(id)
	if err != nil {
		return nil, nil, nil, err
	}
	fail := func(err error) (*os.Root, *os.File, os.FileInfo, error) {
		root.Close()
		return nil, nil, nil, f.mapDiskErr(err)
	}
	st, ranged := readRanges(root, rel)
	_, statErr := root.Stat(partRel(rel))
	if statErr != nil || !ranged || st.Total != total || readPartSession(root, rel) != session {
		removePart(root, rel)
		if onCreate != nil {
			if err := onCreate(); err != nil {
				return fail(err)
			}
		}
		if err := root.MkdirAll(partsDirName, 0o700); err != nil {
			return fail(err)
		}
		if err := root.WriteFile(partRel(rel)+partSessionExt, []byte(session), 0o600); err != nil {
			return fail(err)
		}
		if err := writeRanges(root, rel, rangesState{Total: total, Have: []Range{}}); err != nil {
			return fail(err)
		}
	}
	dst, err := f.openPart(root, id, rel, os.O_CREATE|os.O_WRONLY)
	if err != nil {
		return fail(err)
	}
	ident, err := dst.Stat()
	if err != nil {
		dst.Close()
		return fail(err)
	}
	return root, dst, ident, nil
}

// recordRange adds got to the ranges sidecar when the part is still the one
// the chunk wrote into.
func (f *FS) recordRange(l *pathLock, root *os.Root, rel string, ident os.FileInfo, session string, got Range) (RangeState, error) {
	l.meta.Lock()
	defer l.meta.Unlock()
	fi, err := root.Stat(partRel(rel))
	if err != nil || !os.SameFile(fi, ident) || readPartSession(root, rel) != session {
		return RangeState{}, ErrPartChanged
	}
	st, ok := readRanges(root, rel)
	if !ok {
		return RangeState{}, ErrPartChanged
	}
	if got.Len() > 0 {
		st.Have = addRange(st.Have, got)
		if len(st.Have) > MaxRanges {
			return RangeState{}, fmt.Errorf("%w: the upload holds more than %d separate ranges; send the gaps between them", ErrBadRequest, MaxRanges)
		}
		if err := writeRanges(root, rel, st); err != nil {
			return RangeState{}, f.mapDiskErr(err)
		}
	}
	return stateOf(st), nil
}

// PartRanges answers where session's ranged upload of rel stands, false
// when nothing ranged is staged for that session.
func (f *FS) PartRanges(id, rel, session string) (RangeState, bool) {
	if !shareid.ValidRelPath(rel) {
		return RangeState{}, false
	}
	root, err := f.root(id)
	if err != nil {
		return RangeState{}, false
	}
	defer root.Close()
	if _, err := root.Stat(partRel(rel)); err != nil {
		return RangeState{}, false
	}
	st, ok := readRanges(root, rel)
	if !ok || readPartSession(root, rel) != session {
		return RangeState{}, false
	}
	return stateOf(st), true
}

// CommitRanged commits rel's ranged part the way Commit commits a part
// Write staged, record included, once every byte of total is recorded
// under session. The hash is one read of the assembled part. ErrNotFound when no ranged part of
// that session and total is staged (a sibling chunk committed it first, or
// it was swept); ErrBadRequest while ranges are missing.
func (f *FS) CommitRanged(id, rel string, total int64, session string, record Record) (Committed, error) {
	if !shareid.ValidRelPath(rel) {
		return Committed{}, ErrBadPath
	}
	unlock := f.lockPath(id, rel)
	defer unlock()
	release := f.rlockShare(id)
	defer release()
	root, err := f.root(id)
	if err != nil {
		return Committed{}, err
	}
	defer root.Close()
	st, ok := readRanges(root, rel)
	if _, serr := root.Stat(partRel(rel)); serr != nil || !ok || st.Total != total || readPartSession(root, rel) != session {
		return Committed{}, ErrNotFound
	}
	if m := missingRanges(st.Have, total); len(m) > 0 {
		return Committed{}, fmt.Errorf("%w: %d byte ranges still missing", ErrBadRequest, len(m))
	}
	return f.commitPart(root, rel, total, nil, record)
}
