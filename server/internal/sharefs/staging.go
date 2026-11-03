package sharefs

import (
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"hyperdrop/server/internal/bytefmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"

	"hyperdrop/server/internal/shareid"
)

// openPart opens a staged part with flag. A plain upload's parts/ is
// created as needed and the share noted for SweepStaleParts; every caller
// holds the share's lock shared, which is what keeps the note and the
// sweep's forgetting of a share from crossing. A publish's stage directory
// is never created here, only by OpenStage, so a write racing RemoveStage
// fails rather than bringing the stage back.
func (f *FS) openPart(r *os.Root, id string, p partAt, flag int) (*os.File, error) {
	if p.stage == "" {
		if err := r.MkdirAll(partsDirName, 0o700); err != nil {
			return nil, err
		}
		f.noteStaged(id)
	}
	return r.OpenFile(p.path, flag, 0o600)
}

// removePart discards a staged part and its sidecars, best effort. A
// publish's record (.path) goes first, so it never outlives the bytes it
// describes.
func removePart(r *os.Root, part string) {
	r.Remove(part + partPathExt)
	r.Remove(part)
	r.Remove(part + partHashExt)
	r.Remove(part + partSessionExt)
	r.Remove(part + partRangesExt)
	r.Remove(part + partPrevExt)
}

// stagePart holds the share lock in shared mode for exactly the steps that can recreate
// its directory tree, the root and the part's open, and hands both back
// with the lock already released: the copy that follows holds nothing, so a
// RemoveShare never waits behind a multi-GB body. Anything staged for the
// path goes first, the fresh body replacing it. A publish's part needs its
// stage open (ErrNoStage otherwise) and holding no commit journal
// (ErrStageCommitting).
func (f *FS) stagePart(id string, p partAt) (*os.Root, *os.File, error) {
	release := f.rlockShare(id)
	defer release()
	root, err := f.writablePartRoot(id, p)
	if err != nil {
		return nil, nil, err
	}
	removePart(root, p.path)
	dst, err := f.openPart(root, id, p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		root.Close()
		return nil, nil, f.mapDiskErr(err)
	}
	return root, dst, nil
}

// copyToFile copies src into f, then syncs and closes it, mapping ENOSPC to
// ErrDiskFull. Callers decide the part's fate on error.
func (f *FS) copyToFile(dst *os.File, src io.Reader) (int64, error) {
	n, err := CopyBuffer(dst, src)
	if err == nil {
		err = dst.Sync()
	}
	if closeErr := dst.Close(); err == nil {
		err = closeErr
	}
	return n, f.mapDiskErr(err)
}

// diskFullErr wraps ErrDiskFull with the reserve; the API sends err.Error()
// to clients verbatim.
func (f *FS) diskFullErr() error {
	switch {
	case f.ReservePercent == FlatReserve:
		return fmt.Errorf("%w: the server keeps up to %s of disk in reserve", ErrDiskFull, bytefmt.Decimal(reserveFloorBytes))
	case f.ReservePercent > 0:
		return fmt.Errorf("%w: the server keeps %d%% of disk in reserve", ErrDiskFull, f.ReservePercent)
	}
	return ErrDiskFull
}

// Write stages a whole body for rel, replacing any staged part and its
// sidecars, hashing as it copies so Commit needs no second read. Returns the
// bytes written. A failed copy discards the part: a one-shot body has no
// resume state worth keeping.
//
// The share's lock is held shared only while the part opens, never across the copy,
// so a delete of the share does not wait for the body. A RemoveShare that
// wins that race unlinks the part, the copy finishes into an unlinked
// inode, the digest sidecar's write fails harmlessly and the Commit that
// follows answers ErrNotFound through root.
func (f *FS) Write(id, rel string, r io.Reader) (int64, error) {
	if !shareid.ValidNewRelPath(rel) {
		return 0, ErrBadPath
	}
	unlock := f.lockPath(id, rel)
	defer unlock()
	p := plainPart(rel)
	root, dst, err := f.stagePart(id, p)
	if err != nil {
		return 0, err
	}
	defer root.Close()
	h := sha256.New()
	n, err := f.copyToFile(dst, io.TeeReader(f.landing(id, r), h))
	if err != nil {
		removePart(root, p.path)
		return 0, err
	}
	savePartDigest(root, p.path, h, n)
	return n, nil
}

// PartSize reports how many bytes of rel's upload are staged, 0 when none:
// the received bytes of a ranged part, the part's length otherwise.
func (f *FS) PartSize(id, rel string) (int64, error) {
	if !shareid.ValidRelPath(rel) {
		return 0, ErrBadPath
	}
	root, err := f.root(id)
	if errors.Is(err, ErrNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer root.Close()
	fi, err := root.Stat(partRel(rel))
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	// A ranged part is sparse: its length is the furthest byte written, not
	// how many arrived. Its recorded ranges plus the chunks still arriving
	// are what has arrived, never more than the file's size (a chunk sent
	// again over recorded bytes counts them twice while it arrives).
	if st, ok := readRanges(root, partRel(rel)); ok {
		n := receivedBytes(st.Have) + f.inflight.get(inflightKey(id, rel))
		if st.Total > 0 && n > st.Total {
			n = st.Total
		}
		return n, nil
	}
	return fi.Size(), nil
}

// PartAge reports how long ago rel's staged part was last written, and
// false when nothing is staged. The stalled sweep asks it per candidate.
func (f *FS) PartAge(id, rel string) (time.Duration, bool) {
	if !shareid.ValidRelPath(rel) {
		return 0, false
	}
	root, err := f.root(id)
	if err != nil {
		return 0, false
	}
	defer root.Close()
	fi, err := root.Stat(partRel(rel))
	if err != nil {
		return 0, false
	}
	return time.Since(fi.ModTime()), true
}

// Discard removes rel's staged part and sidecars. Absent is fine.
func (f *FS) Discard(id, rel string) {
	if !shareid.ValidRelPath(rel) {
		return
	}
	unlock := f.lockPath(id, rel)
	defer unlock()
	root, err := f.root(id)
	if err != nil {
		return
	}
	defer root.Close()
	removePart(root, partRel(rel))
}

// HasRecentPart reports whether anything staged in the share was written
// within window: a part in parts/, the resume state of a live upload, or
// an open publish (its directory or a file in it), a site being built.
// Either keeps an otherwise empty share from the empty sweep.
func (f *FS) HasRecentPart(id string, window time.Duration) bool {
	root, err := f.root(id)
	if err != nil {
		return false
	}
	defer root.Close()
	if f.recentStage(root, id, window) {
		return true
	}
	d, err := root.Open(partsDirName)
	if err != nil {
		return false
	}
	defer d.Close()
	entries, err := d.ReadDir(-1)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".part") {
			continue
		}
		if fi, err := e.Info(); err == nil && time.Since(fi.ModTime()) < window {
			return true
		}
	}
	return false
}

// The session sidecar: <part>.session records which client upload session
// staged a ranged part. Not an optimization: it is the identity check that
// stops one session's chunks landing in another's part, so a missing or
// unreadable sidecar reads as the empty session, which matches no session
// a client may send.

func readPartSession(r *os.Root, part string) string {
	data, err := r.ReadFile(part + partSessionExt)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// The digest sidecar: <part>.hash keeps the SHA-256 Write computed while
// it copied, so the Commit that follows needs no second read, as an 8-byte
// big-endian count of the bytes hashed plus the digest's marshaled state.
// Purely an optimization: anything off about it makes Commit hash the part
// from disk.

// loadPartDigest restores the digest covering exactly count bytes, or nil
// (dropping the sidecar) when there is no matching state.
func loadPartDigest(r *os.Root, part string, count int64) hash.Hash {
	side := part + partHashExt
	data, err := r.ReadFile(side)
	if err != nil {
		return nil
	}
	h := digestState(data, count)
	if h == nil {
		r.Remove(side)
	}
	return h
}

// digestState decodes a digest sidecar's content, nil unless it covers
// exactly count bytes.
func digestState(data []byte, count int64) hash.Hash {
	h := sha256.New()
	if len(data) < 8 || int64(binary.BigEndian.Uint64(data)) != count ||
		h.(encoding.BinaryUnmarshaler).UnmarshalBinary(data[8:]) != nil {
		return nil
	}
	return h
}

// encodeDigest is a digest sidecar's content: the digest state covering
// count bytes.
func encodeDigest(h hash.Hash, count int64) ([]byte, error) {
	state, err := h.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 8, 8+len(state))
	binary.BigEndian.PutUint64(buf, uint64(count))
	return append(buf, state...), nil
}

// savePartDigest persists the digest state as covering count bytes. Best
// effort: on any failure the sidecar is removed, never half-written.
func savePartDigest(r *os.Root, part string, h hash.Hash, count int64) {
	side := part + partHashExt
	data, err := encodeDigest(h, count)
	if err != nil || r.WriteFile(side, data, 0o600) != nil {
		r.Remove(side)
	}
}
