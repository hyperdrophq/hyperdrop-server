package sharefs

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"syscall"

	"hyperdrop/server/internal/mimetype"
	"hyperdrop/server/internal/shareid"
)

// Committed is what a staged part turned out to be, for the row.
type Committed struct {
	Size   int64
	SHA256 string
	Mime   string
}

// Record writes the row for a part Commit has just renamed into files/. It
// runs under the path's lock, so nothing else at that path (another commit,
// a removal, the stalled sweep) lands between the bytes and their row. An
// error it returns is the row refusing the bytes: they go, and whatever the
// path held before is put back.
type Record func(Committed) error

// hashPart reads the staged part once and returns its SHA-256, for a part
// whose digest sidecar is missing or stale.
func hashPart(r *os.Root, rel string) (string, error) {
	src, err := r.Open(partRel(rel))
	if err != nil {
		return "", err
	}
	defer src.Close()
	return sha256Of(src)
}

// sha256Of reads r to the end and returns the hex SHA-256 of what it read.
func sha256Of(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := CopyBuffer(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Commit turns rel's staged part into its stored file: the hash comes from
// the digest sidecar when it covers the whole part and from one read of the
// part otherwise, the type is sniffed from the part, and the part is renamed
// into files/ with its parents created. The rename replaces an earlier file
// at the same path atomically, and record (when set) then writes the row
// under the same lock. The earlier file stays beside the new one (keepAside)
// until the row is written, so a refused row restores it rather than leaving
// the path with no bytes. A crash between the rename and the row leaves a
// pending row and a file nothing serves, which the client's retry
// overwrites and the stalled sweep removes.
//
// expect is the size the caller was promised, and a part that differs is
// refused with ErrBadRequest and left staged for the caller to discard, so a
// truncated transfer is caught here rather than published as the whole
// file. A negative expect skips the check, for the callers that have no
// declared size to hold the part to. A ranged part (CommitRanged's) answers
// ErrNotFound: no part Write staged is there.
func (f *FS) Commit(id, rel string, expect int64, record Record) (Committed, error) {
	return f.CommitChecked(id, rel, expect, nil, record)
}

// CommitChecked is Commit with check, which runs under the path's lock
// before anything in files/ moves. An error it returns refuses the commit
// with the path untouched and the part still staged: a refusal that does
// not depend on the bytes (a path an anonymous upload must not replace) is
// decided there rather than by record, after the rename.
func (f *FS) CommitChecked(id, rel string, expect int64, check func() error, record Record) (Committed, error) {
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
	// A ranged part is committed only by CommitRanged, which checks its
	// ranges: its sparse length can equal expect while it still has holes.
	if hasRangesSidecar(root, rel) {
		return Committed{}, ErrNotFound
	}
	return f.commitPart(root, rel, expect, check, record)
}

// linkFile makes a hard link inside a root; a test stands in a filesystem
// without hard links.
var linkFile = func(r *os.Root, oldname, newname string) error { return r.Link(oldname, newname) }

// commitPart is Commit's work on an open root, with the path locked
// exclusively by the caller. check, when set, runs before the rename.
func (f *FS) commitPart(root *os.Root, rel string, expect int64, check func() error, record Record) (Committed, error) {
	part := partRel(rel)
	fi, err := root.Stat(part)
	if errors.Is(err, fs.ErrNotExist) {
		return Committed{}, ErrNotFound
	}
	if err != nil {
		return Committed{}, err
	}
	c := Committed{Size: fi.Size()}
	if expect >= 0 && c.Size != expect {
		return Committed{}, fmt.Errorf("%w: staged %d bytes, expected %d", ErrBadRequest, c.Size, expect)
	}
	if h := loadPartDigest(root, rel, c.Size); h != nil {
		c.SHA256 = hex.EncodeToString(h.Sum(nil))
	} else if c.SHA256, err = hashPart(root, rel); err != nil {
		return Committed{}, err
	}
	src, err := root.Open(part)
	if err != nil {
		return Committed{}, err
	}
	c.Mime = mimetype.Detect(src, path.Base(rel))
	src.Close()
	if check != nil {
		if err := check(); err != nil {
			return Committed{}, err
		}
	}
	final := fileRel(rel)
	if err := root.MkdirAll(filepath.Dir(final), 0o700); err != nil {
		return Committed{}, f.mapDiskErr(pathErr(err))
	}
	prev := part + partPrevExt
	kept, movedAside, err := keepAside(root, final, prev, record != nil)
	if err != nil {
		return Committed{}, f.mapDiskErr(err)
	}
	if err := root.Rename(part, final); err != nil {
		if movedAside {
			root.Rename(prev, final)
		} else {
			root.Remove(prev)
		}
		return Committed{}, f.mapDiskErr(pathErr(err))
	}
	// The row is durable the moment it is written, so the rename must be
	// first, or a power cut could leave a committed row naming nothing.
	syncDir(root, filepath.Dir(final))
	root.Remove(part + partHashExt)
	root.Remove(part + partSessionExt)
	root.Remove(part + partRangesExt)
	if record == nil {
		return c, nil
	}
	if err := record(c); err != nil {
		if !kept || root.Rename(prev, final) != nil {
			root.Remove(final)
			pruneEmptyParents(root, rel)
		}
		root.Remove(prev)
		return Committed{}, err
	}
	root.Remove(prev)
	return c, nil
}

// keepAside keeps the bytes final holds at prev while a commit replaces
// them, so a refused row can put them back: a hard link, which leaves the
// path served throughout, or on a filesystem without hard links a rename,
// which leaves the path without a file until the commit's own rename. A
// path with no file needs nothing kept, and neither does a commit with no
// row to refuse it. When neither can keep the bytes the commit is refused
// rather than run without the copy that would restore them. movedAside
// reports the rename, after which only prev holds the earlier bytes.
//
// prev is cleared first, except when final is missing while prev exists:
// that is a crash between the aside rename and the commit's, and prev is
// the path's only copy, so it goes back to final before anything else.
func keepAside(root *os.Root, final, prev string, want bool) (kept, movedAside bool, err error) {
	fi, ferr := root.Lstat(final)
	if errors.Is(ferr, fs.ErrNotExist) {
		if pfi, perr := root.Lstat(prev); perr == nil && pfi.Mode().IsRegular() {
			if err := root.Rename(prev, final); err != nil {
				return false, false, err
			}
			fi, ferr = pfi, nil
		}
	}
	root.Remove(prev)
	switch {
	case errors.Is(ferr, fs.ErrNotExist) || !want:
		return false, false, nil
	case ferr != nil:
		return false, false, ferr
	case !fi.Mode().IsRegular():
		return false, false, nil // the rename refuses what stands there
	}
	if linkFile(root, final, prev) == nil {
		return true, false, nil
	}
	if err := root.Rename(final, prev); err != nil {
		return false, false, fmt.Errorf("keeping the previous version of the file: %w", pathErr(err))
	}
	return true, true, nil
}

// pathErr maps the errors a relpath can provoke against what is already on
// disk (a file where a directory is needed, a directory where a file is)
// and against the filesystem's own name limit to ErrBadPath, and passes
// everything else through.
func pathErr(err error) error {
	if errors.Is(err, syscall.ENAMETOOLONG) {
		return fmt.Errorf("%w: name too long for the server's filesystem", ErrBadPath)
	}
	if errors.Is(err, syscall.EISDIR) || errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.ENOTEMPTY) || errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("%w: %v", ErrBadPath, err)
	}
	return err
}

// Open opens a stored file for serving. A Stat settles the type, the open is
// non-blocking, and the opened handle must be a regular file and the file
// that was stat'ed, so a FIFO swapped in between opens at once and is
// refused rather than holding the request until somebody writes to it.
// Anything that is not a regular file, and any path that leaves the share,
// answers ErrNotFound.
func (f *FS) Open(id, rel string) (*os.File, os.FileInfo, error) {
	if !shareid.ValidRelPath(rel) {
		return nil, nil, ErrNotFound
	}
	root, err := f.root(id)
	if err != nil {
		return nil, nil, err
	}
	defer root.Close()
	final := fileRel(rel)
	fi, err := root.Stat(final)
	if err != nil || !fi.Mode().IsRegular() {
		return nil, nil, ErrNotFound
	}
	if afterTypeCheck != nil {
		afterTypeCheck()
	}
	fh, err := root.OpenFile(final, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, ErrNotFound
	}
	if ofi, err := fh.Stat(); err != nil || !ofi.Mode().IsRegular() || !os.SameFile(fi, ofi) {
		fh.Close()
		return nil, nil, ErrNotFound
	}
	return fh, fi, nil
}

// afterTypeCheck, when set, runs between Open's type check and its open: the
// window a test swaps a file in.
var afterTypeCheck func()

// readSidecar reads a served sidecar (a gallery tile, the poster and the
// slug it was taken from) the way Open reads a stored file: non-blocking,
// and only when the opened handle is a regular file, so a FIFO where one
// was answers fs.ErrNotExist at once. At most SidecarMaxBytes are read, the
// most any sidecar holds.
func readSidecar(root *os.Root, name string) ([]byte, error) {
	fh, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	if fi, err := fh.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil, fs.ErrNotExist
	}
	return io.ReadAll(io.LimitReader(fh, SidecarMaxBytes))
}

// Stat answers a stored file's info without opening it: a regular file
// only, through the share's root, ErrNotFound for anything else.
func (f *FS) Stat(id, rel string) (os.FileInfo, error) {
	if !shareid.ValidRelPath(rel) {
		return nil, ErrNotFound
	}
	root, err := f.root(id)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	fi, err := root.Stat(fileRel(rel))
	if err != nil || !fi.Mode().IsRegular() {
		return nil, ErrNotFound
	}
	return fi, nil
}

// FileMissing answers whether a stored file's bytes are absent: its share
// directory or the file itself does not exist, or what stands there is not a
// regular file. Any other failure to look (permission, I/O) is returned as an
// error and says nothing about the file.
func (f *FS) FileMissing(id, rel string) (bool, error) {
	if !shareid.ValidRelPath(rel) {
		return false, ErrBadPath
	}
	root, err := f.root(id)
	if errors.Is(err, ErrNotFound) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	defer root.Close()
	fi, err := root.Stat(fileRel(rel))
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return !fi.Mode().IsRegular(), nil
}

// pruneEmptyParents removes emptied directories above rel up to, never
// including, files/.
func pruneEmptyParents(r *os.Root, rel string) {
	for d := filepath.Dir(fileRel(rel)); d != filesDirName && d != "." && d != "/"; d = filepath.Dir(d) {
		if r.Remove(d) != nil {
			return
		}
	}
}

// RemoveFile unlinks rel's stored file and any staged part for it, pruning
// emptied parents. Absent is fine: rows are the truth, and the caller has
// already removed the row.
func (f *FS) RemoveFile(id, rel string) error {
	_, err := f.RemoveFileIf(id, rel, nil)
	return err
}

// RemoveFileIf is RemoveFile for a caller deciding from a snapshot: cond,
// when set, runs under the path's lock and the removal goes ahead only if it
// still answers true. A commit writes its row under the same lock, so cond
// sees either no commit of rel or the whole of one. It answers whether the
// removal ran.
func (f *FS) RemoveFileIf(id, rel string, cond func() bool) (bool, error) {
	if !shareid.ValidRelPath(rel) {
		return false, ErrBadPath
	}
	unlock := f.lockPath(id, rel)
	defer unlock()
	if cond != nil && !cond() {
		return false, nil
	}
	root, err := f.root(id)
	if errors.Is(err, ErrNotFound) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	defer root.Close()
	if err := root.Remove(fileRel(rel)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	removePart(root, rel)
	pruneEmptyParents(root, rel)
	return true, nil
}

// Rename moves a stored file or a whole subtree from one relpath to
// another, creating the target's parents and pruning the source's. The
// caller has already moved the rows and refused a taken target.
func (f *FS) Rename(id, from, to string) error {
	if !shareid.ValidRelPath(from) || !shareid.ValidRelPath(to) {
		return ErrBadPath
	}
	release := f.rlockShare(id)
	defer release()
	root, err := f.root(id)
	if err != nil {
		return err
	}
	defer root.Close()
	if _, err := root.Stat(fileRel(from)); err != nil {
		return ErrNotFound
	}
	if err := root.MkdirAll(filepath.Dir(fileRel(to)), 0o700); err != nil {
		return pathErr(err)
	}
	if err := root.Rename(fileRel(from), fileRel(to)); err != nil {
		return pathErr(err)
	}
	pruneEmptyParents(root, from)
	return nil
}

// RemoveShare removes the share's directory, everything staged in it and its
// reservation. It holds the share exclusively, so no commit can recreate the
// directory underneath it. The caller has already removed the rows, so the
// hold goes whether or not the directory did: nothing is left to upload
// into it, and a hold nobody can consume would pin disk from other shares
// until the idle sweep took it.
func (f *FS) RemoveShare(id string) error {
	dir, err := f.ShareDir(id)
	if err != nil {
		return err
	}
	release := f.lockShare(id)
	defer release()
	err = os.RemoveAll(dir)
	f.ReleaseReservation(id)
	return err
}
