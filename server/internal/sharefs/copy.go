package sharefs

import (
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"os"
	"syscall"

	"hyperdrop/server/internal/shareid"
)

// cloneFile makes dst share src's blocks (Linux FICLONE: btrfs, xfs), so a
// duplicated share costs no disk until either copy changes. A test stands in
// a refusal or a failure.
var cloneFile = cloneFileOS

// errNoClone is cloneFileOS's answer on a system with no clone to ask.
var errNoClone = errors.New("no filesystem clone on this system")

// cloneRefused reports a clone the filesystem cannot make between these two
// files (no reflink support, two filesystems, no such ioctl) or the system
// forbids (an unprivileged container answers EPERM for the ioctl on every
// filesystem), which a plain copy stands in for: the copy reads and writes
// the two open files, so it fails by itself where the files are the problem.
// Anything else is a failure of the copy.
func cloneRefused(err error) bool {
	return errors.Is(err, errNoClone) || errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.EXDEV) ||
		errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTTY) || errors.Is(err, syscall.ENOSYS) ||
		errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)
}

// StageCopy stages a copy of srcID's stored file srcRel as dstID's upload of
// dstRel: the part Write would stage, at the name only this package composes,
// which the ordinary Commit then turns into the file. The source is opened the
// way it is served (Open, through its share's root), the part is created
// through the destination's, a clone is tried first and a plain copy stands
// in when the filesystem refuses it, and the part is synced before it is
// handed over. Returns the bytes staged.
//
// A part staged for dstRel before (an interrupted upload or copy) is
// replaced, never appended to. On any failure after the part was created
// the part goes, so a refused copy leaves nothing staged. A full disk is
// ErrDiskFull. The path's lock is held from the part's creation through the
// copy, as Write holds it, and the destination share's lock only while the
// part opens.
func (f *FS) StageCopy(srcID, srcRel, dstID, dstRel string) (int64, error) {
	if !shareid.ValidID(srcID) || !shareid.ValidID(dstID) {
		return 0, ErrNotFound
	}
	if !shareid.ValidRelPath(srcRel) || !shareid.ValidNewRelPath(dstRel) {
		return 0, ErrBadPath
	}
	src, _, err := f.Open(srcID, srcRel)
	if err != nil {
		return 0, err
	}
	defer src.Close()
	unlock := f.lockPath(dstID, dstRel)
	defer unlock()
	p := plainPart(dstRel)
	root, dst, err := f.stagePart(dstID, p)
	if err != nil {
		return 0, err
	}
	defer root.Close()
	n, err := f.fillPart(root, p.path, dstID, dst, src)
	if err != nil {
		removePart(root, p.path)
		return 0, err
	}
	return n, nil
}

// fillPart copies src into the freshly created part dst, then syncs and
// closes it: by clone when the filesystem makes one, otherwise by a copy
// that hashes as it goes and leaves the digest sidecar Commit reads instead
// of the part (a clone reads nothing, so its Commit hashes the part once).
// Every byte is credited to the destination's reservation, as an upload's.
func (f *FS) fillPart(root *os.Root, part, dstID string, dst, src *os.File) (int64, error) {
	cerr := cloneFile(dst, src)
	if cerr == nil {
		fi, err := dst.Stat()
		if err == nil {
			err = dst.Sync()
		}
		if closeErr := dst.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return 0, f.mapDiskErr(err)
		}
		f.landed(dstID, fi.Size())
		return fi.Size(), nil
	}
	if !cloneRefused(cerr) {
		dst.Close()
		return 0, f.mapDiskErr(cerr)
	}
	// A refused clone writes nothing, but the part must hold only the copy.
	if err := dst.Truncate(0); err != nil {
		dst.Close()
		return 0, f.mapDiskErr(err)
	}
	if _, err := dst.Seek(0, io.SeekStart); err != nil {
		dst.Close()
		return 0, err
	}
	h := sha256.New()
	n, err := f.copyToFile(dst, io.TeeReader(f.landing(dstID, src), h))
	if err != nil {
		return 0, err
	}
	savePartDigest(root, part, h, n)
	return n, nil
}

// CopyThumbs copies a share's gallery tiles into its duplicate, re-keyed to
// the duplicate's slugs: thumbs/<old>.jpg lands as thumbs/<slugMap[old]>.jpg.
// A slug with no tile is skipped (the app backfills tiles). The copy line
// calls it once per page of entries, so no map holds a whole share; every
// write goes through SetThumb, so the bytes spend owner's quota and pass the
// disk reserve like any tile. RecountSidecars settles the duplicate's count
// once the last page and the poster are in.
//
// Both ids and every slug in slugMap are validated before anything is
// written: a bad id is ErrNotFound, a bad slug ErrBadRequest.
func (f *FS) CopyThumbs(srcID, dstID string, slugMap map[string]string, owner string) error {
	if !shareid.ValidID(srcID) || !shareid.ValidID(dstID) {
		return ErrNotFound
	}
	for old, slug := range slugMap {
		if !ValidSlug(old) || !ValidSlug(slug) {
			return ErrBadRequest
		}
	}
	for old, slug := range slugMap {
		data, err := f.Thumb(srcID, old)
		if errors.Is(err, ErrNoThumb) {
			continue
		}
		if err != nil {
			return err
		}
		if err := f.SetThumb(dstID, owner, slug, data, nil); err != nil {
			return err
		}
	}
	return nil
}

// CopyPoster copies a share's poster into its duplicate, naming the slug
// copied answers for the entry the original's poster names. The poster is
// copied only when that entry came across (copied answers ok) or it names
// none: a poster naming an entry the duplicate does not hold, or a note that
// cannot be read, is one the original withholds from its card, so the
// duplicate must not show it. The write goes through SetPoster, so its
// bytes spend owner's quota and pass the disk reserve.
func (f *FS) CopyPoster(srcID, dstID, owner string, copied func(old string) (slug string, ok bool, err error)) error {
	if !shareid.ValidID(srcID) || !shareid.ValidID(dstID) {
		return ErrNotFound
	}
	data, err := f.Poster(srcID)
	if errors.Is(err, ErrNoPoster) || errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	old, err := f.PosterSource(srcID)
	if errors.Is(err, ErrBadRequest) {
		return nil
	}
	if err != nil {
		return err
	}
	slug := ""
	if old != "" {
		var ok bool
		if slug, ok, err = copied(old); err != nil || !ok {
			return err
		}
		if !ValidSlug(slug) {
			return ErrBadRequest
		}
	}
	return f.SetPoster(dstID, owner, slug, data)
}
