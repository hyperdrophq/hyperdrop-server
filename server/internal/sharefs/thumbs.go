package sharefs

import (
	"bytes"
	"errors"
	"image/jpeg"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"hyperdrop/server/internal/shareid"
)

// ValidSlug accepts only the UUIDv4 shape the database mints for a file. A
// slug reaches this package from a URL path and becomes a FILENAME, so the
// check is the same kind of boundary shareid.ValidID is.
func ValidSlug(slug string) bool { return shareid.ValidSlug(slug) }

// thumbRel is a tile's location inside the share root.
func thumbRel(slug string) string { return filepath.Join(thumbsDirName, slug+".jpg") }

// SetThumb stores or replaces one file's gallery tile. Only a decodable
// JPEG of at most SidecarMaxBytes lands, because what lands here is served
// to strangers as image/jpeg. Whether the slug names one of the share's files
// is the caller's check, holds, which answers ErrNotFound when false; nil
// skips it.
//
// The tile is written without replaceFile's durable syncs: the rename keeps
// a reader mid-replace on a whole file, and every sidecar is derived from a
// file the share still holds, so durability across a power loss buys
// nothing worth an fsync per tile of a 1,500-photo gallery.
func (f *FS) SetThumb(id, slug string, data []byte, holds func() bool) error {
	if !ValidSlug(slug) {
		return ErrNotFound
	}
	if len(data) == 0 || len(data) > SidecarMaxBytes {
		return ErrBadRequest
	}
	if _, err := jpeg.DecodeConfig(bytes.NewReader(data)); err != nil {
		return ErrBadRequest
	}
	// Two writers of one tile would otherwise interleave through
	// replaceFile's deterministic temporary name, and holds is asked under
	// the lock RemoveThumb takes, so a file deleted meanwhile either takes
	// the tile with it or refuses it.
	defer f.lockPath(id, thumbRel(slug))()
	if holds != nil && !holds() {
		return ErrNotFound
	}
	release := f.rlockShare(id)
	defer release()
	root, err := f.ensureRoot(id)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.MkdirAll(thumbsDirName, 0o700); err != nil {
		return err
	}
	return replaceFile(root, thumbRel(slug), data, false)
}

// Thumb returns one file's stored tile, or ErrNoThumb.
func (f *FS) Thumb(id, slug string) ([]byte, error) {
	if !ValidSlug(slug) {
		return nil, ErrNoThumb
	}
	root, err := f.root(id)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrNoThumb
	}
	if err != nil {
		return nil, err
	}
	defer root.Close()
	data, err := root.ReadFile(thumbRel(slug))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoThumb
	}
	return data, err
}

// RemoveThumb forgets a tile whose slug no longer names live content, best
// effort. A stale tile is worse than none: it shows the picture that was
// replaced. It runs after the rows went, under SetThumb's lock.
func (f *FS) RemoveThumb(id, slug string) {
	if !ValidSlug(slug) {
		return
	}
	defer f.lockPath(id, thumbRel(slug))()
	root, err := f.root(id)
	if err != nil {
		return
	}
	defer root.Close()
	root.Remove(thumbRel(slug))
}

// thumbEntries lists the tiles a share holds. A share with no directory or no
// thumbs/ answers nothing and no error: "none yet" is the ordinary case.
func (f *FS) thumbEntries(id string) ([]fs.DirEntry, error) {
	root, err := f.root(id)
	if errors.Is(err, ErrNotFound) {
		if _, derr := f.ShareDir(id); derr != nil {
			return nil, derr
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer root.Close()
	d, err := root.Open(thumbsDirName)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer d.Close()
	return d.ReadDir(-1)
}

// ThumbTimes reports which of a share's files have a tile and when each was
// written, so a caller can tell a tile older than the file it stands for.
func (f *FS) ThumbTimes(id string) (map[string]time.Time, error) {
	entries, err := f.thumbEntries(id)
	if err != nil {
		return nil, err
	}
	out := make(map[string]time.Time, len(entries))
	for _, e := range entries {
		slug, ok := strings.CutSuffix(e.Name(), ".jpg")
		if e.IsDir() || !ok || !ValidSlug(slug) {
			continue
		}
		if info, err := e.Info(); err == nil {
			out[slug] = info.ModTime()
		}
	}
	return out, nil
}

// ThumbSlugs reports which of a share's files have a tile.
func (f *FS) ThumbSlugs(id string) (map[string]bool, error) {
	entries, err := f.thumbEntries(id)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(entries))
	for _, e := range entries {
		slug, ok := strings.CutSuffix(e.Name(), ".jpg")
		if !e.IsDir() && ok && ValidSlug(slug) {
			out[slug] = true
		}
	}
	return out, nil
}
