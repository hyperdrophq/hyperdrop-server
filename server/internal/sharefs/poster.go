package sharefs

import (
	"bytes"
	"errors"
	"image/jpeg"
	"io/fs"
)

// SetPoster stores or replaces the share's link-preview image together with
// the note naming the entry it is taken from (sourceSlug, "" for a poster that
// names no entry), a sidecar beside the files rather than one of them: it
// takes no slug, no listing row, no zip entry and no quota byte. Bounded by
// SidecarMaxBytes so a client cannot fill a share directory with something no
// quota accounts for, and only a decodable JPEG lands, because what lands here
// is served to strangers as image/jpeg, on the app origin as well as the file
// origin. A refused image changes neither file.
//
// The note is written before the image, and both under the share's poster
// lock, which RemovePoster holds too: an image never lands beside an older
// poster's note, nor beside no note after a removal ran between the two writes.
func (f *FS) SetPoster(id, sourceSlug string, data []byte) error {
	if len(data) == 0 || len(data) > SidecarMaxBytes {
		return ErrBadRequest
	}
	if _, err := jpeg.DecodeConfig(bytes.NewReader(data)); err != nil {
		return ErrBadRequest
	}
	if sourceSlug != "" && !ValidSlug(sourceSlug) {
		return ErrBadRequest
	}
	defer f.lockPoster(id)()
	release := f.rlockShare(id)
	defer release()
	root, err := f.ensureRoot(id)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := writePosterSource(root, sourceSlug); err != nil {
		return err
	}
	return replaceFile(root, posterFileName, data, false)
}

// lockPoster takes the share's poster lock, which covers the image and its
// note as one: every writer of either holds it, so replaceFile's
// deterministic temporary names never interleave and the pair changes
// together. Returns the unlock func.
func (f *FS) lockPoster(id string) func() {
	return f.lockPath(id, posterFileName)
}

// Poster returns the stored preview image, or ErrNoPoster.
func (f *FS) Poster(id string) ([]byte, error) {
	root, err := f.root(id)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrNoPoster
	}
	if err != nil {
		return nil, err
	}
	defer root.Close()
	data, err := readSidecar(root, posterFileName)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoPoster
	}
	return data, err
}

// HasPoster reports whether a preview image is stored, without reading it.
func (f *FS) HasPoster(id string) bool {
	root, err := f.root(id)
	if err != nil {
		return false
	}
	defer root.Close()
	fi, err := root.Stat(posterFileName)
	return err == nil && fi.Size() > 0
}

// RemovePoster deletes the preview image and the note naming the entry it was
// taken from. A share with no poster, or no directory, is not an error.
func (f *FS) RemovePoster(id string) error {
	defer f.lockPoster(id)()
	release := f.rlockShare(id)
	defer release()
	root, err := f.root(id)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.Remove(posterFileName); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := root.Remove(posterSourceFileName); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
