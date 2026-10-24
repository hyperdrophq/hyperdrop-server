package sharefs

import (
	"bytes"
	"errors"
	"image/jpeg"
	"io/fs"
)

// SetPoster stores or replaces the share's link-preview image, a sidecar
// beside the files rather than one of them: it takes no slug, no listing
// row, no zip entry and no quota byte. Bounded by SidecarMaxBytes so a
// client cannot fill a share directory with something no quota accounts for,
// and only a decodable JPEG lands, because what lands here is served to
// strangers as image/jpeg, on the app origin as well as the file origin.
func (f *FS) SetPoster(id string, data []byte) error {
	if len(data) == 0 || len(data) > SidecarMaxBytes {
		return ErrBadRequest
	}
	if _, err := jpeg.DecodeConfig(bytes.NewReader(data)); err != nil {
		return ErrBadRequest
	}
	// Two writers of the poster would otherwise interleave through
	// replaceFile's deterministic temporary name.
	defer f.lockPath(id, posterFileName)()
	release := f.rlockShare(id)
	defer release()
	root, err := f.ensureRoot(id)
	if err != nil {
		return err
	}
	defer root.Close()
	return replaceFile(root, posterFileName, data, false)
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
	data, err := root.ReadFile(posterFileName)
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
