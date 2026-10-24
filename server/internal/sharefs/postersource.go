package sharefs

import (
	"errors"
	"io/fs"
	"strings"
)

// posterSourceFileName is the note beside poster.jpg naming, by slug, the
// entry the poster was taken from.
const posterSourceFileName = "poster.slug"

// SetPosterSource records which of the share's entries the poster is taken
// from, so a public card can withhold the poster once that entry stops being
// shown. "" removes the note: the poster names no entry. The caller writes
// the note before the poster it describes. Like the poster it takes no slug,
// no listing row, no zip entry and no quota byte.
func (f *FS) SetPosterSource(id, slug string) error {
	if slug != "" && !ValidSlug(slug) {
		return ErrBadRequest
	}
	defer f.lockPath(id, posterSourceFileName)()
	release := f.rlockShare(id)
	defer release()
	if slug == "" {
		root, err := f.root(id)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		defer root.Close()
		if err := root.Remove(posterSourceFileName); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	root, err := f.ensureRoot(id)
	if err != nil {
		return err
	}
	defer root.Close()
	return replaceFile(root, posterSourceFileName, []byte(slug), false)
}

// PosterSource returns the slug of the entry the stored poster was taken
// from, "" when the poster names no entry. A note that does not hold a slug
// is ErrBadRequest, so a caller deciding whether to show the poster can
// withhold it rather than guess.
func (f *FS) PosterSource(id string) (string, error) {
	root, err := f.root(id)
	if errors.Is(err, ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer root.Close()
	data, err := root.ReadFile(posterSourceFileName)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	slug := strings.TrimSpace(string(data))
	if !ValidSlug(slug) {
		return "", ErrBadRequest
	}
	return slug, nil
}
