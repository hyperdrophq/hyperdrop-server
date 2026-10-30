package sharefs

import (
	"errors"
	"io/fs"
	"os"
	"strings"
)

// posterSourceFileName is the note beside poster.jpg naming, by slug, the
// entry the poster was taken from.
const posterSourceFileName = "poster.slug"

// writePosterSource records which of the share's entries the poster is taken
// from, so a public card can withhold the poster once that entry stops being
// shown. "" removes the note: the poster names no entry. The caller holds the
// poster lock and has validated the slug.
func writePosterSource(root *os.Root, slug string) error {
	if slug == "" {
		if err := root.Remove(posterSourceFileName); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
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
	data, err := readSidecar(root, posterSourceFileName)
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
