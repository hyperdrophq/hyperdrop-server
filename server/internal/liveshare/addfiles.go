package liveshare

import (
	"errors"
	"slices"
	"time"
)

// ErrTooManyFiles refuses an edit that would leave a live share describing
// more files than Config.MaxFiles.
var ErrTooManyFiles = errors.New("a live share describes too many files")

// Edit is one change a running relay's owner makes. Add hands the relay more
// files and Replace swaps its whole list (at most one of the two); ZipSize,
// when positive and either list is given, replaces the archive length the
// share declares; Meta changes the share-level fields.
//
// A path the relay ALREADY serves keeps its slug under either list, the
// same rule `add` follows for a stored share: the point of both is that a
// link already sent keeps resolving, to the new bytes. Every other path gets
// a slug of its own, so it has a link like the first ones.
//
// The relay's own client is what serves the bytes, so a file list only
// widens what the server will hand out jobs for; a client that has not
// learned about the new files yet simply fails those jobs the way it fails
// any file it cannot read. /zip declares ZipSize as Content-Length before a
// byte moves, so a wider file list owes a new figure or the archive ends
// short of what was promised.
type Edit struct {
	Add, Replace []File
	ZipSize      int64
	Meta         Meta
}

// Meta is the share-level fields a PATCH can change without touching files.
type Meta struct {
	Listing, Media *bool
	// Entry: nil = unchanged, pointer to "" = no web page, otherwise the page.
	Entry *string
	Name  *string
	// PasswordHash: nil = unchanged, pointer to "" = remove, otherwise set.
	PasswordHash *string
	SetExpiry    bool
	ExpiresAt    *time.Time
}

// Patch applies e to a copy of the live share's record, hands the record as
// it stands and the result to check (nil for none), and stores the result
// only when check accepts it and it describes at most Config.MaxFiles
// files, so a refused edit leaves the share exactly as it was. The id must
// name a live share this account owns; "wrong id" and "not yours" are one
// error (ErrNoShare), so an id cannot be probed.
//
// It runs under the registry lock, which every public read of a live share
// takes, so the merge is one pass over each list through a path index, and
// check must be as cheap. The stored file list is never edited in place: a
// Record handed out earlier shares its slice, so the result is always a new
// one.
func (g *Registry) Patch(id, owner string, e Edit, check func(current, next Record) error) (Record, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweepLocked()
	s, ok := g.shares[id]
	if !ok || s.rec.Owner != owner {
		return Record{}, ErrNoShare
	}
	next := s.rec
	switch {
	case len(e.Replace) > 0:
		next.Files = g.mergeFiles(s.rec.Files, e.Replace, true)
	case len(e.Add) > 0:
		next.Files = g.mergeFiles(s.rec.Files, e.Add, false)
	}
	if (len(e.Replace) > 0 || len(e.Add) > 0) && e.ZipSize > 0 {
		next.ZipSize = e.ZipSize
	}
	applyMeta(&next, e.Meta)
	if len(next.Files) > g.cfg.MaxFiles {
		return Record{}, ErrTooManyFiles
	}
	if check != nil {
		if err := check(s.rec, next); err != nil {
			return Record{}, err
		}
	}
	s.rec = next
	return next, nil
}

// mergeFiles answers the file list after files land on current: in place of
// current's entries of the same path when adding, as the whole list when
// replacing. A known path keeps its slug either way.
func (g *Registry) mergeFiles(current, files []File, replace bool) []File {
	index := make(map[string]int, len(current))
	for i, f := range current {
		index[f.Path] = i
	}
	var out []File
	if replace {
		out = make([]File, 0, len(files))
	} else {
		out = slices.Grow(slices.Clone(current), len(files))
	}
	for _, f := range files {
		i, known := index[f.Path]
		switch {
		case replace && known:
			f.Slug = current[i].Slug
		case known:
			// Adding: the index points into out, which began as current.
			f.Slug = out[i].Slug
			out[i] = f
			continue
		default:
			f.Slug = g.cfg.NewSlug()
		}
		if !replace {
			index[f.Path] = len(out)
		}
		out = append(out, f)
	}
	return out
}

func applyMeta(rec *Record, meta Meta) {
	if meta.Listing != nil {
		rec.Listing = *meta.Listing
	}
	if meta.Media != nil {
		rec.Media = *meta.Media
	}
	if meta.Entry != nil {
		rec.Entry = *meta.Entry
	}
	// A last-resort clamp, not the validation. What a link opens is one
	// question, and the API refuses a PATCH whose RESULTING state answers it
	// twice (linkOpens.refuse in the api package), so this is unreachable
	// from a request. It stays so the registry cannot hold a record claiming
	// to be both, and it clears Listing rather than Media because a gallery
	// IS the landing page.
	if rec.Listing && rec.Media {
		rec.Listing = false
	}
	if meta.Name != nil {
		rec.Name = *meta.Name
	}
	if meta.PasswordHash != nil {
		rec.PasswordHash = *meta.PasswordHash
		rec.PasswordGen++
	}
	if meta.SetExpiry {
		rec.ExpiresAt = meta.ExpiresAt
	}
}
