package linked

import (
	"os"
	"path"
)

// The Opener: a share's linked entries opened for serving against one read of
// its specs.

// Opener opens linked entries' bytes for serving, many entries of one share
// against one read of its specs, opening each source's root once and keeping
// it until Close, so a zip of a 10,000-file folder resolves each source and
// reads its filter once. Every open resolves rel to its source the way
// Collides resolves it, refuses an entry Shown refuses (a hidden segment, a
// revoked source, a path the source's filter takes out), and returns only a
// regular file, through the source's root. An Opener is used by one
// goroutine.
type Opener struct {
	roots   *Roots
	specs   []SourceSpec
	sources map[string]*openSource
}

// openSource is one source's boundary as Opener opened it, or the error
// opening it gave. fixed is its fixed list as a set (fixedSet).
type openSource struct {
	root  *os.Root
	sub   string
	st    os.FileInfo
	err   error
	fixed map[string]bool
}

// NewOpener answers an Opener over specs; nothing is opened until an entry is.
func NewOpener(roots *Roots, specs []SourceSpec) *Opener {
	return &Opener{roots: roots, specs: specs, sources: map[string]*openSource{}}
}

// Open opens one entry; the caller closes the file, and the root it came
// through stays open until Close.
func (o *Opener) Open(rel string) (*os.File, os.FileInfo, error) {
	f, fi, _, err := o.open(rel)
	return f, fi, err
}

// Close closes every source root the Opener opened.
func (o *Opener) Close() {
	for _, src := range o.sources {
		if src.root != nil {
			src.root.Close()
		}
	}
	o.sources = nil
}

func (o *Opener) open(rel string) (*os.File, os.FileInfo, *openSource, error) {
	spec, inner, name, ok := entrySource(o.specs, rel)
	if !ok {
		return nil, nil, nil, os.ErrNotExist
	}
	src := o.source(spec)
	if src.err != nil {
		return nil, nil, nil, os.ErrNotExist
	}
	// spec.shows, over the fixed list as a set.
	if (src.fixed != nil && !src.fixed[nfc(name)]) || Skipped(spec.Hidden, name) {
		return nil, nil, nil, os.ErrNotExist
	}
	target := path.Join(src.sub, inner)
	var pin os.FileInfo
	if src.sub != "." {
		// A source that is one FILE lists under its base name, which is the
		// only relpath it can serve: naming it is what the share is for. A
		// prefixed share spent that name on the first segment.
		want := path.Base(src.sub)
		if prefixed(o.specs) {
			want = ""
		}
		if inner != want {
			return nil, nil, nil, os.ErrNotExist
		}
		target, pin = src.sub, src.st
	} else if inner == "" {
		return nil, nil, nil, os.ErrNotExist
	} else {
		f, fi, resolved, err := openEntryResolved(src.root, target)
		if err != nil {
			return nil, nil, nil, err
		}
		// In a filtered source the path a link resolves to must be shown
		// too; the source is the folder itself, so resolved is already
		// source-relative.
		if resolved != target && spec.filtered() && !spec.shows(resolved) {
			f.Close()
			return nil, nil, nil, os.ErrNotExist
		}
		return f, fi, src, nil
	}
	f, fi, err := OpenRegular(src.root, target, pin)
	if err != nil {
		return nil, nil, nil, err
	}
	return f, fi, src, nil
}

// source opens spec's boundary the first time an entry of it is asked for.
func (o *Opener) source(spec SourceSpec) *openSource {
	if src, ok := o.sources[spec.Path]; ok {
		return src
	}
	src := &openSource{}
	if spec.Fixed != nil {
		src.fixed = fixedSet(*spec.Fixed)
	}
	src.root, src.sub, src.err = o.roots.Open(spec.Path)
	if src.err == nil {
		src.st, src.err = src.root.Lstat(src.sub)
		if src.err == nil && src.sub != "." && !src.st.Mode().IsRegular() {
			src.err = os.ErrNotExist
		}
		if src.err != nil {
			src.root.Close()
			src.root = nil
		}
	}
	o.sources[spec.Path] = src
	return src
}
