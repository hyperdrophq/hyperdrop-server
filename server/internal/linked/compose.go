package linked

import (
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/text/unicode/norm"
)

// Composing a linked share's listing: a share whose content is a folder or a
// file already on the server's own disk stores no bytes and keeps no entries
// log, so its file list is a walk of its sources taken on every read, minus
// what each source is set to show. This file holds that composition, the one
// refusal a source imposes on an upload's name, and the open of a single
// entry's bytes, all of them reading the sources through the roots alone.

// SourceSpec is one source of a linked share and what it shows of its walk:
// Fixed nil is live (whatever the folder holds), non-nil is only those
// paths; Hidden applies either way, prefix-matched on a segment boundary.
// Paths are source-relative, and a filter compares them in NFC (nfc).
type SourceSpec struct {
	Path   string
	Fixed  *[]string
	Hidden []string
	// Revoked marks a source the owner's allowlist no longer covers: it is
	// walked, collided against and opened as if it were not there, while
	// still counting toward how many sources the share lists under.
	Revoked bool
}

func (s SourceSpec) filtered() bool { return s.Fixed != nil || len(s.Hidden) > 0 }

// nfc is the spelling a filter compares in. A hidden path is recorded in
// NFC, the server's rule for every relpath it is sent, while the walk hands
// out the filesystem's own bytes, which a folder copied from a Mac often
// holds decomposed, and a fixed list records the walk's bytes.
func nfc(s string) string { return norm.NFC.String(s) }

// fixedSet is a fixed list as a set of NFC names.
func fixedSet(fixed []string) map[string]bool {
	out := make(map[string]bool, len(fixed))
	for _, rel := range fixed {
		out[nfc(rel)] = true
	}
	return out
}

// shows reports whether the source's filter keeps rel, a source-relative
// name: in the fixed list when there is one, and under no hidden path.
func (s SourceSpec) shows(rel string) bool {
	want := nfc(rel)
	if s.Fixed != nil && !slices.ContainsFunc(*s.Fixed, func(f string) bool { return nfc(f) == want }) {
		return false
	}
	return !Skipped(s.Hidden, rel)
}

// RevokedState is when a source was revoked and how many entries it
// listed then (nil when the folder was unreadable at that moment).
type RevokedState struct {
	At    time.Time `json:"at"`
	Files *int      `json:"files,omitempty"`
}

// SourceState is what a source's filter did on one read, and whether the
// source is revoked.
type SourceState struct {
	Fixed   bool          `json:"fixed,omitempty"`
	Hidden  int           `json:"hidden,omitempty"`
	Revoked *RevokedState `json:"revoked,omitempty"`
}

// Listing is the composed walk of every source.
type Listing struct {
	Entries   []Entry
	Truncated bool
	// State has an entry for every source that has a filter.
	State map[string]SourceState
}

// Compose walks every source within one budget. With several sources each
// folder's entries list under the folder's base name and a file source
// lists as itself; one source lists bare. A source that cannot be read is
// skipped like an unreadable subfolder; readable is false only when no
// source could be read, which is what marks a share unavailable.
func Compose(roots *Roots, specs []SourceSpec, max int) (l Listing, readable bool) {
	for _, spec := range specs {
		if len(l.Entries) >= max {
			l.Truncated = true
			break
		}
		if spec.Revoked {
			continue
		}
		root, sub, err := roots.Open(spec.Path)
		if err != nil {
			continue
		}
		entries, more, err := walkSource(root, sub, max-len(l.Entries))
		root.Close()
		if err != nil {
			continue
		}
		readable = true
		l.Truncated = l.Truncated || more
		// What this source SHOWS of what it holds, applied on the
		// source-relative names the filter is written in, before a
		// several-source share prefixes them.
		if spec.filtered() {
			shown := Filtered(spec, entries)
			if l.State == nil {
				l.State = map[string]SourceState{}
			}
			l.State[spec.Path] = SourceState{Fixed: spec.Fixed != nil, Hidden: len(entries) - len(shown)}
			entries = shown
		}
		if len(specs) > 1 && sub == "." {
			base := path.Base(spec.Path) + "/"
			for i := range entries {
				entries[i].Rel = base + entries[i].Rel
			}
		}
		l.Entries = append(l.Entries, entries...)
	}
	return l, readable
}

// Roots.Open encodes the established boundary in sub: "." is a directory
// root; any other value is ONE file within its parent. Never reclassify that
// file as a directory after a replacement, which would walk a new folder
// using its parent's broader confinement boundary.
func walkSource(root *os.Root, sub string, max int) ([]Entry, bool, error) {
	if sub == "." {
		return Walk(root, max)
	}
	info, err := root.Lstat(sub)
	if err != nil || !info.Mode().IsRegular() {
		return nil, false, os.ErrNotExist
	}
	return []Entry{{Rel: sub, Size: info.Size(), ModTime: info.ModTime()}}, false, nil
}

// resolve answers the spec rel belongs to and the path inside that source.
// A share of one source is the whole of rel; prefixed, rel's first segment
// names the source by its base name and the rest is the path inside it, so
// an empty inner names the source's own listing entry.
func resolve(specs []SourceSpec, prefixed bool, rel string) (SourceSpec, string, bool) {
	if len(specs) == 0 {
		return SourceSpec{}, "", false
	}
	if !prefixed {
		return specs[0], rel, true
	}
	head, inner, _ := strings.Cut(rel, "/")
	for _, spec := range specs {
		if path.Base(spec.Path) == head {
			return spec, inner, true
		}
	}
	return SourceSpec{}, "", false
}

// Collides reports whether an upload at rel would list on top of, or
// beneath, something a source serves live: rel names an entry the source
// holds exactly, or a proper prefix of rel is a FILE the source holds. A
// folder the source holds is open: an upload inside it lists beside the
// folder's own files. prefixed says the share lists each source under its
// base name; then rel's first segment picks the source and the rest is the
// path inside it, a name no source has is free, and a file source's own
// name and anything below it are taken. A hidden segment collides with
// nothing, because the walk never serves it.
func Collides(roots *Roots, specs []SourceSpec, prefixed bool, rel string) bool {
	if rel == "" || Hidden(rel) {
		return false
	}
	spec, inner, ok := resolve(specs, prefixed, rel)
	if !ok {
		return false
	}
	if spec.Revoked {
		return false
	}
	if prefixed && inner == "" {
		return true // the source's own listing name, folder or file
	}
	root, sub, err := roots.Open(spec.Path)
	if err != nil {
		return false
	}
	defer root.Close()
	st, err := root.Lstat(sub)
	if err != nil {
		return false
	}
	if sub != "." {
		if !st.Mode().IsRegular() {
			return false
		}
		if prefixed {
			return true // below a file source's name
		}
		base := path.Base(sub)
		return Under(inner, base)
	}
	// Down the path one segment at a time: a prefix the source does not have
	// means nothing of rel's exists below it, a prefix that is a file is
	// taken along with everything under it, and the whole path existing is
	// taken whatever it is.
	segs := strings.Split(inner, "/")
	for i := range segs {
		st, err := root.Stat(path.Join(sub, strings.Join(segs[:i+1], "/")))
		if err != nil {
			return false
		}
		if i == len(segs)-1 || !st.IsDir() {
			return true
		}
	}
	return false
}

// Shown reports whether the share's listing may name rel, judged from the
// specs alone, with no filesystem read: rel is a valid relpath with no
// hidden segment, its source is not revoked, and that source's filter shows
// it. It is what a route keyed by a linked entry but answered without a walk
// (a gallery tile) asks, so a revoked source or a hidden entry answers there
// exactly as it answers on the listing.
func Shown(specs []SourceSpec, prefixed bool, rel string) bool {
	_, _, ok := shown(specs, prefixed, rel)
	return ok
}

// shown is Shown answering the source rel belongs to and the path inside
// it. The filter is written in source-relative names: a folder source's
// entry is its inner path, and a file source lists as its own base name,
// which a prefixed share spends as rel's first segment.
func shown(specs []SourceSpec, prefixed bool, rel string) (SourceSpec, string, bool) {
	spec, inner, name, ok := entrySource(specs, prefixed, rel)
	if !ok || !spec.shows(name) {
		return SourceSpec{}, "", false
	}
	return spec, inner, true
}

// entrySource is everything shown asks before the filter: rel is a valid
// relpath with no hidden segment and its source is not revoked. It answers
// that source, the path inside it, and the name its filter is written in.
func entrySource(specs []SourceSpec, prefixed bool, rel string) (spec SourceSpec, inner, name string, ok bool) {
	if !ValidRel(rel) || Hidden(rel) {
		return SourceSpec{}, "", "", false
	}
	spec, inner, ok = resolve(specs, prefixed, rel)
	if !ok || spec.Revoked {
		return SourceSpec{}, "", "", false
	}
	name = inner
	if prefixed && inner == "" {
		name = path.Base(spec.Path)
	}
	return spec, inner, name, true
}

// Opener opens linked entries' bytes for serving, many entries of one share
// against one read of its specs, opening each source's root once and keeping
// it until Close, so a zip of a 10,000-file folder resolves each source and
// reads its filter once. Every open resolves rel to its source the way
// Collides resolves it, refuses an entry Shown refuses (a hidden segment, a
// revoked source, a path the source's filter takes out), and returns only a
// regular file, through the source's root. An Opener is used by one
// goroutine.
type Opener struct {
	roots    *Roots
	specs    []SourceSpec
	prefixed bool
	sources  map[string]*openSource
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
func NewOpener(roots *Roots, specs []SourceSpec, prefixed bool) *Opener {
	return &Opener{roots: roots, specs: specs, prefixed: prefixed, sources: map[string]*openSource{}}
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
	spec, inner, name, ok := entrySource(o.specs, o.prefixed, rel)
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
		if o.prefixed {
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

// OpenEntry opens rel inside a folder source the way Walk reaches it: down
// real directories only, each opened from its parent's handle and checked to
// be the directory that was Lstat'ed (openDirectory), then the last name
// from that directory's handle. A folder link anywhere on the way is
// refused, since the walk never enters one, so a folder swapped for a link
// after the listing was read serves nothing under its old name. A last name
// that is a file link serves its target when no hop of the way to it passes
// a hidden name (resolveLinks, the rule Walk lists by), and the target is
// then opened down real directories the same way. Anything else answers
// os.ErrNotExist.
func OpenEntry(root *os.Root, rel string) (*os.File, os.FileInfo, error) {
	f, fi, _, err := openEntryResolved(root, rel)
	return f, fi, err
}

// openEntryResolved is OpenEntry plus the path it opened: rel itself for a
// regular file, the link's resolved target for a file link.
func openEntryResolved(root *os.Root, rel string) (f *os.File, fi os.FileInfo, resolved string, err error) {
	f, fi, link, err := openPlain(root, rel)
	if !link {
		return f, fi, rel, err
	}
	resolved, ok := resolveLinks(root, rel)
	if !ok {
		return nil, nil, "", os.ErrNotExist
	}
	f, fi, link, err = openPlain(root, resolved)
	if link || err != nil {
		return nil, nil, "", os.ErrNotExist
	}
	return f, fi, resolved, nil
}

// openPlain opens rel down real directories and answers its regular file,
// or link true when the last name is a symlink, which it does not follow.
func openPlain(root *os.Root, rel string) (f *os.File, fi os.FileInfo, link bool, err error) {
	if !ValidRel(rel) {
		return nil, nil, false, os.ErrNotExist
	}
	dir, err := openDirectory(root, path.Dir(rel))
	if err != nil {
		return nil, nil, false, os.ErrNotExist
	}
	defer dir.Close()
	base := path.Base(rel)
	st, err := dir.Lstat(base)
	if err != nil {
		return nil, nil, false, os.ErrNotExist
	}
	if st.Mode()&fs.ModeSymlink != 0 {
		return nil, nil, true, nil
	}
	f, fi, err = OpenRegular(dir, base, st)
	return f, fi, false, err
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

// OpenRegular opens name inside root only when it is a regular file: a Stat
// settles the type, the open is non-blocking (readFlags), and the opened
// handle must be a regular file and the file that was stat'ed, or pin when
// the caller already resolved which file it means. A FIFO swapped in between
// the Stat and the open therefore opens at once and is refused on its
// handle, rather than holding the request until somebody writes to it, and
// any other file swapped in is refused rather than served.
func OpenRegular(root *os.Root, name string, pin os.FileInfo) (*os.File, os.FileInfo, error) {
	st, err := root.Stat(name)
	if err != nil || !st.Mode().IsRegular() {
		return nil, nil, os.ErrNotExist
	}
	if pin == nil {
		pin = st
	}
	if afterTypeCheck != nil {
		afterTypeCheck()
	}
	f, err := root.OpenFile(name, readFlags, 0)
	if err != nil {
		return nil, nil, os.ErrNotExist
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || !os.SameFile(pin, fi) {
		f.Close()
		return nil, nil, os.ErrNotExist
	}
	return f, fi, nil
}

// readFlags opens linked bytes for reading without waiting on the other end
// of a FIFO. O_NONBLOCK changes nothing for a regular file's reads, the only
// kind OpenRegular hands out.
const readFlags = os.O_RDONLY | syscall.O_NONBLOCK

// afterTypeCheck, when set, runs between OpenRegular's type check and its
// open: the window a test swaps a file in.
var afterTypeCheck func()

// Filtered applies one spec's filter to walked entries, in walk order.
func Filtered(spec SourceSpec, entries []Entry) []Entry {
	if !spec.filtered() {
		return entries
	}
	var fixed map[string]bool
	if spec.Fixed != nil {
		fixed = fixedSet(*spec.Fixed)
	}
	hidden := make([]string, len(spec.Hidden))
	for i, h := range spec.Hidden {
		hidden[i] = nfc(h)
	}
	out := make([]Entry, 0, len(entries))
	for _, e := range entries {
		rel := nfc(e.Rel)
		if fixed != nil && !fixed[rel] {
			continue
		}
		if skipped(hidden, rel) {
			continue
		}
		// A file link is shown only when the filter also shows what it
		// points at, so a shown name never serves the bytes of a name the
		// filter keeps out.
		if e.Target != "" {
			target := nfc(e.Target)
			if (fixed != nil && !fixed[target]) || skipped(hidden, target) {
				continue
			}
		}
		out = append(out, e)
	}
	return out
}

// Skipped reports whether rel is one of hidden or lies under one of them,
// compared in NFC. A segment boundary, so hiding "a" takes "a/b.txt" and
// never "ab.txt".
func Skipped(hidden []string, rel string) bool {
	rel = nfc(rel)
	for _, h := range hidden {
		if Under(rel, nfc(h)) {
			return true
		}
	}
	return false
}

// skipped is Skipped over names already in NFC.
func skipped(hidden []string, rel string) bool {
	for _, h := range hidden {
		if Under(rel, h) {
			return true
		}
	}
	return false
}
