package api

import (
	"path"
	"time"

	"hyperdrop/server/internal/linked"
	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/mimetype"
)

// fileView is one file as the API sees it: a row, or a linked entry from a
// source's walk.
type fileView struct {
	metadb.File
	Linked bool
}

// shareView is one share as the API sees it: the row plus the facts the rows
// cannot hold. Files replaces the row's own list (linked entries join stored
// ones); Share.Files is always nil on a view.
type shareView struct {
	metadb.Share
	Files         []fileView
	SourceMissing bool
	LinkedState   map[string]linked.SourceState
	LiveShare     bool
	TotalBytes    int64
	// ownerNoEmbed is the owner's no-embed setting as the public gate read
	// it (visibleShareAnyVia); false on a view the gate did not produce.
	ownerNoEmbed bool
	// whole is the whole share's count and bytes on a view whose Files is
	// one page of it (publicShare); nil on every other view.
	whole *shareTotals
}

// shareTotals is how many files a share holds and their bytes.
type shareTotals struct {
	count int
	bytes int64
}

// viewOf lifts a row into a view. A linked share's walk is the handler's
// (linkedView), because it needs the roots.
//
// TotalBytes covers every file the view holds, a pending entry at the size
// it declared: a share is as big as what it is going to hold, which is what
// a client sizes a progress bar against while the bytes are still arriving.
func viewOf(d metadb.Share) shareView {
	v := shareView{Share: d, Files: make([]fileView, 0, len(d.Files))}
	for _, f := range d.Files {
		v.Files = append(v.Files, fileView{File: f})
		v.TotalBytes += f.Size
	}
	v.Share.Files = nil
	return v
}

// Totals describes the whole share: the files the view holds and the bytes
// they declare. A public page's view answers the totals it was given. A view
// whose file list is a WINDOW cannot count itself, so it answers the row's
// counters instead, which cover committed bytes alone. A live share has no
// counters and always answers its walk.
//
// A linked share is counted from both halves, because neither knows the
// other: the counters are the STORED files, exactly as they are for an
// ordinary share, and the walk is the only thing that can count the linked
// entries beside them. The walk is never windowed by the file cap, so a
// truncated linked share is one whose SOURCE held more than linked.MaxWalk,
// and there is nothing better to report for it than what the walk returned.
func (v shareView) Totals() (count int, bytes int64) {
	if v.whole != nil {
		return v.whole.count, v.whole.bytes
	}
	if v.LiveShare || !v.Truncated {
		return len(v.Files), v.TotalBytes
	}
	count, bytes = v.FileCount, v.Bytes
	for _, f := range v.Files {
		if f.Linked {
			count++
			bytes += f.Size
		}
	}
	return count, bytes
}

// MimeOrGuess is the entry's type, or an extension guess while its bytes
// have not landed. Nothing is sniffed until a file commits, so a surface
// that has to say what the finished file will open as (the waiting page's
// copy, a client laying out a share mid-upload) reads the name instead.
func (f fileView) MimeOrGuess() string {
	if f.Mime == "" && f.Pending {
		return mimetype.ByName(path.Base(f.Path))
	}
	return f.Mime
}

func (v shareView) Expired() bool {
	return v.ExpiresAt != nil && !time.Now().Before(*v.ExpiresAt)
}

func (v shareView) AnyPending() bool {
	for _, f := range v.Files {
		if f.Pending {
			return true
		}
	}
	return false
}

// SourceList is every source path; nil for an ordinary share.
func (v shareView) SourceList() []string {
	if len(v.Sources) == 0 {
		return nil
	}
	out := make([]string, 0, len(v.Sources))
	for _, s := range v.Sources {
		out = append(out, s.Path)
	}
	return out
}

// Source is the first source's path, "" for an ordinary share.
func (v shareView) Source() string {
	if len(v.Sources) == 0 {
		return ""
	}
	return v.Sources[0].Path
}

// Prefixed reports whether linked entries list under their source's base
// name, which a share of several sources does.
func (v shareView) Prefixed() bool { return len(v.Sources) > 1 }

func (v shareView) StoredFiles() []fileView {
	out := make([]fileView, 0, len(v.Files))
	for _, f := range v.Files {
		if !f.Linked {
			out = append(out, f)
		}
	}
	return out
}

// FileByPath finds an entry by its relpath. A stored entry matches the
// spelling exactly; a linked entry keeps the server filesystem's bytes, so
// it also matches any spelling with the same NFC (relPath).
func (v shareView) FileByPath(rel string) (fileView, bool) {
	for _, f := range v.Files {
		if f.Path == rel {
			return f, true
		}
	}
	want := relPath(rel)
	for _, f := range v.Files {
		if f.Linked && relPath(f.Path) == want {
			return f, true
		}
	}
	return fileView{}, false
}

func (v shareView) FileBySlug(slug string) (fileView, bool) {
	if slug == "" {
		return fileView{}, false
	}
	for _, f := range v.Files {
		if f.Slug == slug {
			return f, true
		}
	}
	return fileView{}, false
}

// dbSpecs turns a share's sources and filters into what the linked package
// composes from. The filters are one read; a share with no filter costs none.
// A failed read answers the error and no specs: specs without their filters
// would serve what the owner hid, so every caller refuses instead.
func (h *handler) dbSpecs(d metadb.Share) ([]linked.SourceSpec, error) {
	specs := make([]linked.SourceSpec, 0, len(d.Sources))
	var filters map[string]metadb.Filter
	for _, s := range d.Sources {
		if (s.Fixed || s.Hidden > 0) && filters == nil {
			var err error
			if filters, err = h.db.Filters(d.ID); err != nil {
				return nil, err
			}
		}
	}
	for _, s := range d.Sources {
		spec := linked.SourceSpec{Path: s.Path}
		spec.Revoked = s.Revoked()
		if f, ok := filters[s.Path]; ok {
			spec.Fixed, spec.Hidden = f.Fixed, f.Hidden
		}
		specs = append(specs, spec)
	}
	return specs, nil
}

// linkedView appends a linked share's walk to v. A stored file shadows a
// linked entry of its relpath, so the listing names the path once, as the
// upload. Nothing readable marks the share SourceMissing with the stored
// files alone. Counts and sizes cover what the walk returned; Truncated
// says more exist, and it is ORed with the row's own so a windowed stored
// half is not forgotten when the walk fits.
//
// cached takes the walk and the slugs from h.walks (linkedwalk.go), which a
// public read wants and an owner's read does not.
func (h *handler) linkedView(d metadb.Share, v *shareView, cached bool) {
	walk, ok := h.linkedWalkOf(d, v, cached)
	if !ok {
		return
	}
	stored := make(map[string]bool, len(v.Files))
	for _, f := range v.Files {
		stored[f.Path] = true
	}
	// A new slice rather than a filter in place: a cached walk's entries are
	// shared by every reader of it.
	rels := make([]string, 0, len(walk.entries))
	entries := make([]linked.Entry, 0, len(walk.entries))
	for _, e := range walk.entries {
		if !stored[e.Rel] {
			entries = append(entries, e)
			rels = append(rels, e.Rel)
		}
	}
	slugMap, err := walk.slugs(rels)
	if err != nil {
		v.SourceMissing = true
		return
	}
	for _, e := range entries {
		v.Files = append(v.Files, linkedFile(e, slugMap[e.Rel]))
		v.TotalBytes += e.Size
	}
}

// linkedFile is one linked entry as a view holds it.
func linkedFile(e linked.Entry, slug string) fileView {
	at := e.ModTime.UTC().Truncate(time.Second)
	return fileView{Linked: true, File: metadb.File{
		Path: e.Rel, Size: e.Size, Slug: slug,
		Mime: mimetype.ByName(path.Base(e.Rel)), CommittedAt: &at}}
}

// composedWalk is a linked share's walk as one read holds it: the entries,
// and the slug minting their links need.
type composedWalk struct {
	entries []linked.Entry
	slugs   func(rels []string) (map[string]string, error)
}

// linkedWalkOf composes a linked share's walk and records what it learnt on
// v: each source's state, SourceMissing when no source could be read, and
// Truncated when the walk stopped at linked.MaxWalk. ok is false when there
// is no walk to add: the share has no source, or none could be read.
//
// A cached walk's entries are in relpath byte order (linkedwalk.go), which
// is what lets a public page take one range of them.
func (h *handler) linkedWalkOf(d metadb.Share, v *shareView, cached bool) (composedWalk, bool) {
	if !d.Linked() {
		return composedWalk{}, false
	}
	for _, s := range d.Sources {
		if !s.Revoked() {
			continue
		}
		if v.LinkedState == nil {
			v.LinkedState = map[string]linked.SourceState{}
		}
		v.LinkedState[s.Path] = linked.SourceState{Revoked: &linked.RevokedState{At: *s.RevokedAt, Files: s.RevokedFiles}}
	}
	compose := func() (linked.Listing, bool) {
		specs, err := h.dbSpecs(d)
		if err != nil {
			return linked.Listing{}, false
		}
		return linked.Compose(h.roots, specs, linked.MaxWalk)
	}
	walk := composedWalk{slugs: func(rels []string) (map[string]string, error) { return h.linkedSlugs(d.ID, rels) }}
	var l linked.Listing
	var readable bool
	if cached {
		w := h.walks.get(d.ID, walkKey(d)+h.sourcesOpen(d), func() (linked.Listing, bool) {
			l, ok := compose()
			sortEntriesByPath(l.Entries)
			return l, ok
		})
		l, readable = w.listing, w.readable
		walk.slugs = func(rels []string) (map[string]string, error) {
			return w.slugs(rels, func(missing []string) (map[string]string, error) {
				return h.linkedSlugs(d.ID, missing)
			})
		}
	} else {
		l, readable = compose()
	}
	if !readable {
		v.SourceMissing = true
		return composedWalk{}, false
	}
	for path, st := range l.State {
		if v.LinkedState == nil {
			v.LinkedState = map[string]linked.SourceState{}
		}
		st.Revoked = v.LinkedState[path].Revoked
		v.LinkedState[path] = st
	}
	v.Truncated = v.Truncated || l.Truncated
	walk.entries = l.Entries
	return walk, true
}

// linkedSlugs answers a slug for every listed linked entry, minting and
// storing one for each entry that has none.
func (h *handler) linkedSlugs(shareID string, rels []string) (map[string]string, error) {
	return h.db.AssignSlugs(shareID, rels)
}

// viewFrom lifts a row already read into its view: the row, then the walk.
// An edit composes its answer from the row its write returned, so it reports
// what it wrote without reading it back.
func (h *handler) viewFrom(d metadb.Share) shareView {
	v := viewOf(d)
	h.linkedView(d, &v, false)
	return v
}

// view reads one share as a view: the full read, then the walk.
func (h *handler) view(id string) (shareView, error) {
	d, err := h.db.Share(id)
	if err != nil {
		return shareView{}, err
	}
	return h.viewFrom(d), nil
}

// publicView is view for a public route: a linked share's walk comes from
// h.walks, so a run of anonymous reads of one share costs one walk per
// linkedWalkTTL rather than one per request (linkedwalk.go).
func (h *handler) publicView(id string) (shareView, error) {
	return h.publicRead(id, 0)
}

// publicViewCapped is publicView over viewCapped's windowed read.
func (h *handler) publicViewCapped(id string) (shareView, error) {
	return h.publicRead(id, listMaxFilesPerShare)
}

func (h *handler) publicRead(id string, maxFiles int) (shareView, error) {
	read := h.db.Share
	if maxFiles > 0 {
		read = func(id string) (metadb.Share, error) { return h.db.ShareCapped(id, maxFiles) }
	}
	d, err := read(id)
	if err != nil {
		return shareView{}, err
	}
	v := viewOf(d)
	h.linkedView(d, &v, true)
	return v, nil
}

// viewMeta reads a share's IDENTITY and nothing else: the row's own fields
// with at most one file entry and NO source walk. It is the read for a route
// that needs only the id, the owner, the password, the kind and the expiry:
// the two sidecar images (a gallery tile, a card poster), whose bytes are
// named by a slug and bounded by sharefs.ValidSlug, never by the share's file
// list; the password form's submit; and serveFile's gate, which asks for the
// one file it serves through fileLookup afterwards.
//
// The walk is the whole point of leaving it out. A gallery fires one tile
// request per picture, and composing a LINKED share costs a full source walk
// plus a slug-assigning WRITE transaction, so a route answered once per tile
// must not compose it: the tile route asks its one entry's question instead
// (linkedTileShown).
//
// SourceMissing stays false on such a view, which is what the gate wants
// here: neither route serves a file of the share, so an unreadable source has
// nothing to say about whether a sidecar can be answered.
func (h *handler) viewMeta(id string) (shareView, error) {
	d, err := h.db.ShareCapped(id, 1)
	if err != nil {
		return shareView{}, err
	}
	return viewOf(d), nil
}

// viewCapped is view over the windowed read the listing and the feeds use.
func (h *handler) viewCapped(id string) (shareView, error) {
	d, err := h.db.ShareCapped(id, listMaxFilesPerShare)
	if err != nil {
		return shareView{}, err
	}
	return h.viewFrom(d), nil
}
