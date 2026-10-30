package api

import (
	"html/template"
	"net/http"
	"sort"
	"strings"

	"hyperdrop/server/internal/bytefmt"
	"hyperdrop/server/internal/shareid"
)

// The share listing page: branded, fully self-contained (inline CSS + SVG,
// no JavaScript except the pending-upload poller on the waiting page). It
// shows ONE folder at a time with breadcrumbs, at most publicPageSize of its
// direct children per page, so a visitor never downloads the whole file list
// and the server never reads it (publicpage.go).
var listingTmpl = page("listing", "listing.html")

// listingFile is one file row. Name is display-only (basename within the
// current folder); View/Down are prebuilt slug hrefs so URLs never carry names.
type listingFile struct {
	Name string
	View string
	Down string
	Size string
}

func sortByLowerName[T any](items []T, name func(T) string) {
	keys := make([]string, len(items))
	for i, it := range items {
		keys[i] = strings.ToLower(name(it))
	}
	sort.Sort(&byKey[T]{items: items, keys: keys})
}

// byKey sorts items alongside their precomputed keys.
type byKey[T any] struct {
	items []T
	keys  []string
}

func (b *byKey[T]) Len() int           { return len(b.items) }
func (b *byKey[T]) Less(i, j int) bool { return b.keys[i] < b.keys[j] }
func (b *byKey[T]) Swap(i, j int) {
	b.items[i], b.items[j] = b.items[j], b.items[i]
	b.keys[i], b.keys[j] = b.keys[j], b.keys[i]
}

type listingData struct {
	ID        string
	Title     string
	Folder    bool
	Count     int
	TotalSize string
	// Page is the one folder this response shows: its breadcrumbs, its
	// subfolder rows and the files directly in it.
	Page folderPage
	// Site is the /site URL of this share's entry point when it has one that
	// resolves, on the file origin when there is one. Non-empty only on
	// ?files=1, since otherwise the page would have redirected there.
	Site string
	// ZipAll is the archive of the whole share, on the file origin when
	// there is one.
	ZipAll string
	// FolderZip is the archive of the folder being shown, empty at the root
	// (Download all already is that archive) and empty for a folder holding
	// no files.
	FolderZip string
	// Gallery is /share/{id} when this share is a media share, whose plain
	// address renders the gallery. Non-empty only on ?files=1, for the same
	// reason as Site, and never alongside it: media with entry is refused.
	// Rendered as the footer's "View as a gallery" link, the mirror of the
	// gallery page's own "View as a file list", so the two ways across read
	// as the same control.
	Gallery string
	// Offline marks a live share whose owner's client is not connected right
	// now: the listing itself still renders (its metadata never lived on
	// disk in the first place), but every link on it would 503 until the
	// owner reconnects, so the page says so instead of leaving that to be
	// discovered one dead link at a time.
	Offline bool
	// More is the address of the folder's next page, "" on its last.
	More string
	OG   template.HTML
}

func (h *handler) sharePage(w http.ResponseWriter, r *http.Request) {
	p, ok := h.loadPublicPage(w, r)
	if !ok {
		return
	}
	v := p.v
	query := r.URL.Query()
	after := query.Get("after")
	// Every unfurler is answered here, before the single-file redirect:
	// unfurlers that don't follow redirects would otherwise see nothing at
	// all.
	if isUnfurler(r.UserAgent()) {
		if f, one, err := p.onlyFile(); err == nil && one {
			cv := v
			cv.Files = []fileView{f}
			h.renderCard(w, h.fileCard(r, cv, f))
		} else {
			h.renderCard(w, h.shareCard(r, p.cardView()))
		}
		return
	}
	id := v.ID
	// A share still uploading is the waiting page, whatever it will open as:
	// the visitor watches the whole share's progress and is reloaded into
	// the gallery, the site, the file or the listing the moment the last
	// file lands. Ahead of every other branch, and of ?files=1, so no page
	// ever renders a half-uploaded share.
	if p.pending() {
		h.renderWaiting(w, v, nil, true)
		return
	}
	// One visitor, counted here for every answer the page gives: the gallery,
	// the site redirect, the single-file redirect and the listing. The page
	// mints the cookie and counts under it, so the payload request a redirect
	// leads to is the same visitor. After the unfurler card and the waiting
	// page, which are not reads of the share.
	h.recordVisit(v, h.mintVisitor(w, r))
	// A media share IS a gallery: the link opens the pictures rather than the
	// file list they are built from. ?files=1 is the listing's own address and
	// the way back, the same escape hatch a site entry uses.
	//
	// Ahead of the single-file redirect, so a gallery of one photo still opens
	// as a gallery: the owner chose the kind deliberately, and handing over
	// the raw image instead would answer a different question.
	if v.Media && query.Get("files") != "1" {
		h.galleryPage(w, r, p, after)
		return
	}
	// A share with an entry point IS a site: the link opens the page rather
	// than the file list it is built from. ?files=1 is the listing's own
	// address and the only way back, since the site page is the user's own
	// HTML and injecting a way back into it would corrupt their document.
	//
	// Ahead of the single-file redirect so a one-page share with an entry
	// still lands on its /site URL, where a relative reference could resolve,
	// rather than on the /view slug URL, where none can.
	entry, err := p.siteEntry()
	if err != nil {
		h.pageError(w, err)
		return
	}
	site := ""
	if entry != "" {
		site = h.payloadURL(entry)
	}
	if site != "" && query.Get("files") != "1" {
		http.Redirect(w, r, site, http.StatusFound)
		return
	}
	// A share of one file hands out that file, which is what a link to a
	// single document should do. Listing opts out: the owner asked for the
	// page, and for a file no browser renders it is the only View link there
	// is. After the gallery and site branches, which answer the same question
	// and already won. A later page of a listing is never this answer.
	if after == "" && !v.Listing {
		f, one, err := p.onlyFile()
		if err != nil {
			h.pageError(w, err)
			return
		}
		if one {
			http.Redirect(w, r, h.payloadURL("/view/"+id+"/"+f.Slug), http.StatusFound)
			return
		}
	}

	title := shareTitle(v)
	// The folder shown: the root, or the dir query parameter, which must be
	// a clean relpath naming a folder of the share. Anything else is the
	// same 404 an unknown slug gets.
	dir := query.Get("dir")
	if dir != "" && !shareid.ValidRelPath(dir) {
		h.notFoundPage(w, r)
		return
	}
	filesFlag := query.Get("files") == "1"
	page, more, ok, err := h.folderPageOf(p, dir, after, filesFlag)
	if err != nil {
		h.pageError(w, err)
		return
	}
	if !ok {
		h.notFoundPage(w, r)
		return
	}
	page.Crumbs = crumbsFor(id, title, dir, filesFlag)
	folderZip := ""
	if dir != "" && page.beneath > 0 {
		folderZip = h.payloadURL(zipHref(id, dir))
	}
	count, total := v.Totals()
	data := listingData{ID: id, Title: title, Folder: v.Folder, Count: count,
		TotalSize: humanSize(total), Page: page, FolderZip: folderZip,
		ZipAll:  h.payloadURL("/zip/" + id),
		Site:    site,
		Gallery: galleryBackURL(v),
		More:    more,
		Offline: v.LiveShare && !h.liveShareReg.Online(v.ID),
		OG:      h.shareCard(r, p.cardView()).tags()}
	h.renderPage(w, framable, 0, false, listingTmpl, data)
}

// folderPageOf is one page of folder dir: up to publicPageSize of its direct
// children after after, subfolders first, each kind in name order. more is
// the next page's address, "" on the last. A folder that fits one page, of a
// share of at most publicFolderTotalsMax entries, shows each subfolder's
// count and size, one range aggregate apiece; any other page shows neither,
// since its subfolders could hold the whole share and the aggregate reads
// every row beneath them. ok is false when dir names no folder of the share.
func (h *handler) folderPageOf(p *publicShare, dir, after string, filesFlag bool) (page folderPage, more string, ok bool, err error) {
	id := p.v.ID
	children, hasMore, err := p.children(dir, after, publicPageSize)
	if err != nil {
		return folderPage{}, "", false, err
	}
	if dir != "" && (after != "" || len(children) == 0) {
		if ok, err := p.hasFolder(dir); err != nil || !ok {
			return folderPage{}, "", false, err
		}
	}
	uncounted := hasMore || after != "" || p.v.whole.count > publicFolderTotalsMax
	prefix := folderPrefix(dir)
	page.Dir = dir
	var dirs []string
	for _, c := range children {
		if !c.dir {
			f := c.file
			page.Files = append(page.Files, listingFile{Name: c.name,
				View: h.payloadURL(viewURL(p.v, f, "")), Down: h.payloadURL(downloadURL(p.v, f)),
				Size: humanSize(f.Size)})
			continue
		}
		row := folderRow{Name: c.name, Path: prefix + c.name, Uncounted: uncounted}
		row.Href = folderHref(id, row.Path, filesFlag)
		if c.files {
			row.Zip = h.payloadURL(zipHref(id, row.Path))
		}
		page.Dirs = append(page.Dirs, row)
		dirs = append(dirs, row.Path)
	}
	page.beneath = len(page.Files)
	if !uncounted && len(dirs) > 0 {
		totals, err := p.folderTotals(dirs)
		if err != nil {
			return folderPage{}, "", false, err
		}
		for i := range page.Dirs {
			t := totals[page.Dirs[i].Path]
			page.Dirs[i].Count, page.Dirs[i].Size = t.Files, humanSize(t.Bytes)
			if t.Files == 0 {
				page.Dirs[i].Zip = ""
			}
		}
	}
	for _, row := range page.Dirs {
		if row.Zip != "" {
			page.beneath += max(row.Count, 1)
		}
	}
	sortByLowerName(page.Dirs, func(r folderRow) string { return r.Name })
	sortByLowerName(page.Files, func(f listingFile) string { return f.Name })
	if hasMore {
		more = moreHref(id, dir, children[len(children)-1].key(), filesFlag)
	}
	return page, more, true, nil
}

// humanSize renders a file's size on the public listing page. Binary, unlike
// everything the SHARER reads: this is the page a recipient opens, and the
// figure beside a filename is the one a file manager shows them.
func humanSize(n int64) string { return bytefmt.Binary(n) }
