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
// shows ONE folder at a time with breadcrumbs, so a visitor never downloads
// the whole file list and the server never builds a whole-share tree per
// request (folderview.go).
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
	OG      template.HTML
}

func (h *handler) sharePage(w http.ResponseWriter, r *http.Request) {
	v, ok := h.loadPublicShare(w, r)
	if !ok {
		return
	}
	// Every unfurler is answered here, before the single-file redirect:
	// unfurlers that don't follow redirects would otherwise see nothing at
	// all.
	if isUnfurler(r.UserAgent()) {
		if len(v.Files) == 1 {
			h.renderCard(w, h.fileCard(r, v, v.Files[0]))
		} else {
			h.renderCard(w, h.shareCard(r, v))
		}
		return
	}
	id := v.ID
	// A share still uploading is the waiting page, whatever it will open as:
	// the visitor watches the whole share's progress and is reloaded into
	// the gallery, the site, the file or the listing the moment the last
	// file lands. Ahead of every other branch, and of ?files=1, so no page
	// ever renders a half-uploaded share.
	if v.AnyPending() {
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
	if v.Media && r.URL.Query().Get("files") != "1" {
		h.galleryPage(w, r, v)
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
	site := h.payloadURLOr(siteEntryURL(v, ""))
	if site != "" && r.URL.Query().Get("files") != "1" {
		http.Redirect(w, r, site, http.StatusFound)
		return
	}
	// A share of one file hands out that file, which is what a link to a
	// single document should do. Listing opts out: the owner asked for the
	// page, and for a file no browser renders it is the only View link there
	// is. After the gallery and site branches, which answer the same question
	// and already won.
	if len(v.Files) == 1 && !v.Listing {
		http.Redirect(w, r, h.payloadURL("/view/"+id+"/"+v.Files[0].Slug), http.StatusFound)
		return
	}

	title := shareTitle(v)
	// The folder shown: the root, or the dir query parameter, which must be
	// a clean relpath naming a folder of the share. Anything else is the
	// same 404 an unknown slug gets.
	dir := r.URL.Query().Get("dir")
	if dir != "" && !shareid.ValidRelPath(dir) {
		h.notFoundPage(w, r)
		return
	}
	var total int64
	// Iterate the manifest without copying it. Only direct children need
	// file links; deeper entries contribute their count and bytes alone.
	prefix := ""
	if dir != "" {
		prefix = dir + "/"
	}
	entries := func(yield func(folderEntry) bool) {
		for _, f := range v.Files {
			total += f.Size
			e := folderEntry{Path: f.Path, Size: f.Size}
			if rest, ok := strings.CutPrefix(f.Path, prefix); ok && !strings.Contains(rest, "/") {
				e.View = h.payloadURL(viewURL(v, f, ""))
				e.Down = h.payloadURL(downloadURL(v, f))
			}
			if !yield(e) {
				return
			}
		}
	}
	page, ok := folderView(entries, v.Folders, dir)
	if !ok {
		h.notFoundPage(w, r)
		return
	}
	filesFlag := r.URL.Query().Get("files") == "1"
	// A folder holds files somewhere beneath it, which is what makes it
	// downloadable: an empty folder record is listed but has nothing to
	// archive.
	beneath := len(page.Files)
	for i := range page.Dirs {
		page.Dirs[i].Href = folderHref(id, page.Dirs[i].Path, filesFlag)
		if page.Dirs[i].Count > 0 {
			page.Dirs[i].Zip = h.payloadURL(zipHref(id, page.Dirs[i].Path))
		}
		beneath += page.Dirs[i].Count
	}
	page.Crumbs = crumbsFor(id, title, dir, filesFlag)
	folderZip := ""
	if dir != "" && beneath > 0 {
		folderZip = h.payloadURL(zipHref(id, dir))
	}
	data := listingData{ID: id, Title: title, Folder: v.Folder, Count: len(v.Files),
		TotalSize: humanSize(total), Page: page, FolderZip: folderZip,
		ZipAll:  h.payloadURL("/zip/" + id),
		Site:    site,
		Gallery: galleryBackURL(v),
		Offline: v.LiveShare && !h.liveShareReg.Online(v.ID),
		OG:      h.shareCard(r, v).tags()}
	h.renderPage(w, framable, 0, false, listingTmpl, data)
}

// humanSize renders a file's size on the public listing page. Binary, unlike
// everything the SHARER reads: this is the page a recipient opens, and the
// figure beside a filename is the one a file manager shows them.
func humanSize(n int64) string { return bytefmt.Binary(n) }
