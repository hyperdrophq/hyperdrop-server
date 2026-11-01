package api

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"path"
	"time"

	"hyperdrop/server/internal/metadb"
)

// galleryItem is one file as the gallery page reads it. The keys are short
// because the whole list is inlined into the page: a 2,000-photo gallery is
// the size of its own item list, and "slug"/"thumbnail" spelled out for every
// row costs more than the pictures' names do.
//
// Everything past Down is optional. A gallery with none of it renders as
// square tiles in name order, which is what a share created from a terminal
// gets and is still a usable page.
type galleryItem struct {
	Slug string `json:"s"`
	Name string `json:"n"`
	// Path is the relpath, sent only when it differs from Name, so a flat
	// share does not carry every filename twice. The search box matches it,
	// so a folder name finds what is inside it.
	Path  string `json:"p,omitempty"`
	Kind  string `json:"k"`
	Size  int64  `json:"z"`
	View  string `json:"v"`
	Down  string `json:"d"`
	Thumb string `json:"t,omitempty"`
	W     int    `json:"w,omitempty"`
	H     int    `json:"h,omitempty"`
	MS    int    `json:"ms,omitempty"`
	Taken string `json:"ta,omitempty"`
	At    string `json:"ca,omitempty"`
}

// payloadURL is where a page points at bytes. Absolute on the file
// origin whenever there is one: the page itself runs on the app origin, so a
// root-relative /view would take the origin router's 308 once per picture,
// which is 200 extra round trips on a page whose whole job is showing 200
// pictures. A server with no domain has no split and no host to name.
func (h *handler) payloadURL(p string) string {
	return h.payloadBase() + p
}

// payloadBase is what payloadURL puts in front of a root-relative path:
// "https://files.<domain>", or "" when there is no origin split.
func (h *handler) payloadBase() string {
	o := h.origins()
	if !o.Split() {
		return ""
	}
	return "https://" + o.File
}

// galleryItems joins the view's files with the two sidecars, read for those
// files' slugs alone. Both sidecar reads are best effort: a share whose
// metadata or thumbnails are missing renders without them rather than not at
// all.
func (h *handler) galleryItems(v shareView) []galleryItem {
	slugs := make([]string, 0, len(v.Files))
	for _, f := range v.Files {
		slugs = append(slugs, f.Slug)
	}
	meta, err := h.db.GalleryOf(v.ID, slugs)
	if err != nil {
		meta = map[string]metadb.GalleryItem{}
	}
	thumbs, err := h.fs.ThumbsAmong(v.ID, slugs)
	if err != nil {
		thumbs = map[string]bool{}
	}
	base := h.payloadBase()
	out := make([]galleryItem, 0, len(v.Files))
	for _, f := range v.Files {
		name := path.Base(f.Path)
		it := galleryItem{
			Slug: f.Slug, Name: name, Kind: mediaKind(f.Mime, f.Path),
			Size: f.Size,
			// viewURL, not a hand-built /view: an HTML file in a gallery's
			// file list opens by PATH like it does in the listing, so its
			// relative references resolve. Every other kind gets /view.
			View: base + viewURL(v, f, ""),
			Down: base + downloadURL(v, f),
		}
		if f.Path != name {
			it.Path = f.Path
		}
		if thumbs[f.Slug] {
			it.Thumb = base + "/thumb/" + v.ID + "/" + f.Slug
		}
		if m, ok := meta[f.Slug]; ok {
			it.W, it.H, it.MS = m.Width, m.Height, m.DurationMS
			if m.TakenAt != nil {
				it.Taken = m.TakenAt.UTC().Format(time.RFC3339)
			}
		}
		if f.CommittedAt != nil {
			it.At = f.CommittedAt.UTC().Format(time.RFC3339)
		}
		out = append(out, it)
	}
	return out
}

// galleryTmpl is a media share's public page: a justified thumbnail grid, a
// lightbox, sorting, filtering, search and a slideshow.
//
// Self-contained like every other public page here: inline CSS, inline
// vanilla JS, inline SVG, no request to anything but this server. It renders
// on the APP origin (isPagePath) while every picture it points at is an
// absolute URL on the FILE origin, so a viewer's cookie reaches the bytes
// (openDests honours image, video and audio) and no uploaded file is ever
// same-origin with this page.
//
// html/template parses what is inside <script>, so the script carries no
// regex literals, and the item JSON reaches it through the one action in a
// script block, which json.Marshal has already escaped out of </script>.
//
// The grid is justified by FLEXBOX rather than by measurement: each tile
// carries a flex-grow proportional to its aspect ratio, and flex-wrap fills
// each line, so a 2,000-item gallery lays out as fast as a 20-item one and a
// resize costs no JavaScript except at the one breakpoint where the tile
// height itself changes. Tiles crop (object-fit: cover) rather than
// distorting, and the grid's ::after with an enormous flex-grow stops the
// last line stretching its two survivors across the whole width.
var galleryTmpl = page("gallery", "gallery.html")

// galleryData is what the gallery template renders.
type galleryData struct {
	ID        string
	Title     string
	Count     int
	TotalSize string
	// Items is the JSON array above. It reaches the page through a
	// template.JS, which is safe because json.Marshal escapes <, > and & to
	// their \u form: a file called </script> cannot close the block it is
	// written into.
	Items    template.JS
	ZipURL   string
	FilesURL string
	// More is the address of the gallery's next page, "" on its last.
	More string
	OG   template.HTML
}

// galleryPage renders one page of a media share's pictures: up to
// publicPageSize files after after in relpath order, and a More link past
// the last. The caller has already put the share through loadPublicPage, so
// expiry, a suspended owner, an inbox link and the password gate are all
// settled before anything here runs.
func (h *handler) galleryPage(w http.ResponseWriter, r *http.Request, p *publicShare, after string) {
	files, more, err := p.filesAfter(after, publicPageSize)
	if err == nil {
		files, err = p.named(files)
	}
	if err != nil {
		h.pageError(w, err)
		return
	}
	v := p.v
	v.Files = files
	items := h.galleryItems(v)
	data, err := json.Marshal(items)
	if err != nil {
		data = []byte("[]")
	}
	card := v
	if after != "" {
		card = p.cardView()
	}
	next := ""
	if more {
		next = "/share/" + v.ID + "?" + url.Values{"after": {files[len(files)-1].Path}}.Encode()
	}
	count, total := v.Totals()
	h.renderPage(w, framable, 0, false, galleryTmpl, galleryData{
		ID: v.ID, Title: shareTitle(v), Count: count, TotalSize: humanSize(total),
		Items:    template.JS(data), // #nosec G203 -- json.Marshal escapes <, > and &, see Items
		ZipURL:   h.payloadURL("/zip/" + v.ID),
		FilesURL: "/share/" + v.ID + "?files=1",
		More:     next,
		OG:       h.shareCard(r, card).tags(),
	})
}

// galleryBackURL is the address of this share's gallery, for the file list's
// way back, or "" for a share that has none. The plain /share/{id} renders
// the gallery whenever the share is a media share, so that is the whole rule.
func galleryBackURL(v shareView) string {
	if !v.Media {
		return ""
	}
	return "/share/" + v.ID
}
