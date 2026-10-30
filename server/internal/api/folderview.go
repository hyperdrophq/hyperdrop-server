package api

import (
	"net/url"
	"strings"
)

// folderRow is one subfolder on a folder page: what a visitor is about to
// open, counted and sized so they know before they click.
type folderRow struct {
	Name  string // basename
	Path  string // relpath, what the link carries
	Href  string // filled by the caller from Path (folderHref)
	Zip   string // filled by the caller from Path (zipHref), "" when empty
	Count int    // files anywhere beneath
	Size  string // bytes anywhere beneath, humanSize
	// Uncounted marks a row on a page of a folder too big for one page,
	// which reads neither Count nor Size.
	Uncounted bool
}

// crumb is one breadcrumb: the share name for the root, then each folder
// on the way to the one shown. The last crumb is the folder shown and has
// no Href.
type crumb struct {
	Name string
	Href string
}

// folderPage is what ONE folder of a share renders as.
type folderPage struct {
	Dir    string // "" for the root
	Crumbs []crumb
	Dirs   []folderRow
	Files  []listingFile
	// beneath is how many files the page knows of beneath the folder: none
	// means there is nothing to archive.
	beneath int
}

// zipHref is the archive of ONE folder of a share: the whole-share route with
// the folder named, so a visitor takes a subtree home without opening it and
// picking the files out one at a time. Empty for a folder holding no files,
// which the route itself refuses.
func zipHref(id, dir string) string {
	if dir == "" {
		return "/zip/" + id
	}
	return "/zip/" + id + "?" + url.Values{"dir": {dir}}.Encode()
}

// folderHref is a folder page's address: the share's immutable /share URL,
// the folder in the dir query parameter (never in the path, which is what
// keeps every share address one route), and files=1 carried along when the
// listing is the share's escape hatch from its gallery or site.
func folderHref(id, dir string, filesFlag bool) string {
	q := url.Values{}
	if dir != "" {
		q.Set("dir", dir)
	}
	if filesFlag {
		q.Set("files", "1")
	}
	if len(q) == 0 {
		return "/share/" + id
	}
	return "/share/" + id + "?" + q.Encode()
}

// crumbsFor is the breadcrumb trail for dir: the share name linking to the
// root, one link per folder on the way, and the folder shown last with no
// link. The root itself has no trail.
func crumbsFor(id, title, dir string, filesFlag bool) []crumb {
	if dir == "" {
		return nil
	}
	crumbs := []crumb{{Name: title, Href: folderHref(id, "", filesFlag)}}
	segs := strings.Split(dir, "/")
	for i, seg := range segs {
		c := crumb{Name: seg}
		if i < len(segs)-1 {
			c.Href = folderHref(id, strings.Join(segs[:i+1], "/"), filesFlag)
		}
		crumbs = append(crumbs, c)
	}
	return crumbs
}
