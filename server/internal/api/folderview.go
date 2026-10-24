package api

import (
	"iter"
	"net/url"
	"strings"
)

// folderEntry is one file of a share as the folder page reads it: its
// relpath, its size in bytes, and its two prebuilt slug links.
type folderEntry struct {
	Path string
	Size int64
	View string
	Down string
}

// folderRow is one subfolder on a folder page: what a visitor is about to
// open, counted and sized so they know before they click.
type folderRow struct {
	Name  string // basename
	Path  string // relpath, what the link carries
	Href  string // filled by the caller from Path (folderHref)
	Zip   string // filled by the caller from Path (zipHref), "" when empty
	Count int    // files anywhere beneath
	Size  string // bytes anywhere beneath, humanSize
	bytes int64
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
}

// folderView computes one folder of a share in a single pass over its flat
// file list: the files directly in dir become rows, every deeper file is
// folded into the subfolder it sits under, and the explicit folder records
// add the subfolders no file implies. Memory is proportional to the
// folder's own children, never to the share, which is what lets a share of
// a hundred thousand files answer a page.
//
// ok is false when dir names no folder of the share: no file sits beneath
// it and no folder record is it or lies beneath it. The root always exists.
func folderView(entries iter.Seq[folderEntry], folders []string, dir string) (folderPage, bool) {
	prefix := ""
	if dir != "" {
		prefix = dir + "/"
	}
	page := folderPage{Dir: dir}
	subs := map[string]*folderRow{}
	sub := func(name string) *folderRow {
		row := subs[name]
		if row == nil {
			row = &folderRow{Name: name, Path: prefix + name}
			subs[name] = row
		}
		return row
	}
	found := dir == ""
	for e := range entries {
		if !strings.HasPrefix(e.Path, prefix) {
			continue
		}
		found = true
		rest := e.Path[len(prefix):]
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			row := sub(rest[:i])
			row.Count++
			row.bytes += e.Size
			continue
		}
		page.Files = append(page.Files, listingFile{Name: rest, View: e.View, Down: e.Down, Size: humanSize(e.Size)})
	}
	for _, f := range folders {
		if f == dir {
			found = true
			continue
		}
		if !strings.HasPrefix(f, prefix) {
			continue
		}
		found = true
		rest := f[len(prefix):]
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			rest = rest[:i]
		}
		sub(rest)
	}
	if !found {
		return folderPage{}, false
	}
	for _, row := range subs {
		row.Size = humanSize(row.bytes)
		page.Dirs = append(page.Dirs, *row)
	}
	sortByLowerName(page.Dirs, func(r folderRow) string { return r.Name })
	sortByLowerName(page.Files, func(f listingFile) string { return f.Name })
	return page, true
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
