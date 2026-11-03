package api

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"

	"hyperdrop/server/internal/linked"
	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/shareid"
)

// publicPageSize is how many entries one public page of a share shows: a
// listing's children of the folder shown, or a gallery's tiles. A bigger
// folder or gallery links the rest with a More link, ?after= the last
// entry's key, so a stranger's page view reads what it shows and never the
// whole share. The owner's reads and the zip are not pages and read whole.
const publicPageSize = 500

// publicFolderTotalsMax is the largest share whose listing counts and sizes
// its subfolders. Those totals are range aggregates over every row beneath
// each subfolder, so above this a page that fits shows its subfolders
// uncounted too, as a paged one does. It matches linked.MaxWalk, the most a
// linked share's walk holds.
const publicFolderTotalsMax = 10000

// publicShare is one share as a public page reads it: the row without its
// file list, and the entries no files row holds, in relpath byte order: a
// linked walk's (less any an upload shadows), slugless until a page shows
// them, or a live share's whole list, which lives in memory anyway.
type publicShare struct {
	h *handler
	// v is the gate's view with Files empty and whole set to the whole
	// share's count and bytes.
	v shareView
	// stored says the share has rows in the files table; a live share has
	// none.
	stored bool
	mem    []fileView
	// slugs mints the slugs of mem's linked entries; nil when mem carries
	// them.
	slugs func(rels []string) (map[string]string, error)
}

// loadPublicPage is loadPublicShare for a page that shows the share one page
// at a time: the gate runs over the row and the linked walk, and no file row
// is read until the page asks for its own.
func (h *handler) loadPublicPage(w http.ResponseWriter, r *http.Request) (*publicShare, bool) {
	var walk composedWalk
	var hasWalk bool
	read := func(id string) (shareView, error) {
		d, err := h.db.ShareWithoutFiles(id)
		if err != nil {
			return shareView{}, err
		}
		v := viewOf(d)
		v.Truncated = false
		walk, hasWalk = h.linkedWalkOf(d, &v, true)
		return v, nil
	}
	v, ok := h.loadPublicShareVia(w, r, read)
	if !ok {
		return nil, false
	}
	p := &publicShare{h: h}
	var whole shareTotals
	if v.LiveShare {
		p.mem = slices.Clone(v.Files)
		sortFilesByPath(p.mem)
		whole = shareTotals{count: len(v.Files), bytes: v.TotalBytes}
	} else {
		p.stored = true
		whole = shareTotals{count: v.FileCount, bytes: v.Bytes}
		if hasWalk {
			mem, err := h.unshadowed(v.ID, v.FileCount, walk.entries)
			if err != nil {
				h.pageError(w, err)
				return nil, false
			}
			p.mem, p.slugs = mem, walk.slugs
		}
		for _, f := range p.mem {
			whole.count++
			whole.bytes += f.Size
		}
	}
	p.v = v
	p.v.Files = nil
	p.v.whole = &whole
	return p, true
}

// unshadowed lifts a linked walk into slugless file entries, less those an
// upload of the same relpath shadows; a share with no file row has none to
// ask about.
func (h *handler) unshadowed(id string, fileRows int, entries []linked.Entry) ([]fileView, error) {
	var shadowed map[string]bool
	if fileRows > 0 && len(entries) > 0 {
		rels := make([]string, len(entries))
		for i, e := range entries {
			rels[i] = e.Rel
		}
		var err error
		if shadowed, err = h.db.StoredPaths(id, rels); err != nil {
			return nil, err
		}
	}
	out := make([]fileView, 0, len(entries))
	for _, e := range entries {
		if !shadowed[e.Rel] {
			out = append(out, linkedFile(e, ""))
		}
	}
	return out, nil
}

// sortFilesByPath orders files by relpath in byte order, the files table's.
func sortFilesByPath(files []fileView) {
	slices.SortFunc(files, func(a, b fileView) int { return strings.Compare(a.Path, b.Path) })
}

// pageError answers a public page whose read failed: the cause goes to the
// log under a reference, the visitor gets the reference alone.
func (h *handler) pageError(w http.ResponseWriter, err error) {
	ref := internalError(err)
	http.Error(w, ref.msg, ref.status)
}

// memFrom is the index of mem's first entry at or after from (inclusive)
// or strictly after it.
func (p *publicShare) memFrom(from string, inclusive bool) int {
	return sort.Search(len(p.mem), func(i int) bool {
		if inclusive {
			return p.mem[i].Path >= from
		}
		return p.mem[i].Path > from
	})
}

// pending reports whether any file is still uploading: the row's counters
// for a stored share, which its triggers keep in the statement that writes
// each file row, and the list for a live share.
func (p *publicShare) pending() bool {
	if p.stored {
		return p.v.FileCount > p.v.Committed
	}
	return slices.ContainsFunc(p.mem, func(f fileView) bool { return f.Pending })
}

// filesAfter is up to limit of the share's files after after in relpath
// byte order, stored and in-memory merged; more reports that further files
// follow. Linked entries carry no slug yet (named).
func (p *publicShare) filesAfter(after string, limit int) (files []fileView, more bool, err error) {
	var stored []metadb.File
	if p.stored {
		if stored, more, err = p.h.db.ShareFilesAfter(p.v.ID, after, limit); err != nil {
			return nil, false, err
		}
	}
	mem := p.mem[p.memFrom(after, false):]
	files = make([]fileView, 0, min(limit, len(stored)+len(mem)))
	i, j := 0, 0
	for len(files) < limit && (i < len(stored) || j < len(mem)) {
		if j >= len(mem) || (i < len(stored) && stored[i].Path < mem[j].Path) {
			files = append(files, fileView{File: stored[i]})
			i++
		} else {
			files = append(files, mem[j])
			j++
		}
	}
	return files, more || i < len(stored) || j < len(mem), nil
}

// named fills the slugs of the linked entries among files, minting what the
// share has not yet, so a page mints slugs for its own entries alone.
func (p *publicShare) named(files []fileView) ([]fileView, error) {
	if p.slugs == nil {
		return files, nil
	}
	var rels []string
	for _, f := range files {
		if f.Linked && f.Slug == "" {
			rels = append(rels, f.Path)
		}
	}
	if len(rels) == 0 {
		return files, nil
	}
	slugs, err := p.slugs(rels)
	if err != nil {
		return nil, err
	}
	for i := range files {
		if files[i].Linked && files[i].Slug == "" {
			files[i].Slug = slugs[files[i].Path]
		}
	}
	return files, nil
}

// onlyFile is the share's one file when it holds exactly one, wherever it
// sits, read as one row.
func (p *publicShare) onlyFile() (fileView, bool, error) {
	if p.v.whole.count != 1 {
		return fileView{}, false, nil
	}
	files, _, err := p.filesAfter("", 1)
	if err == nil && len(files) == 1 {
		files, err = p.named(files)
	}
	if err != nil || len(files) != 1 {
		return fileView{}, false, err
	}
	return files[0], true, nil
}

// hasFile reports whether the share holds rel, by one lookup: a stored row of
// exactly that spelling, or an entry of the walk, which a linked entry
// matches in any spelling with the same NFC, as FileByPath does.
func (p *publicShare) hasFile(rel string) (bool, error) {
	if !shareid.ValidRelPath(rel) {
		return false, nil
	}
	if p.stored {
		_, err := p.h.db.File(p.v.ID, rel)
		if err == nil {
			return true, nil
		}
		if !errors.Is(err, metadb.ErrNotFound) {
			return false, err
		}
	}
	if i := p.memFrom(rel, true); i < len(p.mem) && p.mem[i].Path == rel {
		return true, nil
	}
	want := relPath(rel)
	return slices.ContainsFunc(p.mem, func(f fileView) bool { return f.Linked && relPath(f.Path) == want }), nil
}

// cardView is the view a link card is drawn from: the whole share's totals
// and its first page of files, which is the whole share for one of
// publicPageSize files or fewer.
func (p *publicShare) cardView() shareView {
	v := p.v
	v.Files, _, _ = p.filesAfter("", publicPageSize)
	return v
}

// pageChild is one direct child of the folder a listing page shows.
type pageChild struct {
	name string
	dir  bool
	file fileView // a file child's entry
	// files says a subfolder has a file somewhere beneath it, which is what
	// makes it downloadable; a folder record alone has none.
	files bool
}

// key is the child's place in its folder (metadb.ChildKey).
func (c pageChild) key() string { return metadb.ChildKey(c.name, c.dir) }

// children is up to limit direct children of folder dir whose keys sort
// after after, in key order, which is relpath order: the stored rows'
// (metadb.FolderChildren), the in-memory entries' and the folder records',
// each subfolder once. more reports that further children follow.
func (p *publicShare) children(dir, after string, limit int) (out []pageChild, more bool, err error) {
	byKey := map[string]int{}
	add := func(c pageChild) {
		k := c.key()
		if after != "" && k <= after {
			return
		}
		if at, ok := byKey[k]; ok {
			out[at].files = out[at].files || c.files
			return
		}
		byKey[k] = len(out)
		out = append(out, c)
	}
	if p.stored {
		rows, rowsMore, err := p.h.db.FolderChildren(p.v.ID, dir, after, limit)
		if err != nil {
			return nil, false, err
		}
		for _, c := range rows {
			add(pageChild{name: c.Name, dir: c.Dir, file: fileView{File: c.File}, files: c.Dir})
		}
		more = rowsMore
	}
	for _, c := range p.memChildren(dir, after, limit+1) {
		add(c)
	}
	prefix := folderPrefix(dir)
	for _, f := range p.v.Folders {
		rest, ok := strings.CutPrefix(f, prefix)
		if !ok || rest == "" {
			continue
		}
		name, _, _ := strings.Cut(rest, "/")
		add(pageChild{name: name, dir: true})
	}
	slices.SortFunc(out, func(a, b pageChild) int { return strings.Compare(a.key(), b.key()) })
	if len(out) > limit {
		out, more = out[:limit], true
	}
	var files []fileView
	for _, c := range out {
		if !c.dir {
			files = append(files, c.file)
		}
	}
	if files, err = p.named(files); err != nil {
		return nil, false, err
	}
	for i, n := 0, 0; i < len(out); i++ {
		if !out[i].dir {
			out[i].file = files[n]
			n++
		}
	}
	return out, more, nil
}

// memChildren is up to n children of folder dir among the in-memory entries,
// after after: a binary search to the range, and one more past each
// subfolder's subtree.
func (p *publicShare) memChildren(dir, after string, n int) []pageChild {
	prefix := folderPrefix(dir)
	from, inclusive, below := metadb.ChildRange(dir, after)
	var out []pageChild
	for i := p.memFrom(from, inclusive); i < len(p.mem) && len(out) < n; {
		f := p.mem[i]
		if below != "" && f.Path >= below {
			break
		}
		rest := strings.TrimPrefix(f.Path, prefix)
		if name, _, deeper := strings.Cut(rest, "/"); deeper {
			out = append(out, pageChild{name: name, dir: true, files: true})
			next, _, _ := metadb.ChildRange(dir, name+"/")
			i = p.memFrom(next, true)
			continue
		}
		out = append(out, pageChild{name: rest, file: f})
		i++
	}
	return out
}

// hasFolder reports whether dir is a folder of the share: a folder record is
// it or lies beneath it, or a file does.
func (p *publicShare) hasFolder(dir string) (bool, error) {
	prefix := folderPrefix(dir)
	for _, f := range p.v.Folders {
		if f == dir || strings.HasPrefix(f, prefix) {
			return true, nil
		}
	}
	if i := p.memFrom(prefix, true); i < len(p.mem) && strings.HasPrefix(p.mem[i].Path, prefix) {
		return true, nil
	}
	if !p.stored {
		return false, nil
	}
	rows, _, err := p.h.db.FolderChildren(p.v.ID, dir, "", 1)
	return len(rows) > 0, err
}

// folderTotals is each named subfolder's files and bytes beneath it, stored
// and in memory.
func (p *publicShare) folderTotals(dirs []string) (map[string]metadb.FolderTotal, error) {
	totals := map[string]metadb.FolderTotal{}
	if p.stored {
		var err error
		if totals, err = p.h.db.FolderTotals(p.v.ID, dirs); err != nil {
			return nil, err
		}
	}
	for _, dir := range dirs {
		t := totals[dir]
		for i := p.memFrom(dir+"/", true); i < len(p.mem) && p.mem[i].Path < dir+"0"; i++ {
			t.Files++
			t.Bytes += p.mem[i].Size
		}
		totals[dir] = t
	}
	return totals, nil
}

// folderPrefix is what every relpath beneath dir starts with: "" for the
// root.
func folderPrefix(dir string) string {
	if dir == "" {
		return ""
	}
	return dir + "/"
}

// moreHref is the address of the page after the one shown: the share's
// /share URL with the folder, the files=1 flag and the last entry's key,
// encoded as one query string.
func moreHref(id, dir, after string, filesFlag bool) string {
	q := url.Values{"after": {after}}
	if dir != "" {
		q.Set("dir", dir)
	}
	if filesFlag {
		q.Set("files", "1")
	}
	return "/share/" + id + "?" + q.Encode()
}
