package api

import (
	"fmt"
	"reflect"
	"testing"

	"hyperdrop/server/internal/metadb"
)

// folderFixture is a share whose entries live in memory, as a live share's
// do, so the folder logic runs with no file row: the stored half is the
// same merge, read through metadb.FolderChildren (listingpage_test.go).
func folderFixture(t *testing.T, folders ...string) (*handler, *publicShare) {
	t.Helper()
	_, h := newTestAPIParts(t)
	mem := []fileView{
		{File: metadb.File{Path: "z.txt", Size: 1, Slug: "s1"}},
		{File: metadb.File{Path: "b/inner/deep.txt", Size: 10, Slug: "s2"}},
		{File: metadb.File{Path: "b/a.txt", Size: 100, Slug: "s3"}},
		{File: metadb.File{Path: "A.txt", Size: 1000, Slug: "s4"}},
		{File: metadb.File{Path: "b.txt", Size: 5, Slug: "s5"}},
	}
	sortFilesByPath(mem)
	return h, &publicShare{h: h, mem: mem,
		v: shareView{Share: metadb.Share{ID: "abcdefghjk", Folders: folders}, whole: &shareTotals{count: len(mem)}}}
}

// folderOf is one folder's first page of the fixture.
func folderOf(t *testing.T, h *handler, p *publicShare, dir string) (folderPage, bool) {
	t.Helper()
	page, _, ok, err := h.folderPageOf(p, dir, "", false)
	if err != nil {
		t.Fatal(err)
	}
	return page, ok
}

// The root page holds the files directly in the root and ONE row per
// subfolder, sized by everything beneath it, folders first, both sorted
// case-insensitively. A file named like a folder with a suffix (b.txt beside
// folder b) is a file, not the folder.
func TestFolderViewRoot(t *testing.T) {
	h, p := folderFixture(t)
	page, ok := folderOf(t, h, p, "")
	if !ok {
		t.Fatal("the root always exists")
	}
	if page.Dir != "" {
		t.Errorf("Dir = %q, want root", page.Dir)
	}
	if len(page.Dirs) != 1 || page.Dirs[0].Name != "b" || page.Dirs[0].Path != "b" {
		t.Fatalf("root dirs = %+v, want one row b", page.Dirs)
	}
	if page.Dirs[0].Count != 2 || page.Dirs[0].Size != humanSize(110) || page.Dirs[0].Uncounted {
		t.Errorf("b = %+v, want 2 files anywhere beneath, %s", page.Dirs[0], humanSize(110))
	}
	got := []string{}
	for _, f := range page.Files {
		got = append(got, f.Name)
	}
	if want := []string{"A.txt", "b.txt", "z.txt"}; !reflect.DeepEqual(got, want) {
		t.Errorf("root files = %v, want %v", got, want)
	}
	if page.Files[0].View != "/view/abcdefghjk/s4" || page.Files[0].Down != "/download/abcdefghjk/s4" || page.Files[0].Size != humanSize(1000) {
		t.Errorf("A.txt row = %+v, want its own links and size", page.Files[0])
	}
}

// A folder page holds only that folder's children: names are basenames, a
// deeper file shows as its subfolder, and nothing from outside the folder
// leaks in.
func TestFolderViewSubfolder(t *testing.T) {
	h, p := folderFixture(t)
	page, ok := folderOf(t, h, p, "b")
	if !ok {
		t.Fatal("b exists: files sit beneath it")
	}
	if len(page.Dirs) != 1 || page.Dirs[0].Name != "inner" || page.Dirs[0].Path != "b/inner" || page.Dirs[0].Count != 1 {
		t.Errorf("b dirs = %+v, want inner with one file", page.Dirs)
	}
	if len(page.Files) != 1 || page.Files[0].Name != "a.txt" {
		t.Errorf("b files = %+v, want a.txt only", page.Files)
	}
	deep, ok := folderOf(t, h, p, "b/inner")
	if !ok || len(deep.Dirs) != 0 || len(deep.Files) != 1 || deep.Files[0].Name != "deep.txt" {
		t.Errorf("b/inner = %+v %v, want deep.txt alone", deep, ok)
	}
}

// A folder nothing sits beneath does not exist, and a file is not a folder.
func TestFolderViewUnknownFolder(t *testing.T) {
	h, p := folderFixture(t)
	for _, dir := range []string{"nope", "b/missing", "z.txt", "b/a.txt", "inner"} {
		if _, ok := folderOf(t, h, p, dir); ok {
			t.Errorf("dir %q reported as existing", dir)
		}
	}
}

// Explicit folder records add the subfolders no file implies, an empty one
// counts zero, and the record itself is a folder a visitor can open.
func TestFolderViewExplicitFolders(t *testing.T) {
	h, p := folderFixture(t, "drafts", "b/notes/2024")
	root, _ := folderOf(t, h, p, "")
	names := []string{}
	for _, d := range root.Dirs {
		names = append(names, d.Name+":"+d.Size)
	}
	if want := []string{"b:" + humanSize(110), "drafts:" + humanSize(0)}; !reflect.DeepEqual(names, want) {
		t.Errorf("root dirs = %v, want %v", names, want)
	}
	if root.Dirs[1].Count != 0 || root.Dirs[1].Zip != "" {
		t.Errorf("drafts = %+v, want count 0 and nothing to archive", root.Dirs[1])
	}
	empty, ok := folderOf(t, h, p, "drafts")
	if !ok || len(empty.Dirs) != 0 || len(empty.Files) != 0 {
		t.Errorf("drafts = %+v %v, want an existing empty page", empty, ok)
	}
	b, _ := folderOf(t, h, p, "b")
	if len(b.Dirs) != 2 || b.Dirs[0].Name != "inner" || b.Dirs[1].Name != "notes" {
		t.Errorf("b dirs = %+v, want inner and notes", b.Dirs)
	}
	if _, ok := folderOf(t, h, p, "b/notes"); !ok {
		t.Error("b/notes is implied by the record b/notes/2024")
	}
	bare := &publicShare{h: h, v: shareView{Share: metadb.Share{ID: "abcdefghjk", Folders: []string{"b/notes/2024"}}, whole: &shareTotals{}}}
	if _, ok := folderOf(t, h, bare, "b/notes/2024"); !ok {
		t.Error("an explicit record with no files is still a folder")
	}
}

// A folder of more children than a page pages them in key order, rows
// uncounted, and the More link carries the last key.
func TestFolderViewPagesABigFolder(t *testing.T) {
	_, h := newTestAPIParts(t)
	var mem []fileView
	for i := range publicPageSize + 1 {
		mem = append(mem, fileView{File: metadb.File{Path: fmt.Sprintf("d%03d/x", i), Slug: "s"}})
	}
	p := &publicShare{h: h, mem: mem, v: shareView{Share: metadb.Share{ID: "abcdefghjk"}, whole: &shareTotals{count: len(mem)}}}
	page, more, ok, err := h.folderPageOf(p, "", "", false)
	if err != nil || !ok || len(page.Dirs) != publicPageSize || more != "/share/abcdefghjk?after=d499%2F" {
		t.Fatalf("page of %d, more %q, %v %v", len(page.Dirs), more, ok, err)
	}
	if !page.Dirs[0].Uncounted || page.Dirs[0].Size != "" || page.Dirs[0].Zip == "" {
		t.Errorf("a paged row = %+v, want uncounted and downloadable", page.Dirs[0])
	}
	page, more, _, _ = h.folderPageOf(p, "", "d499/", false)
	if len(page.Dirs) != 1 || page.Dirs[0].Name != "d500" || more != "" || !page.Dirs[0].Uncounted {
		t.Errorf("last page %+v, more %q", page.Dirs, more)
	}
}

// Folder links keep the share's immutable address and carry the folder in
// the query only; files=1 rides along so a gallery or site share keeps
// listing.
func TestFolderHrefAndCrumbs(t *testing.T) {
	if got := folderHref("abc", "", false); got != "/share/abc" {
		t.Errorf("root href = %q", got)
	}
	if got := folderHref("abc", "a b/c&d", false); got != "/share/abc?dir=a+b%2Fc%26d" {
		t.Errorf("escaped href = %q", got)
	}
	if got := folderHref("abc", "", true); got != "/share/abc?files=1" {
		t.Errorf("root href with files = %q", got)
	}
	if got := folderHref("abc", "a", true); got != "/share/abc?dir=a&files=1" {
		t.Errorf("folder href with files = %q", got)
	}
	crumbs := crumbsFor("abc", "vacation", "2024/beach", true)
	want := []crumb{
		{Name: "vacation", Href: "/share/abc?files=1"},
		{Name: "2024", Href: "/share/abc?dir=2024&files=1"},
		{Name: "beach", Href: ""},
	}
	if !reflect.DeepEqual(crumbs, want) {
		t.Errorf("crumbs = %+v, want %+v", crumbs, want)
	}
	if got := crumbsFor("abc", "vacation", "", false); got != nil {
		t.Errorf("the root has no breadcrumbs, got %+v", got)
	}
}
