package api

import (
	"iter"
	"reflect"
	"slices"
	"testing"
)

func folderFixture() iter.Seq[folderEntry] {
	return slices.Values([]folderEntry{
		{Path: "z.txt", Size: 1, View: "v1", Down: "d1"},
		{Path: "b/inner/deep.txt", Size: 10, View: "v2", Down: "d2"},
		{Path: "b/a.txt", Size: 100, View: "v3", Down: "d3"},
		{Path: "A.txt", Size: 1000, View: "v4", Down: "d4"},
		{Path: "b.txt", Size: 5, View: "v5", Down: "d5"},
	})
}

// The root page holds the files directly in the root and ONE row per
// subfolder, sized by everything beneath it, folders first, both sorted
// case-insensitively. A file named like a folder with a suffix (b.txt beside
// folder b) is a file, not the folder.
func TestFolderViewRoot(t *testing.T) {
	page, ok := folderView(folderFixture(), nil, "")
	if !ok {
		t.Fatal("the root always exists")
	}
	if page.Dir != "" {
		t.Errorf("Dir = %q, want root", page.Dir)
	}
	if len(page.Dirs) != 1 || page.Dirs[0].Name != "b" || page.Dirs[0].Path != "b" {
		t.Fatalf("root dirs = %+v, want one row b", page.Dirs)
	}
	if page.Dirs[0].Count != 2 || page.Dirs[0].Size != humanSize(110) {
		t.Errorf("b = %+v, want 2 files anywhere beneath, %s", page.Dirs[0], humanSize(110))
	}
	got := []string{}
	for _, f := range page.Files {
		got = append(got, f.Name)
	}
	if want := []string{"A.txt", "b.txt", "z.txt"}; !reflect.DeepEqual(got, want) {
		t.Errorf("root files = %v, want %v", got, want)
	}
	if page.Files[0].View != "v4" || page.Files[0].Down != "d4" || page.Files[0].Size != humanSize(1000) {
		t.Errorf("A.txt row = %+v, want its own links and size", page.Files[0])
	}
}

// A folder page holds only that folder's children: names are basenames, a
// deeper file shows as its subfolder, and nothing from outside the folder
// leaks in.
func TestFolderViewSubfolder(t *testing.T) {
	page, ok := folderView(folderFixture(), nil, "b")
	if !ok {
		t.Fatal("b exists: files sit beneath it")
	}
	if len(page.Dirs) != 1 || page.Dirs[0].Name != "inner" || page.Dirs[0].Path != "b/inner" || page.Dirs[0].Count != 1 {
		t.Errorf("b dirs = %+v, want inner with one file", page.Dirs)
	}
	if len(page.Files) != 1 || page.Files[0].Name != "a.txt" {
		t.Errorf("b files = %+v, want a.txt only", page.Files)
	}
	deep, ok := folderView(folderFixture(), nil, "b/inner")
	if !ok || len(deep.Dirs) != 0 || len(deep.Files) != 1 || deep.Files[0].Name != "deep.txt" {
		t.Errorf("b/inner = %+v %v, want deep.txt alone", deep, ok)
	}
}

// A folder nothing sits beneath does not exist, and a file is not a folder.
func TestFolderViewUnknownFolder(t *testing.T) {
	for _, dir := range []string{"nope", "b/missing", "z.txt", "b/a.txt", "inner"} {
		if _, ok := folderView(folderFixture(), nil, dir); ok {
			t.Errorf("dir %q reported as existing", dir)
		}
	}
}

// Explicit folder records add the subfolders no file implies, an empty one
// counts zero, and the record itself is a folder a visitor can open.
func TestFolderViewExplicitFolders(t *testing.T) {
	folders := []string{"drafts", "b/notes/2024"}
	root, _ := folderView(folderFixture(), folders, "")
	names := []string{}
	for _, d := range root.Dirs {
		names = append(names, d.Name+":"+d.Size)
	}
	if want := []string{"b:" + humanSize(110), "drafts:" + humanSize(0)}; !reflect.DeepEqual(names, want) {
		t.Errorf("root dirs = %v, want %v", names, want)
	}
	if root.Dirs[1].Count != 0 {
		t.Errorf("drafts count = %d, want 0", root.Dirs[1].Count)
	}
	empty, ok := folderView(folderFixture(), folders, "drafts")
	if !ok || len(empty.Dirs) != 0 || len(empty.Files) != 0 {
		t.Errorf("drafts = %+v %v, want an existing empty page", empty, ok)
	}
	b, _ := folderView(folderFixture(), folders, "b")
	if len(b.Dirs) != 2 || b.Dirs[0].Name != "inner" || b.Dirs[1].Name != "notes" {
		t.Errorf("b dirs = %+v, want inner and notes", b.Dirs)
	}
	if _, ok := folderView(folderFixture(), folders, "b/notes"); !ok {
		t.Error("b/notes is implied by the record b/notes/2024")
	}
	if _, ok := folderView(slices.Values([]folderEntry(nil)), folders, "b/notes/2024"); !ok {
		t.Error("an explicit record with no files is still a folder")
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
