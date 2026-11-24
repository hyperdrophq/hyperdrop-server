package api

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"hyperdrop/server/internal/linked"
	"hyperdrop/server/internal/metadb"
)

func TestViewOfCopiesRowsAndSumsDeclaredBytes(t *testing.T) {
	at := time.Now().UTC().Truncate(time.Second)
	d := metadb.Share{ID: "abcdefghij", Owner: "admin", FileCount: 2, Committed: 1, Bytes: 5,
		Files: []metadb.File{
			{Path: "a.txt", Size: 5, Slug: "slug-a", CommittedAt: &at},
			{Path: "b.txt", Size: 9, Slug: "slug-b", Pending: true},
		}}
	v := viewOf(d)
	if len(v.Files) != 2 {
		t.Fatalf("view holds %d files, want both", len(v.Files))
	}
	if v.Share.Files != nil {
		t.Error("the row's own file list must be nil on a view, so nothing reads it twice")
	}
	if v.TotalBytes != 14 {
		t.Errorf("TotalBytes = %d, want 14: the landed 5 plus the 9 still arriving", v.TotalBytes)
	}
	count, bytes := v.Totals()
	if count != 2 || bytes != 14 {
		t.Errorf("Totals() = %d, %d; want the whole share 2, 14", count, bytes)
	}
	// A WINDOW onto a bigger share cannot count itself, so it answers the
	// row's counters, which cover what has landed.
	windowed := viewOf(metadb.Share{ID: "abcdefghij", Owner: "admin", FileCount: 40, Bytes: 5,
		Truncated: true, Files: d.Files})
	if count, bytes := windowed.Totals(); count != 40 || bytes != 5 {
		t.Errorf("windowed Totals() = %d, %d; want the counters 40, 5", count, bytes)
	}
	// A LINKED share is counted from both halves: the counters answer for
	// the stored files and the walk for the linked entries beside them,
	// because neither half knows the other's size.
	at2 := at
	linkedShare := viewOf(metadb.Share{ID: "abcdefghij", Owner: "admin", FileCount: 40, Bytes: 5,
		Truncated: true, Sources: []metadb.Source{{Path: "vol/photo"}}, Files: d.Files})
	linkedShare.Files = append(linkedShare.Files,
		fileView{Linked: true, File: metadb.File{Path: "c.txt", Size: 7, CommittedAt: &at2}})
	if count, bytes := linkedShare.Totals(); count != 41 || bytes != 12 {
		t.Errorf("windowed linked Totals() = %d, %d; want the counters 40, 5 plus the one "+
			"linked entry: 41, 12", count, bytes)
	}
}

func TestLinkedViewShadowsStoredPathsAndAssignsSlugs(t *testing.T) {
	vol := t.TempDir()
	if err := os.WriteFile(filepath.Join(vol, "a.txt"), []byte("from the folder"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vol, "b.txt"), []byte("bb"), 0o644); err != nil {
		t.Fatal(err)
	}
	roots, err := linked.NewRoots([]string{vol}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	b := testBackend(t)
	b.Roots = roots
	h := newHandler(b, "2.0.0", testDomain(t), nil, Deployment{})

	d, err := b.DB.CreateShare(metadb.CreateOptions{Name: "trip", Owner: metadb.DefaultAdminName,
		Folder: true, Sources: []string{filepath.Base(vol)}})
	if err != nil {
		t.Fatal(err)
	}
	// An upload of the same relpath shadows the folder's own entry.
	commitFile(t, b, d.ID, "a.txt", "uploaded")

	v, err := h.view(d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if v.SourceMissing {
		t.Fatal("a readable source must not read as missing")
	}
	var paths []string
	for _, f := range v.Files {
		paths = append(paths, f.Path)
	}
	if len(v.Files) != 2 {
		t.Fatalf("files = %v, want a.txt once and b.txt", paths)
	}
	a, ok := v.FileByPath("a.txt")
	if !ok || a.Linked || a.Size != int64(len("uploaded")) {
		t.Errorf("a.txt = %+v, want the upload rather than the folder's copy", a)
	}
	bEntry, ok := v.FileByPath("b.txt")
	if !ok || !bEntry.Linked || bEntry.Slug == "" {
		t.Fatalf("b.txt = %+v, want a linked entry with a slug", bEntry)
	}
	again, err := h.view(d.ID)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := again.FileByPath("b.txt")
	if second.Slug != bEntry.Slug {
		t.Errorf("slug for b.txt moved between reads: %q then %q", bEntry.Slug, second.Slug)
	}
	if _, ok := again.FileBySlug(bEntry.Slug); !ok {
		t.Error("a linked entry is not reachable by its own slug")
	}
}

func TestLinkedViewMarksAMissingSourceUnavailable(t *testing.T) {
	roots, err := linked.NewRoots([]string{t.TempDir()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	b := testBackend(t)
	b.Roots = roots
	h := newHandler(b, "2.0.0", testDomain(t), nil, Deployment{})

	d, err := b.DB.CreateShare(metadb.CreateOptions{Name: "gone", Owner: metadb.DefaultAdminName,
		Folder: true, Sources: []string{"no-such-folder"}})
	if err != nil {
		t.Fatal(err)
	}
	v, err := h.view(d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !v.SourceMissing {
		t.Error("a source that cannot be read must mark the share unavailable")
	}
}

func TestShareViewHelpers(t *testing.T) {
	past := time.Now().Add(-time.Minute)
	future := time.Now().Add(time.Hour)
	if (shareView{Share: metadb.Share{ExpiresAt: &past}}).Expired() != true {
		t.Error("a share past its expiry is expired")
	}
	if (shareView{Share: metadb.Share{ExpiresAt: &future}}).Expired() != false {
		t.Error("a share before its expiry is not expired")
	}
	if (shareView{}).Expired() != false {
		t.Error("a share with no expiry never expires")
	}

	one := shareView{Share: metadb.Share{Sources: []metadb.Source{{Path: "vol/photo"}}}}
	if one.Source() != "vol/photo" || len(one.SourceList()) != 1 || one.Prefixed() {
		t.Errorf("one source: %q %v %v", one.Source(), one.SourceList(), one.Prefixed())
	}
	two := shareView{Share: metadb.Share{Sources: []metadb.Source{{Path: "vol/a"}, {Path: "vol/b"}}}}
	if two.Source() != "vol/a" || len(two.SourceList()) != 2 || !two.Prefixed() {
		t.Errorf("two sources: %q %v %v", two.Source(), two.SourceList(), two.Prefixed())
	}
	none := shareView{}
	if none.Source() != "" || none.SourceList() != nil || none.Prefixed() {
		t.Error("an ordinary share names no source")
	}

	v := shareView{Files: []fileView{
		{File: metadb.File{Path: "a.txt", Slug: "sa"}},
		{File: metadb.File{Path: "b.txt", Slug: "sb"}, Linked: true},
		{File: metadb.File{Path: "c.txt", Slug: "sc", Pending: true}},
	}}
	if !v.AnyPending() {
		t.Error("a share holding one pending file reports it")
	}
	if len(v.StoredFiles()) != 2 {
		t.Errorf("StoredFiles = %d, want the two that are not linked", len(v.StoredFiles()))
	}
	if f, ok := v.FileByPath("b.txt"); !ok || !f.Linked {
		t.Error("FileByPath misses the linked entry")
	}
	if _, ok := v.FileByPath("nope.txt"); ok {
		t.Error("FileByPath answered for a path the share does not hold")
	}
	if f, ok := v.FileBySlug("sc"); !ok || f.Path != "c.txt" {
		t.Error("FileBySlug misses the pending entry")
	}
	if _, ok := v.FileBySlug(""); ok {
		t.Error("the empty slug must never resolve")
	}
	landed := shareView{Files: []fileView{{File: metadb.File{Path: "a.txt"}}}}
	if landed.AnyPending() {
		t.Error("a fully uploaded share has nothing pending")
	}
}
