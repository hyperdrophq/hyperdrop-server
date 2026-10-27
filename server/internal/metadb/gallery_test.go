package metadb

import "testing"

func TestGalleryMergesBySlugAndFollowsTheFile(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "pics", Owner: "alice", Media: true})
	a := commit(t, db, d.ID, "a.jpg", 1)
	b := commit(t, db, d.ID, "b.mp4", 1)
	taken := at
	if err := db.SetGallery(d.ID, map[string]GalleryItem{a.Slug: {Width: 10, Height: 20, TakenAt: &taken}, "not-a-slug": {Width: 1}}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetGallery(d.ID, map[string]GalleryItem{b.Slug: {DurationMS: 3000}}); err != nil {
		t.Fatal(err)
	}
	g, err := db.Gallery(d.ID)
	if err != nil || len(g) != 2 || g[a.Slug].Width != 10 || !g[a.Slug].TakenAt.Equal(at) || g[b.Slug].DurationMS != 3000 {
		t.Fatalf("gallery: %+v, %v", g, err)
	}
	if _, _, err := db.RemoveFiles(d.ID, []string{"a.jpg"}); err != nil {
		t.Fatal(err)
	}
	if g, _ = db.Gallery(d.ID); len(g) != 1 {
		t.Fatalf("gallery row must go with its file: %+v", g)
	}
}

// A donated slug carries the new file's link, so the row measuring the old
// bytes must not stay behind it, on either route that donates one.
func TestGalleryRowGoesWithADonatedSlug(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "pics", Owner: "alice", Media: true})
	a := commit(t, db, d.ID, "a.jpg", 1)
	commit(t, db, d.ID, "b.jpg", 1)
	taken := at
	if err := db.SetGallery(d.ID, map[string]GalleryItem{a.Slug: {Width: 10, Height: 20, TakenAt: &taken}}); err != nil {
		t.Fatal(err)
	}
	got, err := db.ReplaceEntry(d.ID, "b.jpg", "a.jpg")
	if err != nil || len(got.Files) != 1 || got.Files[0].Path != "b.jpg" || got.Files[0].Slug != a.Slug {
		t.Fatalf("replace: %+v, %v", got, err)
	}
	g, err := db.Gallery(d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := g[a.Slug]; ok {
		t.Fatalf("donated slug keeps the old bytes' row: %+v", g)
	}
	if len(g) != 0 {
		t.Fatalf("gallery: %+v, want no rows", g)
	}

	// Replace All donates too, and its trailing dangling prune cannot see the
	// donated slug: the UPDATE has already put it on the surviving file.
	d2 := mustShare(t, db, CreateOptions{Name: "clips", Owner: "alice", Media: true})
	c := commit(t, db, d2.ID, "c.mp4", 1)
	commit(t, db, d2.ID, "d.mp4", 1)
	if err := db.SetGallery(d2.ID, map[string]GalleryItem{c.Slug: {Width: 640, Height: 480, DurationMS: 3000}}); err != nil {
		t.Fatal(err)
	}
	got, err = db.ReplaceAll(d2.ID, "d.mp4")
	if err != nil || len(got.Files) != 1 || got.Files[0].Path != "d.mp4" || got.Files[0].Slug != c.Slug {
		t.Fatalf("replace all: %+v, %v", got, err)
	}
	g, err = db.Gallery(d2.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(g) != 0 {
		t.Fatalf("replace all keeps the donor's row: %+v", g)
	}
}

// A linked entry's slug is minted beside the walk and lives in linked_slugs,
// never in files. A gallery row keyed on one must be stored and must survive
// the prunes that follow a file leaving the share: without it a NAS folder
// shared as a gallery lays every tile out square in name order, because
// nothing the app measured about it can be kept.
func TestGalleryHoldsALinkedEntrysRow(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "nas", Owner: "alice", Media: true,
		Sources: []string{"clips"}})
	slugs, err := db.AssignSlugs(d.ID, []string{"a.mp4"})
	if err != nil {
		t.Fatal(err)
	}
	linked := slugs["a.mp4"]
	taken := at
	if err := db.SetGallery(d.ID, map[string]GalleryItem{
		linked: {Width: 2688, Height: 1512, DurationMS: 15880, TakenAt: &taken}}); err != nil {
		t.Fatal(err)
	}
	g, err := db.Gallery(d.ID)
	if err != nil || g[linked].Width != 2688 || g[linked].Height != 1512 ||
		g[linked].DurationMS != 15880 || !g[linked].TakenAt.Equal(at) {
		t.Fatalf("a linked entry's gallery row: %+v, %v", g, err)
	}

	// A share holds uploads beside its sources, and removing one prunes the
	// rows that name no file. The linked entry is not one of them.
	commit(t, db, d.ID, "note.jpg", 1)
	if _, _, err := db.RemoveFiles(d.ID, []string{"note.jpg"}); err != nil {
		t.Fatal(err)
	}
	if g, _ = db.Gallery(d.ID); len(g) != 1 || g[linked].Width != 2688 {
		t.Fatalf("an upload leaving must not take the linked rows with it: %+v", g)
	}
}
