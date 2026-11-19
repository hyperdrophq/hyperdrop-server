package metadb

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestSourcesFiltersAndSlugsPersist(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "nas", Owner: "alice", Sources: []string{"photos", "docs"}})
	slugs, err := db.AssignSlugs(d.ID, []string{"photos/a.jpg", "docs/b.pdf"})
	if err != nil || len(slugs) != 2 || slugs["photos/a.jpg"] == "" {
		t.Fatalf("assign: %v, %v", slugs, err)
	}
	again, _ := db.AssignSlugs(d.ID, []string{"photos/a.jpg", "photos/c.jpg"})
	if again["photos/a.jpg"] != slugs["photos/a.jpg"] || again["photos/c.jpg"] == "" {
		t.Fatalf("slugs must be stable: %v", again)
	}
	got, err := db.EditFilter(d.ID, []FilterEdit{{Source: "photos", Hide: []string{"private"}}, {Source: "docs", SetFixed: true, Fixed: true, FixedList: []string{"b.pdf", "c.pdf"}}})
	if err != nil {
		t.Fatal(err)
	}
	if got.Sources[0].Hidden != 1 || !got.Sources[1].Fixed {
		t.Fatalf("source state: %+v", got.Sources)
	}
	f, _ := db.Filters(d.ID)
	if f["photos"].Fixed != nil || len(f["photos"].Hidden) != 1 || f["docs"].Fixed == nil || len(*f["docs"].Fixed) != 2 {
		t.Fatalf("filters: %+v", f)
	}
	got, _ = db.EditFilter(d.ID, []FilterEdit{{Source: "photos", Show: []string{"private"}}, {Source: "docs", SetFixed: true, Fixed: false}})
	f, _ = db.Filters(d.ID)
	if len(f["photos"].Hidden) != 0 || f["docs"].Fixed != nil {
		t.Fatalf("undo: %+v", f)
	}
	if _, err := db.EditFilter(d.ID, []FilterEdit{{Source: "music", Hide: []string{"x"}}}); !errors.Is(err, ErrNotASource) {
		t.Fatalf("not a source: %v", err)
	}
	big := make([]string, MaxFilterPaths+1)
	for i := range big {
		big[i] = "p" + string(rune('0'+i%10)) + "/" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)) + string(rune('a'+(i/676)%26))
	}
	if _, err := db.EditFilter(d.ID, []FilterEdit{{Source: "photos", Hide: big}}); !errors.Is(err, ErrLinkedFilterTooBig) {
		t.Fatalf("cap: %v", err)
	}
	got, _, err = db.SetSources(d.ID, []string{"docs", "music"}, nil, nil)
	if err != nil || len(got.Sources) != 2 || got.Sources[0].Path != "docs" || got.Sources[1].Path != "music" {
		t.Fatalf("set sources: %+v, %v", got.Sources, err)
	}
	f, _ = db.Filters(d.ID)
	if _, stillThere := f["photos"]; stillThere {
		t.Fatal("a removed source's filter must go")
	}
	if s, _ := db.AssignSlugs(d.ID, []string{"docs/b.pdf"}); s["docs/b.pdf"] != slugs["docs/b.pdf"] {
		t.Fatal("slugs of remaining sources survive a source edit")
	}
}

// A source that leaves a share takes its slugs with it: added back later, its
// entries are minted fresh slugs, so a link copied before the removal does
// not revive. The sources that stay keep theirs.
func TestARemovedSourcesSlugsLeaveWithIt(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "nas", Owner: "alice", Sources: []string{"vol/a", "vol/b", "vol/c"}})
	rels := []string{"a/x.jpg", "b/y.jpg", "c/z.jpg", "c", "cc/q.jpg"}
	before, err := db.AssignSlugs(d.ID, rels)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.SetSources(d.ID, []string{"vol/a", "vol/b"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	left, err := db.Slugs(d.ID, rels)
	if err != nil {
		t.Fatal(err)
	}
	if left["c/z.jpg"] != "" || left["c"] != "" {
		t.Fatalf("the removed source's slugs stayed: %v", left)
	}
	for _, rel := range []string{"a/x.jpg", "b/y.jpg", "cc/q.jpg"} {
		if left[rel] != before[rel] {
			t.Fatalf("%s lost its slug: %v, want %v", rel, left, before)
		}
	}
	if _, _, err := db.SetSources(d.ID, []string{"vol/a", "vol/b", "vol/c"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	again, err := db.AssignSlugs(d.ID, []string{"c/z.jpg"})
	if err != nil {
		t.Fatal(err)
	}
	if again["c/z.jpg"] == "" || again["c/z.jpg"] == before["c/z.jpg"] {
		t.Fatalf("re-added source's slug = %q, want a fresh one (was %q)", again["c/z.jpg"], before["c/z.jpg"])
	}
}

// A removed source's gallery rows leave with its slugs, in the same
// transaction, and SetSources names those slugs so their tiles can go too;
// the staying source keeps its rows.
func TestARemovedSourcesGalleryRowsLeaveWithIt(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "nas", Owner: "alice", Sources: []string{"vol/a", "vol/b"}})
	slugs, err := db.AssignSlugs(d.ID, []string{"a/x.jpg", "b/y.jpg"})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetGallery(d.ID, map[string]GalleryItem{
		slugs["a/x.jpg"]: {Width: 4, Height: 3},
		slugs["b/y.jpg"]: {Width: 4, Height: 3},
	}); err != nil {
		t.Fatal(err)
	}
	_, removed, err := db.SetSources(d.ID, []string{"vol/a"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0] != slugs["b/y.jpg"] {
		t.Fatalf("removed = %v, want only %s", removed, slugs["b/y.jpg"])
	}
	items, err := db.allGalleryRows(d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := items[slugs["b/y.jpg"]]; ok {
		t.Fatalf("the removed source's gallery row stayed: %v", items)
	}
	if _, ok := items[slugs["a/x.jpg"]]; !ok {
		t.Fatalf("the staying source lost its gallery row: %v", items)
	}
}

// Leaving a share of ONE source clears that source's whole map, because an
// unprefixed share lists every entry bare. Going from several to one deletes
// by the names the share listed BEFORE the edit, and only then moves the one
// that stays onto its bare names, so an entry of the staying source whose
// bare name reads like the removed source's prefix keeps its slug.
func TestSetSourcesDeletesByTheNamesListedBeforeTheEdit(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	one := mustShare(t, db, CreateOptions{Name: "one", Owner: "alice", Sources: []string{"vol/a"}})
	if _, err := db.AssignSlugs(one.ID, []string{"x.jpg", "sub/y.jpg"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.SetSources(one.ID, []string{"vol/b"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if left, _ := db.Slugs(one.ID, []string{"x.jpg", "sub/y.jpg"}); len(left) != 0 {
		t.Fatalf("a replaced single source kept slugs: %v", left)
	}

	two := mustShare(t, db, CreateOptions{Name: "two", Owner: "alice", Sources: []string{"vol/a", "vol/b"}})
	before, err := db.AssignSlugs(two.ID, []string{"a/b/k.jpg", "b/k.jpg"})
	if err != nil {
		t.Fatal(err)
	}
	unprefix := func(rel string) string {
		if len(rel) > 2 && rel[:2] == "a/" {
			return rel[2:]
		}
		return rel
	}
	if _, _, err := db.SetSources(two.ID, []string{"vol/a"}, unprefix, nil); err != nil {
		t.Fatal(err)
	}
	got, err := db.Slugs(two.ID, []string{"b/k.jpg", "a/b/k.jpg"})
	if err != nil {
		t.Fatal(err)
	}
	if got["b/k.jpg"] != before["a/b/k.jpg"] || got["a/b/k.jpg"] != "" {
		t.Fatalf("slugs after several to one = %v, want b/k.jpg to carry %q", got, before["a/b/k.jpg"])
	}
}

// A linked entry's slug follows the NAME the share lists it under: a share
// that starts listing its sources under their base names must keep the slug
// every link already copied, or every one of those links dies.
func TestSetSourcesRekeysTheWholeMapAndKeepsTheSlug(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "nas", Owner: "alice", Sources: []string{"photos"}})
	bare, err := db.AssignSlugs(d.ID, []string{"a.jpg", "b.jpg"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.SetSources(d.ID, []string{"photos", "docs"}, func(rel string) string { return "photos/" + rel }, nil); err != nil {
		t.Fatal(err)
	}
	moved, err := db.AssignSlugs(d.ID, []string{"photos/a.jpg", "photos/b.jpg"})
	if err != nil {
		t.Fatal(err)
	}
	if moved["photos/a.jpg"] != bare["a.jpg"] || moved["photos/b.jpg"] != bare["b.jpg"] {
		t.Fatalf("slugs did not follow: %v, want %v", moved, bare)
	}
	// The old keys are gone, so nothing holds two names for one entry.
	back, err := db.AssignSlugs(d.ID, []string{"a.jpg"})
	if err != nil {
		t.Fatal(err)
	}
	if back["a.jpg"] == bare["a.jpg"] {
		t.Fatal("the old key survived the move")
	}
	// A rekey that moves nothing leaves every slug where it is.
	if _, _, err := db.SetSources(d.ID, []string{"photos", "docs"}, func(rel string) string { return rel }, nil); err != nil {
		t.Fatal(err)
	}
	same, _ := db.AssignSlugs(d.ID, []string{"photos/a.jpg"})
	if same["photos/a.jpg"] != bare["a.jpg"] {
		t.Fatalf("a no-op rekey changed a slug: %v", same)
	}
	if _, _, err := db.SetSources("../etc", []string{"photos"}, func(rel string) string { return rel }, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bad id: %v", err)
	}
}

// TestARekeyThatDropsASlugNamesIt pins that a slug a rekey overwrites leaves
// like a removed source's: its gallery row goes in the same transaction and
// SetSources names it, so its tile goes too.
func TestARekeyThatDropsASlugNamesIt(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "nas", Owner: "alice", Sources: []string{"vol/docs", "vol/photos"}})
	slugs, err := db.AssignSlugs(d.ID, []string{"docs/a.jpg", "photos/a.jpg"})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetGallery(d.ID, map[string]GalleryItem{
		slugs["docs/a.jpg"]:   {Width: 4, Height: 3},
		slugs["photos/a.jpg"]: {Width: 4, Height: 3},
	}); err != nil {
		t.Fatal(err)
	}
	base := func(rel string) string { return rel[strings.Index(rel, "/")+1:] }
	_, removed, err := db.SetSources(d.ID, []string{"vol/docs", "vol/photos"}, base, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := db.Slugs(d.ID, []string{"a.jpg"})
	if err != nil {
		t.Fatal(err)
	}
	kept := got["a.jpg"]
	dropped := slugs["docs/a.jpg"]
	if kept == dropped {
		dropped = slugs["photos/a.jpg"]
	}
	if len(removed) != 1 || removed[0] != dropped {
		t.Fatalf("removed = %v, want the dropped slug %s", removed, dropped)
	}
	items, err := db.allGalleryRows(d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := items[dropped]; ok || len(items) != 1 {
		t.Fatalf("gallery after the rekey: %v, want only %s", items, kept)
	}
}

// Every public read of a linked share assigns slugs, so a listing whose
// entries all have one must not take the write lock, and neither call
// touches the change journal: a slug is not a change to the share.
func TestAssignSlugsWritesOnlyForEntriesWithNoSlug(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "nas", Owner: "alice", Sources: []string{"photos"}})
	rels := []string{"photos/a.jpg", "photos/b.jpg"}
	before := db.writeCount()
	first, err := db.AssignSlugs(d.ID, rels)
	if err != nil || len(first) != 2 {
		t.Fatalf("first assign: %v, %v", first, err)
	}
	minted := db.writeCount()
	if minted != before+1 {
		t.Fatalf("minting took %d write transactions, want 1", minted-before)
	}
	b, err := db.Since("0", "alice", 10)
	if err != nil {
		t.Fatal(err)
	}
	seq := b.Next
	again, err := db.AssignSlugs(d.ID, rels)
	if err != nil {
		t.Fatal(err)
	}
	if db.writeCount() != minted {
		t.Fatalf("a second assign took %d write transactions, want none", db.writeCount()-minted)
	}
	for _, rel := range rels {
		if again[rel] != first[rel] || again[rel] == "" {
			t.Fatalf("slugs must be stable: %v vs %v", again, first)
		}
	}
	// A third call for one known and one new entry mints the new one alone.
	mixed, err := db.AssignSlugs(d.ID, []string{"photos/a.jpg", "photos/c.jpg"})
	if err != nil || mixed["photos/a.jpg"] != first["photos/a.jpg"] || mixed["photos/c.jpg"] == "" {
		t.Fatalf("mixed assign: %v, %v", mixed, err)
	}
	after, err := db.Since(seq, "alice", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Changes) != 0 {
		t.Fatalf("assigning slugs recorded %d change(s)", len(after.Changes))
	}
}

func TestCombinedSourcesAndFilterRollsBackSlugsAndExistingSources(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Owner: "alice", Sources: []string{"photos", "docs"}})
	before, err := db.AssignSlugs(d.ID, []string{"photos/a.jpg", "docs/b.pdf"})
	if err != nil {
		t.Fatal(err)
	}
	hidden := make([]string, MaxFilterPaths+1)
	for i := range hidden {
		hidden[i] = fmt.Sprintf("hide-%d", i)
	}
	_, removed, err := db.SetSources(d.ID, []string{"photos", "new"}, func(rel string) string { return "changed/" + rel }, []FilterEdit{{Source: "new", SetFixed: true, Fixed: true, Hide: hidden}})
	if !errors.Is(err, ErrLinkedFilterTooBig) || len(removed) != 0 {
		t.Fatalf("failure=%v removed=%v", err, removed)
	}
	filters, err := db.Filters(d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(filters) != 2 {
		t.Fatalf("sources changed: %v", filters)
	}
	if _, ok := filters["docs"]; !ok {
		t.Fatalf("old source disappeared: %v", filters)
	}
	after, err := db.Slugs(d.ID, []string{"photos/a.jpg", "docs/b.pdf"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("slugs changed: before=%v after=%v", before, after)
	}
}
