package linked

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// composeFixture builds one volume holding a share with a folder and a file
// in it, and answers the roots over that volume: the sources are then
// "share/photos" and "share/doc.txt".
func composeFixture(t *testing.T) *Roots {
	t.Helper()
	vol := t.TempDir()
	mk := func(p, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(vol, p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(vol, p), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("share/photos/a.jpg", "a")
	mk("share/photos/b.jpg", "bb")
	mk("share/photos/sub/c.jpg", "ccc")
	mk("share/photos/#recycle/x", "xxxx")
	mk("share/doc.txt", "ddddd")
	r, err := NewRoots(nil, []string{vol}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func rels(entries []Entry) string {
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Rel)
	}
	return strings.Join(names, ",")
}

func TestComposeListsOneSourceBareAndSeveralUnderTheirBaseNames(t *testing.T) {
	roots := composeFixture(t)

	l, readable := Compose(roots, []SourceSpec{{Path: "share/photos"}}, MaxWalk)
	if !readable || l.Truncated {
		t.Fatalf("readable=%v truncated=%v", readable, l.Truncated)
	}
	if got := rels(l.Entries); got != "a.jpg,b.jpg,sub/c.jpg" {
		t.Errorf("one source = %q", got)
	}
	if l.Entries[1].Size != 2 || l.Entries[1].ModTime.IsZero() {
		t.Errorf("size and mtime not filled: %+v", l.Entries[1])
	}
	if len(l.State) != 0 {
		t.Errorf("an unfiltered source reported state: %+v", l.State)
	}

	l, readable = Compose(roots, []SourceSpec{{Path: "share/photos"}, {Path: "share/doc.txt"}}, MaxWalk)
	if !readable || l.Truncated {
		t.Fatalf("readable=%v truncated=%v", readable, l.Truncated)
	}
	if got := rels(l.Entries); got != "photos/a.jpg,photos/b.jpg,photos/sub/c.jpg,doc.txt" {
		t.Errorf("two sources = %q", got)
	}
	if l.Entries[3].Size != 5 {
		t.Errorf("file source size = %d", l.Entries[3].Size)
	}
}

func TestComposeAppliesFixedAndHiddenPerSourceAndReportsState(t *testing.T) {
	roots := composeFixture(t)
	fixed := []string{"a.jpg", "sub/c.jpg"}
	specs := []SourceSpec{{Path: "share/photos", Fixed: &fixed, Hidden: []string{"sub"}}}

	l, readable := Compose(roots, specs, MaxWalk)
	if !readable {
		t.Fatal("unreadable")
	}
	if got := rels(l.Entries); got != "a.jpg" {
		t.Errorf("entries = %q", got)
	}
	if len(l.State) != 1 {
		t.Fatalf("state = %+v", l.State)
	}
	if st := l.State["share/photos"]; !st.Fixed || st.Hidden != 2 {
		t.Errorf("state = %+v", st)
	}
}

func TestComposeSkipsAnUnreadableSourceAndIsUnreadableOnlyWhenAllAre(t *testing.T) {
	roots := composeFixture(t)

	l, readable := Compose(roots, []SourceSpec{{Path: "share/photos"}, {Path: "share/missing"}}, MaxWalk)
	if !readable {
		t.Fatal("one unreadable source made the whole share unreadable")
	}
	if got := rels(l.Entries); got != "photos/a.jpg,photos/b.jpg,photos/sub/c.jpg" {
		t.Errorf("entries = %q", got)
	}

	l, readable = Compose(roots, []SourceSpec{{Path: "share/missing"}}, MaxWalk)
	if readable || len(l.Entries) != 0 {
		t.Errorf("readable=%v entries=%q", readable, rels(l.Entries))
	}
}

func TestComposeHonoursTheBudget(t *testing.T) {
	roots := composeFixture(t)
	l, readable := Compose(roots, []SourceSpec{{Path: "share/photos"}}, 2)
	if !readable || !l.Truncated || len(l.Entries) != 2 {
		t.Fatalf("readable=%v truncated=%v entries=%q", readable, l.Truncated, rels(l.Entries))
	}
}

// An upload is refused only where it would list on top of, or beneath, an
// entry a source serves. A folder the source holds is taken under its own
// name and open inside: an upload below it lists beside the folder's own
// files. A file is taken along with everything below it, a file holding
// nothing.
func TestCollidesFollowsTheUploadRule(t *testing.T) {
	roots := composeFixture(t)

	single := []SourceSpec{{Path: "share/photos"}}
	for rel, want := range map[string]bool{
		"a.jpg": true, "sub": true, "sub/c.jpg": true, "a.jpg/x": true,
		"sub/new.txt": false, "new.txt": false, ".hidden/x": false, "": false,
	} {
		if got := Collides(roots, single, false, rel); got != want {
			t.Errorf("single %q = %v, want %v", rel, got, want)
		}
	}

	prefixed := []SourceSpec{{Path: "share/photos"}, {Path: "share/doc.txt"}}
	for rel, want := range map[string]bool{
		"photos": true, "photos/a.jpg": true, "doc.txt": true, "doc.txt/x": true,
		"photos/new.txt": false, "other/x": false,
	} {
		if got := Collides(roots, prefixed, true, rel); got != want {
			t.Errorf("prefixed %q = %v, want %v", rel, got, want)
		}
	}

	if Collides(roots, nil, false, "a.jpg") {
		t.Error("a share with no source collided with something")
	}
}

// openOne opens rel through an Opener of its own, the one entry it opens,
// closed when the test ends; the caller closes the file.
func openOne(t *testing.T, roots *Roots, specs []SourceSpec, prefixed bool, rel string) (*os.File, os.FileInfo, error) {
	t.Helper()
	o := NewOpener(roots, specs, prefixed)
	t.Cleanup(o.Close)
	return o.Open(rel)
}

func TestAnOpenerServesRegularFilesInsideTheSource(t *testing.T) {
	roots := composeFixture(t)

	single := []SourceSpec{{Path: "share/photos"}}
	f, fi, err := openOne(t, roots, single, false, "a.jpg")
	if err != nil {
		t.Fatalf("a.jpg: %v", err)
	}
	if fi.Size() != 1 {
		t.Errorf("a.jpg size = %d", fi.Size())
	}
	f.Close()
	for _, rel := range []string{"sub", "#recycle/x", "../doc.txt", "nope.jpg", ""} {
		if f, _, err := openOne(t, roots, single, false, rel); err == nil {
			f.Close()
			t.Errorf("single %q opened", rel)
		}
	}

	prefixed := []SourceSpec{{Path: "share/photos"}, {Path: "share/doc.txt"}}
	for rel, size := range map[string]int64{"photos/a.jpg": 1, "doc.txt": 5} {
		f, fi, err := openOne(t, roots, prefixed, true, rel)
		if err != nil {
			t.Fatalf("prefixed %q: %v", rel, err)
		}
		if fi.Size() != size {
			t.Errorf("prefixed %q size = %d, want %d", rel, fi.Size(), size)
		}
		f.Close()
	}
	for _, rel := range []string{"nope/x", "photos", "doc.txt/x", "photos/#recycle/x"} {
		if f, _, err := openOne(t, roots, prefixed, true, rel); err == nil {
			f.Close()
			t.Errorf("prefixed %q opened", rel)
		}
	}
}

func TestSkippedMatchesOnASegmentBoundary(t *testing.T) {
	hidden := []string{"a"}
	for rel, want := range map[string]bool{"a": true, "a/b.txt": true, "ab.txt": false, "b/a": false} {
		if got := Skipped(hidden, rel); got != want {
			t.Errorf("Skipped(%q) = %v, want %v", rel, got, want)
		}
	}
	if Skipped(nil, "a") {
		t.Error("nothing hidden hid something")
	}
}

func TestFilteredKeepsWalkOrderAndPassesAnUnfilteredSource(t *testing.T) {
	entries := []Entry{{Rel: "a.jpg"}, {Rel: "b.jpg"}, {Rel: "sub/c.jpg"}}
	if got := rels(Filtered(SourceSpec{}, entries)); got != "a.jpg,b.jpg,sub/c.jpg" {
		t.Errorf("no filter = %q", got)
	}
	fixed := []string{"sub/c.jpg", "b.jpg"}
	if got := rels(Filtered(SourceSpec{Fixed: &fixed}, entries)); got != "b.jpg,sub/c.jpg" {
		t.Errorf("fixed = %q", got)
	}
	if got := rels(Filtered(SourceSpec{Hidden: []string{"sub"}}, entries)); got != "a.jpg,b.jpg" {
		t.Errorf("hidden = %q", got)
	}
	empty := []string{}
	if got := Filtered(SourceSpec{Fixed: &empty}, entries); len(got) != 0 {
		t.Errorf("an empty fixed list showed %q", rels(got))
	}
}

// Shown answers from the specs alone what the composed listing would name:
// the filter is asked in source-relative names (a folder source's inner path,
// a file source's own base name), and a revoked source names nothing.
func TestShownAppliesTheFilterWithoutTheFilesystem(t *testing.T) {
	fixed := []string{"a.jpg", "sub/c.jpg"}
	folder := SourceSpec{Path: "photo/2024", Fixed: &fixed, Hidden: []string{"sub"}}
	file := SourceSpec{Path: "docs/report.pdf", Hidden: []string{"report.pdf"}}
	cases := []struct {
		specs    []SourceSpec
		prefixed bool
		rel      string
		want     bool
	}{
		{[]SourceSpec{folder}, false, "a.jpg", true},
		{[]SourceSpec{folder}, false, "b.jpg", false},     // not in the fixed list
		{[]SourceSpec{folder}, false, "sub/c.jpg", false}, // hidden under sub
		{[]SourceSpec{folder}, false, ".git/a.jpg", false},
		{[]SourceSpec{folder}, false, "../a.jpg", false},
		{[]SourceSpec{folder, file}, true, "2024/a.jpg", true},
		{[]SourceSpec{folder, file}, true, "2024/b.jpg", false},
		{[]SourceSpec{folder, file}, true, "report.pdf", false}, // a file source hidden by its own name
		{[]SourceSpec{folder, file}, true, "other/a.jpg", false},
		{[]SourceSpec{{Path: "photo/2024", Revoked: true}}, false, "a.jpg", false},
		{[]SourceSpec{{Path: "docs/report.pdf"}}, false, "report.pdf", true},
	}
	for _, c := range cases {
		if got := Shown(c.specs, c.prefixed, c.rel); got != c.want {
			t.Errorf("Shown(%v, %v, %q) = %v, want %v", c.specs, c.prefixed, c.rel, got, c.want)
		}
	}
}

// An Opener refuses an entry its source's filter takes out, the rule the
// listing applies, so no reader can serve a hidden or unfixed entry by
// naming it.
func TestAnOpenerRefusesWhatTheFilterTakesOut(t *testing.T) {
	r := testRoots(t, map[string]string{"photo/2024/a.jpg": "A", "photo/2024/b.jpg": "B"})
	fixed := []string{"a.jpg", "b.jpg"}
	specs := []SourceSpec{{Path: "photo/2024", Fixed: &fixed, Hidden: []string{"b.jpg"}}}
	f, _, err := openOne(t, r, specs, false, "a.jpg")
	if err != nil {
		t.Fatalf("a shown entry: %v", err)
	}
	f.Close()
	if _, _, err := openOne(t, r, specs, false, "b.jpg"); err == nil {
		t.Fatal("a hidden entry opened")
	}
	only := []string{"a.jpg"}
	if _, _, err := openOne(t, r, []SourceSpec{{Path: "photo/2024", Fixed: &only}}, false, "b.jpg"); err == nil {
		t.Fatal("an entry outside the fixed list opened")
	}
}

// linkFolder builds a roots over a volume holding the folder "share/f" with
// the given files, then the given symlinks (name -> target), and answers the
// roots and the folder's path on disk.
func linkFolder(t *testing.T, files map[string]string, links map[string]string) (*Roots, string) {
	t.Helper()
	vol := t.TempDir()
	dir := filepath.Join(vol, "share", "f")
	for p, body := range files {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, p), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	r, err := NewRoots(nil, []string{vol}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r, dir
}

func readAll(t *testing.T, f *os.File) string {
	t.Helper()
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestALinkInAFixedSourceServesOnlyATargetTheListShows(t *testing.T) {
	roots, _ := linkFolder(t, map[string]string{"private.txt": "secret"}, map[string]string{"public.txt": "private.txt"})
	fixed := []string{"public.txt"}
	specs := []SourceSpec{{Path: "share/f", Fixed: &fixed}}
	l, _ := Compose(roots, specs, 100)
	if got := rels(l.Entries); got != "" {
		t.Fatalf("listed %q, want nothing: the list does not show private.txt", got)
	}
	if _, _, err := openOne(t, roots, specs, false, "public.txt"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("open: %v, want ErrNotExist", err)
	}
}

func TestALinkToAHiddenEntryIsNeitherListedNorServed(t *testing.T) {
	roots, _ := linkFolder(t, map[string]string{"private/key.txt": "secret"}, map[string]string{"pub.txt": "private/key.txt"})
	specs := []SourceSpec{{Path: "share/f", Hidden: []string{"private"}}}
	l, _ := Compose(roots, specs, 100)
	if got := rels(l.Entries); got != "" {
		t.Fatalf("listed %q, want nothing", got)
	}
	if _, _, err := openOne(t, roots, specs, false, "pub.txt"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("open: %v, want ErrNotExist", err)
	}
}

func TestALinkWhoseTargetTheFilterShowsIsServed(t *testing.T) {
	roots, _ := linkFolder(t, map[string]string{"b.txt": "bee"}, map[string]string{"a.txt": "b.txt"})
	fixed := []string{"a.txt", "b.txt"}
	specs := []SourceSpec{{Path: "share/f", Fixed: &fixed}}
	l, _ := Compose(roots, specs, 100)
	if got := rels(l.Entries); got != "a.txt,b.txt" {
		t.Fatalf("listed %q", got)
	}
	f, _, err := openOne(t, roots, specs, false, "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, f); got != "bee" {
		t.Fatalf("served %q", got)
	}
}

func TestALinkInAnUnfilteredSourceStillServesItsTarget(t *testing.T) {
	roots, _ := linkFolder(t, map[string]string{"sub/b.txt": "bee"}, map[string]string{"a.txt": "sub/b.txt"})
	specs := []SourceSpec{{Path: "share/f"}}
	l, _ := Compose(roots, specs, 100)
	if got := rels(l.Entries); got != "a.txt,sub/b.txt" {
		t.Fatalf("listed %q", got)
	}
	f, _, err := openOne(t, roots, specs, false, "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, f); got != "bee" {
		t.Fatalf("served %q", got)
	}
}

func TestALinkRetargetedAfterTheListingIsCheckedAtOpen(t *testing.T) {
	roots, dir := linkFolder(t, map[string]string{"other.txt": "o", "private.txt": "secret"}, map[string]string{"public.txt": "other.txt"})
	fixed := []string{"public.txt", "other.txt"}
	specs := []SourceSpec{{Path: "share/f", Fixed: &fixed}}
	l, _ := Compose(roots, specs, 100)
	if got := rels(l.Entries); got != "other.txt,public.txt" {
		t.Fatalf("listed %q", got)
	}
	if err := os.Remove(filepath.Join(dir, "public.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("private.txt", filepath.Join(dir, "public.txt")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := openOne(t, roots, specs, false, "public.txt"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("open: %v, want ErrNotExist", err)
	}
}
