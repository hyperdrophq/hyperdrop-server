package linked

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

func fixture(t *testing.T) (*os.Root, string) {
	t.Helper()
	dir := t.TempDir()
	mk := func(p, body string) {
		os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o755)
		os.WriteFile(filepath.Join(dir, p), []byte(body), 0o644)
	}
	mk("photo/2024/b.jpg", "bb")
	mk("photo/2024/a.jpg", "a")
	mk("photo/2024/@eaDir/a.jpg/thumb", "x")
	mk("photo/2024/.DS_Store", "x")
	mk("photo/2024/#recycle/deleted.txt", "gone")
	mk("photo/2024/@tmp/x", "x")
	mk("photo/2024/sub/c.png", "ccc")
	mk("photo/2023/z.jpg", "z")
	os.MkdirAll(filepath.Join(dir, "other"), 0o755)
	mk("other/o.txt", "o")
	os.Symlink(filepath.Join(dir, "other"), filepath.Join(dir, "photo", "2024", "linkdir"))
	r, err := os.OpenRoot(filepath.Join(dir, "photo"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r, dir
}

// walkAt walks the directory sub inside root, the way a source rooted
// there is walked.
func walkAt(t *testing.T, root *os.Root, sub string, max int) ([]Entry, bool, error) {
	t.Helper()
	at, err := root.OpenRoot(sub)
	if err != nil {
		t.Fatal(err)
	}
	defer at.Close()
	return Walk(at, max)
}

func TestWalkIsSortedDepthFirstAndHidesNoise(t *testing.T) {
	root, _ := fixture(t)
	got, trunc, err := walkAt(t, root, "2024", MaxWalk)
	if err != nil || trunc {
		t.Fatal(err, trunc)
	}
	want := []string{"a.jpg", "b.jpg", "sub/c.png"}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i, w := range want {
		if got[i].Rel != w {
			t.Errorf("[%d] = %q, want %q", i, got[i].Rel, w)
		}
	}
	if got[1].Size != 2 || got[1].ModTime.IsZero() {
		t.Errorf("size/mtime not filled: %+v", got[1])
	}
}

func TestWalkOfTheRootItselfAndOfOneFile(t *testing.T) {
	root, _ := fixture(t)
	got, _, err := Walk(root, MaxWalk)
	if err != nil || len(got) != 4 || got[0].Rel != "2023/z.jpg" {
		t.Fatalf("root walk: %+v %v", got, err)
	}
	// A file source is its parent's root and its base name.
	parent, err := root.OpenRoot("2024")
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	one, _, err := walkSource(parent, "a.jpg", MaxWalk)
	if err != nil || len(one) != 1 || one[0].Rel != "a.jpg" || one[0].Size != 1 {
		t.Fatalf("file walk: %+v %v", one, err)
	}
}

func TestWalkStopsAtMaxAndReportsTruncation(t *testing.T) {
	root, _ := fixture(t)
	got, trunc, err := walkAt(t, root, "2024", 2)
	if err != nil || !trunc || len(got) != 2 {
		t.Fatalf("%+v %v %v", got, trunc, err)
	}
}

func TestWalkOfAMissingPathErrors(t *testing.T) {
	root, _ := fixture(t)
	if _, _, err := walkSource(root, "2099", MaxWalk); err == nil {
		t.Fatal("missing path walked")
	}
}

// TestWalkStopsDescendingOnceMaxIsReached checks that Walk returns a nil
// error, truncated true, and at most max entries when a locked subtree sits
// past the cap: "a" and "b" fill the cap before the sorted walk reaches
// "z-locked". The cap check in Walk precedes every stat, open and
// recursion, and ReadDirCapped reads at most budget+1 entries a chunk at a
// time.
func TestWalkStopsDescendingOnceMaxIsReached(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission bits are not enforced for root")
	}
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "root"), 0o755)
	os.WriteFile(filepath.Join(dir, "root", "a"), []byte("a"), 0o644)
	os.WriteFile(filepath.Join(dir, "root", "b"), []byte("b"), 0o644)
	locked := filepath.Join(dir, "root", "z-locked")
	os.MkdirAll(locked, 0o755)
	os.WriteFile(filepath.Join(locked, "inner"), []byte("x"), 0o644)
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o755) })

	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })

	got, trunc, err := walkAt(t, root, "root", 2)
	if err != nil {
		t.Fatalf("walk descended into the locked subtree: %v", err)
	}
	if !trunc || len(got) != 2 {
		t.Fatalf("got %+v trunc=%v", got, trunc)
	}
}

// Hidden is the ONE definition of what a share never shows: Walk skips these
// names and every reader that resolves a relpath refuses them, so a path the
// listing cannot produce is a path nothing serves.
func TestHiddenNamesEveryUnservedSegment(t *testing.T) {
	for _, rel := range []string{".env", "sub/.git/config", "@eaDir", "a/@eaDir/x", ".",
		"#recycle", "#recycle/deleted.txt", "sub/#snapshot/x", "@tmp/x"} {
		if !Hidden(rel) {
			t.Errorf("Hidden(%q) = false", rel)
		}
	}
	for _, rel := range []string{"a.jpg", "sub/a.jpg", "eaDir/x", "a/b.c/d"} {
		if Hidden(rel) {
			t.Errorf("Hidden(%q) = true", rel)
		}
	}
}

// A Synology shared folder keeps its deleted files in #recycle and its
// snapshots in #snapshot, beside the @eaDir thumbnails: a linked share of
// the whole folder must publish none of them.
func TestWalkHidesTheSystemDirectoriesANASKeepsInAShare(t *testing.T) {
	root, _ := fixture(t)
	got, _, err := walkAt(t, root, "2024", MaxWalk)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range got {
		if strings.HasPrefix(e.Rel, "#") || strings.HasPrefix(e.Rel, "@") || strings.HasPrefix(e.Rel, ".") {
			t.Errorf("listed a system path: %q (whole listing %+v)", e.Rel, got)
		}
	}
	if len(got) != 3 {
		t.Fatalf("listing = %+v", got)
	}
}

// One folder whose permission was withdrawn must not cost the whole share:
// an unreadable subdirectory is skipped, and only the SOURCE failing is an
// error (fillLinked turns that error into SourceMissing).
func TestWalkSkipsAnUnreadableSubdirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission bits are not enforced for root")
	}
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "src", "shut"), 0o755)
	os.WriteFile(filepath.Join(dir, "src", "a.txt"), []byte("a"), 0o644)
	os.WriteFile(filepath.Join(dir, "src", "z.txt"), []byte("z"), 0o644)
	os.WriteFile(filepath.Join(dir, "src", "shut", "inner"), []byte("x"), 0o644)
	if err := os.Chmod(filepath.Join(dir, "src", "shut"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(filepath.Join(dir, "src", "shut"), 0o755) })

	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })

	got, trunc, err := walkAt(t, root, "src", MaxWalk)
	if err != nil {
		t.Fatalf("an unreadable subdirectory failed the whole walk: %v", err)
	}
	if trunc || len(got) != 2 || got[0].Rel != "a.txt" || got[1].Rel != "z.txt" {
		t.Fatalf("got %+v trunc=%v", got, trunc)
	}
}

// A directory far larger than the cap is read a budget at a time, so the
// walk pays for the cap rather than for the folder. Which names come back is
// deliberately not asserted: past the budget the read is in directory order,
// so the window is not the alphabetical head.
func TestWalkReadsADirectoryLargerThanTheCapWithoutReadingItAll(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "many"), 0o755)
	for i := range 200 {
		os.WriteFile(filepath.Join(dir, "many", fmt.Sprintf("f%03d.txt", i)), []byte("x"), 0o644)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })

	got, trunc, err := walkAt(t, root, "many", 10)
	if err != nil || !trunc {
		t.Fatalf("trunc=%v err=%v", trunc, err)
	}
	if len(got) > 10 {
		t.Fatalf("walked past the cap: %d entries", len(got))
	}
	if !sort.SliceIsSorted(got, func(i, j int) bool { return got[i].Rel < got[j].Rel }) {
		t.Fatalf("the window is unsorted: %+v", got)
	}
}

// A folder is dated by the newest file directly inside it, never by its own
// mtime, which a NAS indexer moves whenever it rewrites the thumbnail folder.
func TestFolderDateIsTheNewestFileInside(t *testing.T) {
	vol := t.TempDir()
	day := filepath.Join(vol, "2026-09-20")
	os.MkdirAll(filepath.Join(day, "@eaDir"), 0o755)
	os.MkdirAll(filepath.Join(day, "sub"), 0o755)
	os.WriteFile(filepath.Join(day, "a.mp4"), []byte("a"), 0o644)
	os.WriteFile(filepath.Join(day, "b.mp4"), []byte("b"), 0o644)
	os.WriteFile(filepath.Join(day, "@eaDir", "thumb.jpg"), []byte("t"), 0o644)
	os.WriteFile(filepath.Join(day, "sub", "later.mp4"), []byte("l"), 0o644)
	sept := func(day int) time.Time { return time.Date(2026, 9, day, 12, 0, 0, 0, time.UTC) }
	os.Chtimes(filepath.Join(day, "a.mp4"), sept(20), sept(20))
	os.Chtimes(filepath.Join(day, "b.mp4"), sept(19), sept(19))
	os.Chtimes(filepath.Join(day, "@eaDir", "thumb.jpg"), sept(30), sept(30))
	os.Chtimes(filepath.Join(day, "sub", "later.mp4"), sept(30), sept(30))
	os.Chtimes(day, sept(30), sept(30))
	root, err := os.OpenRoot(vol)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if got := FolderDate(root, "2026-09-20", sept(30)); !got.Equal(sept(20)) {
		t.Fatalf("FolderDate = %v, want the newest file inside, %v", got, sept(20))
	}
	// No file directly inside: the folder's own date stands.
	os.MkdirAll(filepath.Join(vol, "empty"), 0o755)
	os.MkdirAll(filepath.Join(vol, "dirs-only", "x"), 0o755)
	for _, d := range []string{"empty", "dirs-only"} {
		if got := FolderDate(root, d, sept(5)); !got.Equal(sept(5)) {
			t.Fatalf("%s: FolderDate = %v, want its own %v", d, got, sept(5))
		}
	}
}

// A file link with an ordinary name whose target, at any hop, passes a name
// Hidden refuses is neither listed nor opened: innocent.txt pointing into
// .secret must not publish what the hidden rule keeps out of every share.
// A link to an ordinary file inside the source still is.
func TestALinkThroughAHiddenNameIsNeitherListedNorOpened(t *testing.T) {
	vol := t.TempDir()
	src := filepath.Join(vol, "v")
	os.MkdirAll(filepath.Join(src, ".secret"), 0o755)
	os.MkdirAll(filepath.Join(src, "sub"), 0o755)
	os.WriteFile(filepath.Join(src, ".secret", "key"), []byte("K"), 0o644)
	os.WriteFile(filepath.Join(src, "a.txt"), []byte("a"), 0o644)
	os.Symlink(".secret/key", filepath.Join(src, "innocent.txt"))
	os.Symlink("hop.txt", filepath.Join(src, "chain.txt"))
	os.Symlink(".secret/key", filepath.Join(src, "hop.txt"))
	os.Symlink("../.secret/key", filepath.Join(src, "sub", "up.txt"))
	os.Symlink("a.txt", filepath.Join(src, "plain.txt"))
	root, err := os.OpenRoot(src)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	got, _, err := Walk(root, MaxWalk)
	if err != nil {
		t.Fatal(err)
	}
	var rels []string
	for _, e := range got {
		rels = append(rels, e.Rel)
	}
	if strings.Join(rels, ",") != "a.txt,plain.txt" {
		t.Fatalf("listed %v, want a.txt and plain.txt alone", rels)
	}
	r, err := NewRoots([]string{src}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	specs := []SourceSpec{{Path: "v"}}
	for _, rel := range []string{"innocent.txt", "chain.txt", "hop.txt", "sub/up.txt"} {
		if _, _, err := openOne(t, r, specs, false, rel); err == nil {
			t.Errorf("%s opened a hidden file", rel)
		}
	}
	f, _, err := openOne(t, r, specs, false, "plain.txt")
	if err != nil {
		t.Fatalf("plain.txt: %v", err)
	}
	f.Close()
}

// A FIFO, a socket or a device can never be served, so the walk never lists
// it: a listed entry that 404s on every read is a broken link handed out.
func TestWalkListsRegularFilesOnly(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0o644)
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe"), 0o644); err != nil {
		t.Skip("no FIFO here:", err)
	}
	os.Symlink("pipe", filepath.Join(dir, "pipe-link"))
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	got, _, err := Walk(root, MaxWalk)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Rel != "a.txt" {
		t.Fatalf("listed %+v, want a.txt alone", got)
	}
}

// The cap bounds what the walk READS, not only what it lists: a tree of
// many folders and no files stops within the read budget, marked truncated,
// rather than visiting every folder.
func TestWalkBoundsTheFoldersItVisits(t *testing.T) {
	dir := t.TempDir()
	for i := range 600 {
		os.MkdirAll(filepath.Join(dir, fmt.Sprintf("d%04d", i), "inner"), 0o755)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	got, trunc, err := Walk(root, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 || !trunc {
		t.Fatalf("got %d entries, truncated=%v; want none, truncated", len(got), trunc)
	}
}

// An Opener that keeps its sources open answers exactly what a fresh
// Opener answers, entry by entry, over one open of each source.
func TestAnOpenerAnswersTheSameAcrossEntries(t *testing.T) {
	r := testRoots(t, map[string]string{"photo/2024/a.jpg": "A", "photo/2024/b.jpg": "B", "docs/x.pdf": "X"})
	fixed := []string{"a.jpg", "b.jpg"}
	specs := []SourceSpec{{Path: "photo/2024", Fixed: &fixed, Hidden: []string{"b.jpg"}}, {Path: "docs/x.pdf"}}
	o := NewOpener(r, specs, true)
	defer o.Close()
	for _, rel := range []string{"2024/a.jpg", "2024/b.jpg", "x.pdf", "x.pdf/y", "2024", "nope/a.jpg"} {
		f1, _, err1 := openOne(t, r, specs, true, rel)
		if f1 != nil {
			f1.Close()
		}
		f2, _, err2 := o.Open(rel)
		if f2 != nil {
			f2.Close()
		}
		if (err1 == nil) != (err2 == nil) {
			t.Errorf("%s: fresh Opener err=%v, shared Opener err=%v", rel, err1, err2)
		}
	}
	if len(o.sources) != 2 {
		t.Fatalf("opened %d sources, want each of the two once", len(o.sources))
	}
}
