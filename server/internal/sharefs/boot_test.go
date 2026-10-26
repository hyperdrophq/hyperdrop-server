package sharefs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func backdate(t *testing.T, p string, age time.Duration) {
	t.Helper()
	old := time.Now().Add(-age)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
}

func TestOrphansRemovesOldRowlessDirectoriesAndKeepsTheRest(t *testing.T) {
	f := openTest(t)
	const kept, youngOrphan, oldOrphan = "abcdefghjk", "abcdefghjm", "abcdefghjn"
	for _, id := range []string{kept, youngOrphan, oldOrphan} {
		stage(t, f, id, "a", "x")
	}
	backdate(t, shareDir(f, oldOrphan), 2*DefaultAbandonedUpload)
	stray := filepath.Join(f.DataDir(), sharesDirName, "not-a-share-id")
	if err := os.MkdirAll(stray, 0o755); err != nil {
		t.Fatal(err)
	}
	backdate(t, stray, 48*time.Hour)
	var asked []string
	hasRow := func(id string) bool { asked = append(asked, id); return id == kept }
	removed, err := f.Orphans(hasRow)
	if err != nil || removed != 1 {
		t.Fatalf("Orphans: %d, %v", removed, err)
	}
	if exists(shareDir(f, oldOrphan)) {
		t.Fatal("old orphan kept")
	}
	if !exists(shareDir(f, youngOrphan)) {
		t.Fatal("a young orphan may still be a delete in progress; it waits for the window")
	}
	if !exists(shareDir(f, kept)) || !exists(stray) {
		t.Fatal("a share with a row, and a stray name, must be left alone")
	}
	if len(asked) != 3 || strings.Contains(strings.Join(asked, ","), "not-a-share-id") {
		t.Fatalf("hasRow asked for %v", asked)
	}
}

func TestOrphansCleansStalePartsAndOrphanedSidecars(t *testing.T) {
	f := openTest(t)
	const id = "abcdefghjk"
	if _, err := f.WriteRange(id, "stale", strings.NewReader("ab"), Range{0, 2}, 4, "s", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteRange(id, "fresh", strings.NewReader("ab"), Range{0, 2}, 4, "s", nil); err != nil {
		t.Fatal(err)
	}
	dir := shareDir(f, id)
	backdate(t, filepath.Join(dir, partRel("stale")), 2*DefaultAbandonedUpload)
	orphanHash := filepath.Join(dir, partRel("gone")+partHashExt)
	orphanSession := filepath.Join(dir, partRel("gone")+partSessionExt)
	for _, p := range []string{orphanHash, orphanSession} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.Orphans(func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.PartRanges(id, "stale", "s"); ok || exists(filepath.Join(dir, partRel("stale")+partSessionExt)) {
		t.Fatal("a stale part and its sidecars must go")
	}
	if st, ok := f.PartRanges(id, "fresh", "s"); !ok || st.Received != 2 {
		t.Fatal("a fresh part is resume state and survives")
	}
	if exists(orphanHash) || exists(orphanSession) {
		t.Fatal("sidecars with no part must go")
	}
}

func TestOrphansReportsAnUnreadableSharesTree(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	f := openTest(t)
	shares := filepath.Join(f.DataDir(), sharesDirName)
	if err := os.Chmod(shares, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(shares, 0o755) })
	if _, err := f.Orphans(func(string) bool { return true }); err == nil {
		t.Fatal("a sealed shares/ must surface as an error, not as zero orphans")
	}
}

// A share some writer holds (a commit hashing a large part) is skipped by
// the sweep rather than waited for: a sweep queued for the exclusive lock
// would block every new upload into the share until that writer finished.
// The share stays noted, and the next pass cleans it.
func TestSweepStalePartsSkipsABusyShare(t *testing.T) {
	f := openTest(t)
	f.AbandonedWindow = time.Nanosecond
	if _, err := f.Write(testID, "stale.bin", strings.NewReader("x")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)
	release := f.rlockShare(testID)
	swept := make(chan int)
	go func() { swept <- f.SweepStaleParts() }()
	select {
	case n := <-swept:
		if n != 0 {
			t.Fatalf("swept %d parts of a share a writer holds", n)
		}
	case <-time.After(2 * time.Second):
		release()
		<-swept
		t.Fatal("the sweep waited for the share's writer")
	}
	wrote := make(chan error, 1)
	go func() { _, err := f.Write(testID, "other.bin", strings.NewReader("y")); wrote <- err }()
	select {
	case err := <-wrote:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		release()
		t.Fatal("an upload into the share blocked behind the sweep")
	}
	release()
	time.Sleep(time.Millisecond)
	if n := f.SweepStaleParts(); n != 2 {
		t.Fatalf("next pass swept %d parts, want both", n)
	}
}
