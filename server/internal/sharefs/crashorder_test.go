package sharefs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Create: row first, the directory on the first upload. The file layer
// therefore has nothing to do for a new share, and a share with rows and no
// directory reads as empty rather than as an error.
func TestAShareWithRowsAndNoDirectoryReadsAsEmpty(t *testing.T) {
	f := openTest(t)
	if _, _, err := f.Open(testID, "a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Open: %v", err)
	}
	if size, err := f.PartSize(testID, "a"); err != nil || size != 0 {
		t.Fatalf("PartSize: %d, %v", size, err)
	}
	if slugs, err := f.ThumbSlugs(testID); err != nil || len(slugs) != 0 {
		t.Fatalf("ThumbSlugs: %v, %v", slugs, err)
	}
	if f.HasPoster(testID) || f.HasRecentPart(testID, 1<<62) {
		t.Fatal("nothing is there")
	}
	if err := f.RemoveFile(testID, "a"); err != nil {
		t.Fatalf("RemoveFile on nothing: %v", err)
	}
	if err := f.RemoveShare(testID); err != nil {
		t.Fatalf("RemoveShare on nothing: %v", err)
	}
}

// Commit: rename then row. A crash between leaves a file under files/ and a
// pending row. The client's retry stages and commits again, and the second
// rename replaces the stray file, so the bytes converge on the row.
func TestARetriedCommitReplacesAStrayFile(t *testing.T) {
	f := openTest(t)
	stage(t, f, testID, "a", "first attempt")
	if _, err := f.Commit(testID, "a", -1, nil); err != nil {
		t.Fatal(err)
	}
	// The row was never written; the client retries with the same bytes.
	stage(t, f, testID, "a", "first attempt")
	c, err := f.Commit(testID, "a", -1, nil)
	if err != nil || c.SHA256 != sha256Hex("first attempt") {
		t.Fatalf("retry: %+v, %v", c, err)
	}
	fh, fi, err := f.Open(testID, "a")
	if err != nil || fi.Size() != int64(len("first attempt")) {
		t.Fatalf("after retry: %v, %v", fi, err)
	}
	fh.Close()
	// The stalled sweep, giving up on the pending row, removes the file
	// the row names, whether or not a stray copy landed.
	if err := f.RemoveFile(testID, "a"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.Open(testID, "a"); !errors.Is(err, ErrNotFound) {
		t.Fatal("stray file survived the sweep's RemoveFile")
	}
}

// Delete: rows first, then the directory. A crash between leaves an orphan
// directory, which the boot pass removes once it is older than the window.
func TestAnOrphanDirectoryIsRemovedAtBoot(t *testing.T) {
	f := openTest(t)
	stage(t, f, testID, "a", "x")
	if _, err := f.Commit(testID, "a", -1, nil); err != nil {
		t.Fatal(err)
	}
	backdate(t, shareDir(f, testID), 2*DefaultAbandonedUpload)
	removed, err := f.Orphans(func(string) bool { return false })
	if err != nil || removed != 1 {
		t.Fatalf("Orphans: %d, %v", removed, err)
	}
	if exists(shareDir(f, testID)) {
		t.Fatal("orphan survived")
	}
}

// The files tree never holds anything but stored files: no staging, no
// sidecars, no temporary names survive a commit.
func TestNothingButStoredFilesLivesUnderFiles(t *testing.T) {
	f := openTest(t)
	stage(t, f, testID, "d/a", "x")
	if _, err := f.Commit(testID, "d/a", -1, nil); err != nil {
		t.Fatal(err)
	}
	stage(t, f, testID, "d/b", "y")
	if _, err := f.Commit(testID, "d/b", -1, nil); err != nil {
		t.Fatal(err)
	}
	var names []string
	filepath.WalkDir(filepath.Join(shareDir(f, testID), filesDirName), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			names = append(names, filepath.Base(p))
		}
		return nil
	})
	if len(names) != 2 || strings.Contains(strings.Join(names, ","), ".") {
		t.Fatalf("files/ holds %v", names)
	}
}
