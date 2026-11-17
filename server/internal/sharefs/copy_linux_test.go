//go:build linux

package sharefs

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

// On a filesystem that makes reflinks (btrfs, xfs) the copy is a clone, not
// a fallback. Skipped elsewhere: run with TMPDIR on such a filesystem.
func TestStageCopyClonesOnAReflinkFilesystem(t *testing.T) {
	f := openTest(t)
	if !reflinks(t, f.DataDir()) {
		t.Skip("the temporary directory's filesystem makes no reflinks")
	}
	data := storeFile(t, f, testID, "big.bin", 1<<20)
	cloned := false
	withClone(t, func(dst, src *os.File) error {
		err := cloneFileOS(dst, src)
		cloned = err == nil
		return err
	})
	n, err := f.StageCopy(testID, "big.bin", copyDstID, "big.bin")
	if err != nil {
		t.Fatal(err)
	}
	if !cloned {
		t.Fatal("StageCopy fell back to a copy on a filesystem that clones")
	}
	if _, err := f.Commit(copyDstID, "big.bin", n, nil); err != nil {
		t.Fatal(err)
	}
	if storedSum(t, f, copyDstID, "big.bin") != sha256.Sum256(data) {
		t.Fatal("the clone serves different bytes")
	}
}

// reflinks reports whether dir's filesystem clones one file into another.
func reflinks(t *testing.T, dir string) bool {
	t.Helper()
	src, err := os.Create(filepath.Join(dir, "probe-src"))
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	if _, err := src.Write(make([]byte, 4096)); err != nil {
		t.Fatal(err)
	}
	dst, err := os.Create(filepath.Join(dir, "probe-dst"))
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	return cloneFileOS(dst, src) == nil
}
