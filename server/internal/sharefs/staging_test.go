package sharefs

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestWriteStagesAWholeBodyAndReplacesAnEarlierPart(t *testing.T) {
	f := openTest(t)
	n, err := f.Write(testID, "a.txt", strings.NewReader("hello"))
	if err != nil || n != 5 {
		t.Fatalf("Write: %d, %v", n, err)
	}
	if size, _ := f.PartSize(testID, "a.txt"); size != 5 {
		t.Fatalf("PartSize = %d", size)
	}
	if n, _ := f.Write(testID, "a.txt", strings.NewReader("hi")); n != 2 {
		t.Fatalf("second Write: %d", n)
	}
	if size, _ := f.PartSize(testID, "a.txt"); size != 2 {
		t.Fatalf("PartSize after replace = %d", size)
	}
	if _, err := f.Write(testID, "../x", strings.NewReader("x")); !errors.Is(err, ErrBadPath) {
		t.Fatalf("bad rel: %v", err)
	}
	if _, err := f.Write("bad", "a", strings.NewReader("x")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bad id: %v", err)
	}
	if exists(filepath.Join(shareDir(f, testID), filesDirName)) {
		t.Fatal("staging must not create files/")
	}
}

func TestDiscardAgeAndRecentParts(t *testing.T) {
	f := openTest(t)
	if f.HasRecentPart(testID, time.Hour) {
		t.Fatal("no parts yet")
	}
	if _, err := f.Write(testID, "r", strings.NewReader("ab")); err != nil {
		t.Fatal(err)
	}
	age, ok := f.PartAge(testID, "r")
	if !ok || age > time.Minute {
		t.Fatalf("PartAge = %v, %v", age, ok)
	}
	if !f.HasRecentPart(testID, time.Hour) {
		t.Fatal("a fresh part is recent")
	}
	part := filepath.Join(shareDir(f, testID), partRel("r"))
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(part, old, old); err != nil {
		t.Fatal(err)
	}
	if f.HasRecentPart(testID, time.Hour) {
		t.Fatal("an old part is not recent")
	}
	f.Discard(testID, "r")
	if size, _ := f.PartSize(testID, "r"); size != 0 || exists(part+partHashExt) {
		t.Fatal("Discard left staging behind")
	}
	if _, ok := f.PartAge(testID, "r"); ok {
		t.Fatal("PartAge after Discard")
	}
	f.Discard(testID, "never") // absent is fine
	f.Discard("bad", "x")      // invalid is fine
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// blockingReader yields one chunk and then blocks until it is released, so
// a test can hold a copy open while another goroutine deletes the share.
type blockingReader struct {
	chunk   []byte
	started chan struct{}
	release chan struct{}
	done    bool
}

func (b *blockingReader) Read(p []byte) (int, error) {
	if b.done {
		return 0, io.EOF
	}
	n := copy(p, b.chunk)
	close(b.started)
	<-b.release
	b.done = true
	return n, nil
}

// The share lock, held shared, covers the steps that can recreate the directory
// tree, not the copy, so a delete never waits behind a body that may stream
// for hours.
func TestRemoveShareDoesNotWaitBehindACopy(t *testing.T) {
	f := openTest(t)
	r := &blockingReader{chunk: []byte("head"), started: make(chan struct{}), release: make(chan struct{})}
	wrote := make(chan error, 1)
	go func() { _, err := f.Write(testID, "a", r); wrote <- err }()
	<-r.started
	removed := make(chan error, 1)
	go func() { removed <- f.RemoveShare(testID) }()
	select {
	case err := <-removed:
		if err != nil {
			t.Fatalf("RemoveShare: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("RemoveShare waited for the copy to finish")
	}
	close(r.release)
	if err := <-wrote; err != nil {
		t.Logf("the copy into the deleted share answered %v", err)
	}
	if _, err := f.Commit(testID, "a", -1, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("commit after the delete: %v", err)
	}
	if exists(shareDir(f, testID)) {
		t.Fatal("the copy recreated the share directory")
	}
}

// A full disk is ErrDiskFull wherever a write meets it, never a raw error
// the API would answer with a 500.
func TestMapDiskErrNamesAFullDisk(t *testing.T) {
	f := openTest(t)
	if err := f.mapDiskErr(&os.PathError{Op: "mkdirat", Path: "files/d", Err: syscall.ENOSPC}); !errors.Is(err, ErrDiskFull) {
		t.Fatalf("mapDiskErr(ENOSPC) = %v", err)
	}
	if err := f.mapDiskErr(nil); err != nil {
		t.Fatalf("mapDiskErr(nil) = %v", err)
	}
	if err := f.mapDiskErr(syscall.EIO); !errors.Is(err, syscall.EIO) {
		t.Fatalf("mapDiskErr(EIO) = %v", err)
	}
}
