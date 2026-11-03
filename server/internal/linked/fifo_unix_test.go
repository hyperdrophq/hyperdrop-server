//go:build unix

package linked

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// swapInFIFO makes the next OpenRegular find a FIFO where its type check
// found a regular file, and unblocks a reader stuck opening it when the test
// ends, so a failing run does not leak a goroutine past the test.
func swapInFIFO(t *testing.T, file string) {
	t.Helper()
	afterTypeCheck = func() {
		afterTypeCheck = nil
		if err := os.Remove(file); err != nil {
			t.Error(err)
		}
		if err := syscall.Mkfifo(file, 0o644); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() {
		afterTypeCheck = nil
		if w, err := os.OpenFile(file, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			w.Close()
		}
	})
}

// openWithin runs open and fails the test when it has not answered within
// the deadline: an open of a FIFO that waits for a writer never answers.
func openWithin(t *testing.T, open func() (*os.File, error)) error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		f, err := open()
		if f != nil {
			f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("the open is still waiting on a FIFO")
		return nil
	}
}

func TestAnOpenerRefusesAFIFOSwappedInWithoutWaiting(t *testing.T) {
	roots := composeFixture(t)
	root, _, err := roots.Open("share/photos")
	if err != nil {
		t.Fatal(err)
	}
	dir := root.Name()
	root.Close()
	swapInFIFO(t, filepath.Join(dir, "a.jpg"))
	o := NewOpener(roots, []SourceSpec{{Path: "share/photos"}}, false)
	defer o.Close()
	err = openWithin(t, func() (*os.File, error) {
		f, _, err := o.Open("a.jpg")
		return f, err
	})
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v, want ErrNotExist", err)
	}
}

func TestOpenRegularRefusesAFIFOSwappedInWithoutWaiting(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	swapInFIFO(t, filepath.Join(dir, "f"))
	err = openWithin(t, func() (*os.File, error) {
		f, _, err := OpenRegular(root, "f", nil)
		return f, err
	})
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v, want ErrNotExist", err)
	}
}
