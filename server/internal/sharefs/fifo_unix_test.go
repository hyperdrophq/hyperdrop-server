//go:build unix

package sharefs

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A gallery tile and a poster are served bytes too: a FIFO standing where
// one was answers as no tile or no poster, at once.
func TestTilesAndPostersNeverWaitOnAFIFO(t *testing.T) {
	f := openTest(t)
	if err := f.SetThumb(testID, "alice", slugA, jpegBytes(t), nil); err != nil {
		t.Fatal(err)
	}
	if err := f.SetPoster(testID, slugA, jpegBytes(t)); err != nil {
		t.Fatal(err)
	}
	dir := shareDir(f, testID)
	for _, p := range []string{filepath.Join(dir, thumbRel(slugA)), filepath.Join(dir, posterFileName), filepath.Join(dir, posterSourceFileName)} {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(p, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if w, err := os.OpenFile(p, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
				w.Close()
			}
		})
	}
	done := make(chan [3]error, 1)
	go func() {
		_, a := f.Thumb(testID, slugA)
		_, b := f.Poster(testID)
		_, c := f.PosterSource(testID)
		done <- [3]error{a, b, c}
	}()
	select {
	case errs := <-done:
		if !errors.Is(errs[0], ErrNoThumb) || !errors.Is(errs[1], ErrNoPoster) || errs[2] != nil {
			t.Fatalf("errs = %v", errs)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a read is still waiting on a FIFO")
	}
}

func TestOpenRefusesAFIFOSwappedInWithoutWaiting(t *testing.T) {
	f := openTest(t)
	stage(t, f, testID, "a.txt", "abc")
	if _, err := f.Commit(testID, "a.txt", -1, nil); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(shareDir(f, testID), filesDirName, "a.txt")
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
	done := make(chan error, 1)
	go func() {
		fh, _, err := f.Open(testID, "a.txt")
		if fh != nil {
			fh.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("err = %v, want ErrNotFound", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the open is still waiting on a FIFO")
	}
}
