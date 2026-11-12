package logfile_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"hyperdrop/server/internal/logfile"
)

func TestRotatesAtMaxSizeAndKeepsAtMostKeepFiles(t *testing.T) {
	dir := t.TempDir()
	w, err := logfile.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	line := append(bytes.Repeat([]byte("x"), 1023), '\n')
	for i := 0; i < 12*1024; i++ { // 12 MB: more than one rotation
		if _, err := w.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	w.Close()
	names, _ := filepath.Glob(filepath.Join(dir, logfile.Name+"*"))
	if len(names) < 2 || len(names) > logfile.Keep {
		t.Fatalf("files after 12 MB: %v", names)
	}
	st, err := os.Stat(filepath.Join(dir, logfile.Name))
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() > logfile.MaxSize {
		t.Fatalf("current file is %d bytes, over MaxSize", st.Size())
	}
}

func TestTheOldestFileFallsOffAtKeep(t *testing.T) {
	dir := t.TempDir()
	w, err := logfile.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	line := append(bytes.Repeat([]byte("y"), 1023), '\n')
	for i := 0; i < 12*10*1024; i++ { // 120 MB: past Keep rotations
		if _, err := w.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	w.Close()
	names, _ := filepath.Glob(filepath.Join(dir, logfile.Name+"*"))
	if len(names) != logfile.Keep {
		t.Fatalf("kept %d files, want %d: %v", len(names), logfile.Keep, names)
	}
}

func TestTailSpansRotatedFilesInOrder(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, logfile.Name+".2"), []byte("a\n"), 0o644)
	os.WriteFile(filepath.Join(dir, logfile.Name+".1"), []byte("b\nc\n"), 0o644)
	os.WriteFile(filepath.Join(dir, logfile.Name), []byte("d\n"), 0o644)
	got, err := logfile.Tail(dir, 3)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "b\nc\nd\n" {
		t.Fatalf("got %q", got)
	}
	all, _ := logfile.Tail(dir, 100)
	if string(all) != "a\nb\nc\nd\n" {
		t.Fatalf("asking for more than exists: %q", all)
	}
}

// A reader paging back skips the newest lines it already holds.
func TestTailSkipsTheNewestLinesItIsToldTo(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, logfile.Name+".1"), []byte("a\nb\n"), 0o644)
	os.WriteFile(filepath.Join(dir, logfile.Name), []byte("c\nd\n"), 0o644)
	got, err := logfile.TailBefore(dir, 2, 1)
	if err != nil || string(got) != "b\nc\n" {
		t.Fatalf("got %q, %v", got, err)
	}
	if got, _ := logfile.TailBefore(dir, 10, 3); string(got) != "a\n" {
		t.Fatalf("past the start: %q", got)
	}
	if got, _ := logfile.TailBefore(dir, 10, 9); len(got) != 0 {
		t.Fatalf("skipping everything: %q", got)
	}
}

func TestTailOfNothingIsEmpty(t *testing.T) {
	got, err := logfile.Tail(t.TempDir(), 10)
	if err != nil || len(got) != 0 {
		t.Fatalf("got %q, %v", got, err)
	}
}

// The log names share paths, so its directory and files are the server
// account's alone.
func TestTheLogIsCreatedOwnerOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	w, err := logfile.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("line\n")); err != nil {
		t.Fatal(err)
	}
	w.Close()
	for _, p := range []string{dir, filepath.Join(dir, logfile.Name)} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s is %v, want no group or other bits", p, st.Mode().Perm())
		}
	}
}
