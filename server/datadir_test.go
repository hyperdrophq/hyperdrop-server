package main

import (
	"os"
	"strings"
	"testing"
)

func TestCheckDataWritableAcceptsAWritableDir(t *testing.T) {
	dir := t.TempDir()
	if err := checkDataWritable(dir); err != nil {
		t.Fatalf("a writable directory was refused: %v", err)
	}
	if _, err := os.Stat(dir + "/.write-check"); !os.IsNotExist(err) {
		t.Fatalf("the probe file was left behind: %v", err)
	}
}

func TestCheckDataWritableNamesTheChown(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes anywhere")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	err := checkDataWritable(dir)
	if err == nil {
		t.Fatal("a read-only directory was accepted")
	}
	for _, want := range []string{"chown -R", dir, "not writable"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q lacks %q", err.Error(), want)
		}
	}
}

func TestCheckDataWritableCreatesAMissingDirPrivate(t *testing.T) {
	dir := t.TempDir() + "/data"
	if err := checkDataWritable(dir); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o700 {
		t.Fatalf("mode %v, want 0700", st.Mode().Perm())
	}
}
