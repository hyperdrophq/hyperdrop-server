package fsatomic

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteReplacesWholeAndLeavesNoTemporary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	for _, data := range []string{"first", "second, longer"} {
		if err := Write(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != data {
			t.Fatalf("read back %q, %v, want %q", got, err, data)
		}
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, %v", fi.Mode(), err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("directory holds %v, want the file alone", entries)
	}
	if err := Write(filepath.Join(dir, "missing", "x"), []byte("x"), 0o600); err == nil {
		t.Fatal("a write into a missing directory succeeded")
	}
}
