package sharefs

import (
	"os"
	"path/filepath"
	"testing"
)

// openTest opens a file layer over a fresh temporary data directory.
func openTest(t *testing.T) *FS {
	t.Helper()
	f, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return f
}

// shareDir composes a share's directory for assertions that look at the disk.
func shareDir(f *FS, id string) string { return filepath.Join(f.DataDir(), sharesDirName, id) }

// exists reports whether a path is present, for assertions.
func exists(p string) bool { _, err := os.Stat(p); return err == nil }

const testID = "abcdefghjk"

// len is how many keys are held, for the tests that check none leak.
func (k *keyedLocks[T]) len() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.m)
}
