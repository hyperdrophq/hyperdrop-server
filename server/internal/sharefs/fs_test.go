package sharefs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenCreatesTheSharesTreeAndASecretOnce(t *testing.T) {
	dir := t.TempDir()
	f, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !exists(filepath.Join(dir, sharesDirName)) {
		t.Fatal("shares/ not created")
	}
	secret := f.Secret()
	if len(secret) != 32 {
		t.Fatalf("secret length %d", len(secret))
	}
	g, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(g.Secret()) != string(secret) {
		t.Fatal("reopening minted a new secret")
	}
	if f.ServerID() != g.ServerID() || len(f.ServerID()) != 16 {
		t.Fatalf("ServerID %q vs %q", f.ServerID(), g.ServerID())
	}
	if f.DataDir() != dir {
		t.Fatalf("DataDir = %q", f.DataDir())
	}
}

func TestPathsAreValidatedBeforeTheyAreComposed(t *testing.T) {
	f := openTest(t)
	if _, err := f.ShareDir("../x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bad id: %v", err)
	}
	if _, err := f.ShareDir("abcdefghj0"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("zero is not base58: %v", err)
	}
	d, err := f.ShareDir(testID)
	if err != nil || d != shareDir(f, testID) {
		t.Fatalf("ShareDir = %q, %v", d, err)
	}
	if _, err := f.FilePath(testID, "../a"); !errors.Is(err, ErrBadPath) {
		t.Fatalf("bad rel: %v", err)
	}
	if _, err := f.FilePath("bad", "a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bad id with good rel: %v", err)
	}
	p, err := f.FilePath(testID, "dir/a.txt")
	if err != nil || p != filepath.Join(d, filesDirName, "dir", "a.txt") {
		t.Fatalf("FilePath = %q, %v", p, err)
	}
	if fileRel("dir/a.txt") != filepath.Join(filesDirName, "dir", "a.txt") {
		t.Fatalf("fileRel = %q", fileRel("dir/a.txt"))
	}
	if pr := partRel("dir/a.txt"); filepath.Dir(pr) != partsDirName || len(filepath.Base(pr)) != 64+len(".part") {
		t.Fatalf("partRel = %q", pr)
	}
	if partRel("a") == partRel("a/b") {
		t.Fatal("distinct relpaths must stage under distinct names")
	}
}

func TestRootsRefuseAMissingShareAndEnsureRootCreatesIt(t *testing.T) {
	f := openTest(t)
	if _, err := f.root(testID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("root of a missing share: %v", err)
	}
	r, err := f.ensureRoot(testID)
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	if !exists(shareDir(f, testID)) {
		t.Fatal("ensureRoot did not create the directory")
	}
	r, err = f.root(testID)
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	if _, err := f.ensureRoot("bad"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ensureRoot bad id: %v", err)
	}
}

func TestTheAbandonedWindow(t *testing.T) {
	f := openTest(t)
	if f.AbandonedUploadWindow() != DefaultAbandonedUpload {
		t.Fatalf("unset window = %v", f.AbandonedUploadWindow())
	}
	f.AbandonedWindow = 45 * time.Minute
	if f.AbandonedUploadWindow() != 45*time.Minute {
		t.Fatalf("window = %v", f.AbandonedUploadWindow())
	}
}

func TestLocksAreRefcountedAndReleased(t *testing.T) {
	f := openTest(t)
	unlock := f.lockPath(testID, "a")
	if f.pathLocks.len() != 1 {
		t.Fatalf("pathLocks = %d", f.pathLocks.len())
	}
	unlock()
	if f.pathLocks.len() != 0 {
		t.Fatal("path lock entry leaked")
	}
	release := f.rlockShare(testID)
	release2 := f.rlockShare(testID) // readers share
	release()
	release2()
	done := make(chan struct{})
	w := f.lockShare(testID)
	go func() { r := f.rlockShare(testID); r(); close(done) }()
	select {
	case <-done:
		t.Fatal("a reader got in while the writer held the share")
	default:
	}
	w()
	<-done
	if f.shareLocks.len() != 0 {
		t.Fatal("share lock entry leaked")
	}
}

// Uploaded bytes are read by the server process alone, so the tree the file
// layer creates carries no group or other bits, whatever directory it sits in.
func TestTheSharesTreeIsCreatedOwnerOnly(t *testing.T) {
	f := openTest(t)
	stage(t, f, testID, "docs/note.txt", "hello world")
	if _, err := f.Commit(testID, "docs/note.txt", 11, nil); err != nil {
		t.Fatal(err)
	}
	stage(t, f, testID, "pending.txt", "not yet")
	if err := f.SetThumb(testID, slugA, jpegBytes(t), nil); err != nil {
		t.Fatal(err)
	}
	seen := 0
	err := filepath.WalkDir(filepath.Join(f.DataDir(), sharesDirName), func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		st, err := os.Stat(p)
		if err != nil {
			return err
		}
		if st.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s is %v, want no group or other bits", p, st.Mode().Perm())
		}
		seen++
		return nil
	})
	if err != nil || seen < 8 {
		t.Fatalf("walked %d entries: %v", seen, err)
	}
}
