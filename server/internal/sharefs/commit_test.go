package sharefs

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func stage(t *testing.T, f *FS, id, rel, body string) {
	t.Helper()
	if _, err := f.Write(id, rel, strings.NewReader(body)); err != nil {
		t.Fatal(err)
	}
}

func TestCommitHashesSniffsAndRenamesIntoFiles(t *testing.T) {
	f := openTest(t)
	stage(t, f, testID, "docs/note.txt", "hello world")
	c, err := f.Commit(testID, "docs/note.txt", 11, nil)
	if err != nil || c.Size != 11 || c.SHA256 != sha256Hex("hello world") || !strings.HasPrefix(c.Mime, "text/plain") {
		t.Fatalf("Commit: %+v, %v", c, err)
	}
	final := filepath.Join(shareDir(f, testID), filesDirName, "docs", "note.txt")
	if data, err := os.ReadFile(final); err != nil || string(data) != "hello world" {
		t.Fatalf("final file: %q, %v", data, err)
	}
	parts := filepath.Join(shareDir(f, testID), partsDirName)
	if entries, _ := os.ReadDir(parts); len(entries) != 0 {
		t.Fatalf("staging left behind: %v", entries)
	}
	if _, err := f.Commit(testID, "docs/note.txt", -1, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second commit with nothing staged: %v", err)
	}
	if _, err := f.Commit(testID, "../x", -1, nil); !errors.Is(err, ErrBadPath) {
		t.Fatalf("bad rel: %v", err)
	}
	stage(t, f, testID, "png", "\x89PNG\r\n\x1a\n0000000000000000")
	if c, _ := f.Commit(testID, "png", -1, nil); c.Mime != "image/png" {
		t.Fatalf("an extensionless file is sniffed: %q", c.Mime)
	}
	stage(t, f, testID, "docs/note.txt", "v2")
	if c, err := f.Commit(testID, "docs/note.txt", 2, nil); err != nil || c.Size != 2 {
		t.Fatalf("re-upload replaces: %+v, %v", c, err)
	}
	if data, _ := os.ReadFile(final); string(data) != "v2" {
		t.Fatalf("replaced content: %q", data)
	}
}

// A part that does not match the size the caller was promised is a
// truncated transfer, not a file: it is refused and left staged, so the
// client resumes from what landed.
func TestCommitRefusesAPartThatIsNotTheDeclaredSize(t *testing.T) {
	f := openTest(t)
	stage(t, f, testID, "a", "hello")
	_, err := f.Commit(testID, "a", 9, nil)
	if !errors.Is(err, ErrBadRequest) || !strings.Contains(err.Error(), "staged 5 bytes, expected 9") {
		t.Fatalf("short part: %v", err)
	}
	if size, _ := f.PartSize(testID, "a"); size != 5 {
		t.Fatal("a refused commit must leave the part staged")
	}
	if _, _, err := f.Open(testID, "a"); !errors.Is(err, ErrNotFound) {
		t.Fatal("a refused commit must store nothing")
	}
	if c, err := f.Commit(testID, "a", 5, nil); err != nil || c.Size != 5 {
		t.Fatalf("the matching size: %+v, %v", c, err)
	}
}

func TestCommitHashesFromTheSidecarOrTheDisk(t *testing.T) {
	f := openTest(t)
	// Write saves the digest it computed and Commit reads the hash from it.
	if _, err := f.Write(testID, "d", strings.NewReader("abcdef")); err != nil {
		t.Fatal(err)
	}
	side := filepath.Join(shareDir(f, testID), partRel("d")+partHashExt)
	if !exists(side) {
		t.Fatal("digest sidecar not saved by Write")
	}
	if c, err := f.Commit(testID, "d", -1, nil); err != nil || c.SHA256 != sha256Hex("abcdef") {
		t.Fatalf("hash from the sidecar: %+v, %v", c, err)
	}
	// A corrupt sidecar is dropped, and Commit hashes the part from disk.
	if _, err := f.Write(testID, "e", strings.NewReader("abcdef")); err != nil {
		t.Fatal(err)
	}
	side = filepath.Join(shareDir(f, testID), partRel("e")+partHashExt)
	if err := os.WriteFile(side, []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	if c, err := f.Commit(testID, "e", -1, nil); err != nil || c.SHA256 != sha256Hex("abcdef") {
		t.Fatalf("hash from the disk: %+v, %v", c, err)
	}
	// A sidecar that covers fewer bytes than the part is ignored too.
	if _, err := f.Write(testID, "g", strings.NewReader("abcd")); err != nil {
		t.Fatal(err)
	}
	part := filepath.Join(shareDir(f, testID), partRel("g"))
	if err := os.WriteFile(part, []byte("abcdef"), 0o644); err != nil {
		t.Fatal(err)
	}
	if c, err := f.Commit(testID, "g", -1, nil); err != nil || c.SHA256 != sha256Hex("abcdef") || c.Size != 6 {
		t.Fatalf("stale sidecar ignored: %+v, %v", c, err)
	}
}

func TestOpenServesRegularFilesOnlyAndNeverLeavesTheShare(t *testing.T) {
	f := openTest(t)
	stage(t, f, testID, "a.txt", "abc")
	if _, err := f.Commit(testID, "a.txt", -1, nil); err != nil {
		t.Fatal(err)
	}
	fh, fi, err := f.Open(testID, "a.txt")
	if err != nil || fi.Size() != 3 {
		t.Fatalf("Open: %v, %v", fi, err)
	}
	data, _ := io.ReadAll(fh)
	fh.Close()
	if string(data) != "abc" {
		t.Fatalf("read %q", data)
	}
	if _, _, err := f.Open(testID, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if _, _, err := f.Open("abcdefghjm", "a.txt"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing share: %v", err)
	}
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("leak"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(shareDir(f, testID), filesDirName, "link.txt")
	if err := os.Symlink(outside, link); err != nil {
		t.Skip("symlinks unsupported here")
	}
	if _, _, err := f.Open(testID, "link.txt"); err == nil {
		t.Fatal("a symlink out of the share must not open")
	}
	dir := filepath.Join(shareDir(f, testID), filesDirName, "sub")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.Open(testID, "sub"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a directory is not a file: %v", err)
	}
}

func TestRemoveFilePrunesParentsAndIsIdempotent(t *testing.T) {
	f := openTest(t)
	stage(t, f, testID, "a/b/c.txt", "x")
	if _, err := f.Commit(testID, "a/b/c.txt", -1, nil); err != nil {
		t.Fatal(err)
	}
	stage(t, f, testID, "a/keep.txt", "y")
	if _, err := f.Commit(testID, "a/keep.txt", -1, nil); err != nil {
		t.Fatal(err)
	}
	stage(t, f, testID, "a/b/c.txt", "staged again")
	if err := f.RemoveFile(testID, "a/b/c.txt"); err != nil {
		t.Fatal(err)
	}
	files := filepath.Join(shareDir(f, testID), filesDirName)
	if exists(filepath.Join(files, "a", "b")) {
		t.Fatal("emptied parent not pruned")
	}
	if !exists(filepath.Join(files, "a", "keep.txt")) {
		t.Fatal("a sibling was removed")
	}
	if size, _ := f.PartSize(testID, "a/b/c.txt"); size != 0 {
		t.Fatal("the staged part must go with the file")
	}
	if err := f.RemoveFile(testID, "a/b/c.txt"); err != nil {
		t.Fatalf("absent: %v", err)
	}
	if err := f.RemoveFile("abcdefghjm", "x"); err != nil {
		t.Fatalf("absent share: %v", err)
	}
	if err := f.RemoveFile(testID, "../x"); !errors.Is(err, ErrBadPath) {
		t.Fatalf("bad rel: %v", err)
	}
	if !exists(files) {
		t.Fatal("files/ itself must never be pruned")
	}
}

func TestRenameMovesFilesAndSubtrees(t *testing.T) {
	f := openTest(t)
	for _, p := range []string{"src/index.html", "src/css/a.css", "readme"} {
		stage(t, f, testID, p, p)
		if _, err := f.Commit(testID, p, -1, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Rename(testID, "src", "www"); err != nil {
		t.Fatal(err)
	}
	files := filepath.Join(shareDir(f, testID), filesDirName)
	for _, p := range []string{"www/index.html", "www/css/a.css", "readme"} {
		if data, err := os.ReadFile(filepath.Join(files, filepath.FromSlash(p))); err != nil || string(data) != strings.Replace(p, "www", "src", 1) {
			t.Fatalf("%s after rename: %q, %v", p, data, err)
		}
	}
	if exists(filepath.Join(files, "src")) {
		t.Fatal("old subtree left behind")
	}
	if err := f.Rename(testID, "readme", "docs/deep/readme.txt"); err != nil {
		t.Fatal(err)
	}
	if !exists(filepath.Join(files, "docs", "deep", "readme.txt")) {
		t.Fatal("parents not created")
	}
	if err := f.Rename(testID, "nothing", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing source: %v", err)
	}
	if err := f.Rename(testID, "www", "../x"); !errors.Is(err, ErrBadPath) {
		t.Fatalf("bad target: %v", err)
	}
}

func TestRemoveShareTakesTheDirectoryAndAStaleCommitCannotResurrectIt(t *testing.T) {
	f := openTest(t)
	stage(t, f, testID, "a", "x")
	if err := f.Reserve(testID, "alice", 10); err != nil {
		t.Fatal(err)
	}
	if err := f.RemoveShare(testID); err != nil {
		t.Fatal(err)
	}
	if exists(shareDir(f, testID)) {
		t.Fatal("directory still there")
	}
	if _, err := f.Commit(testID, "a", -1, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("commit after delete: %v", err)
	}
	if exists(shareDir(f, testID)) {
		t.Fatal("a commit after delete recreated the directory")
	}
	if err := f.RemoveShare(testID); err != nil {
		t.Fatalf("second remove: %v", err)
	}
	if err := f.RemoveShare("bad"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bad id: %v", err)
	}
	f.resMu.Lock()
	_, held := f.reservations[testID]
	f.resMu.Unlock()
	if held {
		t.Fatal("reservation not released")
	}
}

// The rows are gone before the directory is touched, so a removal that
// fails still gives the hold back: nothing can upload into the share, and a
// hold nobody can consume keeps other shares off the disk.
func TestRemoveShareReleasesTheHoldEvenWhenTheDirectoryStays(t *testing.T) {
	f := openTest(t)
	stage(t, f, testID, "a", "x")
	if err := f.Reserve(testID, "alice", 10); err != nil {
		t.Fatal(err)
	}
	shares := filepath.Join(f.DataDir(), sharesDirName)
	if err := os.Chmod(shares, 0o500); err != nil {
		t.Skip("cannot make the shares directory unwritable here")
	}
	err := f.RemoveShare(testID)
	os.Chmod(shares, 0o755)
	if err == nil {
		t.Skip("the directory came away anyway, nothing to prove")
	}
	f.resMu.Lock()
	_, held := f.reservations[testID]
	f.resMu.Unlock()
	if held {
		t.Fatal("a failed removal kept the reservation")
	}
}

func TestStatAnswersRegularFilesOnly(t *testing.T) {
	f := openTest(t)
	stage(t, f, testID, "docs/note.txt", "hello world")
	if _, err := f.Commit(testID, "docs/note.txt", 11, nil); err != nil {
		t.Fatal(err)
	}
	fi, err := f.Stat(testID, "docs/note.txt")
	if err != nil || fi.Size() != 11 || !fi.Mode().IsRegular() {
		t.Fatalf("Stat: %v, %v", fi, err)
	}
	if _, err := f.Stat(testID, "docs/missing.txt"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if _, err := f.Stat(testID, "docs"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("directory: %v", err)
	}
	if _, err := f.Stat(testID, "../x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bad rel: %v", err)
	}
}

// A name the filesystem refuses is the request's fault, not the server's:
// it maps to ErrBadPath (a 400) without the raw error's paths.
func TestPathErrMapsANameTooLong(t *testing.T) {
	err := pathErr(&os.LinkError{Op: "renameat", Old: "parts/x.part", New: "files/long", Err: syscall.ENAMETOOLONG})
	if !errors.Is(err, ErrBadPath) || strings.Contains(err.Error(), "parts/") {
		t.Fatalf("pathErr = %v", err)
	}
}

// record runs under the path's lock after the rename. When it refuses, the
// new bytes go and what the path held comes back; a path that held nothing
// is removed with its emptied parents. Either way parts/ is left empty.
func TestCommitRestoresThePreviousFileWhenTheRowRefuses(t *testing.T) {
	f := openTest(t)
	refuse := errors.New("refused")
	final := filepath.Join(shareDir(f, testID), filesDirName, "d", "a.txt")
	parts := filepath.Join(shareDir(f, testID), partsDirName)

	stage(t, f, testID, "d/a.txt", "v1")
	var seen Committed
	if _, err := f.Commit(testID, "d/a.txt", 2, func(c Committed) error { seen = c; return nil }); err != nil || seen.Size != 2 {
		t.Fatalf("accepted commit: %+v, %v", seen, err)
	}
	stage(t, f, testID, "d/a.txt", "version two")
	if _, err := f.Commit(testID, "d/a.txt", -1, func(Committed) error {
		if data, _ := os.ReadFile(final); string(data) != "version two" {
			t.Errorf("record ran before the rename: %q", data)
		}
		return refuse
	}); !errors.Is(err, refuse) {
		t.Fatalf("refused commit: %v", err)
	}
	if data, err := os.ReadFile(final); err != nil || string(data) != "v1" {
		t.Fatalf("after the refusal the path holds %q, %v, want v1", data, err)
	}
	if entries, _ := os.ReadDir(parts); len(entries) != 0 {
		t.Fatalf("staging left behind: %v", entries)
	}

	stage(t, f, testID, "new/b.txt", "b")
	if _, err := f.Commit(testID, "new/b.txt", 1, func(Committed) error { return refuse }); !errors.Is(err, refuse) {
		t.Fatalf("refused new path: %v", err)
	}
	if exists(filepath.Join(shareDir(f, testID), filesDirName, "new")) {
		t.Fatal("a refused new path left its file or folder behind")
	}
	if entries, _ := os.ReadDir(parts); len(entries) != 0 {
		t.Fatalf("staging left behind: %v", entries)
	}
}

// A removal decided from a snapshot (the stalled sweep's) waits for a commit
// in progress at the same path and re-checks under the lock, so it can never
// land between the commit's rename and its row.
func TestRemoveFileIfWaitsForACommitAndRechecks(t *testing.T) {
	f := openTest(t)
	stage(t, f, testID, "a.txt", "bytes")
	inRecord := make(chan struct{})
	finish := make(chan struct{})
	committed := false
	go func() {
		f.Commit(testID, "a.txt", 5, func(Committed) error {
			close(inRecord)
			<-finish
			committed = true
			return nil
		})
	}()
	<-inRecord
	removed := make(chan bool)
	go func() {
		ok, _ := f.RemoveFileIf(testID, "a.txt", func() bool { return !committed })
		removed <- ok
	}()
	close(finish)
	if <-removed {
		t.Fatal("the removal ran over a commit that wrote its row")
	}
	if _, err := f.Stat(testID, "a.txt"); err != nil {
		t.Fatalf("the committed file is gone: %v", err)
	}
	if ok, err := f.RemoveFileIf(testID, "a.txt", func() bool { return true }); !ok || err != nil {
		t.Fatalf("an unconditional removal = %v, %v", ok, err)
	}
	if _, err := f.Stat(testID, "a.txt"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after the removal: %v", err)
	}
}

// On a filesystem without hard links the earlier file is renamed aside
// rather than linked, so a refused row still puts it back; a commit that can
// keep it neither way is refused before the path changes.
func TestCommitKeepsThePreviousFileWithoutHardLinks(t *testing.T) {
	f := openTest(t)
	final := filepath.Join(shareDir(f, testID), filesDirName, "a.txt")
	stage(t, f, testID, "a.txt", "owner's")
	if _, err := f.Commit(testID, "a.txt", -1, func(Committed) error { return nil }); err != nil {
		t.Fatal(err)
	}
	link := linkFile
	t.Cleanup(func() { linkFile = link })
	linkFile = func(*os.Root, string, string) error { return syscall.EPERM }

	refuse := errors.New("refused")
	stage(t, f, testID, "a.txt", "stranger's")
	if _, err := f.Commit(testID, "a.txt", -1, func(Committed) error { return refuse }); !errors.Is(err, refuse) {
		t.Fatalf("refused commit: %v", err)
	}
	if data, err := os.ReadFile(final); err != nil || string(data) != "owner's" {
		t.Fatalf("after the refusal the path holds %q, %v, want the owner's bytes", data, err)
	}

	stage(t, f, testID, "a.txt", "version two")
	if _, err := f.Commit(testID, "a.txt", -1, func(Committed) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(final); string(data) != "version two" {
		t.Fatalf("accepted overwrite holds %q", data)
	}
	if entries, _ := os.ReadDir(filepath.Join(shareDir(f, testID), partsDirName)); len(entries) != 0 {
		t.Fatalf("staging left behind: %v", entries)
	}
}

// A crash between the aside rename and the commit's own leaves the earlier
// file only at .prev; the next commit of that path puts it back before
// anything else, so a refused row restores it rather than deleting it.
func TestCommitRestoresAnAsideFileACrashLeft(t *testing.T) {
	f := openTest(t)
	final := filepath.Join(shareDir(f, testID), filesDirName, "a.txt")
	stage(t, f, testID, "a.txt", "owner's")
	if _, err := f.Commit(testID, "a.txt", -1, nil); err != nil {
		t.Fatal(err)
	}
	stage(t, f, testID, "a.txt", "stranger's")
	prev := filepath.Join(shareDir(f, testID), partRel("a.txt")+partPrevExt)
	if err := os.Rename(final, prev); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Commit(testID, "a.txt", -1, func(Committed) error { return errors.New("refused") }); err == nil {
		t.Fatal("the refusal was lost")
	}
	if data, err := os.ReadFile(final); err != nil || string(data) != "owner's" {
		t.Fatalf("after the refusal the path holds %q, %v, want the owner's bytes", data, err)
	}
}

// A check refusing a commit runs before anything in files/ moves: the path
// keeps its file, the part stays staged, and the row is never asked.
func TestCommitCheckedRefusesBeforeThePathChanges(t *testing.T) {
	f := openTest(t)
	final := filepath.Join(shareDir(f, testID), filesDirName, "a.txt")
	stage(t, f, testID, "a.txt", "owner's")
	if _, err := f.Commit(testID, "a.txt", -1, nil); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(final)
	stage(t, f, testID, "a.txt", "stranger's")
	taken := errors.New("taken")
	_, err := f.CommitChecked(testID, "a.txt", -1, func() error { return taken }, func(Committed) error {
		t.Error("record ran after the check refused")
		return nil
	})
	if !errors.Is(err, taken) {
		t.Fatalf("checked commit: %v", err)
	}
	after, err := os.Stat(final)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("the path's file changed: %v", err)
	}
	if n, err := f.PartSize(testID, "a.txt"); err != nil || n != int64(len("stranger's")) {
		t.Fatalf("part = %d, %v, want it still staged", n, err)
	}
}
