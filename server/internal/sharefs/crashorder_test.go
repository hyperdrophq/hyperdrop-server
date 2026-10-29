package sharefs

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Create: row first, the directory on the first upload. The file layer
// therefore has nothing to do for a new share, and a share with rows and no
// directory reads as empty rather than as an error.
func TestAShareWithRowsAndNoDirectoryReadsAsEmpty(t *testing.T) {
	f := openTest(t)
	if _, _, err := f.Open(testID, "a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Open: %v", err)
	}
	if size, err := f.PartSize(testID, "a"); err != nil || size != 0 {
		t.Fatalf("PartSize: %d, %v", size, err)
	}
	if slugs, err := f.ThumbSlugs(testID); err != nil || len(slugs) != 0 {
		t.Fatalf("ThumbSlugs: %v, %v", slugs, err)
	}
	if f.HasPoster(testID) || f.HasRecentPart(testID, 1<<62) {
		t.Fatal("nothing is there")
	}
	if err := f.RemoveFile(testID, "a"); err != nil {
		t.Fatalf("RemoveFile on nothing: %v", err)
	}
	if err := f.RemoveShare(testID); err != nil {
		t.Fatalf("RemoveShare on nothing: %v", err)
	}
}

// Commit: rename then row. A crash between leaves a file under files/ and a
// pending row. The client's retry stages and commits again, and the second
// rename replaces the stray file, so the bytes converge on the row.
func TestARetriedCommitReplacesAStrayFile(t *testing.T) {
	f := openTest(t)
	stage(t, f, testID, "a", "first attempt")
	if _, err := f.Commit(testID, "a", -1, nil); err != nil {
		t.Fatal(err)
	}
	// The row was never written; the client retries with the same bytes.
	stage(t, f, testID, "a", "first attempt")
	c, err := f.Commit(testID, "a", -1, nil)
	if err != nil || c.SHA256 != sha256Hex("first attempt") {
		t.Fatalf("retry: %+v, %v", c, err)
	}
	fh, fi, err := f.Open(testID, "a")
	if err != nil || fi.Size() != int64(len("first attempt")) {
		t.Fatalf("after retry: %v, %v", fi, err)
	}
	fh.Close()
	// The stalled sweep, giving up on the pending row, removes the file
	// the row names, whether or not a stray copy landed.
	if err := f.RemoveFile(testID, "a"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.Open(testID, "a"); !errors.Is(err, ErrNotFound) {
		t.Fatal("stray file survived the sweep's RemoveFile")
	}
}

// Delete: rows first, then the directory. A crash between leaves an orphan
// directory, which the boot pass removes once it is older than the window.
func TestAnOrphanDirectoryIsRemovedAtBoot(t *testing.T) {
	f := openTest(t)
	stage(t, f, testID, "a", "x")
	if _, err := f.Commit(testID, "a", -1, nil); err != nil {
		t.Fatal(err)
	}
	backdate(t, shareDir(f, testID), 2*DefaultAbandonedUpload)
	removed, err := f.Orphans(func(string) bool { return false })
	if err != nil || removed != 1 {
		t.Fatalf("Orphans: %d, %v", removed, err)
	}
	if exists(shareDir(f, testID)) {
		t.Fatal("orphan survived")
	}
}

// The files tree never holds anything but stored files: no staging, no
// sidecars, no temporary names survive a commit.
func TestNothingButStoredFilesLivesUnderFiles(t *testing.T) {
	f := openTest(t)
	stage(t, f, testID, "d/a", "x")
	if _, err := f.Commit(testID, "d/a", -1, nil); err != nil {
		t.Fatal(err)
	}
	stage(t, f, testID, "d/b", "y")
	if _, err := f.Commit(testID, "d/b", -1, nil); err != nil {
		t.Fatal(err)
	}
	var names []string
	filepath.WalkDir(filepath.Join(shareDir(f, testID), filesDirName), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			names = append(names, filepath.Base(p))
		}
		return nil
	})
	if len(names) != 2 || strings.Contains(strings.Join(names, ","), ".") {
		t.Fatalf("files/ holds %v", names)
	}
}

// reopen is the file layer of a fresh process over f's data directory,
// after its boot pass: what a server sees when it starts after a crash.
func reopen(t *testing.T, f *FS) *FS {
	t.Helper()
	g, err := Open(f.DataDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Orphans(func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	return g
}

// publishVolume is a share holding a.txt and b.txt, with a publish staging
// a new a.txt and d/c.txt: the commit under test replaces a.txt, adds
// d/c.txt and deletes b.txt.
func publishVolume(t *testing.T, f *FS) (pid string, j Journal) {
	t.Helper()
	store(t, f, "a.txt", "old a")
	store(t, f, "b.txt", "old b")
	pid = openStage(t, f)
	stageWhole(t, f, pid, "a.txt", []byte("new a, longer"))
	stageWhole(t, f, pid, "d/c.txt", []byte("new c"))
	return pid, Journal{Files: []string{"a.txt", "d/c.txt"}, Delete: []string{"b.txt"}}
}

// forward is the database's verdict on publishVolume's journal once its
// rows are written: every path renamed to itself, b.txt removed.
func forward(Journal) (JournalDecision, error) {
	return JournalDecision{Forward: true,
		Renames: []Rename{{From: "a.txt", To: "a.txt"}, {From: "d/c.txt", To: "d/c.txt"}},
		Removes: []string{"b.txt"}}, nil
}

// Publish, before the journal: the commit wrote nothing, so the boot pass
// finds an open publish with no journal and leaves it as it was.
func TestACrashBeforeThePublishJournalLeavesThePublishOpen(t *testing.T) {
	f := openTest(t)
	pid, _ := publishVolume(t, f)
	g := reopen(t, f)
	if js, err := g.Journals(); err != nil || len(js) != 0 {
		t.Fatalf("Journals = %+v, %v; want none", js, err)
	}
	if files, err := g.StagedFiles(testID, pid); err != nil || len(files) != 2 {
		t.Fatalf("the open publish after the boot pass: %v, %v", files, err)
	}
	if got := storedBytes(t, g, "a.txt"); string(got) != "old a" {
		t.Fatalf("a.txt = %q", got)
	}
	if n := g.OpenPublishes("alice"); n != 1 {
		t.Fatalf("open publishes = %d, want 1", n)
	}
}

// Publish, after the journal and before the rows: the database's verdict
// is that the rows do not name the publish, so the boot pass removes the
// journal and the publish stays open, committable again, with nothing moved.
func TestTheBootPassReopensAJournalTheRowsDoNotName(t *testing.T) {
	f := openTest(t)
	pid, j := publishVolume(t, f)
	if err := f.WriteJournal(testID, pid, j); err != nil {
		t.Fatal(err)
	}
	g := reopen(t, f)
	js, err := g.Journals()
	if err != nil || len(js) != 1 || js[0].ShareID != testID || js[0].PID != pid {
		t.Fatalf("Journals = %+v, %v", js, err)
	}
	fwd, err := g.FinishPublish(testID, pid, js[0].Journal, func(got Journal) (JournalDecision, error) {
		if len(got.Files) != 2 || len(got.Delete) != 1 {
			t.Errorf("decide was handed %+v", got)
		}
		return JournalDecision{}, nil
	})
	if err != nil || fwd {
		t.Fatalf("FinishPublish = %v, %v; want reopened", fwd, err)
	}
	if _, ok, _ := g.ReadJournal(testID, pid); ok {
		t.Fatal("the journal survived a reopen")
	}
	if files, err := g.StagedFiles(testID, pid); err != nil || len(files) != 2 {
		t.Fatalf("the reopened publish: %v, %v", files, err)
	}
	if got := storedBytes(t, g, "a.txt"); string(got) != "old a" {
		t.Fatalf("a.txt = %q", got)
	}
	if got := storedBytes(t, g, "b.txt"); string(got) != "old b" {
		t.Fatalf("b.txt = %q", got)
	}
	if n := g.OpenPublishes("alice"); n != 1 {
		t.Fatalf("open publishes = %d, want 1", n)
	}
}

// Publish, after the rows: before any rename, and midway through them. The
// boot pass renames every part still staged, removes the deleted path's
// bytes and then the stage, so every file the rows name holds its bytes.
func TestTheBootPassFinishesARenameTheJournalNames(t *testing.T) {
	for _, midway := range []bool{false, true} {
		f := openTest(t)
		pid, j := publishVolume(t, f)
		if err := f.WriteJournal(testID, pid, j); err != nil {
			t.Fatal(err)
		}
		if midway {
			if err := f.SwapIn(testID, pid, []Rename{{From: "a.txt", To: "a.txt"}}, nil); err != nil {
				t.Fatal(err)
			}
		}
		g := reopen(t, f)
		fwd, err := g.FinishPublish(testID, pid, j, forward)
		if err != nil || !fwd {
			t.Fatalf("midway %v: FinishPublish = %v, %v; want forward", midway, fwd, err)
		}
		for rel, want := range map[string]string{"a.txt": "new a, longer", "d/c.txt": "new c"} {
			if got := storedBytes(t, g, rel); sha256Hex(string(got)) != sha256Hex(want) {
				t.Fatalf("midway %v: %s = %q", midway, rel, got)
			}
		}
		if exists(filepath.Join(shareDir(g, testID), fileRel("b.txt"))) {
			t.Fatalf("midway %v: the deleted file is still there", midway)
		}
		if exists(filepath.Join(shareDir(g, testID), stageRel(pid))) || g.StageExists(testID, pid) {
			t.Fatalf("midway %v: the stage survived its commit", midway)
		}
		if n := g.OpenPublishes("alice"); n != 0 {
			t.Fatalf("midway %v: open publishes = %d, want 0", midway, n)
		}
	}
}

// A verdict the database cannot give leaves the journal and the stage as
// they are, for the next boot: neither finished nor reopened.
func TestAJournalTheDatabaseCannotJudgeIsLeftAlone(t *testing.T) {
	f := openTest(t)
	pid, j := publishVolume(t, f)
	if err := f.WriteJournal(testID, pid, j); err != nil {
		t.Fatal(err)
	}
	g := reopen(t, f)
	boom := errors.New("database unreadable")
	if fwd, err := g.FinishPublish(testID, pid, j, func(Journal) (JournalDecision, error) { return JournalDecision{}, boom }); !errors.Is(err, boom) || fwd {
		t.Fatalf("FinishPublish = %v, %v", fwd, err)
	}
	if _, ok, _ := g.ReadJournal(testID, pid); !ok {
		t.Fatal("the journal went with an unanswered verdict")
	}
	if files, _ := g.StagedFiles(testID, pid); len(files) != 2 {
		t.Fatalf("the stage lost files: %v", files)
	}
}

// While a commit's journal remains, its rows may already name the staged
// bytes, so nothing changes what is staged: no chunk, no whole upload, no
// finish and no discard, each refused with ErrStageCommitting.
func TestAJournaledPublishTakesNoStagedWrite(t *testing.T) {
	f := openTest(t)
	pid, j := publishVolume(t, f)
	writeStaged(t, f, pid, "half.bin", payload(20), Range{0, 10}, "s")
	if err := f.WriteJournal(testID, pid, j); err != nil {
		t.Fatal(err)
	}
	before, err := f.StagedFiles(testID, pid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteRangeStaged(testID, pid, "a.txt", strings.NewReader("xx"), Range{0, 2}, 2, "other"); !errors.Is(err, ErrStageCommitting) {
		t.Fatalf("a chunk = %v", err)
	}
	if _, err := f.WriteStaged(testID, pid, "a.txt", strings.NewReader("xx")); !errors.Is(err, ErrStageCommitting) {
		t.Fatalf("a whole upload = %v", err)
	}
	if _, err := f.WriteRangeStaged(testID, pid, "half.bin", bytes.NewReader(payload(20)[10:]), Range{10, 20}, 20, "s"); !errors.Is(err, ErrStageCommitting) {
		t.Fatalf("a chunk of an unfinished part = %v", err)
	}
	if _, err := f.FinishStaged(testID, pid, "half.bin", "s", 20); !errors.Is(err, ErrStageCommitting) {
		t.Fatalf("a finish = %v", err)
	}
	f.DiscardStaged(testID, pid, "a.txt")
	after, err := f.StagedFiles(testID, pid)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("staged files changed under a journal: %+v, want %+v (%v)", after, before, err)
	}
}

// Rollback: the previous release's file layer composes only files/,
// parts/, thumbs/ and the poster. A committed publish leaves ordinary
// stored files under files/ and nothing in stage/; an open one keeps its
// bytes in stage/<pid>/ alone, where no read of that release looks, and
// goes with the share.
func TestAPublishLeavesOnlyWhatThePreviousReleaseReads(t *testing.T) {
	f := openTest(t)
	committed, j := publishVolume(t, f)
	open := openStage(t, f)
	stageWhole(t, f, open, "open.txt", []byte("not yet"))
	if err := f.WithSwap(testID, append(append([]string{}, j.Files...), j.Delete...), nil, func() error {
		if err := f.SwapIn(testID, committed, []Rename{{From: "a.txt", To: "a.txt"}, {From: "d/c.txt", To: "d/c.txt"}}, j.Delete); err != nil {
			return err
		}
		return f.RetireStageLocked(testID, committed)
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.PurgeStage(testID, committed); err != nil {
		t.Fatal(err)
	}
	var stored []string
	filepath.WalkDir(filepath.Join(shareDir(f, testID), filesDirName), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(filepath.Join(shareDir(f, testID), filesDirName), p)
			stored = append(stored, filepath.ToSlash(rel))
		}
		return nil
	})
	if !reflect.DeepEqual(stored, []string{"a.txt", "d/c.txt"}) {
		t.Fatalf("files/ holds %v", stored)
	}
	if exists(filepath.Join(shareDir(f, testID), partsDirName, partName("open.txt"))) {
		t.Fatal("an open publish's bytes are in parts/")
	}
	entries, _ := os.ReadDir(filepath.Join(shareDir(f, testID), stageDirName))
	if len(entries) != 1 || entries[0].Name() != open {
		t.Fatalf("stage/ holds %v, want only the open publish", entries)
	}
	if err := f.RemoveShare(testID); err != nil || exists(shareDir(f, testID)) {
		t.Fatalf("the share with an open publish was not removed: %v", err)
	}
}
