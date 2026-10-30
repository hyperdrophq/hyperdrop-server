package sharefs

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"hyperdrop/server/internal/shareid"
)

// store stages body for rel and commits it, as a plain upload does.
func store(t *testing.T, f *FS, rel, body string) {
	t.Helper()
	stage(t, f, testID, rel, body)
	if _, err := f.Commit(testID, rel, int64(len(body)), nil); err != nil {
		t.Fatal(err)
	}
}

// openStage opens a fresh publish on testID and answers its id.
func openStage(t *testing.T, f *FS) string {
	t.Helper()
	pid := shareid.NewPublishID()
	if err := f.OpenStage(testID, pid, "alice"); err != nil {
		t.Fatalf("OpenStage: %v", err)
	}
	return pid
}

// writeStaged sends data[rg] of rel's staged upload under session.
func writeStaged(t *testing.T, f *FS, pid, rel string, data []byte, rg Range, session string) RangeState {
	t.Helper()
	st, err := f.WriteRangeStaged(testID, pid, rel, bytes.NewReader(data[rg.Start:rg.End]), rg, int64(len(data)), session)
	if err != nil {
		t.Fatalf("WriteRangeStaged(%v): %v", rg, err)
	}
	return st
}

// stageWhole stages data for rel in pid with two chunks and finishes it.
func stageWhole(t *testing.T, f *FS, pid, rel string, data []byte) Staged {
	t.Helper()
	half := int64(len(data) / 2)
	writeStaged(t, f, pid, rel, data, Range{half, int64(len(data))}, "s")
	if st := writeStaged(t, f, pid, rel, data, Range{0, half}, "s"); !st.Complete {
		t.Fatalf("after both chunks: %+v", st)
	}
	s, err := f.FinishStaged(testID, pid, rel, "s", int64(len(data)))
	if err != nil {
		t.Fatalf("FinishStaged: %v", err)
	}
	return s
}

func TestAStagedRangedUploadLandsInItsStage(t *testing.T) {
	f := openTest(t)
	pid := openStage(t, f)
	if !f.StageExists(testID, pid) {
		t.Fatal("an opened stage does not exist")
	}
	data := []byte("<html>hello, staged world</html>")
	writeStaged(t, f, pid, "site/index.html", data, Range{0, 10}, "s")
	if st, ok := f.PartRangesStaged(testID, pid, "site/index.html", "s"); !ok || st.Received != 10 || st.Complete {
		t.Fatalf("PartRangesStaged = %+v, %v", st, ok)
	}
	if _, ok := f.PartRanges(testID, "site/index.html", "s"); ok {
		t.Fatal("a staged upload answers as a plain one")
	}
	writeStaged(t, f, pid, "site/index.html", data, Range{10, int64(len(data))}, "s")
	s, err := f.FinishStaged(testID, pid, "site/index.html", "s", int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if s.Path != "site/index.html" || s.Size != int64(len(data)) || s.SHA256 != sum(data) || !strings.HasPrefix(s.Mime, "text/html") {
		t.Fatalf("FinishStaged = %+v", s)
	}
	dir := shareDir(f, testID)
	part := filepath.Join(dir, stagedPartRel(pid, "site/index.html"))
	for _, p := range []string{part, part + partHashExt, part + partPathExt} {
		if !exists(p) {
			t.Errorf("%s missing from the stage", p)
		}
	}
	for _, d := range []string{partsDirName, filesDirName} {
		if exists(filepath.Join(dir, d)) {
			t.Errorf("a staged upload wrote %s/", d)
		}
	}
	files, err := f.StagedFiles(testID, pid)
	if err != nil || len(files) != 1 || files["site/index.html"] != s {
		t.Fatalf("StagedFiles = %v, %v; want %+v", files, err, s)
	}
	// Finishing again answers the same record.
	if again, err := f.FinishStaged(testID, pid, "site/index.html", "s", int64(len(data))); err != nil || again != s {
		t.Fatalf("FinishStaged again = %+v, %v", again, err)
	}
}

func TestFinishStagedRefusesAMissingRange(t *testing.T) {
	f := openTest(t)
	pid := openStage(t, f)
	data := payload(40)
	writeStaged(t, f, pid, "a.bin", data, Range{0, 10}, "s")
	writeStaged(t, f, pid, "a.bin", data, Range{20, 40}, "s")
	if _, err := f.FinishStaged(testID, pid, "a.bin", "s", 40); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("FinishStaged with a hole = %v, want ErrBadRequest", err)
	}
	if exists(filepath.Join(shareDir(f, testID), stagedPartRel(pid, "a.bin")+partPathExt)) {
		t.Fatal("an incomplete part was recorded")
	}
	if files, err := f.StagedFiles(testID, pid); err != nil || len(files) != 0 {
		t.Fatalf("StagedFiles = %v, %v; want none", files, err)
	}
	if _, err := f.FinishStaged(testID, pid, "a.bin", "other", 40); !errors.Is(err, ErrNotFound) {
		t.Fatalf("FinishStaged under another session = %v, want ErrNotFound", err)
	}
}

func TestAChunkAfterFinishWritesNothing(t *testing.T) {
	f := openTest(t)
	pid := openStage(t, f)
	data := payload(20)
	s := stageWhole(t, f, pid, "a.bin", data)
	other := bytes.Repeat([]byte{0xff}, 20)
	st, err := f.WriteRangeStaged(testID, pid, "a.bin", bytes.NewReader(other[:10]), Range{0, 10}, 20, "s")
	if err != nil || !st.Complete {
		t.Fatalf("a chunk after the finish = %+v, %v", st, err)
	}
	got, err := os.ReadFile(filepath.Join(shareDir(f, testID), stagedPartRel(pid, "a.bin")))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("the finished part changed: %v", err)
	}
	if files, _ := f.StagedFiles(testID, pid); files["a.bin"] != s {
		t.Fatalf("the record changed: %+v", files["a.bin"])
	}
}

func TestANewSessionRestagesAFinishedPath(t *testing.T) {
	f := openTest(t)
	pid := openStage(t, f)
	stageWhole(t, f, pid, "a.bin", payload(20))
	writeStaged(t, f, pid, "a.bin", payload(30), Range{0, 5}, "s2")
	if files, _ := f.StagedFiles(testID, pid); len(files) != 0 {
		t.Fatalf("a restaged path still lists its old record: %v", files)
	}
}

func TestTwoPublishesStagingOnePathStayApart(t *testing.T) {
	f := openTest(t)
	p1, p2 := openStage(t, f), openStage(t, f)
	one, two := []byte("first version of the page"), []byte("second, longer version of the page")
	// Interleaved, under one session name, so nothing but the stage tells them apart.
	writeStaged(t, f, p1, "index.html", one, Range{0, 5}, "s")
	writeStaged(t, f, p2, "index.html", two, Range{0, 5}, "s")
	writeStaged(t, f, p1, "index.html", one, Range{5, int64(len(one))}, "s")
	writeStaged(t, f, p2, "index.html", two, Range{5, int64(len(two))}, "s")
	s1, err := f.FinishStaged(testID, p1, "index.html", "s", int64(len(one)))
	if err != nil {
		t.Fatal(err)
	}
	s2, err := f.FinishStaged(testID, p2, "index.html", "s", int64(len(two)))
	if err != nil {
		t.Fatal(err)
	}
	if s1.SHA256 != sum(one) || s2.SHA256 != sum(two) {
		t.Fatalf("the publishes mixed: %+v %+v", s1, s2)
	}
	if err := f.RemoveStage(testID, p1); err != nil {
		t.Fatal(err)
	}
	if files, err := f.StagedFiles(testID, p2); err != nil || files["index.html"] != s2 {
		t.Fatalf("removing one publish touched the other: %v, %v", files, err)
	}
}

func TestWriteStagedRecordsTheFile(t *testing.T) {
	f := openTest(t)
	pid := openStage(t, f)
	s, err := f.WriteStaged(testID, pid, "notes/a.txt", strings.NewReader("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Path != "notes/a.txt" || s.Size != 5 || s.SHA256 != sha256Hex("hello") || s.Mime == "" {
		t.Fatalf("WriteStaged = %+v", s)
	}
	if exists(filepath.Join(shareDir(f, testID), partsDirName)) {
		t.Fatal("a staged write used parts/")
	}
	empty, err := f.WriteStaged(testID, pid, "empty", strings.NewReader(""))
	if err != nil || empty.Size != 0 || empty.SHA256 != sha256Hex("") {
		t.Fatalf("WriteStaged of nothing = %+v, %v", empty, err)
	}
	files, err := f.StagedFiles(testID, pid)
	if err != nil || len(files) != 2 || files["notes/a.txt"] != s || files["empty"] != empty {
		t.Fatalf("StagedFiles = %v, %v", files, err)
	}
}

func TestAStagedWriteNeedsAnOpenStage(t *testing.T) {
	f := openTest(t)
	pid := shareid.NewPublishID()
	if _, err := f.WriteRangeStaged(testID, pid, "a", strings.NewReader("ab"), Range{0, 2}, 2, "s"); !errors.Is(err, ErrNoStage) {
		t.Fatalf("WriteRangeStaged into no stage = %v, want ErrNoStage", err)
	}
	if _, err := f.WriteStaged(testID, pid, "a", strings.NewReader("ab")); !errors.Is(err, ErrNoStage) {
		t.Fatalf("WriteStaged into no stage = %v, want ErrNoStage", err)
	}
	for _, bad := range []string{"", "..", "abc/def", testID} {
		if _, err := f.WriteStaged(testID, bad, "a", strings.NewReader("ab")); !errors.Is(err, ErrNoStage) {
			t.Fatalf("WriteStaged into %q = %v, want ErrNoStage", bad, err)
		}
		if f.StageExists(testID, bad) {
			t.Fatalf("StageExists(%q)", bad)
		}
		if err := f.OpenStage(testID, bad, "alice"); !errors.Is(err, ErrBadPath) {
			t.Fatalf("OpenStage(%q) = %v, want ErrBadPath", bad, err)
		}
	}
	if exists(filepath.Join(shareDir(f, testID), stageDirName)) {
		t.Fatal("a refused staged write created stage/")
	}
}

func TestRemoveStageRemovesEverything(t *testing.T) {
	f := openTest(t)
	pid := openStage(t, f)
	stageWhole(t, f, pid, "a.bin", payload(20))
	writeStaged(t, f, pid, "b.bin", payload(20), Range{0, 4}, "s")
	if _, err := f.WriteStaged(testID, pid, "c.txt", strings.NewReader("c")); err != nil {
		t.Fatal(err)
	}
	if err := f.RemoveStage(testID, pid); err != nil {
		t.Fatal(err)
	}
	stageDir := filepath.Join(shareDir(f, testID), stageDirName)
	entries, err := os.ReadDir(stageDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("stage/ after RemoveStage: %v, %v", entries, err)
	}
	if f.StageExists(testID, pid) {
		t.Fatal("a removed stage exists")
	}
	if _, err := f.WriteRangeStaged(testID, pid, "b.bin", bytes.NewReader(payload(20)[4:8]), Range{4, 8}, 20, "s"); !errors.Is(err, ErrNoStage) {
		t.Fatalf("a chunk after RemoveStage = %v, want ErrNoStage", err)
	}
	if exists(filepath.Join(stageDir, pid)) {
		t.Fatal("a late chunk recreated a removed stage")
	}
	if err := f.RemoveStage(testID, pid); err != nil {
		t.Fatalf("RemoveStage of a removed stage = %v", err)
	}
}

func TestSwapInReplacesAddsAndRemoves(t *testing.T) {
	f := openTest(t)
	store(t, f, "a.txt", "old a")
	store(t, f, "gone/c.txt", "c")
	store(t, f, "keep.txt", "keep")
	pid := openStage(t, f)
	stageWhole(t, f, pid, "a.txt", []byte("new a, longer"))
	stageWhole(t, f, pid, "dir/b.txt", []byte("new b!"))
	renames := []Rename{{From: "a.txt", To: "a.txt"}, {From: "dir/b.txt", To: "dir/b.txt"}}
	swap := func() error {
		paths := []string{"a.txt", "dir/b.txt", "gone/c.txt"}
		return f.WithSwap(testID, paths, nil, func() error { return f.SwapIn(testID, pid, renames, []string{"gone/c.txt"}) })
	}
	if err := swap(); err != nil {
		t.Fatal(err)
	}
	if got := storedBytes(t, f, "a.txt"); string(got) != "new a, longer" {
		t.Fatalf("a.txt = %q", got)
	}
	if got := storedBytes(t, f, "dir/b.txt"); string(got) != "new b!" {
		t.Fatalf("dir/b.txt = %q", got)
	}
	if got := storedBytes(t, f, "keep.txt"); string(got) != "keep" {
		t.Fatalf("keep.txt = %q", got)
	}
	dir := shareDir(f, testID)
	if exists(filepath.Join(dir, fileRel("gone/c.txt"))) || exists(filepath.Join(dir, fileRel("gone"))) {
		t.Fatal("the removed file or its emptied folder is still there")
	}
	if exists(filepath.Join(dir, stagedPartRel(pid, "a.txt"))) {
		t.Fatal("the staged part is still in the stage")
	}
	// The boot pass replays a commit a crash interrupted: everything done is fine.
	if err := swap(); err != nil {
		t.Fatalf("SwapIn again = %v", err)
	}
	if got := storedBytes(t, f, "a.txt"); string(got) != "new a, longer" {
		t.Fatalf("a.txt after the replay = %q", got)
	}
}

func TestSwapInRenamesToTheSpelledPath(t *testing.T) {
	f := openTest(t)
	pid := openStage(t, f)
	stageWhole(t, f, pid, "Photo.JPG", []byte("pixels"))
	if err := f.SwapIn(testID, pid, []Rename{{From: "Photo.JPG", To: "photo.jpg"}}, nil); err != nil {
		t.Fatal(err)
	}
	if got := storedBytes(t, f, "photo.jpg"); string(got) != "pixels" {
		t.Fatalf("photo.jpg = %q", got)
	}
}

func TestSwapInTurnsAFileIntoAFolder(t *testing.T) {
	f := openTest(t)
	store(t, f, "a", "a file")
	pid := openStage(t, f)
	stageWhole(t, f, pid, "a/b", []byte("inside"))
	if err := f.SwapIn(testID, pid, []Rename{{From: "a/b", To: "a/b"}}, []string{"a"}); err != nil {
		t.Fatal(err)
	}
	if got := storedBytes(t, f, "a/b"); string(got) != "inside" {
		t.Fatalf("a/b = %q", got)
	}
}

func TestSwapInRefusesBadNames(t *testing.T) {
	f := openTest(t)
	pid := openStage(t, f)
	if err := f.SwapIn(testID, pid, []Rename{{From: "a", To: "../x"}}, nil); !errors.Is(err, ErrBadPath) {
		t.Fatalf("SwapIn to ../x = %v", err)
	}
	if err := f.SwapIn(testID, pid, nil, []string{"."}); !errors.Is(err, ErrBadPath) {
		t.Fatalf("SwapIn removing . = %v", err)
	}
	if err := f.SwapIn(testID, "../../x", nil, nil); !errors.Is(err, ErrNoStage) {
		t.Fatalf("SwapIn of a bad publish id = %v", err)
	}
}

func TestTheBootPassRemovesAStageWithoutOwner(t *testing.T) {
	f := openTest(t)
	kept := openStage(t, f)
	stageWhole(t, f, kept, "a.bin", payload(10))
	stageDir := filepath.Join(shareDir(f, testID), stageDirName)
	ownerless := shareid.NewPublishID()
	if err := os.MkdirAll(filepath.Join(stageDir, ownerless), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stageDir, ownerless, "x.part"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// What RemoveStage leaves when a crash stops it midway, and a stray file.
	doomed := filepath.Join(stageDir, "."+shareid.NewPublishID())
	if err := os.MkdirAll(doomed, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(doomed, stageOwnerName), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stageDir, "stray"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Orphans(func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(stageDir)
	if len(entries) != 1 || entries[0].Name() != kept {
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("stage/ after the boot pass: %v, want only %s", names, kept)
	}
	if files, err := f.StagedFiles(testID, kept); err != nil || len(files) != 1 {
		t.Fatalf("the open publish lost its files: %v, %v", files, err)
	}
}

func TestTheSwapLockIsSeparateFromTheShareLock(t *testing.T) {
	f := openTest(t)
	// RemoveShare's exclusive hold does not stop a reader's swap.
	release := f.lockShare(testID)
	done := make(chan error, 1)
	go func() { done <- f.ReadSwapped(testID, func() error { return nil }) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadSwapped waited for the share lock")
	}
	release()
}

func TestWithSwapExcludesReaders(t *testing.T) {
	f := openTest(t)
	var inside atomic.Bool
	entered, leave := make(chan struct{}), make(chan struct{})
	go f.WithSwap(testID, nil, nil, func() error {
		inside.Store(true)
		close(entered)
		<-leave
		inside.Store(false)
		return nil
	})
	<-entered
	read := make(chan bool, 1)
	go f.ReadSwapped(testID, func() error { read <- inside.Load(); return nil })
	select {
	case <-read:
		t.Fatal("a reader ran inside a swap")
	case <-time.After(50 * time.Millisecond):
	}
	close(leave)
	if during := <-read; during {
		t.Fatal("a reader saw the swap in progress")
	}
	// Readers share the lock: one holding it does not stop another.
	holding, free := make(chan struct{}), make(chan struct{})
	go f.ReadSwapped(testID, func() error { close(holding); <-free; return nil })
	<-holding
	second := make(chan error, 1)
	go func() { second <- f.ReadSwapped(testID, func() error { return nil }) }()
	select {
	case err := <-second:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a reader waited for another reader")
	}
	close(free)
	want := errors.New("refused")
	if err := f.WithSwap(testID, nil, nil, func() error { return want }); err != want {
		t.Fatalf("WithSwap = %v, want fn's error", err)
	}
	if f.swapLocks.len() != 0 {
		t.Fatal("a swap lock leaked")
	}
}

// waitsUntil reports whether done stays open for a moment and then closes
// once release has run.
func waitsUntil(t *testing.T, done <-chan struct{}, release func()) {
	t.Helper()
	select {
	case <-done:
		t.Fatal("did not wait")
	case <-time.After(50 * time.Millisecond):
	}
	release()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("still waiting after the release")
	}
}

func TestWithSwapHoldsThePathLocks(t *testing.T) {
	f := openTest(t)
	stage(t, f, testID, "b.txt", "plain")
	entered, leave, committed := make(chan struct{}), make(chan struct{}), make(chan struct{})
	swapped := make(chan error, 1)
	go func() {
		swapped <- f.WithSwap(testID, []string{"c.txt", "b.txt", "a.txt"}, nil, func() error {
			close(entered)
			<-leave
			return nil
		})
	}()
	<-entered
	go func() {
		if _, err := f.Commit(testID, "b.txt", 5, nil); err != nil {
			t.Error(err)
		}
		close(committed)
	}()
	waitsUntil(t, committed, func() { close(leave) })
	if err := <-swapped; err != nil {
		t.Fatal(err)
	}
	if f.pathLocks.len() != 0 || f.shareLocks.len() != 0 || f.swapLocks.len() != 0 {
		t.Fatal("a lock leaked")
	}
}

func TestWithSwapFoldsSpellingsIntoOneLock(t *testing.T) {
	f := openTest(t)
	f.SetFoldsCase(true)
	entered, leave := make(chan struct{}), make(chan struct{})
	swapped := make(chan error, 1)
	go func() {
		swapped <- f.WithSwap(testID, []string{"Photo.jpg", "photo.JPG", "photo.jpg"}, nil, func() error {
			close(entered)
			<-leave
			return nil
		})
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("two spellings of one path deadlocked WithSwap")
	}
	locked := make(chan struct{})
	go func() { f.lockPath(testID, "PHOTO.JPG")(); close(locked) }()
	waitsUntil(t, locked, func() { close(leave) })
	if err := <-swapped; err != nil {
		t.Fatal(err)
	}
}

func TestWithSwapRefusesABadPath(t *testing.T) {
	f := openTest(t)
	ran := false
	if err := f.WithSwap(testID, []string{"a", "../b"}, func() error { ran = true; return nil }, func() error { ran = true; return nil }); !errors.Is(err, ErrBadPath) || ran {
		t.Fatalf("WithSwap with ../b = %v, ran %v", err, ran)
	}
}

func TestRetireStageLockedRunsWithARemoveShareWaiting(t *testing.T) {
	f := openTest(t)
	pid := openStage(t, f)
	stageWhole(t, f, pid, "a.bin", payload(10))
	removed := make(chan error, 1)
	err := f.WithSwap(testID, []string{"a.bin"}, nil, func() error {
		go func() { removed <- f.RemoveShare(testID) }()
		time.Sleep(50 * time.Millisecond) // RemoveShare is queued for the share lock
		done := make(chan error, 1)
		go func() { done <- f.RetireStageLocked(testID, pid) }()
		select {
		case err := <-done:
			return err
		case <-time.After(5 * time.Second):
			t.Fatal("RetireStageLocked deadlocked behind the waiting RemoveShare")
			return nil
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-removed; err != nil {
		t.Fatal(err)
	}
	if exists(shareDir(f, testID)) {
		t.Fatal("RemoveShare did not run after the swap")
	}
}

// WithSwap's prepare step runs under the path locks and the share lock but
// not the swap lock: a reader goes ahead while it runs, an upload of a
// named path waits, and the swap step then excludes readers.
func TestWithSwapPreparesBeforeTheSwapLock(t *testing.T) {
	f := openTest(t)
	stage(t, f, testID, "a.txt", "plain")
	entered, leave := make(chan struct{}), make(chan struct{})
	swapped := make(chan error, 1)
	go func() {
		swapped <- f.WithSwap(testID, []string{"a.txt"}, func() error {
			close(entered)
			<-leave
			return nil
		}, func() error { return nil })
	}()
	<-entered
	read := make(chan struct{})
	go func() { f.ReadSwapped(testID, func() error { return nil }); close(read) }()
	select {
	case <-read:
	case <-time.After(2 * time.Second):
		close(leave)
		t.Fatal("a reader waited for the prepare step")
	}
	committed := make(chan struct{})
	go func() {
		if _, err := f.Commit(testID, "a.txt", 5, nil); err != nil {
			t.Error(err)
		}
		close(committed)
	}()
	waitsUntil(t, committed, func() { close(leave) })
	if err := <-swapped; err != nil {
		t.Fatal(err)
	}
	want := errors.New("refused")
	ran := false
	if err := f.WithSwap(testID, nil, func() error { return want }, func() error { ran = true; return nil }); err != want || ran {
		t.Fatalf("WithSwap after a failed prepare = %v, swap ran %v", err, ran)
	}
	if f.pathLocks.len() != 0 || f.shareLocks.len() != 0 || f.swapLocks.len() != 0 {
		t.Fatal("a lock leaked")
	}
}

// Retiring a stage moves it, journal and parts, out of every publish's
// reach in one rename; PurgeStage then removes it, and a retired stage a
// crash left goes at the next boot.
func TestARetiredStageIsPurgedApart(t *testing.T) {
	f := openTest(t)
	pid := openStage(t, f)
	stageWhole(t, f, pid, "a.bin", payload(10))
	if err := f.WriteJournal(testID, pid, Journal{Files: []string{"a.bin"}}); err != nil {
		t.Fatal(err)
	}
	if err := f.RetireStageLocked(testID, pid); err != nil {
		t.Fatal(err)
	}
	retired := filepath.Join(shareDir(f, testID), retiredStageRel(pid))
	if f.StageExists(testID, pid) || f.OpenPublishes("alice") != 0 || !exists(retired) {
		t.Fatalf("after retiring: open %v, retired directory %v", f.StageExists(testID, pid), exists(retired))
	}
	if _, held, _ := f.ReadJournal(testID, pid); held {
		t.Fatal("a retired stage's journal is still read")
	}
	if err := f.PurgeStage(testID, pid); err != nil {
		t.Fatal(err)
	}
	if exists(retired) {
		t.Fatal("PurgeStage left the retired stage")
	}

	again := openStage(t, f)
	stageWhole(t, f, again, "b.bin", payload(10))
	if err := f.RetireStageLocked(testID, again); err != nil {
		t.Fatal(err)
	}
	g, err := Open(f.DataDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Orphans(func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if exists(filepath.Join(shareDir(f, testID), retiredStageRel(again))) {
		t.Fatal("the boot pass left a retired stage")
	}
}
