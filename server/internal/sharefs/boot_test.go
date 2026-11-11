package sharefs

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func backdate(t *testing.T, p string, age time.Duration) {
	t.Helper()
	old := time.Now().Add(-age)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
}

func TestOrphansRemovesOldRowlessDirectoriesAndKeepsTheRest(t *testing.T) {
	f := openTest(t)
	const kept, youngOrphan, oldOrphan = "abcdefghjk", "abcdefghjm", "abcdefghjn"
	for _, id := range []string{kept, youngOrphan, oldOrphan} {
		stage(t, f, id, "a", "x")
	}
	backdate(t, shareDir(f, oldOrphan), 2*DefaultAbandonedUpload)
	stray := filepath.Join(f.DataDir(), sharesDirName, "not-a-share-id")
	if err := os.MkdirAll(stray, 0o755); err != nil {
		t.Fatal(err)
	}
	backdate(t, stray, 48*time.Hour)
	var asked []string
	hasRow := func(id string) bool { asked = append(asked, id); return id == kept }
	removed, err := f.Orphans(hasRow)
	if err != nil || removed != 1 {
		t.Fatalf("Orphans: %d, %v", removed, err)
	}
	if exists(shareDir(f, oldOrphan)) {
		t.Fatal("old orphan kept")
	}
	if !exists(shareDir(f, youngOrphan)) {
		t.Fatal("a young orphan may still be a delete in progress; it waits for the window")
	}
	if !exists(shareDir(f, kept)) || !exists(stray) {
		t.Fatal("a share with a row, and a stray name, must be left alone")
	}
	if len(asked) != 3 || strings.Contains(strings.Join(asked, ","), "not-a-share-id") {
		t.Fatalf("hasRow asked for %v", asked)
	}
}

func TestOrphansCleansStalePartsAndOrphanedSidecars(t *testing.T) {
	f := openTest(t)
	const id = "abcdefghjk"
	if _, err := f.WriteRange(id, "stale", strings.NewReader("ab"), Range{0, 2}, 4, "s", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteRange(id, "fresh", strings.NewReader("ab"), Range{0, 2}, 4, "s", nil); err != nil {
		t.Fatal(err)
	}
	dir := shareDir(f, id)
	backdate(t, filepath.Join(dir, partRel("stale")), 2*DefaultAbandonedUpload)
	orphanHash := filepath.Join(dir, partRel("gone")+partHashExt)
	orphanSession := filepath.Join(dir, partRel("gone")+partSessionExt)
	for _, p := range []string{orphanHash, orphanSession} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.Orphans(func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.PartRanges(id, "stale", "s"); ok || exists(filepath.Join(dir, partRel("stale")+partSessionExt)) {
		t.Fatal("a stale part and its sidecars must go")
	}
	if st, ok := f.PartRanges(id, "fresh", "s"); !ok || st.Received != 2 {
		t.Fatal("a fresh part is resume state and survives")
	}
	if exists(orphanHash) || exists(orphanSession) {
		t.Fatal("sidecars with no part must go")
	}
}

func TestOrphansReportsAnUnreadableSharesTree(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	f := openTest(t)
	shares := filepath.Join(f.DataDir(), sharesDirName)
	if err := os.Chmod(shares, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(shares, 0o755) })
	if _, err := f.Orphans(func(string) bool { return true }); err == nil {
		t.Fatal("a sealed shares/ must surface as an error, not as zero orphans")
	}
}

// A share some writer holds (a commit hashing a large part) is skipped by
// the sweep rather than waited for: a sweep queued for the exclusive lock
// would block every new upload into the share until that writer finished.
// The share stays noted, and the next pass cleans it.
func TestSweepStalePartsSkipsABusyShare(t *testing.T) {
	f := openTest(t)
	f.AbandonedWindow = time.Nanosecond
	if _, err := f.Write(testID, "stale.bin", strings.NewReader("x")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)
	release := f.rlockShare(testID)
	swept := make(chan int)
	go func() { swept <- f.SweepStaleParts() }()
	select {
	case n := <-swept:
		if n != 0 {
			t.Fatalf("swept %d parts of a share a writer holds", n)
		}
	case <-time.After(2 * time.Second):
		release()
		<-swept
		t.Fatal("the sweep waited for the share's writer")
	}
	wrote := make(chan error, 1)
	go func() { _, err := f.Write(testID, "other.bin", strings.NewReader("y")); wrote <- err }()
	select {
	case err := <-wrote:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		release()
		t.Fatal("an upload into the share blocked behind the sweep")
	}
	release()
	time.Sleep(time.Millisecond)
	if n := f.SweepStaleParts(); n != 2 {
		t.Fatalf("next pass swept %d parts, want both", n)
	}
}

// backdateStage makes every file of publish pid, and its directory, age
// old: a publish nothing has written to since.
func backdateStage(t *testing.T, f *FS, pid string, age time.Duration) {
	t.Helper()
	dir := filepath.Join(shareDir(f, testID), stageDirName, pid)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		backdate(t, filepath.Join(dir, e.Name()), age)
	}
	backdate(t, dir, age)
}

// A publish nothing has written to for the abandoned-upload window goes
// with everything staged in it and leaves the owner's count; a younger one
// stays. The window is the operator's (HYPERDROP_ABANDONED_UPLOAD_TTL,
// FS.AbandonedWindow) when set.
func TestTheSweepRemovesAQuietPublish(t *testing.T) {
	f := openTest(t)
	quiet, young, written := openStage(t, f), openStage(t, f), openStage(t, f)
	stageWhole(t, f, quiet, "a.bin", payload(20))
	stageWhole(t, f, written, "b.bin", payload(20))
	backdateStage(t, f, quiet, 2*DefaultAbandonedUpload)
	backdateStage(t, f, young, time.Hour)
	// One fresh write is enough to keep a publish whose other files are old.
	backdateStage(t, f, written, 2*DefaultAbandonedUpload)
	writeStaged(t, f, written, "c.bin", payload(20), Range{0, 4}, "s")
	if n := f.SweepStages(); n != 1 {
		t.Fatalf("SweepStages = %d, want 1", n)
	}
	if f.StageExists(testID, quiet) || exists(filepath.Join(shareDir(f, testID), stageDirName, quiet)) {
		t.Fatal("the quiet publish survived the sweep")
	}
	if !f.StageExists(testID, young) || !f.StageExists(testID, written) {
		t.Fatal("the sweep removed a publish written within the window")
	}
	if n := f.OpenPublishes("alice"); n != 2 {
		t.Fatalf("open publishes after the sweep = %d, want 2", n)
	}
	f.AbandonedWindow = 30 * time.Minute
	if n := f.SweepStages(); n != 1 || f.StageExists(testID, young) {
		t.Fatalf("under a 30-minute window SweepStages = %d, and the hour-old publish exists: %v", n, f.StageExists(testID, young))
	}
	if n := f.OpenPublishes("alice"); n != 1 {
		t.Fatalf("open publishes = %d, want 1", n)
	}
}

// A share some writer holds is skipped rather than waited for, as
// SweepStaleParts skips it, and the next pass removes its quiet publish.
func TestTheSweepSkipsAPublishBeingWritten(t *testing.T) {
	f := openTest(t)
	pid := openStage(t, f)
	stageWhole(t, f, pid, "a.bin", payload(20))
	backdateStage(t, f, pid, 2*DefaultAbandonedUpload)
	release := f.rlockShare(testID)
	swept := make(chan int)
	go func() { swept <- f.SweepStages() }()
	select {
	case n := <-swept:
		if n != 0 {
			t.Fatalf("swept %d publishes of a share a writer holds", n)
		}
	case <-time.After(2 * time.Second):
		release()
		<-swept
		t.Fatal("the sweep waited for the share's writer")
	}
	release()
	if n := f.SweepStages(); n != 1 || f.StageExists(testID, pid) {
		t.Fatalf("next pass swept %d", n)
	}
}

// A publish holding a commit journal is never swept, however old: its
// rows may already name its staged bytes, which the boot pass moves.
func TestTheSweepSkipsAStageHoldingAJournal(t *testing.T) {
	f := openTest(t)
	pid := openStage(t, f)
	stageWhole(t, f, pid, "a.bin", payload(20))
	if err := f.WriteJournal(testID, pid, Journal{Files: []string{"a.bin"}}); err != nil {
		t.Fatal(err)
	}
	backdateStage(t, f, pid, 2*DefaultAbandonedUpload)
	if n := f.SweepStages(); n != 0 || !f.StageExists(testID, pid) {
		t.Fatalf("SweepStages = %d with a journal present", n)
	}
	if n := f.OpenPublishes("alice"); n != 1 {
		t.Fatalf("open publishes = %d, want 1", n)
	}
}

// An open publish written within the window is recent staging, which keeps
// an otherwise empty share from the empty sweep; a quiet one is not.
func TestAnOpenPublishIsRecentStaging(t *testing.T) {
	f := openTest(t)
	window := DefaultAbandonedUpload
	pid := openStage(t, f)
	if !f.HasRecentPart(testID, window) {
		t.Fatal("a publish opened just now is not recent staging")
	}
	stageWhole(t, f, pid, "a.bin", payload(20))
	backdateStage(t, f, pid, 2*window)
	if f.HasRecentPart(testID, window) {
		t.Fatal("a quiet publish counts as recent staging")
	}
}

// A publish is swept a day after it was opened however recently it was
// written, unless it holds a commit journal; the day is counted from the
// time its owner file records, so it survives a restart.
func TestTheSweepRemovesAPublishPastItsLifetime(t *testing.T) {
	f := openTest(t)
	old, journaled, fresh := openStage(t, f), openStage(t, f), openStage(t, f)
	for _, pid := range []string{old, journaled} {
		data, err := json.Marshal(stageOwner{Owner: "alice", Created: time.Now().Add(-DefaultStageLifetime - time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(shareDir(f, testID), stageDirName, pid, stageOwnerName), data, 0o600); err != nil {
			t.Fatal(err)
		}
		stageWhole(t, f, pid, "a.bin", payload(20))
	}
	stageWhole(t, f, fresh, "a.bin", payload(20))
	if err := f.WriteJournal(testID, journaled, Journal{Files: []string{"a.bin"}}); err != nil {
		t.Fatal(err)
	}
	g, err := Open(f.DataDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Orphans(func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if n := g.SweepStages(); n != 1 {
		t.Fatalf("SweepStages = %d, want 1", n)
	}
	if g.StageExists(testID, old) || !g.StageExists(testID, journaled) || !g.StageExists(testID, fresh) {
		t.Fatalf("after the sweep: old %v, journaled %v, fresh %v", g.StageExists(testID, old), g.StageExists(testID, journaled), g.StageExists(testID, fresh))
	}
	g.StageLifetime = time.Nanosecond
	if n := g.SweepStages(); n != 1 || g.StageExists(testID, fresh) {
		t.Fatalf("under a nanosecond lifetime SweepStages = %d, fresh exists %v", n, g.StageExists(testID, fresh))
	}
}

// The bytes an owner's open publishes hold are counted from what each
// upload declared, a finished part's size or a ranged part's total, and
// counted again at boot from the stages themselves; a removed stage, a
// discarded part and a removed share give them back.
func TestStagedBytesAreCountedPerOwner(t *testing.T) {
	f := openTest(t)
	a, b := openStage(t, f), openStage(t, f)
	stageWhole(t, f, a, "whole.bin", payload(20))
	writeStaged(t, f, a, "part.bin", payload(100), Range{0, 10}, "s")
	if _, err := f.WriteStaged(testID, b, "w.txt", strings.NewReader("seven b")); err != nil {
		t.Fatal(err)
	}
	if n := f.StagedBytes("alice"); n != 127 {
		t.Fatalf("StagedBytes = %d, want 127", n)
	}
	if n := f.StagedDeclared(testID, a, "part.bin"); n != 100 {
		t.Fatalf("StagedDeclared(part.bin) = %d, want 100", n)
	}
	g, err := Open(f.DataDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Orphans(func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if n := g.StagedBytes("alice"); n != 127 {
		t.Fatalf("StagedBytes after a restart = %d, want 127", n)
	}
	g.DiscardStaged(testID, a, "part.bin")
	if n := g.StagedBytes("alice"); n != 27 {
		t.Fatalf("StagedBytes after a discard = %d, want 27", n)
	}
	if err := g.RemoveStage(testID, b); err != nil {
		t.Fatal(err)
	}
	if n := g.StagedBytes("alice"); n != 20 {
		t.Fatalf("StagedBytes after a removal = %d, want 20", n)
	}
	if err := g.RemoveShare(testID); err != nil {
		t.Fatal(err)
	}
	if n := g.StagedBytes("alice"); n != 0 {
		t.Fatalf("StagedBytes after the share went = %d, want 0", n)
	}
}

// A publish takes at most StageMaxFiles distinct paths: the next new one
// is refused before any byte, a path already staged is taken again.
func TestAStageRefusesAPathPastItsCap(t *testing.T) {
	f := openTest(t)
	f.StageMaxFiles = 2
	pid := openStage(t, f)
	stageWhole(t, f, pid, "a.bin", payload(4))
	if _, err := f.WriteStaged(testID, pid, "b.txt", strings.NewReader("b")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteRangeStaged(testID, pid, "c.bin", strings.NewReader("cc"), Range{0, 2}, 2, "s"); !errors.Is(err, ErrStageFull) {
		t.Fatalf("a third ranged path = %v, want ErrStageFull", err)
	}
	if _, err := f.WriteStaged(testID, pid, "d.txt", strings.NewReader("d")); !errors.Is(err, ErrStageFull) {
		t.Fatalf("a third whole path = %v, want ErrStageFull", err)
	}
	if exists(filepath.Join(shareDir(f, testID), stagedPartRel(pid, "c.bin"))) {
		t.Fatal("a refused path left a part")
	}
	if _, err := f.WriteStaged(testID, pid, "b.txt", strings.NewReader("b again")); err != nil {
		t.Fatalf("a path already staged: %v", err)
	}
}
