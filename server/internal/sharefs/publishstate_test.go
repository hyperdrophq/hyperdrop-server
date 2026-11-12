package sharefs

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"hyperdrop/server/internal/shareid"
)

// The commit journal names what a commit makes live and removes, durably,
// and is not mistaken for a staged upload.
func TestTheCommitJournalRoundTrips(t *testing.T) {
	f := openTest(t)
	pid := openStage(t, f)
	stageWhole(t, f, pid, "a.txt", payload(10))
	if _, ok, err := f.ReadJournal(testID, pid); ok || err != nil {
		t.Fatalf("a fresh publish has a journal: %v %v", ok, err)
	}
	want := Journal{Files: []string{"a.txt", "dir/b.txt"}, Delete: []string{"old.txt"}}
	if err := f.WriteJournal(testID, pid, want); err != nil {
		t.Fatal(err)
	}
	got, ok, err := f.ReadJournal(testID, pid)
	if err != nil || !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("ReadJournal = %+v %v %v, want %+v", got, ok, err, want)
	}
	if files, err := f.StagedFiles(testID, pid); err != nil || len(files) != 1 {
		t.Fatalf("StagedFiles beside a journal = %v %v", files, err)
	}
	if err := f.RemoveJournal(testID, pid); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := f.ReadJournal(testID, pid); ok {
		t.Fatal("the journal outlived RemoveJournal")
	}
	if err := f.RemoveJournal(testID, pid); err != nil {
		t.Fatalf("removing an absent journal: %v", err)
	}
	if err := f.WriteJournal(testID, shareid.NewPublishID(), want); !errors.Is(err, ErrNoStage) {
		t.Fatalf("a journal for a publish that is not open: %v", err)
	}
}

// A journal that does not decode is reported, never read as empty: the boot
// pass must not take it for a commit that names nothing.
func TestABrokenJournalIsAnError(t *testing.T) {
	f := openTest(t)
	pid := openStage(t, f)
	p := filepath.Join(shareDir(f, testID), stageDirName, pid, journalName)
	if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := f.ReadJournal(testID, pid); err == nil || ok {
		t.Fatalf("ReadJournal of a broken journal = %v %v", ok, err)
	}
}

// The open publishes are counted per owner across every share: opened,
// removed with RemoveStage, RetireStageLocked or the share, and found again
// by the boot pass.
func TestOpenPublishesAreCountedPerOwner(t *testing.T) {
	dir := t.TempDir()
	f, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	const other = "mnpqrstuvw"
	a1, a2, b1 := shareid.NewPublishID(), shareid.NewPublishID(), shareid.NewPublishID()
	for _, s := range []struct{ id, pid, owner string }{{testID, a1, "alice"}, {other, a2, "alice"}, {testID, b1, "bob"}} {
		if err := f.OpenStage(s.id, s.pid, s.owner); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.OpenPublishes("alice"); n != 2 {
		t.Fatalf("alice has %d open publishes, want 2", n)
	}
	if owner, err := f.StageOwner(other, a2); err != nil || owner != "alice" {
		t.Fatalf("StageOwner = %q %v", owner, err)
	}
	if _, err := f.StageOwner(other, b1); !errors.Is(err, ErrNoStage) {
		t.Fatalf("StageOwner of a publish on another share: %v", err)
	}

	// The boot pass of a fresh process finds the same three.
	g, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Orphans(func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if n, m := g.OpenPublishes("alice"), g.OpenPublishes("bob"); n != 2 || m != 1 {
		t.Fatalf("after the boot pass: alice %d, bob %d, want 2 and 1", n, m)
	}

	if err := f.RemoveStage(other, a2); err != nil {
		t.Fatal(err)
	}
	if n := f.OpenPublishes("alice"); n != 1 {
		t.Fatalf("after RemoveStage alice has %d, want 1", n)
	}
	if err := f.WithSwap(testID, nil, nil, func() error { return f.RetireStageLocked(testID, a1) }); err != nil {
		t.Fatal(err)
	}
	if n := f.OpenPublishes("alice"); n != 0 {
		t.Fatalf("after RetireStageLocked alice has %d, want 0", n)
	}
	if err := f.RemoveShare(testID); err != nil {
		t.Fatal(err)
	}
	if n := f.OpenPublishes("bob"); n != 0 {
		t.Fatalf("after RemoveShare bob has %d, want 0", n)
	}
}

// StagedFile answers one finished staged upload, and nothing for a part
// still uploading.
func TestStagedFileAnswersOneFinishedUpload(t *testing.T) {
	f := openTest(t)
	pid := openStage(t, f)
	data := payload(64)
	writeStaged(t, f, pid, "half.bin", data, Range{0, 10}, "s")
	if _, ok := f.StagedFile(testID, pid, "half.bin"); ok {
		t.Fatal("a part still uploading answered as finished")
	}
	want := stageWhole(t, f, pid, "whole.bin", data)
	got, ok := f.StagedFile(testID, pid, "whole.bin")
	if !ok || got != want {
		t.Fatalf("StagedFile = %+v %v, want %+v", got, ok, want)
	}
}

// DiscardStaged removes one staged upload and its record, and leaves the
// publish open.
func TestDiscardStagedRemovesOneUpload(t *testing.T) {
	f := openTest(t)
	pid := openStage(t, f)
	stageWhole(t, f, pid, "a.bin", payload(20))
	stageWhole(t, f, pid, "b.bin", payload(20))
	f.DiscardStaged(testID, pid, "a.bin")
	files, err := f.StagedFiles(testID, pid)
	if err != nil || len(files) != 1 || files["b.bin"].Path != "b.bin" {
		t.Fatalf("after DiscardStaged: %v %v", files, err)
	}
	entries, _ := os.ReadDir(filepath.Join(shareDir(f, testID), stageDirName, pid))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), partName("a.bin")) {
			t.Fatalf("%s survived DiscardStaged", e.Name())
		}
	}
}
