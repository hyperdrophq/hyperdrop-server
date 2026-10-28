package sharefs

import (
	"os"
	"path/filepath"
	"testing"
)

// Open asks the volume once whether it folds case, and answers what a file
// made under one case and looked for under another says.
func TestOpenProbesWhetherTheVolumeFoldsCase(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "probe"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := os.Stat(filepath.Join(dir, "PROBE"))
	want := err == nil
	os.Remove(filepath.Join(dir, "probe"))
	f, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if f.FoldsCase() != want {
		t.Fatalf("FoldsCase = %v, want %v", f.FoldsCase(), want)
	}
	ents, err := os.ReadDir(filepath.Join(dir, sharesDirName))
	if err != nil || len(ents) != 0 {
		t.Fatalf("the probe left %v (%v)", ents, err)
	}
}

// SameName answers what the volume itself does with a pair, on whatever
// volume the test runs: APFS merges straße and strasse and keeps İ apart
// from i, a case-sensitive volume merges nothing.
func TestSameNameAnswersWhatTheVolumeDoes(t *testing.T) {
	f := openTest(t)
	dir := t.TempDir()
	for _, p := range [][2]string{
		{"Report.pdf", "report.pdf"}, {"straße", "strasse"}, {"İ", "i̇"}, {"İ", "i"},
		{"ı", "i"}, {"ı", "I"}, {"ǅ", "ǆ"}, {"K", "k"}, {"ﬁ", "fi"}, {"a", "b"},
	} {
		if err := os.WriteFile(filepath.Join(dir, p[0]), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := os.Stat(filepath.Join(dir, p[1]))
		os.Remove(filepath.Join(dir, p[0]))
		if got, want := f.SameName(p[0], p[1]), err == nil; got != want {
			t.Errorf("SameName(%q, %q) = %v, the volume says %v", p[0], p[1], got, want)
		}
	}
	ents, _ := os.ReadDir(filepath.Join(f.DataDir(), sharesDirName))
	if len(ents) != 0 {
		t.Errorf("the probes left %v", ents)
	}
	f.SetFoldsCase(true)
	if !f.SameName("straße", "STRASSE") || f.SameName("a", "b") {
		t.Error("a simulated volume compares by key")
	}
}

// SamePath asks about the stored files themselves when the held entry has
// bytes: the incoming spelling names that file, a different one, or none.
func TestSamePathAsksAboutTheStoredFile(t *testing.T) {
	f := openTest(t)
	stage(t, f, testID, "Docs/Report.pdf", "r")
	if _, err := f.Commit(testID, "Docs/Report.pdf", -1, nil); err != nil {
		t.Fatal(err)
	}
	folds := f.FoldsCase()
	for _, c := range []struct {
		held, incoming string
		want           bool
	}{
		{"Docs/Report.pdf", "Docs/report.PDF", folds},
		{"Docs", "docs", folds},
		{"Docs/Report.pdf", "Docs/other.pdf", false},
	} {
		if got := f.SamePath(testID, c.held, c.incoming); got != c.want {
			t.Errorf("SamePath(%q, %q) = %v, want %v", c.held, c.incoming, got, c.want)
		}
	}
	// A held entry with no bytes yet is asked with a scratch pair.
	if got := f.SamePath(testID, "Docs/pending.pdf", "Docs/PENDING.pdf"); got != f.SameName("pending.pdf", "PENDING.pdf") {
		t.Errorf("a pending entry: SamePath = %v", got)
	}
}

// A probe a crash interrupted is removed at the next Open.
func TestOpenRemovesWhatAnInterruptedProbeLeft(t *testing.T) {
	dir := t.TempDir()
	shares := filepath.Join(dir, sharesDirName)
	if err := os.MkdirAll(filepath.Join(shares, probePrefix+"123", "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shares, probePrefix+"probe-9"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(shares, testID), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(shares)
	if len(ents) != 1 || ents[0].Name() != testID {
		t.Fatalf("shares/ holds %v", ents)
	}
}

// On a volume that folds case two relpaths differing only in case are one
// file, so they take one path lock; on one that does not, two.
func TestPathLocksFoldWhenTheVolumeDoes(t *testing.T) {
	f := openTest(t)
	for _, folds := range []bool{true, false} {
		f.SetFoldsCase(folds)
		a, doneA := f.pathLockFor(testID, "Docs/Report.pdf")
		b, doneB := f.pathLockFor(testID, "docs/report.pdf")
		if (a == b) != folds {
			t.Errorf("folds=%v: one lock = %v", folds, a == b)
		}
		doneA()
		doneB()
	}
}
