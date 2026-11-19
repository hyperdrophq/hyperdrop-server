package linked

import (
	"os"
	"path/filepath"
	"testing"
)

// unreadableParent makes a directory holding team/report.txt whose own mode
// lets the test's account search and write it but not read it, the way a
// 0711 parent owned by another account looks to the service account.
// Root ignores the read bit, so the case is real only for another account.
func unreadableParent(t *testing.T) (parent, team string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root reads every directory whatever its mode")
	}
	parent = filepath.Join(t.TempDir(), "private")
	team = filepath.Join(parent, "team")
	if err := os.MkdirAll(team, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(team, "report.txt"), []byte("report"), 0o644)
	if err := os.Chmod(parent, 0o311); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(parent, 0o755) })
	if _, err := os.ReadDir(parent); err == nil {
		t.Skip("the parent is still readable to this account")
	}
	return parent, team
}

// A root under a parent the service account can search but not read opens
// and serves: the ".." walk needs search permission only.
func TestARootUnderAnUnreadableParentOpensAndServes(t *testing.T) {
	_, team := unreadableParent(t)
	data := filepath.Join(t.TempDir(), "HyperDrop")
	os.Mkdir(data, 0o755)
	r, err := NewRoots([]string{team}, nil, []string{data})
	if err != nil {
		t.Fatal(err)
	}
	or, sub, err := r.Open("team")
	if err != nil || sub != "." {
		t.Fatalf("Open = %q %v", sub, err)
	}
	defer or.Close()
	ents, _, err := Walk(or, MaxWalk)
	if err != nil || len(ents) != 1 || ents[0].Rel != "report.txt" {
		t.Fatalf("Walk = %+v %v, want [report.txt]", ents, err)
	}
	b, err := or.ReadFile("report.txt")
	if err != nil || string(b) != "report" {
		t.Fatalf("ReadFile = %q %v", b, err)
	}
}

// The same root swapped for a link to the data folder, its holder or a
// folder inside it is still refused under an unreadable parent.
func TestARootUnderAnUnreadableParentSwappedIntoTheDataFolderIsRefused(t *testing.T) {
	for name, target := range map[string]func(data string) string{
		"the data folder": func(d string) string { return d },
		"its holder":      filepath.Dir,
		"inside it":       func(d string) string { return filepath.Join(d, "shares") },
	} {
		t.Run(name, func(t *testing.T) {
			_, team := unreadableParent(t)
			data := filepath.Join(t.TempDir(), "HyperDrop")
			os.MkdirAll(filepath.Join(data, "shares"), 0o755)
			os.WriteFile(filepath.Join(data, "hyperdrop.db"), []byte("db"), 0o600)
			r, err := NewRoots([]string{team}, nil, []string{data})
			if err != nil {
				t.Fatal(err)
			}
			if l := r.List(); len(l) != 1 {
				t.Fatalf("List = %+v", l)
			}
			swapForLink(t, team, target(data))
			assertSwappedRootRefused(t, r)
		})
	}
}
