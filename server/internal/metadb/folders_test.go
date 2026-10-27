package metadb

import (
	"errors"
	"testing"
)

func TestFoldersAreRecordsWithACapAndAnEmptinessRule(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "x", Owner: "alice"})
	commit(t, db, d.ID, "docs/a.txt", 1)
	got, err := db.AddFolder(d.ID, "empty")
	if err != nil || len(got.Folders) != 1 {
		t.Fatalf("add: %v, %v", got.Folders, err)
	}
	if _, err := db.AddFolder(d.ID, "empty"); !errors.Is(err, ErrPathTaken) {
		t.Fatalf("re-adding: %v", err)
	}
	if _, err := db.AddFolder(d.ID, "docs/a.txt"); !errors.Is(err, ErrPathTaken) {
		t.Fatalf("folder at a file: %v", err)
	}
	if _, err := db.AddFolder(d.ID, "docs/a.txt/under"); !errors.Is(err, ErrPathTaken) {
		t.Fatalf("folder beneath a file: %v", err)
	}
	if _, err := db.AddFolder(d.ID, "../x"); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("bad path: %v", err)
	}
	if _, err := db.AddFolder(d.ID, "docs"); !errors.Is(err, ErrPathTaken) {
		t.Fatalf("a folder over an existing tree: %v", err)
	}
	if _, err := db.AddFolder(d.ID, "kept/inner"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddFolder(d.ID, "kept"); !errors.Is(err, ErrPathTaken) {
		t.Fatalf("a folder over a folder record beneath it: %v", err)
	}
	if _, err := db.RemoveFolder(d.ID, "docs"); !errors.Is(err, ErrFolderNotEmpty) {
		t.Fatalf("remove non-empty: %v", err)
	}
	if got, err = db.RemoveFolder(d.ID, "empty"); err != nil || len(got.Folders) != 1 {
		t.Fatalf("remove: %v, %v", got.Folders, err)
	}
	if _, err := db.RemoveFolder(d.ID, "empty"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("remove absent: %v", err)
	}
	for i := 0; i < MaxFolders-1; i++ {
		if _, err := db.AddFolder(d.ID, "f/"+string(rune('a'+i%26))+string(rune('a'+(i/26)%26))+string(rune('a'+(i/676)%26))); err != nil {
			t.Fatalf("folder %d: %v", i, err)
		}
	}
	if _, err := db.AddFolder(d.ID, "one-too-many"); !errors.Is(err, ErrTooManyFolders) {
		t.Fatalf("cap: %v", err)
	}
}

// TestRemoveFolderTakesTheWholeSubtree pins that a folder is removable
// whether it has a record of its own or exists only through its children.
func TestRemoveFolderTakesTheWholeSubtree(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "x", Owner: "alice"})
	if _, err := db.AddFolder(d.ID, "a/b"); err != nil {
		t.Fatal(err)
	}
	got, err := db.RemoveFolder(d.ID, "a")
	if err != nil || len(got.Folders) != 0 {
		t.Fatalf("child only: %v, %v", got.Folders, err)
	}
	for _, rel := range []string{"a", "a/b", "a/b/c", "ab"} {
		if _, err := db.AddFolder(d.ID, rel); err != nil {
			t.Fatal(err)
		}
	}
	got, err = db.RemoveFolder(d.ID, "a")
	if err != nil || len(got.Folders) != 1 || got.Folders[0] != "ab" {
		t.Fatalf("subtree: %v, %v", got.Folders, err)
	}
	if _, err := db.RemoveFolder(d.ID, "a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("nothing left: %v", err)
	}
}

// TestFolderPathsCompareByteForByte pins that the subtree a folder covers is
// matched case-sensitively and with no wildcard: "docs" is not "Docs", and a
// name holding _ or % names only itself.
func TestFolderPathsCompareByteForByte(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "x", Owner: "alice"})
	commit(t, db, d.ID, "Docs/a.txt", 1)
	if _, err := db.AddFolder(d.ID, "Keep/x"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddFolder(d.ID, "a_b/x"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddFolder(d.ID, "docs"); err != nil {
		t.Fatalf("docs beside Docs/a.txt: %v", err)
	}
	if _, err := db.AddFolder(d.ID, "keep"); err != nil {
		t.Fatalf("keep beside the Keep/x record: %v", err)
	}
	if _, err := db.AddFolder(d.ID, "aXb"); err != nil {
		t.Fatalf("aXb beside the a_b/x record: %v", err)
	}
	got, err := db.RemoveFolder(d.ID, "keep")
	if err != nil {
		t.Fatalf("remove keep: %v", err)
	}
	want := []string{"Keep/x", "aXb", "a_b/x", "docs"}
	if len(got.Folders) != len(want) {
		t.Fatalf("folders after removing keep: %v, want %v", got.Folders, want)
	}
	for i := range want {
		if got.Folders[i] != want[i] {
			t.Fatalf("folders after removing keep: %v, want %v", got.Folders, want)
		}
	}
	if _, err := db.RemoveFolder(d.ID, "docs"); err != nil {
		t.Fatalf("remove docs while only Docs/a.txt exists: %v", err)
	}
}
