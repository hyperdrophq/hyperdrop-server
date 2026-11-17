package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/sharefs"
	"hyperdrop/server/internal/shareid"
)

// The boot pass deletes a duplicate a stopped process left copying, rows and
// directory, and keeps its original: the copy's worker died with that
// process, so the share would never fill.
func TestTheBootPassRemovesADuplicateStillCopying(t *testing.T) {
	dir := t.TempDir()
	db, err := metadb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store, err := sharefs.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateUser("alice", "pw", metadb.RoleUser, metadb.Settings{}); err != nil {
		t.Fatal(err)
	}
	src, err := db.CreateShare(metadb.CreateOptions{Owner: "alice", Name: "d"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Write(src.ID, "kept.txt", strings.NewReader("kept")); err != nil {
		t.Fatal(err)
	}
	c, err := store.Commit(src.ID, "kept.txt", 4, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CommitFile(metadb.CommitInput{ShareID: src.ID, Path: "kept.txt", Size: c.Size, SHA256: c.SHA256, Mime: c.Mime}); err != nil {
		t.Fatal(err)
	}
	dup, err := db.DuplicateShare(src.ID, metadb.DuplicateOptions{NewID: shareid.NewID()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.StageCopy(src.ID, "kept.txt", dup.ID, "kept.txt"); err != nil {
		t.Fatal(err)
	}
	copyDir := filepath.Join(dir, "shares", dup.ID)
	if _, err := os.Stat(copyDir); err != nil {
		t.Fatalf("the staged copy left no directory: %v", err)
	}

	bootPass(db, store)

	if _, err := db.Share(dup.ID); !errors.Is(err, metadb.ErrNotFound) {
		t.Fatalf("the unfinished duplicate's row after the boot pass: %v", err)
	}
	if _, err := os.Stat(copyDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the unfinished duplicate's directory after the boot pass: %v", err)
	}
	got, err := db.Share(src.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Committed != 1 {
		t.Fatalf("the original holds %d committed files, want 1", got.Committed)
	}
}
