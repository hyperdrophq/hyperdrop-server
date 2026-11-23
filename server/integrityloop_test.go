package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/api"
	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/sharefs"
)

// integrityVolume is a volume of one share holding a.txt and b.txt, with
// b.txt's bytes gone from disk.
func integrityVolume(t *testing.T) (string, api.Backend) {
	t.Helper()
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
	d, err := db.CreateShare(metadb.CreateOptions{Owner: "alice", Name: "d"})
	if err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"a.txt", "b.txt"} {
		if _, err := store.Write(d.ID, rel, strings.NewReader(rel)); err != nil {
			t.Fatal(err)
		}
		c, err := store.Commit(d.ID, rel, int64(len(rel)), nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.CommitFile(metadb.CommitInput{ShareID: d.ID, Path: rel, Size: c.Size, SHA256: c.SHA256, Mime: c.Mime}); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(filepath.Join(dir, "shares", d.ID, "files", "b.txt")); err != nil {
		t.Fatal(err)
	}
	return dir, api.Backend{DB: db, FS: store}
}

// The integrity loop scans a volume with no recorded scan at once, records
// it, and publishes the count to the health verdict and the status file;
// the next process's upkeep states the recorded count before its listener.
func TestTheIntegrityLoopScansRecordsAndPublishes(t *testing.T) {
	dir, vol := integrityVolume(t)
	bc := bootConfig{DataDir: dir, StatusFile: filepath.Join(dir, "status.json")}
	u := startUpkeep(bc, vol)
	if n := u.missingFiles.Load(); n != 0 {
		t.Fatalf("a volume with no recorded scan starts at %d missing", n)
	}
	ctx, cancel := context.WithCancel(context.Background())
	u.startIntegrity(ctx)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if s, ok, err := vol.DB.LastIntegrityScan(); err != nil {
			t.Fatal(err)
		} else if ok {
			if s.Files != 2 || s.Missing != 1 {
				t.Fatalf("recorded %+v, want 2 files and 1 missing", s)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no scan recorded within 10 s of the loop's start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if !u.wait(housekeepStopLimit) {
		t.Fatal("the integrity loop did not return once its context ended")
	}
	if n := u.missingFiles.Load(); n != 1 {
		t.Fatalf("the health verdict's count is %d, want 1", n)
	}
	if got := readStatus(t, bc.StatusFile).MissingFiles; got != 1 {
		t.Fatalf("the status file's count is %d, want 1", got)
	}

	next := startUpkeep(bc, vol)
	if n := next.missingFiles.Load(); n != 1 {
		t.Fatalf("the next process starts at %d missing, want the recorded 1", n)
	}
	if got := readStatus(t, bc.StatusFile).MissingFiles; got != 1 {
		t.Fatalf("the next process's status file states %d missing, want the recorded 1", got)
	}
}
