package main

import (
	"bytes"
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"hyperdrop/server/internal/api"
	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/sharefs"
)

// bootLogBuffer is a log destination a test reads while goroutines write it.
type bootLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *bootLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *bootLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *bootLogBuffer) has(s string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.Contains(b.buf.String(), s)
}

// The first housekeeping pass waits for the boot sweep's parts: a pending
// row declared more than the abandoned-upload window ago whose part went
// stale before the start loses its part to the sweep, and the stalled step
// then finds neither part nor file and keeps the row and its slug for
// DeclaredLifetime. The sweep is held back, so a pass that did not wait
// would reach the row first and remove it with its part.
func TestTheFirstPassWaitsForTheBootSweepsParts(t *testing.T) {
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
	d, err := db.CreateShare(metadb.CreateOptions{Owner: "alice", Name: "d", Files: []metadb.PendingFile{{Path: "stalled.bin", Size: 4}}})
	if err != nil {
		t.Fatal(err)
	}
	// A committed file keeps the share off the empty sweep, so the pending
	// row is the only thing the pass could take.
	if _, err := store.Write(d.ID, "kept.txt", strings.NewReader("kept")); err != nil {
		t.Fatal(err)
	}
	c, err := store.Commit(d.ID, "kept.txt", 4, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CommitFile(metadb.CommitInput{ShareID: d.ID, Path: "kept.txt", Size: c.Size, SHA256: c.SHA256, Mime: c.Mime}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.WriteRange(d.ID, "stalled.bin", strings.NewReader("ab"), sharefs.Range{Start: 0, End: 2}, 4, "s", nil); err != nil {
		t.Fatal(err)
	}
	part := filepath.Join(dir, "shares", d.ID, "parts")
	ents, err := os.ReadDir(part)
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * sharefs.DefaultAbandonedUpload)
	for _, e := range ents {
		if err := os.Chtimes(filepath.Join(part, e.Name()), old, old); err != nil {
			t.Fatal(err)
		}
	}

	var logged bootLogBuffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	release := make(chan struct{})
	defer func(f func()) { beforeBootSweep = f }(beforeBootSweep)
	beforeBootSweep = func() { <-release }

	vol := api.Backend{DB: db, FS: store}
	sweep := bootPass(db, store)
	bc := bootConfig{DataDir: dir, StatusFile: filepath.Join(dir, "status.json")}
	u := startUpkeep(bc, vol)
	// The pass runs as if the start came later than the row's declaration
	// by more than the window, and well within DeclaredLifetime.
	later := time.Now().Add(2 * sharefs.DefaultAbandonedUpload)
	u.pass.Now = func() time.Time { return later }
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		u.wait(housekeepStopLimit)
	}()
	partsSwept := u.startBootSweep(ctx, store, sweep)
	u.startHousekeeping(ctx, partsSwept)

	time.Sleep(300 * time.Millisecond)
	if logged.has("housekeeping first pass: ") {
		t.Fatal("the first pass ran while the boot sweep's parts were still owed")
	}
	close(release)
	deadline := time.Now().Add(30 * time.Second)
	for !logged.has("housekeeping first pass: ") {
		if time.Now().After(deadline) {
			t.Fatalf("no first pass within 30 s of the sweep's release\n%s", logged.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !logged.has("boot sweep: ") {
		t.Fatal("the boot sweep did not log its line")
	}
	if _, ok := store.PartAge(d.ID, "stalled.bin"); ok {
		t.Fatal("the stale part survived the boot sweep")
	}
	got, err := db.Share(d.ID)
	if err != nil {
		t.Fatal(err)
	}
	kept := map[string]bool{}
	for _, f := range got.Files {
		kept[f.Path] = f.Pending
	}
	if pending, ok := kept["stalled.bin"]; !ok || !pending {
		t.Fatalf("the pending row did not survive the first pass: %+v", got.Files)
	}
}
