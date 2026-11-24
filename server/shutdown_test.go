package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"hyperdrop/server/internal/housekeep"
	"hyperdrop/server/internal/metadb"
)

func TestTheWaitEndsOnceTheBackgroundWorkStopsForItsContext(t *testing.T) {
	u := upkeep{bg: new(sync.WaitGroup)}
	ctx, cancel := context.WithCancel(context.Background())
	u.background(func() { <-ctx.Done() })
	u.background(func() { <-ctx.Done() })
	cancel()
	start := time.Now()
	if !u.wait(housekeepStopLimit) {
		t.Fatalf("the wait gave up after %s with every goroutine stopped", time.Since(start))
	}
}

func TestTheWaitGivesUpOnWorkThatIgnoresItsContext(t *testing.T) {
	defer func(d time.Duration) { housekeepStopLimit = d }(housekeepStopLimit)
	housekeepStopLimit = 50 * time.Millisecond
	u := upkeep{bg: new(sync.WaitGroup)}
	release := make(chan struct{})
	defer close(release)
	u.background(func() { <-release })
	start := time.Now()
	if u.wait(housekeepStopLimit) {
		t.Fatal("the wait answered true with a goroutine still running")
	}
	if took := time.Since(start); took < housekeepStopLimit {
		t.Fatalf("the wait gave up after %s, before its %s", took, housekeepStopLimit)
	}
}

// closeVolume waits for the background work before it closes the database,
// so the close is the last connection's and checkpoints the write-ahead log
// away.
func TestCloseVolumeWaitsThenLeavesNoWriteAheadLog(t *testing.T) {
	dir := t.TempDir()
	db, err := metadb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateUser("alice", "pw", metadb.RoleUser, metadb.Settings{}); err != nil {
		t.Fatal(err)
	}
	wal := filepath.Join(dir, metadb.FileName+"-wal")
	if _, err := os.Stat(wal); err != nil {
		t.Fatalf("no write-ahead log while the database is open: %v", err)
	}
	u := upkeep{bg: new(sync.WaitGroup)}
	ctx, cancel := context.WithCancel(context.Background())
	stopped := false
	u.background(func() {
		for ctx.Err() == nil {
			if _, err := db.ShareIDs(); err != nil {
				t.Errorf("a read before the close: %v", err)
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
		stopped = true
	})
	cancel()
	closeVolume(db, u)
	if !stopped {
		t.Fatal("the database closed before the background work returned")
	}
	if _, err := os.Stat(wal); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("%s after closeVolume: %v, want it gone", wal, err)
	}
	if _, err := os.Stat(filepath.Join(dir, metadb.CleanCloseFile)); err != nil {
		t.Fatalf("no %s after a clean close: %v", metadb.CleanCloseFile, err)
	}
}

// What a damaged daily copy does: a server nothing restarts keeps serving;
// a supervised one exits so its next start checks the file, except while
// this process's own boot checked the file and no copy has passed since,
// where the next start would check the same file and meet the same copy.
func TestADamagedCopyStopsASupervisedServerOncePerCheck(t *testing.T) {
	damaged := housekeep.Result{BackupErr: fmt.Errorf("%w: test", metadb.ErrCopyDamaged)}
	passed := housekeep.Result{BackedUp: true}
	other := housekeep.Result{BackupErr: errors.New("disk full")}
	for _, c := range []struct {
		name                string
		supervised, checked bool
		results             []housekeep.Result
		want                []bool
	}{
		{"unsupervised", false, false, []housekeep.Result{damaged, passed, damaged}, []bool{false, false, false}},
		{"after a trusted boot", true, false, []housekeep.Result{damaged}, []bool{true}},
		{"after a checked boot", true, true, []housekeep.Result{damaged, damaged}, []bool{false, false}},
		{"after a checked boot and a good copy", true, true, []housekeep.Result{passed, damaged}, []bool{false, true}},
		{"another backup error", true, false, []housekeep.Result{other}, []bool{false}},
		{"no backup due", true, false, []housekeep.Result{{}}, []bool{false}},
	} {
		o := owedCheck{supervised: c.supervised, checked: c.checked}
		for i, r := range c.results {
			if got := o.exits(r); got != c.want[i] {
				t.Errorf("%s: result %d exits = %v, want %v", c.name, i, got, c.want[i])
			}
		}
	}
}
