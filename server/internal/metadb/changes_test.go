package metadb

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSinceReportsOnlyTheNewestRowPerShareInOrder(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	mustUser(t, db, "bob")
	start, _ := db.Cursor()
	a := mustShare(t, db, CreateOptions{Name: "a", Owner: "alice"})
	b := mustShare(t, db, CreateOptions{Name: "b", Owner: "bob"})
	commit(t, db, a.ID, "x", 1) // a changed twice
	batch, err := db.Since(start, "alice", 100)
	if err != nil || batch.Reset || len(batch.Changes) != 1 || batch.Changes[0].ShareID != a.ID || batch.More {
		t.Fatalf("alice: %+v, %v", batch, err)
	}
	// Every owner is scoped the same way: bob's own read never carries a's row.
	bobs, _ := db.Since(start, "bob", 100)
	if len(bobs.Changes) != 1 || bobs.Changes[0].ShareID != b.ID {
		t.Fatalf("bob sees only bob's row: %+v", bobs.Changes)
	}
	again, _ := db.Since(batch.Next, "alice", 100)
	if len(again.Changes) != 0 || again.Next != batch.Next {
		t.Fatalf("nothing new: %+v", again)
	}
	db.DeleteShare(a.ID)
	del, _ := db.Since(batch.Next, "alice", 100)
	if len(del.Changes) != 1 || !del.Changes[0].Deleted {
		t.Fatalf("deletion: %+v", del.Changes)
	}
}

func TestSincePagesWithMoreAndResumesExactly(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	start, _ := db.Cursor()
	var ids []string
	for i := 0; i < 5; i++ {
		ids = append(ids, mustShare(t, db, CreateOptions{Name: "d", Owner: "alice"}).ID)
	}
	var seen []string
	cursor := start
	for {
		b, err := db.Since(cursor, "alice", 2)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range b.Changes {
			seen = append(seen, c.ShareID)
		}
		cursor = b.Next
		if !b.More {
			break
		}
	}
	if len(seen) != 5 {
		t.Fatalf("saw %v", seen)
	}
	for i, id := range ids {
		if seen[i] != id {
			t.Fatalf("order: %v vs %v", seen, ids)
		}
	}
}

func TestSinceAnswersResetForGarbageAndPrunedCursors(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	for _, bad := range []string{"", "x", "inst:12"} {
		b, err := db.Since(bad, "alice", 10)
		if err != nil || !b.Reset || b.Next == "" {
			t.Fatalf("%q: %+v, %v", bad, b, err)
		}
	}
	early, _ := db.Cursor()
	mustShare(t, db, CreateOptions{Name: "old", Owner: "alice"})
	mid, _ := db.Cursor()
	time.Sleep(20 * time.Millisecond)
	cut := time.Now()
	mustShare(t, db, CreateOptions{Name: "new", Owner: "alice"})
	n, err := db.PruneChanges(cut)
	if err != nil || n != 1 {
		t.Fatalf("pruned %d, %v", n, err)
	}
	if b, _ := db.Since(early, "alice", 10); !b.Reset {
		t.Fatal("a cursor below the pruned watermark must reset")
	}
	if b, _ := db.Since(mid, "alice", 10); b.Reset || len(b.Changes) != 1 {
		t.Fatalf("a cursor at the watermark continues: %+v", b)
	}
	if _, err := strconv.ParseInt(mid, 10, 64); err != nil {
		t.Fatalf("cursor is decimal seq: %q", mid)
	}
}

func TestCursorAfterATotalPruneDoesNotReset(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	mustShare(t, db, CreateOptions{Name: "x", Owner: "alice"})
	time.Sleep(20 * time.Millisecond)
	cut := time.Now()
	n, err := db.PruneChanges(cut)
	if err != nil || n < 1 {
		t.Fatalf("pruned %d, %v", n, err)
	}
	cursor, err := db.Cursor()
	if err != nil {
		t.Fatal(err)
	}
	if cursor == "0" {
		t.Fatalf("cursor after a total prune must be the pruned watermark, not zero: %q", cursor)
	}
	if _, err := strconv.ParseInt(cursor, 10, 64); err != nil {
		t.Fatalf("cursor is decimal seq: %q", cursor)
	}
	b, err := db.Since(cursor, "alice", 10)
	if err != nil || b.Reset || len(b.Changes) != 0 {
		t.Fatalf("since the watermark: %+v, %v", b, err)
	}
}

func TestConsecutiveChangesToOneShareCoalesce(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	start, _ := db.Cursor()
	a := mustShare(t, db, CreateOptions{Owner: "alice", Name: "a"})
	for i := 0; i < 5; i++ {
		if _, err := db.DeclareFile(a.ID, fmt.Sprintf("f%d", i), 1); err != nil {
			t.Fatal(err)
		}
	}
	b := mustShare(t, db, CreateOptions{Owner: "alice", Name: "b"})
	if _, err := db.DeclareFile(a.ID, "later", 1); err != nil {
		t.Fatal(err)
	}
	batch, err := db.Since(start, "alice", 100)
	if err != nil {
		t.Fatal(err)
	}
	// The table holds one row for a's burst, one for b and one for a
	// again; Since reports the newest row per share, so it answers b then a.
	var ids []string
	for _, c := range batch.Changes {
		ids = append(ids, c.ShareID)
	}
	if strings.Join(ids, ",") != b.ID+","+a.ID {
		t.Fatalf("rows %v", ids)
	}
	var n int
	if err := db.read(func(tx *sql.Tx) error { return tx.QueryRow(`SELECT count(*) FROM changes`).Scan(&n) }); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("changes rows %d", n)
	}
}

// A cursor past the journal's head names a journal this database never
// wrote: the database was restored from a backup, and the client's replica
// holds shares that no longer exist. It resets, like a pruned cursor.
func TestACursorPastTheHeadResets(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	mustShare(t, db, CreateOptions{Name: "x", Owner: "alice"})
	head, _ := db.Cursor()
	n, _ := strconv.ParseInt(head, 10, 64)
	b, err := db.Since(strconv.FormatInt(n+1, 10), "alice", 10)
	if err != nil || !b.Reset || b.Next != head {
		t.Fatalf("since %d: %+v, %v", n+1, b, err)
	}
	if b, _ := db.Since(head, "alice", 10); b.Reset {
		t.Fatal("the head itself must not reset")
	}
}
