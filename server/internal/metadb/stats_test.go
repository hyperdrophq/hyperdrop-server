package metadb

import (
	"errors"
	"testing"
	"time"
)

func TestUsageAndTotalsComeFromCounters(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	mustUser(t, db, "bob")
	a := mustShare(t, db, CreateOptions{Name: "a", Owner: "alice"})
	commit(t, db, a.ID, "x", 10)
	commit(t, db, a.ID, "y", 5)
	b := mustShare(t, db, CreateOptions{Name: "b", Owner: "alice", Files: []PendingFile{{Path: "p", Size: 99}}})
	u, err := db.Usage("alice")
	if err != nil || u.Shares != 2 || u.Committed != 2 || u.Bytes != 15 {
		t.Fatalf("usage: %+v, %v", u, err)
	}
	if u, _ := db.Usage("bob"); u.Shares != 0 {
		t.Fatalf("bob: %+v", u)
	}
	if u, _ := db.Usage("nobody"); u.Shares != 0 {
		t.Fatalf("unknown owner: %+v", u)
	}
	if n, bytes, _ := db.Totals(); n != 2 || bytes != 15 {
		t.Fatalf("totals: %d %d", n, bytes)
	}
	db.DeleteShare(b.ID)
	if u, _ := db.Usage("alice"); u.Shares != 1 {
		t.Fatalf("after delete: %+v", u)
	}
}

func TestEmptySharesAndPendingSweepQueries(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	old := mustShare(t, db, CreateOptions{Name: "old", Owner: "alice", CreatedAt: at.Add(-2 * time.Hour), Files: []PendingFile{{Path: "never", Size: 1}}})
	fresh := mustShare(t, db, CreateOptions{Name: "fresh", Owner: "alice", CreatedAt: at.Add(-time.Minute)})
	linked := mustShare(t, db, CreateOptions{Name: "nas", Owner: "alice", CreatedAt: at.Add(-2 * time.Hour), Sources: []string{"photos"}})
	inbox := mustShare(t, db, CreateOptions{Name: "inbox", Owner: "alice", CreatedAt: at.Add(-2 * time.Hour), Inbox: true})
	full := mustShare(t, db, CreateOptions{Name: "full", Owner: "alice", CreatedAt: at.Add(-2 * time.Hour)})
	commit(t, db, full.ID, "a", 1)
	ids, err := db.EmptyShares(at.Add(-time.Hour))
	if err != nil || len(ids) != 1 || ids[0] != old.ID {
		t.Fatalf("EmptyShares = %v (fresh %s linked %s inbox %s), %v", ids, fresh.ID, linked.ID, inbox.ID, err)
	}
	if err := db.RemovePending(old.ID, "never"); err != nil {
		t.Fatal(err)
	}
	if err := db.RemovePending(full.ID, "a"); err != nil {
		t.Fatal("removing a committed path as pending must be a silent no-op")
	}
	if d, _ := db.Share(full.ID); len(d.Files) != 1 {
		t.Fatal("committed row was removed")
	}
}

func TestCheckAndOptimizeRunOnAServedVolume(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "a", Owner: "alice"})
	commit(t, db, d.ID, "one", 1)
	if err := db.Check(); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if err := db.Optimize(); err != nil {
		t.Fatalf("Optimize: %v", err)
	}
}

// TestEmptySharesSpareAShareBuiltFolderFirst pins that a share whose first
// content is a folder record is not swept as one that never arrived.
func TestEmptySharesSpareAShareBuiltFolderFirst(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	shaped := mustShare(t, db, CreateOptions{Name: "shaped", Owner: "alice", CreatedAt: at.Add(-2 * time.Hour)})
	if _, err := db.AddFolder(shaped.ID, "inbox"); err != nil {
		t.Fatal(err)
	}
	bare := mustShare(t, db, CreateOptions{Name: "bare", Owner: "alice", CreatedAt: at.Add(-2 * time.Hour)})
	ids, err := db.EmptyShares(at.Add(-time.Hour))
	if err != nil || len(ids) != 1 || ids[0] != bare.ID {
		t.Fatalf("EmptyShares = %v (shaped %s), %v", ids, shaped.ID, err)
	}
}

func TestShareIDsListsEveryShare(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	if ids, err := db.ShareIDs(); err != nil || len(ids) != 0 {
		t.Fatalf("empty: %v, %v", ids, err)
	}
	a := mustShare(t, db, CreateOptions{Name: "a", Owner: "alice"})
	b := mustShare(t, db, CreateOptions{Name: "b", Owner: "alice", Inbox: true})
	ids, err := db.ShareIDs()
	if err != nil || len(ids) != 2 {
		t.Fatalf("ShareIDs = %v, %v", ids, err)
	}
	want := map[string]bool{a.ID: true, b.ID: true}
	for _, id := range ids {
		if !want[id] {
			t.Fatalf("unexpected id %s in %v", id, ids)
		}
	}
	if ids[0] > ids[1] {
		t.Fatalf("not ascending: %v", ids)
	}
}

func TestPendingFilesComeFromTheDeclaredStamp(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	old := mustShare(t, db, CreateOptions{Name: "old", Owner: "alice", Files: []PendingFile{{Path: "b", Size: 1}, {Path: "a", Size: 1}}})
	if _, err := db.DeclareFile(old.ID, "late", 1); err != nil {
		t.Fatal(err)
	}
	refs, err := db.PendingFiles(time.Now().Add(time.Second))
	if err != nil || len(refs) != 3 {
		t.Fatalf("all pending: %v, %v", refs, err)
	}
	for _, r := range refs {
		if r.ShareID != old.ID || r.DeclaredAt.IsZero() {
			t.Fatalf("ref: %+v", r)
		}
	}
	if refs[2].Path != "late" {
		t.Fatalf("oldest first: %v", refs)
	}
	if refs, _ := db.PendingFiles(time.Now().Add(-time.Hour)); len(refs) != 0 {
		t.Fatalf("nothing declared an hour ago: %v", refs)
	}
	commit(t, db, old.ID, "a", 1)
	refs, _ = db.PendingFiles(time.Now().Add(time.Second))
	if len(refs) != 2 {
		t.Fatalf("a committed row leaves the pending set: %v", refs)
	}
	if err := db.RemovePending(old.ID, "b"); err != nil {
		t.Fatal(err)
	}
	if refs, _ := db.PendingFiles(time.Now().Add(time.Second)); len(refs) != 1 || refs[0].Path != "late" {
		t.Fatalf("after RemovePending: %v", refs)
	}
}

func TestDeleteExpiredShareRechecksInsideTheTransaction(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	exp := at.Add(time.Hour)
	d := mustShare(t, db, CreateOptions{Name: "x", Owner: "alice", ExpiresAt: &exp})
	if ok, err := db.DeleteExpiredShare(d.ID, at); ok || err != nil {
		t.Fatalf("not yet expired: %v, %v", ok, err)
	}
	later := at.Add(48 * time.Hour)
	if _, err := db.UpdateShare(d.ID, UpdateOptions{SetExpiry: true, ExpiresAt: &later}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := db.DeleteExpiredShare(d.ID, at.Add(2*time.Hour)); ok {
		t.Fatal("an extended expiry must keep the share")
	}
	ok, err := db.DeleteExpiredShare(d.ID, at.Add(72*time.Hour))
	if err != nil || !ok {
		t.Fatalf("expired: %v, %v", ok, err)
	}
	if _, err := db.Share(d.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("rows still there")
	}
	if ok, err := db.DeleteExpiredShare(d.ID, at.Add(72*time.Hour)); ok || err != nil {
		t.Fatalf("second delete: %v, %v", ok, err)
	}
	if ok, err := db.DeleteExpiredShare("nope", at); ok || err != nil {
		t.Fatalf("invalid id: %v, %v", ok, err)
	}
	// The create and the expiry edit coalesce into one row; the deletion
	// differs in `deleted`, so it takes a row of its own.
	if n, del := changeRows(t, db); n != 2 || !del {
		t.Fatalf("changes: n=%d lastDeleted=%v, want the coalesced edit plus the deletion", n, del)
	}
}

func TestDeleteEmptyShareRechecksEveryReasonToKeep(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	cutoff := at.Add(-time.Hour)
	mk := func(name string, o CreateOptions) Share {
		o.Name, o.Owner, o.CreatedAt = name, "alice", at.Add(-2*time.Hour)
		return mustShare(t, db, o)
	}
	empty := mk("empty", CreateOptions{Files: []PendingFile{{Path: "p", Size: 1}}})
	fresh := mustShare(t, db, CreateOptions{Name: "fresh", Owner: "alice", CreatedAt: at.Add(-time.Minute)})
	inbox := mk("receive", CreateOptions{Inbox: true})
	linked := mk("linked", CreateOptions{Sources: []string{"photos"}})
	withFolder := mk("folder", CreateOptions{})
	if _, err := db.AddFolder(withFolder.ID, "docs"); err != nil {
		t.Fatal(err)
	}
	full := mk("full", CreateOptions{})
	commit(t, db, full.ID, "a", 1)
	for name, id := range map[string]string{"fresh": fresh.ID, "receive": inbox.ID, "linked": linked.ID, "folder": withFolder.ID, "full": full.ID} {
		if ok, err := db.DeleteEmptyShare(id, cutoff); ok || err != nil {
			t.Fatalf("%s must be kept: %v, %v", name, ok, err)
		}
	}
	ok, err := db.DeleteEmptyShare(empty.ID, cutoff)
	if err != nil || !ok {
		t.Fatalf("empty: %v, %v", ok, err)
	}
	if _, err := db.Share(empty.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("rows still there")
	}
	if ok, _ := db.DeleteEmptyShare(empty.ID, cutoff); ok {
		t.Fatal("second delete")
	}
	if ok, err := db.DeleteEmptyShare("nope", cutoff); ok || err != nil {
		t.Fatalf("invalid id: %v, %v", ok, err)
	}
}
