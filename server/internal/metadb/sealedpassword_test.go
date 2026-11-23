package metadb

import (
	"bytes"
	"database/sql"
	"errors"
	"testing"
	"time"
)

func sealer(tag string) func(string) ([]byte, error) {
	return func(id string) ([]byte, error) { return []byte(tag + ":" + id), nil }
}

func TestASealedCopyRidesCreateUpdateAndRemove(t *testing.T) {
	db := openTest(t)
	seedUser(t, db, "alice")
	d, err := db.CreateShare(CreateOptions{Name: "x", Owner: "alice", PasswordHash: "h1", SealPassword: sealer("one")})
	if err != nil {
		t.Fatal(err)
	}
	if string(d.PasswordSealed) != "one:"+d.ID {
		t.Fatalf("created sealed = %q (the sealer must see the minted id)", d.PasswordSealed)
	}
	d, err = db.UpdateShare(d.ID, UpdateOptions{SetPassword: true, PasswordHash: "h2", PasswordSealed: []byte("two")})
	if err != nil || string(d.PasswordSealed) != "two" || d.PasswordHash != "h2" {
		t.Fatalf("changed: %q %q %v", d.PasswordSealed, d.PasswordHash, err)
	}
	d, err = db.UpdateShare(d.ID, UpdateOptions{SetPassword: true})
	if err != nil || d.PasswordSealed != nil || d.PasswordHash != "" {
		t.Fatalf("removed: %q %q %v", d.PasswordSealed, d.PasswordHash, err)
	}
}

func TestNoHashKeepsNoCopy(t *testing.T) {
	db := openTest(t)
	seedUser(t, db, "alice")
	called := false
	d, err := db.CreateShare(CreateOptions{Name: "x", Owner: "alice",
		SealPassword: func(string) ([]byte, error) { called = true; return []byte("s"), nil }})
	if err != nil || called || d.PasswordSealed != nil {
		t.Fatalf("a share without a password: sealer called %v, sealed %q, %v", called, d.PasswordSealed, err)
	}
	d, err = db.UpdateShare(d.ID, UpdateOptions{SetPassword: true, PasswordSealed: []byte("orphan")})
	if err != nil || d.PasswordSealed != nil {
		t.Fatalf("a copy without its hash was kept: %q %v", d.PasswordSealed, err)
	}
}

func TestAFailingSealerCreatesNothing(t *testing.T) {
	db := openTest(t)
	seedUser(t, db, "alice")
	boom := errors.New("boom")
	_, err := db.CreateShare(CreateOptions{Name: "x", Owner: "alice", PasswordHash: "h",
		SealPassword: func(string) ([]byte, error) { return nil, boom }})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if page, _ := db.List(ListQuery{Owner: "alice", Limit: 10}); len(page.Shares) != 0 {
		t.Fatalf("a share exists: %+v", page.Shares)
	}
}

func TestAScheduledPasswordCarriesItsSealedCopy(t *testing.T) {
	db := openTest(t)
	seedUser(t, db, "alice")
	d, _ := db.CreateShare(CreateOptions{Name: "x", Owner: "alice", PasswordHash: "h1", SealPassword: sealer("old")})
	applyAt := time.Now().Add(time.Minute)
	if _, err := db.Schedule(d.ID, Scheduled{Kind: ScheduledPassword, ApplyAt: applyAt,
		PasswordHash: "h2", PasswordSealed: []byte("new")}); err != nil {
		t.Fatal(err)
	}
	got, _ := db.Share(d.ID)
	if len(got.Scheduled) != 1 || string(got.Scheduled[0].PasswordSealed) != "new" {
		t.Fatalf("scheduled = %+v", got.Scheduled)
	}
	if string(got.PasswordSealed) != "old:"+d.ID {
		t.Fatalf("the current copy moved before its time: %q", got.PasswordSealed)
	}
	if n, err := db.ApplyDue(applyAt.Add(time.Second)); err != nil || n != 1 {
		t.Fatalf("ApplyDue = %d, %v", n, err)
	}
	got, _ = db.Share(d.ID)
	if string(got.PasswordSealed) != "new" || got.PasswordHash != "h2" {
		t.Fatalf("applied: %q %q", got.PasswordSealed, got.PasswordHash)
	}
}

// journalLength counts the change journal's rows.
func journalLength(t *testing.T, db *DB) (n int) {
	t.Helper()
	if err := db.read(func(tx *sql.Tx) error { return tx.QueryRow(`SELECT count(*) FROM changes`).Scan(&n) }); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestSealedCopiesListsEveryCopyBesideItsHash(t *testing.T) {
	db := openTest(t)
	seedUser(t, db, "alice")
	a, _ := db.CreateShare(CreateOptions{Name: "a", Owner: "alice", PasswordHash: "ha", SealPassword: sealer("a")})
	b, _ := db.CreateShare(CreateOptions{Name: "b", Owner: "alice", PasswordHash: "hb"}) // no copy kept
	if _, err := db.Schedule(b.ID, Scheduled{Kind: ScheduledPassword, ApplyAt: time.Now().Add(time.Hour),
		PasswordHash: "hs", PasswordSealed: []byte("sched")}); err != nil {
		t.Fatal(err)
	}
	copies, err := db.SealedCopies()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]SealedCopy{
		"shares/" + a.ID:    {Table: SealedInShares, ShareID: a.ID, Hash: "ha", Sealed: []byte("a:" + a.ID)},
		"scheduled/" + b.ID: {Table: SealedInScheduled, ShareID: b.ID, Kind: ScheduledPassword, Hash: "hs", Sealed: []byte("sched")},
	}
	if len(copies) != len(want) {
		t.Fatalf("copies = %+v", copies)
	}
	for _, c := range copies {
		w, ok := want[c.Table+"/"+c.ShareID]
		if !ok || w.Kind != c.Kind || w.Hash != c.Hash || !bytes.Equal(w.Sealed, c.Sealed) {
			t.Fatalf("copy %+v, want %+v", c, w)
		}
	}
}

func TestClearSealedClearsOnlyTheCopyItWasShown(t *testing.T) {
	db := openTest(t)
	seedUser(t, db, "alice")
	d, _ := db.CreateShare(CreateOptions{Name: "x", Owner: "alice", PasswordHash: "h1", SealPassword: sealer("one")})
	if _, err := db.Schedule(d.ID, Scheduled{Kind: ScheduledPassword, ApplyAt: time.Now().Add(time.Hour),
		PasswordHash: "hs", PasswordSealed: []byte("sched")}); err != nil {
		t.Fatal(err)
	}
	copies, _ := db.SealedCopies()
	if len(copies) != 2 {
		t.Fatalf("copies = %+v", copies)
	}
	// A request rewrites the share's copy after the sweep read it: the
	// sweep's clear must leave the new copy alone.
	if _, err := db.UpdateShare(d.ID, UpdateOptions{SetPassword: true, PasswordHash: "h2", PasswordSealed: []byte("two")}); err != nil {
		t.Fatal(err)
	}
	before, _ := db.Share(d.ID)
	journal := journalLength(t, db)
	for _, c := range copies {
		if err := db.ClearSealed(c); err != nil {
			t.Fatal(err)
		}
	}
	after, _ := db.Share(d.ID)
	if string(after.PasswordSealed) != "two" {
		t.Fatalf("a copy written after the read was cleared: %q", after.PasswordSealed)
	}
	if !after.ModifiedAt.Equal(*before.ModifiedAt) || journalLength(t, db) != journal {
		t.Fatal("clearing a copy is not a share edit: modified_at or the journal moved")
	}

	// The scheduled row was deleted by the password change; schedule a new
	// one and clear the copy the sweep is shown.
	if _, err := db.Schedule(d.ID, Scheduled{Kind: ScheduledPassword, ApplyAt: time.Now().Add(time.Hour),
		PasswordHash: "hs", PasswordSealed: []byte("sched2")}); err != nil {
		t.Fatal(err)
	}
	copies, _ = db.SealedCopies()
	for _, c := range copies {
		if err := db.ClearSealed(c); err != nil {
			t.Fatal(err)
		}
	}
	after, _ = db.Share(d.ID)
	if after.PasswordSealed != nil || after.PasswordHash != "h2" ||
		len(after.Scheduled) != 1 || after.Scheduled[0].PasswordSealed != nil || after.Scheduled[0].PasswordHash != "hs" {
		t.Fatalf("after clearing: %q %q %+v", after.PasswordSealed, after.PasswordHash, after.Scheduled)
	}
	if copies, _ := db.SealedCopies(); len(copies) != 0 {
		t.Fatalf("copies left: %+v", copies)
	}
}

func TestClearSealedRefusesWhatItCannotName(t *testing.T) {
	db := openTest(t)
	for _, c := range []SealedCopy{
		{Table: "users", ShareID: "abcdefghjk", Sealed: []byte("x")},
		{Table: SealedInShares, ShareID: "../x", Sealed: []byte("x")},
		{Table: SealedInShares, ShareID: "abcdefghjk"},
	} {
		if err := db.ClearSealed(c); !errors.Is(err, ErrBadRequest) {
			t.Fatalf("ClearSealed(%+v) = %v", c, err)
		}
	}
}

// A batch clears every copy it names in one write transaction, still
// compare-and-clear, and a copy it cannot name refuses it before any write.
func TestClearSealedBatchIsOneTransaction(t *testing.T) {
	db := openTest(t)
	seedUser(t, db, "alice")
	var ids []string
	for i := 0; i < 5; i++ {
		d, err := db.CreateShare(CreateOptions{Name: "x", Owner: "alice", PasswordHash: "h", SealPassword: sealer("c")})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, d.ID)
	}
	copies, _ := db.SealedCopies()
	if len(copies) != 5 {
		t.Fatalf("copies = %d", len(copies))
	}
	// One copy is rewritten after the read: the batch must leave it alone.
	if _, err := db.UpdateShare(ids[0], UpdateOptions{SetPassword: true, PasswordHash: "h2", PasswordSealed: []byte("new")}); err != nil {
		t.Fatal(err)
	}
	bad := append(append([]SealedCopy(nil), copies...), SealedCopy{Table: SealedInShares, ShareID: "../x", Sealed: []byte("x")})
	writes := db.writes.Load()
	if err := db.ClearSealedBatch(bad); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("a batch naming a bad copy = %v", err)
	}
	if db.writes.Load() != writes {
		t.Fatal("a refused batch opened a write")
	}
	if left, _ := db.SealedCopies(); len(left) != 5 {
		t.Fatalf("a refused batch cleared %d copies", 5-len(left))
	}
	if err := db.ClearSealedBatch(copies); err != nil {
		t.Fatal(err)
	}
	if got := db.writes.Load() - writes; got != 1 {
		t.Fatalf("the batch took %d write transactions, want 1", got)
	}
	left, _ := db.SealedCopies()
	if len(left) != 1 || left[0].ShareID != ids[0] || string(left[0].Sealed) != "new" {
		t.Fatalf("left = %+v", left)
	}
}
