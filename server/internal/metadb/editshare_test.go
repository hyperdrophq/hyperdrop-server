package metadb

import (
	"database/sql"
	"errors"
	"slices"
	"testing"

	"hyperdrop/server/internal/shareid"
)

// TestEditShareRefusesAnIDNamingNoShare pins that an id the share table does
// not hold, malformed or merely absent, answers ErrNotFound without running
// the edit.
func TestEditShareRefusesAnIDNamingNoShare(t *testing.T) {
	db := openTest(t)
	for _, id := range []string{"../x", "", shareid.NewID()} {
		ran := false
		_, err := db.editShare(id, 0, func(*sql.Tx, shareHead) error { ran = true; return nil })
		if !errors.Is(err, ErrNotFound) || ran {
			t.Fatalf("%q: err %v, edit ran %v", id, err, ran)
		}
	}
}

// TestEditShareWritesNothingWhenTheEditFails pins that an edit's error rolls
// back the edit's own rows, stamps no modified_at, journals no change and
// wakes no subscriber.
func TestEditShareWritesNothingWhenTheEditFails(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "x", Owner: "alice"})
	commit(t, db, d.ID, "a", 1)
	d, err := db.Share(d.ID)
	if err != nil || d.ModifiedAt == nil {
		t.Fatalf("modified %v, %v", d.ModifiedAt, err)
	}
	cursor, err := db.Cursor()
	if err != nil {
		t.Fatal(err)
	}
	wake, cancel := db.Subscribe()
	defer cancel()
	refused := errors.New("refused")
	_, err = db.editShare(d.ID, 0, func(tx *sql.Tx, _ shareHead) error {
		if _, err := tx.Exec(`INSERT INTO folders(share_id, path, fold_key) VALUES(?, ?, ?)`, d.ID, "kept", foldKey("kept")); err != nil {
			return err
		}
		return refused
	})
	if !errors.Is(err, refused) {
		t.Fatalf("err %v, want the edit's own", err)
	}
	got, err := db.Share(d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Folders) != 0 || got.ModifiedAt == nil || !got.ModifiedAt.Equal(*d.ModifiedAt) {
		t.Fatalf("folders %v, modified %v (was %v)", got.Folders, got.ModifiedAt, d.ModifiedAt)
	}
	b, err := db.Since(cursor, "alice", 10)
	if err != nil || len(b.Changes) != 0 {
		t.Fatalf("changes %+v, %v", b.Changes, err)
	}
	select {
	case <-wake:
		t.Fatal("a failed edit woke a subscriber")
	default:
	}
}

// TestEditShareAnswersTheShareItWrote pins the frame around a successful
// edit: the edit sees the share's head, the whole edit is one write
// transaction that stamps modified_at, journals the change and wakes
// subscribers, and the answer is the share read back inside it with at most
// maxFiles entries, every one for 0.
func TestEditShareAnswersTheShareItWrote(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "x", Owner: "alice"})
	for _, p := range []string{"a", "b", "c"} {
		commit(t, db, d.ID, p, 1)
	}
	before, err := db.Share(d.ID)
	if err != nil {
		t.Fatal(err)
	}
	cursor, err := db.Cursor()
	if err != nil {
		t.Fatal(err)
	}
	wake, cancel := db.Subscribe()
	defer cancel()
	for _, tc := range []struct {
		folder   string
		maxFiles int
		want     int
	}{{"one", 1, 1}, {"all", 0, 3}} {
		var head shareHead
		writes := db.writeCount()
		got, err := db.editShare(d.ID, tc.maxFiles, func(tx *sql.Tx, h shareHead) error {
			head = h
			_, err := tx.Exec(`INSERT INTO folders(share_id, path, fold_key) VALUES(?, ?, ?)`, d.ID, tc.folder, foldKey(tc.folder))
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if n := db.writeCount() - writes; n != 1 {
			t.Fatalf("%s: %d write transactions, want 1", tc.folder, n)
		}
		if head.owner != "alice" || head.committed != 3 {
			t.Fatalf("%s: head %+v", tc.folder, head)
		}
		if got.ID != d.ID || len(got.Files) != tc.want || got.FileCount != 3 {
			t.Fatalf("%s: answered %d of %d files for share %s", tc.folder, len(got.Files), got.FileCount, got.ID)
		}
		if !slices.Contains(got.Folders, tc.folder) || got.ModifiedAt.Before(*before.ModifiedAt) {
			t.Fatalf("%s: folders %v, modified %v (was %v)", tc.folder, got.Folders, got.ModifiedAt, before.ModifiedAt)
		}
		select {
		case <-wake:
		default:
			t.Fatalf("%s: the edit woke no subscriber", tc.folder)
		}
	}
	b, err := db.Since(cursor, "alice", 10)
	if err != nil || len(b.Changes) != 1 || b.Changes[0].ShareID != d.ID || b.Changes[0].Deleted {
		t.Fatalf("changes %+v, %v", b.Changes, err)
	}
}
