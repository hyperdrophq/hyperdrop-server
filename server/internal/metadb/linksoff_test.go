package metadb

import (
	"testing"
)

// A share created with its links off reads back off, stamped with when they
// went off; turning them back on clears the stamp.
func TestLinksOffRoundTrips(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "notes", Owner: "alice", LinksOff: true,
		Files: []PendingFile{{Path: "a.txt", Size: 1}}})
	if !d.LinksOff() || d.LinksOffAt == nil {
		t.Fatalf("created with links off, reads back %v at %v", d.LinksOff(), d.LinksOffAt)
	}
	got, err := db.Share(d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.LinksOff() || !sameTime(got.LinksOffAt, d.LinksOffAt) {
		t.Fatalf("Share reads links off %v at %v, want at %v", got.LinksOff(), got.LinksOffAt, d.LinksOffAt)
	}
	on, err := db.UpdateShare(d.ID, UpdateOptions{SetLinksOff: true, LinksOff: false})
	if err != nil {
		t.Fatal(err)
	}
	if on.LinksOff() || on.LinksOffAt != nil {
		t.Fatalf("links turned on, reads back off %v at %v", on.LinksOff(), on.LinksOffAt)
	}
	off, err := db.UpdateShare(d.ID, UpdateOptions{SetLinksOff: true, LinksOff: true})
	if err != nil || !off.LinksOff() {
		t.Fatalf("links turned off again: %v, %v", off.LinksOff(), err)
	}
	plain := mustShare(t, db, CreateOptions{Name: "plain", Owner: "alice", Files: []PendingFile{{Path: "b.txt", Size: 1}}})
	if plain.LinksOff() || plain.LinksOffAt != nil {
		t.Fatalf("a share created without the option reads links off %v at %v", plain.LinksOff(), plain.LinksOffAt)
	}
	// The listing reads the same columns through its own query.
	page, err := db.List(ListQuery{Owner: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range page.Shares {
		if want := s.ID == d.ID; s.LinksOff() != want {
			t.Fatalf("the listing reads %s links off %v, want %v", s.Name, s.LinksOff(), want)
		}
	}
}

// Turning links off or on is not an edit to the share's content, so
// modified_at stays, but every client must learn of it, so the change feed
// holds a row for the share.
func TestTogglingLinksDoesNotMoveModifiedAt(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "notes", Owner: "alice", Files: []PendingFile{{Path: "a.txt", Size: 1}}})
	if _, err := db.CommitFile(CommitInput{ShareID: d.ID, Path: "a.txt", Size: 1, Mime: "text/plain"}); err != nil {
		t.Fatal(err)
	}
	d, err := db.Share(d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if d.ModifiedAt == nil {
		t.Fatal("the committed share has no modifiedAt to compare")
	}
	before, err := db.Cursor()
	if err != nil {
		t.Fatal(err)
	}
	for _, off := range []bool{true, false} {
		got, err := db.UpdateShare(d.ID, UpdateOptions{SetLinksOff: true, LinksOff: off})
		if err != nil {
			t.Fatal(err)
		}
		if !sameTime(got.ModifiedAt, d.ModifiedAt) {
			t.Fatalf("links off %v moved modifiedAt: %v -> %v", off, d.ModifiedAt, got.ModifiedAt)
		}
	}
	b, err := db.Since(before, "alice", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Changes) != 1 || b.Changes[0].ShareID != d.ID || b.Changes[0].Deleted {
		t.Fatalf("the change feed after the toggles holds %+v", b.Changes)
	}
}

// copying_from is written by a duplicate in progress; the read maps it.
func TestCopyingFromReadsBack(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	orig := mustShare(t, db, CreateOptions{Name: "orig", Owner: "alice", Files: []PendingFile{{Path: "a.txt", Size: 1}}})
	cp := mustShare(t, db, CreateOptions{Name: "copy", Owner: "alice", Files: []PendingFile{{Path: "a.txt", Size: 1}}})
	if cp.CopyingFrom != "" {
		t.Fatalf("a fresh share reads copying from %q", cp.CopyingFrom)
	}
	if _, err := db.w.Exec(`UPDATE shares SET copying_from = ? WHERE id = ?`, orig.ID, cp.ID); err != nil {
		t.Fatal(err)
	}
	got, err := db.Share(cp.ID)
	if err != nil || got.CopyingFrom != orig.ID {
		t.Fatalf("copying from reads back %q, %v, want %q", got.CopyingFrom, err, orig.ID)
	}
	page, err := db.List(ListQuery{Owner: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range page.Shares {
		if want := map[bool]string{true: orig.ID}[s.ID == cp.ID]; s.CopyingFrom != want {
			t.Fatalf("the listing reads %s copying from %q, want %q", s.Name, s.CopyingFrom, want)
		}
	}
}
