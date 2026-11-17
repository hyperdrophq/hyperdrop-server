package metadb

import (
	"testing"
)

func tok(b byte) [32]byte { var t [32]byte; t[0] = b; return t }

func TestRecordVisitsCountsDistinctTokensAndJournalsOncePerShare(t *testing.T) {
	db := openTest(t)
	seedUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "x", Owner: "alice"})
	before, err := db.Cursor()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.RecordVisits([]Visit{{d.ID, tok(1)}, {d.ID, tok(1)}, {d.ID, tok(2)}}); err != nil {
		t.Fatal(err)
	}
	got, err := db.Share(d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Visitors != 2 {
		t.Fatalf("Visitors = %d, want 2", got.Visitors)
	}
	if got.ModifiedAt != nil {
		t.Fatal("a visit moved modified_at; a read is not an edit")
	}
	b, err := db.Since(before, "alice", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Changes) != 1 || b.Changes[0].ShareID != d.ID {
		t.Fatalf("journal after one flush = %+v, want one row for %s", b.Changes, d.ID)
	}
	// A token already counted writes nothing and journals nothing.
	after, _ := db.Cursor()
	if err := db.RecordVisits([]Visit{{d.ID, tok(2)}}); err != nil {
		t.Fatal(err)
	}
	if c, _ := db.Cursor(); c != after {
		t.Fatal("a repeated token moved the journal")
	}
}

func TestRecordVisitsSkipsAGoneShareAndStopsAtTheCap(t *testing.T) {
	db := openTest(t)
	seedUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "x", Owner: "alice"})
	// A share deleted between the note and the flush must not fail the batch.
	if err := db.RecordVisits([]Visit{{"zzzzzzzzzz", tok(9)}, {d.ID, tok(1)}}); err != nil {
		t.Fatalf("a gone share in the batch: %v", err)
	}
	old := MaxVisitorsPerShare
	MaxVisitorsPerShare = 2
	t.Cleanup(func() { MaxVisitorsPerShare = old })
	if err := db.RecordVisits([]Visit{{d.ID, tok(2)}, {d.ID, tok(3)}, {d.ID, tok(4)}}); err != nil {
		t.Fatal(err)
	}
	got, _ := db.Share(d.ID)
	if got.Visitors != 2 {
		t.Fatalf("Visitors past the cap = %d, want 2", got.Visitors)
	}
}
