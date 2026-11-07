package metadb

import (
	"testing"
	"time"
)

func sameTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

// A pin orders the owner's own list: it reaches the change feed so every
// client re-sorts, but it is not an edit to the share, so modified_at stays.
// Pinning an already pinned share keeps the pin time, so a second client
// repeating the pin does not reorder the list.
func TestPinningIsRecordedButIsNotAnEdit(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "notes", Owner: "alice", Sources: []string{"photos/a.jpg"}})
	before, err := db.Cursor()
	if err != nil {
		t.Fatal(err)
	}
	pinned, err := db.UpdateShare(d.ID, UpdateOptions{SetPinned: true, Pinned: true})
	if err != nil || pinned.PinnedAt == nil {
		t.Fatalf("pin: %+v %v", pinned.PinnedAt, err)
	}
	if !sameTime(pinned.ModifiedAt, d.ModifiedAt) {
		t.Fatalf("pin moved modifiedAt: %v -> %v", d.ModifiedAt, pinned.ModifiedAt)
	}
	after, err := db.Cursor()
	if err != nil {
		t.Fatal(err)
	}
	if after == before {
		t.Fatal("pin recorded no change")
	}
	again, err := db.UpdateShare(d.ID, UpdateOptions{SetPinned: true, Pinned: true})
	if err != nil || again.PinnedAt == nil || !again.PinnedAt.Equal(*pinned.PinnedAt) {
		t.Fatalf("re-pin: %v, want %v (%v)", again.PinnedAt, pinned.PinnedAt, err)
	}
	unpinned, err := db.UpdateShare(d.ID, UpdateOptions{SetPinned: true, Pinned: false})
	if err != nil || unpinned.PinnedAt != nil {
		t.Fatalf("unpin: %v %v", unpinned.PinnedAt, err)
	}
}
