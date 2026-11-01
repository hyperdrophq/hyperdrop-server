package metadb

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestUpdateShareEditsFieldsAndKeepsOneViewAnswer(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "old", Owner: "alice"})
	commit(t, db, d.ID, "index.html", 1)
	got, err := db.UpdateShare(d.ID, UpdateOptions{SetName: true, Name: "new", SetPassword: true, PasswordHash: "h1"})
	if err != nil || got.Name != "new" || got.PasswordHash != "h1" || got.PasswordGen != 1 {
		t.Fatalf("name+password: %+v, %v", got, err)
	}
	got, _ = db.UpdateShare(d.ID, UpdateOptions{SetPassword: true, PasswordHash: ""})
	if got.HasPassword() || got.PasswordGen != 2 {
		t.Fatalf("remove password: %+v", got)
	}
	got, err = db.UpdateShare(d.ID, UpdateOptions{SetEntry: true, Entry: "index.html"})
	if err != nil || got.Entry != "index.html" {
		t.Fatalf("entry: %+v, %v", got, err)
	}
	if _, err := db.UpdateShare(d.ID, UpdateOptions{SetMedia: true, Media: true}); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("media beside entry must be refused on the RESULTING state: %v", err)
	}
	got, err = db.UpdateShare(d.ID, UpdateOptions{SetMedia: true, Media: true, SetEntry: true, Entry: ""})
	if err != nil || !got.Media || got.Entry != "" {
		t.Fatalf("entry to gallery in one request: %+v, %v", got, err)
	}
	if _, err := db.UpdateShare(d.ID, UpdateOptions{}); !errors.Is(err, ErrBadRequest) {
		t.Fatal("nothing to do must be ErrBadRequest")
	}
	exp := at.Add(time.Hour)
	got, _ = db.UpdateShare(d.ID, UpdateOptions{SetExpiry: true, ExpiresAt: &exp})
	if got.ExpiresAt == nil || !got.ExpiresAt.Equal(exp) {
		t.Fatalf("expiry: %+v", got.ExpiresAt)
	}
	ids, _ := db.Expired(at.Add(2 * time.Hour))
	if len(ids) != 1 || ids[0] != d.ID {
		t.Fatalf("Expired = %v", ids)
	}
	if ids, _ := db.Expired(at); len(ids) != 0 {
		t.Fatalf("not yet expired: %v", ids)
	}
	g := mustShare(t, db, CreateOptions{Name: "gallery", Owner: "alice", Media: true})
	if _, err := db.UpdateShare(g.ID, UpdateOptions{SetEntry: true, Entry: "index.html"}); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("entry beside media must be refused on the RESULTING state: %v", err)
	}
}

func TestSeenAtIsLaterWins(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	c := mustShare(t, db, CreateOptions{Name: "inbox", Owner: "alice", Inbox: true})
	later := at.Add(time.Hour)
	if _, err := db.UpdateShare(c.ID, UpdateOptions{SeenAt: &later}); err != nil {
		t.Fatal(err)
	}
	earlier := at
	if _, err := db.UpdateShare(c.ID, UpdateOptions{SeenAt: &earlier}); err != nil {
		t.Fatal(err)
	}
	got, _ := db.Share(c.ID)
	if got.SeenAt == nil || !got.SeenAt.Equal(at.Add(time.Hour)) {
		t.Fatalf("SeenAt = %v, want the later stamp kept", got.SeenAt)
	}
}

func TestScheduledChangesApplyWhenDueAndAreCancelledByImmediateEdits(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "x", Owner: "alice"})
	exp := at.Add(48 * time.Hour)
	got, err := db.Schedule(d.ID,
		Scheduled{Kind: ScheduledPassword, ApplyAt: at.Add(time.Hour), PasswordHash: "later"},
		Scheduled{Kind: ScheduledExpiry, ApplyAt: at.Add(time.Hour), ExpiresAt: &exp})
	if err != nil || len(got.Scheduled) != 2 {
		t.Fatalf("schedule: %+v, %v", got.Scheduled, err)
	}
	got, _ = db.Schedule(d.ID, Scheduled{Kind: ScheduledPassword, ApplyAt: at.Add(2 * time.Hour), Clear: true})
	if len(got.Scheduled) != 2 {
		t.Fatal("a new schedule for a kind replaces the old one")
	}
	if n, _ := db.ApplyDue(at.Add(30 * time.Minute)); n != 0 {
		t.Fatalf("nothing due yet, applied %d", n)
	}
	n, err := db.ApplyDue(at.Add(90 * time.Minute))
	if err != nil || n != 1 {
		t.Fatalf("expiry due: applied %d, %v", n, err)
	}
	got, _ = db.Share(d.ID)
	if got.ExpiresAt == nil || !got.ExpiresAt.Equal(exp) || len(got.Scheduled) != 1 || got.Scheduled[0].Kind != ScheduledPassword {
		t.Fatalf("after expiry applied: %+v", got)
	}
	// An immediate password edit cancels the scheduled password change.
	got, _ = db.UpdateShare(d.ID, UpdateOptions{SetPassword: true, PasswordHash: "now"})
	if len(got.Scheduled) != 0 {
		t.Fatalf("immediate edit must cancel the scheduled one: %+v", got.Scheduled)
	}
	got, _ = db.Schedule(d.ID, Scheduled{Kind: ScheduledPassword, ApplyAt: at.Add(3 * time.Hour), Clear: true})
	n, _ = db.ApplyDue(at.Add(4 * time.Hour))
	got, _ = db.Share(d.ID)
	if n != 1 || got.HasPassword() || got.PasswordGen != 2 {
		t.Fatalf("clear applied: n=%d %+v", n, got)
	}
	got, _ = db.Schedule(d.ID, Scheduled{Kind: ScheduledExpiry, ApplyAt: at.Add(5 * time.Hour), Clear: true})
	if got, err = db.CancelScheduled(d.ID, "all"); err != nil || len(got.Scheduled) != 0 {
		t.Fatalf("cancel all: %+v, %v", got.Scheduled, err)
	}
	if _, err := db.CancelScheduled(d.ID, "colour"); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("unknown kind: %v", err)
	}
	if _, err := db.Schedule(d.ID, Scheduled{Kind: "colour", ApplyAt: at}); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("unknown kind schedule: %v", err)
	}
}

// TestApplyDueSkipsAChangeTheOwnerOvertook pins the guard the per-row apply
// takes: the snapshot read before the write is applied only while the row it
// came from is still the row the share carries.
func TestApplyDueSkipsAChangeTheOwnerOvertook(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")

	// An immediate edit between the schedule and the apply wins.
	d := mustShare(t, db, CreateOptions{Name: "x", Owner: "alice"})
	if _, err := db.Schedule(d.ID, Scheduled{Kind: ScheduledPassword, ApplyAt: at.Add(time.Hour), PasswordHash: "later"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.UpdateShare(d.ID, UpdateOptions{SetPassword: true, PasswordHash: "immediate"}); err != nil {
		t.Fatal(err)
	}
	n, err := db.ApplyDue(at.Add(2 * time.Hour))
	if err != nil || n != 0 {
		t.Fatalf("cancelled schedule: applied %d, %v", n, err)
	}
	got, _ := db.Share(d.ID)
	if got.PasswordHash != "immediate" {
		t.Fatalf("password = %q, want the immediate edit kept", got.PasswordHash)
	}

	// Rescheduling the same kind later moves the row out of the old window.
	e := mustShare(t, db, CreateOptions{Name: "y", Owner: "alice"})
	if _, err := db.Schedule(e.ID, Scheduled{Kind: ScheduledExpiry, ApplyAt: at.Add(time.Hour), Clear: true}); err != nil {
		t.Fatal(err)
	}
	exp := at.Add(72 * time.Hour)
	if _, err := db.Schedule(e.ID, Scheduled{Kind: ScheduledExpiry, ApplyAt: at.Add(3 * time.Hour), ExpiresAt: &exp}); err != nil {
		t.Fatal(err)
	}
	if n, err := db.ApplyDue(at.Add(2 * time.Hour)); err != nil || n != 0 {
		t.Fatalf("replaced schedule: applied %d, %v", n, err)
	}
	got, _ = db.Share(e.ID)
	if len(got.Scheduled) != 1 || !got.Scheduled[0].ApplyAt.Equal(at.Add(3*time.Hour)) {
		t.Fatalf("the replacement must survive: %+v", got.Scheduled)
	}
	if n, err := db.ApplyDue(at.Add(4 * time.Hour)); err != nil || n != 1 {
		t.Fatalf("replacement due: applied %d, %v", n, err)
	}
	got, _ = db.Share(e.ID)
	if got.ExpiresAt == nil || !got.ExpiresAt.Equal(exp) {
		t.Fatalf("expiry = %v, want %v", got.ExpiresAt, exp)
	}

	// Several sweeps running at once read the same due row; the guard is
	// what makes exactly one of them apply it.
	f := mustShare(t, db, CreateOptions{Name: "z", Owner: "alice"})
	if _, err := db.Schedule(f.ID, Scheduled{Kind: ScheduledPassword, ApplyAt: at.Add(time.Hour), PasswordHash: "once"}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	total := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, err := db.ApplyDue(at.Add(2 * time.Hour))
			mu.Lock()
			defer mu.Unlock()
			total += n
			if err != nil {
				t.Errorf("ApplyDue: %v", err)
			}
		}()
	}
	wg.Wait()
	got, _ = db.Share(f.ID)
	if total != 1 || got.PasswordGen != 1 {
		t.Fatalf("concurrent sweeps applied %d times, password_gen = %d, want 1 and 1", total, got.PasswordGen)
	}
}

// TestSeenAtIsNotAnEdit pins that reading an inbox records its change row
// without moving the share's modified stamp.
func TestSeenAtIsNotAnEdit(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	c := mustShare(t, db, CreateOptions{Name: "inbox", Owner: "alice", Inbox: true})
	before, _ := changeRows(t, db)
	beforeSeq, _ := db.Cursor()
	seen := at
	if _, err := db.UpdateShare(c.ID, UpdateOptions{SeenAt: &seen}); err != nil {
		t.Fatal(err)
	}
	got, _ := db.Share(c.ID)
	if got.ModifiedAt != nil {
		t.Fatalf("ModifiedAt = %v, want nil after a seen-only update", got.ModifiedAt)
	}
	// The seen update coalesces into the creation's row, so the count
	// holds and the journal head moves onto the new row.
	afterSeq, _ := db.Cursor()
	if after, _ := changeRows(t, db); after != before || afterSeq == beforeSeq {
		t.Fatalf("changes went %d to %d, head %s to %s, want one coalesced row at a newer seq", before, after, beforeSeq, afterSeq)
	}
	if _, err := db.UpdateShare(c.ID, UpdateOptions{SetName: true, Name: "read"}); err != nil {
		t.Fatal(err)
	}
	if got, _ = db.Share(c.ID); got.ModifiedAt == nil {
		t.Fatal("a real edit must set ModifiedAt")
	}
}
