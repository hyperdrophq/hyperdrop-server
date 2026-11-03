package liveshare

import (
	"testing"
	"time"
)

func testRegistry(now *time.Time) *Registry {
	n := 0
	return NewRegistry(Config{
		NewID:   func() string { n++; return "id-" + string(rune('a'+n)) + "aaaaaaaa" },
		NewSlug: func() string { n++; return "slug-" + string(rune('a'+n)) },
		Now:     func() time.Time { return *now },
	})
}

func TestCreateMintsIDAndSlugs(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	g := testRegistry(&now)
	rec, err := g.Create(Record{Owner: "amy", Files: []File{{Path: "a.txt", Size: 3}}})
	if err != nil {
		t.Fatal(err)
	}
	if rec.ID == "" || rec.Files[0].Slug == "" || !rec.CreatedAt.Equal(now) {
		t.Fatalf("not filled in: %+v", rec)
	}
	got, ok := g.Get(rec.ID)
	if !ok || got.Files[0].Path != "a.txt" {
		t.Fatalf("Get: %v %+v", ok, got)
	}
}

func TestPerOwnerCap(t *testing.T) {
	now := time.Now()
	g := testRegistry(&now)
	for i := 0; i < 3; i++ {
		if _, err := g.Create(Record{Owner: "amy"}); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	if _, err := g.Create(Record{Owner: "amy"}); err != ErrTooMany {
		t.Fatalf("4th create: %v, want ErrTooMany", err)
	}
	// Another owner is unaffected.
	if _, err := g.Create(Record{Owner: "bob"}); err != nil {
		t.Fatalf("other owner: %v", err)
	}
}

func TestGraceExpiryRemovesTheShare(t *testing.T) {
	now := time.Now()
	g := testRegistry(&now)
	rec, _ := g.Create(Record{Owner: "amy"})
	now = now.Add(5*time.Minute + time.Second)
	if _, ok := g.Get(rec.ID); ok {
		t.Fatal("share survived past grace")
	}
}

// Visit and Visitors sweep like every other public method: an id past its
// own ExpiresAt is gone before either one looks at g.shares, so a visitor
// arriving after expiry counts on nothing and reads back nothing.
func TestVisitAndVisitorsSweepAnExpiredShare(t *testing.T) {
	now := time.Now()
	g := testRegistry(&now)
	exp := now.Add(time.Minute)
	rec, err := g.Create(Record{Owner: "amy", ExpiresAt: &exp})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute) // past ExpiresAt
	g.Visit(rec.ID, [32]byte{1})
	if n := g.Visitors(rec.ID); n != 0 {
		t.Fatalf("Visitors after expiry = %d, want 0", n)
	}
	if _, ok := g.Get(rec.ID); ok {
		t.Fatal("Visit or Visitors resurrected an expired share")
	}
}

func TestMarkSeenResetsGrace(t *testing.T) {
	now := time.Now()
	g := testRegistry(&now)
	rec, _ := g.Create(Record{Owner: "amy"})
	now = now.Add(4 * time.Minute)
	g.MarkSeen(rec.ID)
	now = now.Add(4 * time.Minute) // 8 min total, 4 since seen
	if _, ok := g.Get(rec.ID); !ok {
		t.Fatal("share dropped despite recent MarkSeen")
	}
}

func TestResumeKeepsIdentityAndRejectsChangedSources(t *testing.T) {
	now := time.Now()
	g := testRegistry(&now)
	mtime := now.Add(-time.Hour)
	original, err := g.Create(Record{Owner: "amy", Folder: true, ZipSize: 99,
		Files: []File{{Path: "a.txt", Size: 3, Mime: "text/plain", MTime: mtime}}})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(4 * time.Minute)
	resumed, err := g.Resume(original.ID, Record{Owner: "amy", Folder: true, ZipSize: 99,
		Files: []File{{Path: "a.txt", Size: 3, Mime: "text/plain", MTime: mtime}}})
	if err != nil {
		t.Fatal(err)
	}
	if resumed.ID != original.ID || resumed.Files[0].Slug != original.Files[0].Slug {
		t.Fatalf("resume changed public identity: before=%+v after=%+v", original, resumed)
	}
	if _, err := g.Resume(original.ID, Record{Owner: "amy", Folder: true, ZipSize: 99,
		Files: []File{{Path: "a.txt", Size: 4, Mime: "text/plain", MTime: mtime}}}); err != ErrResumeMismatch {
		t.Fatalf("changed source = %v, want ErrResumeMismatch", err)
	}
	if _, err := g.Resume(original.ID, Record{Owner: "bob", Folder: true, ZipSize: 99,
		Files: []File{{Path: "a.txt", Size: 3, Mime: "text/plain", MTime: mtime}}}); err != ErrNoShare {
		t.Fatalf("other owner = %v, want ErrNoShare", err)
	}
}

func TestOnlineFollowsOfflineAfter(t *testing.T) {
	now := time.Now()
	g := testRegistry(&now)
	rec, _ := g.Create(Record{Owner: "amy"})
	if !g.Online(rec.ID) {
		t.Fatal("fresh share should be online")
	}
	now = now.Add(11 * time.Second)
	if g.Online(rec.ID) {
		t.Fatal("share should be offline 11 s after last seen")
	}
}

func TestDeleteChecksOwner(t *testing.T) {
	now := time.Now()
	g := testRegistry(&now)
	rec, _ := g.Create(Record{Owner: "amy"})
	if g.Delete(rec.ID, "bob") {
		t.Fatal("bob deleted amy's share")
	}
	if !g.Delete(rec.ID, "amy") {
		t.Fatal("amy could not delete her own share")
	}
	if _, ok := g.Get(rec.ID); ok {
		t.Fatal("share still there after delete")
	}
}

func TestVisitCountsDistinctTokensUpToTheCap(t *testing.T) {
	now := time.Now()
	g := testRegistry(&now)
	g.cfg.MaxVisitors = 2
	rec, err := g.Create(Record{Owner: "amy", Files: []File{{Path: "a.txt", Size: 3}}})
	if err != nil {
		t.Fatal(err)
	}
	var a, b, c [32]byte
	a[0], b[0], c[0] = 1, 2, 3
	g.Visit(rec.ID, a)
	g.Visit(rec.ID, a)
	if g.Visitors(rec.ID) != 1 {
		t.Fatalf("one token twice = %d visitors", g.Visitors(rec.ID))
	}
	g.Visit(rec.ID, b)
	g.Visit(rec.ID, c)
	if g.Visitors(rec.ID) != 2 {
		t.Fatalf("past the cap = %d visitors, want 2", g.Visitors(rec.ID))
	}
	got, _ := g.Get(rec.ID)
	if got.Visitors != 2 {
		t.Fatalf("Record.Visitors = %d, want 2", got.Visitors)
	}
	g.Visit("nope", a) // an unknown share is ignored
	if g.Visitors("nope") != 0 {
		t.Fatal("an unknown share reports visitors")
	}
}

// Deleting an account ends its live shares, so a new account of the same
// name cannot take over a link the old one handed out.
func TestDeleteOwnerEndsEveryShareOfThatAccount(t *testing.T) {
	n := 0
	g := NewRegistry(Config{
		NewID:   func() string { n++; return "id" + string(rune('a'+n)) },
		NewSlug: func() string { return "s" },
	})
	bob, _ := g.Create(Record{Owner: "bob"})
	alice, _ := g.Create(Record{Owner: "alice"})
	g.DeleteOwner("bob")
	if _, ok := g.Get(bob.ID); ok {
		t.Fatal("bob's live share survived his account")
	}
	if _, ok := g.Get(alice.ID); !ok {
		t.Fatal("another account's live share ended")
	}
}
