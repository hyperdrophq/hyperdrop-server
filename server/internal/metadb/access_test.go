package metadb

import (
	"errors"
	"testing"
)

func linkedShareFor(t *testing.T, db *DB, owner string, sources ...string) Share {
	t.Helper()
	d, err := db.CreateShare(CreateOptions{Name: "trip", Owner: owner, Folder: true, Sources: sources})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestUpdateUserAccessRevokesAndRestoresASource(t *testing.T) {
	db := openTest(t)
	seedUser(t, db, "alice")
	d := linkedShareFor(t, db, "alice", "photo/2024")
	before, _ := db.Share(d.ID)
	two := 2
	roots := []string{}
	if _, err := db.UpdateUserAccess("alice", Settings{SourceRoots: &roots},
		[]SourceAccess{{ShareID: d.ID, Source: "photo/2024", Revoke: true, Files: &two}}, false); err != nil {
		t.Fatal(err)
	}
	after, err := db.Share(d.ID)
	if err != nil {
		t.Fatal(err)
	}
	src := after.Sources[0]
	if !src.Revoked() || src.RevokedFiles == nil || *src.RevokedFiles != 2 {
		t.Fatalf("source after revoke = %+v", src)
	}
	if after.ModifiedAt == nil || (before.ModifiedAt != nil && !after.ModifiedAt.After(*before.ModifiedAt)) {
		t.Fatalf("revoke did not touch the share: %v then %v", before.ModifiedAt, after.ModifiedAt)
	}
	u, _ := db.User("alice")
	if len(u.SourceRoots) != 0 {
		t.Fatalf("settings not applied in the same call: %v", u.SourceRoots)
	}
	roots = []string{"photo"}
	if _, err := db.UpdateUserAccess("alice", Settings{SourceRoots: &roots},
		[]SourceAccess{{ShareID: d.ID, Source: "photo/2024"}}, false); err != nil {
		t.Fatal(err)
	}
	restored, _ := db.Share(d.ID)
	if restored.Sources[0].Revoked() || restored.Sources[0].RevokedFiles != nil {
		t.Fatalf("source after restore = %+v", restored.Sources[0])
	}
}

func TestRestoringASourceKeepsItsFilter(t *testing.T) {
	db := openTest(t)
	seedUser(t, db, "alice")
	d := linkedShareFor(t, db, "alice", "photo/2024")
	if _, err := db.EditFilter(d.ID, []FilterEdit{{Source: "photo/2024", Hide: []string{"a.jpg"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.UpdateUserAccess("alice", Settings{}, []SourceAccess{{ShareID: d.ID, Source: "photo/2024", Revoke: true}}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := db.UpdateUserAccess("alice", Settings{}, []SourceAccess{{ShareID: d.ID, Source: "photo/2024"}}, false); err != nil {
		t.Fatal(err)
	}
	f, err := db.Filters(d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(f["photo/2024"].Hidden) != 1 || f["photo/2024"].Hidden[0] != "a.jpg" {
		t.Fatalf("filter after restore = %+v, want a.jpg still hidden", f["photo/2024"])
	}
}

func TestLinkedSharesOfListsOnlyThatOwnersLinkedShares(t *testing.T) {
	db := openTest(t)
	seedUser(t, db, "alice")
	seedUser(t, db, "bob")
	mine := linkedShareFor(t, db, "alice", "photo/2024")
	linkedShareFor(t, db, "bob", "photo/2024")
	if _, err := db.CreateShare(CreateOptions{Name: "plain", Owner: "alice"}); err != nil {
		t.Fatal(err)
	}
	got, err := db.LinkedSharesOf("alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != mine.ID || len(got[0].Sources) != 1 {
		t.Fatalf("LinkedSharesOf = %+v", got)
	}
}

func TestUpdateUserAccessRefusesAnotherOwnersShare(t *testing.T) {
	db := openTest(t)
	seedUser(t, db, "alice")
	seedUser(t, db, "bob")
	bobsShare := linkedShareFor(t, db, "bob", "photo/2024")
	if _, err := db.UpdateUserAccess("alice", Settings{},
		[]SourceAccess{{ShareID: bobsShare.ID, Source: "photo/2024", Revoke: true}}, false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	after, err := db.Share(bobsShare.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Sources[0].Revoked() {
		t.Fatalf("bob's source was revoked by alice's call: %+v", after.Sources[0])
	}
}

func TestUpdateUserAccessRefusesAnUnknownSource(t *testing.T) {
	db := openTest(t)
	seedUser(t, db, "alice")
	d := linkedShareFor(t, db, "alice", "photo/2024")
	if _, err := db.UpdateUserAccess("alice", Settings{},
		[]SourceAccess{{ShareID: d.ID, Source: "nope", Revoke: true}}, false); !errors.Is(err, ErrNotASource) {
		t.Fatalf("err = %v, want ErrNotASource", err)
	}
	after, err := db.Share(d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Sources[0].Revoked() {
		t.Fatalf("the real source was touched by a call naming an unknown one: %+v", after.Sources[0])
	}
}

func TestAPasswordSetRacingAPromotionIsRefused(t *testing.T) {
	db := openTest(t)
	seedUser(t, db, "alice")
	seedUser(t, db, "root")
	if _, err := db.UpdateUser("root", Settings{Role: ptr(RoleAdmin)}); err != nil {
		t.Fatal(err)
	}
	before, err := db.User("root")
	if err != nil {
		t.Fatal(err)
	}
	pw := "a-new-password-1"
	_, err = db.UpdateUserAccess("root", Settings{Password: &pw}, nil, true)
	if !errors.Is(err, ErrStepUpRequired) {
		t.Fatalf("a password set on an admin without a step-up = %v, want ErrStepUpRequired", err)
	}
	after, err := db.User("root")
	if err != nil {
		t.Fatal(err)
	}
	if after.PasswordHash != before.PasswordHash {
		t.Fatal("the refused edit changed the password")
	}
}

func TestAPasswordSetOnAUserNeedsNoStepUp(t *testing.T) {
	db := openTest(t)
	seedUser(t, db, "alice")
	before, _ := db.User("alice")
	pw := "a-new-password-1"
	if _, err := db.UpdateUserAccess("alice", Settings{Password: &pw}, nil, true); err != nil {
		t.Fatal(err)
	}
	after, _ := db.User("alice")
	if after.PasswordHash == before.PasswordHash {
		t.Fatal("the password was not set")
	}
}
