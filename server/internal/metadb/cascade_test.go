package metadb

import (
	"database/sql"
	"errors"
	"slices"
	"testing"
	"time"
)

// cascadeAccount is alice holding a phone, a computer the phone signed in,
// a web session the phone approved, a phone linked through Sign In a Phone
// from it and an unrelated laptop, by label to token id.
func cascadeAccount(t *testing.T) (*DB, map[string]string) {
	t.Helper()
	db, phone := desktopTestDB(t)
	now := time.Now()
	ids := map[string]string{"iPhone": phone}
	_, raw, err := db.MintDesktopSignIn("alice", phone, "MacBook", "macos", "m", now)
	if err != nil {
		t.Fatal(err)
	}
	ids["MacBook"] = tokenOf(t, db, "alice", TokenHash(raw)).ID
	_, rawWeb, err := db.MintWebSessionApprovedBy("alice", phone, "Web browser", now)
	if err != nil {
		t.Fatal(err)
	}
	ids["web"] = tokenOf(t, db, "alice", WebSessionHash(rawWeb)).ID
	ids["iPad"] = mintedID(t, db, "alice", "iPad")
	setViaToken(t, db, ids["iPad"], phone)
	ids["laptop"] = mintedID(t, db, "alice", "laptop")
	return db, ids
}

func sorted(ids ...string) []string {
	out := slices.Clone(ids)
	slices.Sort(out)
	return out
}

// assertRemaining fails unless alice holds exactly the tokens want.
func assertRemaining(t *testing.T, db *DB, want ...string) {
	t.Helper()
	if got := sorted(tokenIDs(t, db, "alice")...); !slices.Equal(got, sorted(want...)) {
		t.Fatalf("alice holds %v, want %v", got, sorted(want...))
	}
}

func TestRevokeCascadesPhoneSignInsAndWebSessions(t *testing.T) {
	db, ids := cascadeAccount(t)
	revoked, err := db.RevokeTokenCascade("alice", ids["iPhone"], nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(revoked) == 0 || revoked[0] != ids["iPhone"] {
		t.Fatalf("revoked %v, want the root first", revoked)
	}
	if got, want := sorted(revoked...), sorted(ids["iPhone"], ids["MacBook"], ids["web"]); !slices.Equal(got, want) {
		t.Fatalf("revoked %v, want %v", got, want)
	}
	assertRemaining(t, db, ids["iPad"], ids["laptop"])
}

func TestRevokeLeavesLinkedPhonesUnlessListed(t *testing.T) {
	db, ids := cascadeAccount(t)
	// The laptop is listed but the walk never reaches it: a listed id outside
	// the cascade is never revoked.
	revoked, err := db.RevokeTokenCascade("alice", ids["iPhone"], []string{ids["iPad"], ids["laptop"], "", "nonsense"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := sorted(revoked...), sorted(ids["iPhone"], ids["MacBook"], ids["web"], ids["iPad"]); !slices.Equal(got, want) {
		t.Fatalf("revoked %v, want %v", got, want)
	}
	assertRemaining(t, db, ids["laptop"])
}

// A listed linked phone's own dependents are walked; an unlisted one's are
// not, so a computer behind a phone the person kept stays signed in with it.
func TestRevokeWalksOnlyThroughListedLinkedPhones(t *testing.T) {
	for _, listed := range []bool{false, true} {
		db, ids := cascadeAccount(t)
		behind := mintedID(t, db, "alice", "iMac")
		setViaToken(t, db, behind, ids["iPad"])
		setPhoneMethod(t, db, behind)
		var also []string
		if listed {
			also = []string{ids["iPad"]}
		}
		if _, err := db.RevokeTokenCascade("alice", ids["iPhone"], also); err != nil {
			t.Fatal(err)
		}
		if listed {
			assertRemaining(t, db, ids["laptop"])
		} else {
			assertRemaining(t, db, ids["iPad"], ids["laptop"], behind)
		}
	}
}

// setPhoneMethod marks token id as a computer signed in by phone.
func setPhoneMethod(t *testing.T, db *DB, id string) {
	t.Helper()
	err := db.write(func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE tokens SET sign_in_method = ? WHERE id = ?`, SignInMethodPhone, id)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRevokeCascadeIsTransitive(t *testing.T) {
	db, ids := cascadeAccount(t)
	// Computer B (MacBook) holds a web session C of its own approval.
	rawC, err := db.MintWebSession("alice", "Web browser C", false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	c := tokenOf(t, db, "alice", WebSessionHash(rawC)).ID
	setViaToken(t, db, c, ids["MacBook"])
	revoked, err := db.RevokeTokenCascade("alice", ids["iPhone"], nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(revoked, c) {
		t.Fatalf("revoked %v, want B's web session %s too", revoked, c)
	}
	assertRemaining(t, db, ids["iPad"], ids["laptop"])
}

// A cycle in via_token, which no mint writes, ends the walk rather than
// looping, and every token on it goes once.
func TestRevokeCascadeSurvivesACycle(t *testing.T) {
	db, ids := cascadeAccount(t)
	setViaToken(t, db, ids["iPhone"], ids["MacBook"])
	revoked, err := db.RevokeTokenCascade("alice", ids["iPhone"], nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := sorted(revoked...), sorted(ids["iPhone"], ids["MacBook"], ids["web"]); !slices.Equal(got, want) {
		t.Fatalf("revoked %v, want %v", got, want)
	}
}

// The walk never leaves the account, even through a via_token naming another
// account's token, and an unknown or foreign root is ErrNoSuchToken.
func TestRevokeCascadeStaysInTheAccount(t *testing.T) {
	db, ids := cascadeAccount(t)
	if _, err := db.CreateUser("bob", "pw-bob", RoleUser, Settings{}); err != nil {
		t.Fatal(err)
	}
	bobs := mintedID(t, db, "bob", "bob's Mac")
	setViaToken(t, db, bobs, ids["iPhone"])
	setPhoneMethod(t, db, bobs)
	if _, err := db.RevokeTokenCascade("alice", ids["iPhone"], []string{bobs}); err != nil {
		t.Fatal(err)
	}
	if got := tokenIDs(t, db, "bob"); !slices.Equal(got, []string{bobs}) {
		t.Fatalf("bob holds %v, want %v", got, []string{bobs})
	}
	if _, err := db.RevokeTokenCascade("alice", bobs, nil); !errors.Is(err, ErrNoSuchToken) {
		t.Fatalf("another account's root: %v, want ErrNoSuchToken", err)
	}
	if _, err := db.RevokeTokenCascade("alice", "missing", nil); !errors.Is(err, ErrNoSuchToken) {
		t.Fatalf("unknown root: %v, want ErrNoSuchToken", err)
	}
	if _, err := db.RevokeTokenCascade("nobody", ids["laptop"], nil); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("unknown account: %v, want ErrUserNotFound", err)
	}
}
