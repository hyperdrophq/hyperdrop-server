package metadb

import (
	"errors"
	"testing"
	"time"
)

func twoAdmins(t *testing.T) *DB {
	t.Helper()
	db := openTest(t)
	for _, n := range []string{"anna", "boris"} {
		if _, err := db.CreateUser(n, "password", RoleAdmin, Settings{}); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

// Two admins acting on each other each pass the rule that stops an admin
// locking themselves out; the store refuses the second edit, whichever it
// is, so the server keeps an admin.
func TestTheLastActiveAdminCannotBeTakenAway(t *testing.T) {
	user, off, past := RoleUser, true, time.Now().Add(-time.Minute)
	for _, tc := range []struct {
		name string
		s    Settings
	}{
		{"demoted", Settings{Role: &user}},
		{"suspended", Settings{Disabled: &off}},
		{"expired", Settings{AccountExpiresAt: &past}},
	} {
		db := twoAdmins(t)
		if _, err := db.UpdateUser("boris", tc.s); err != nil {
			t.Fatalf("%s: the first admin: %v", tc.name, err)
		}
		if _, err := db.UpdateUser("anna", tc.s); !errors.Is(err, ErrLastAdmin) {
			t.Fatalf("%s: the last admin: %v, want ErrLastAdmin", tc.name, err)
		}
		if u, _ := db.User("anna"); !u.IsAdmin() || !u.Active(time.Now()) {
			t.Fatalf("%s: the refused edit landed: %+v", tc.name, u)
		}
	}
}

// Two admins setting a future expiry on each other would leave both
// expiring and no admin to undo it once they do.
func TestTheLastAdminThatNeverExpiresKeepsThatStanding(t *testing.T) {
	db := twoAdmins(t)
	later := time.Now().Add(24 * time.Hour)
	if _, err := db.UpdateUser("boris", Settings{AccountExpiresAt: &later}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.UpdateUser("anna", Settings{AccountExpiresAt: &later}); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("expiring the last lasting admin: %v, want ErrLastAdmin", err)
	}
	// Other edits of an admin stay open.
	if _, err := db.UpdateUser("anna", Settings{NoEmbed: ptr(true)}); err != nil {
		t.Fatal(err)
	}
}

func TestTheLastAdminCannotBeDeleted(t *testing.T) {
	db := twoAdmins(t)
	if err := db.DeleteKeepsAnAdmin("boris"); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteUser("boris"); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteKeepsAnAdmin("anna"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("asking about the last admin: %v, want ErrLastAdmin", err)
	}
	if err := db.DeleteUser("anna"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("deleting the last admin: %v, want ErrLastAdmin", err)
	}
}

// The admin second-factor reset reads the account and then clears it; a
// promotion between the two must not let the clearing skip the step-up an
// admin's factor takes.
func TestANonAdminResetRefusesAnAccountPromotedSince(t *testing.T) {
	db := openTest(t)
	if _, err := db.CreateUser("alice", "password", RoleUser, Settings{}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.UpdateUser("alice", Settings{Role: ptr(RoleAdmin)}); err != nil {
		t.Fatal(err)
	}
	if err := db.DisableNonAdminTOTP("alice"); !errors.Is(err, ErrIsAdmin) {
		t.Fatalf("clearing a promoted account as a non-admin: %v, want ErrIsAdmin", err)
	}
	if err := db.DisableTOTP("alice"); err != nil {
		t.Fatal(err)
	}
}
