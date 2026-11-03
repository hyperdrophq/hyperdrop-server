package metadb

import (
	"testing"
	"time"
)

// enrol confirms a second factor for name.
func enrol(t *testing.T, db *DB, name string) {
	t.Helper()
	secret, err := db.StartTOTP(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ConfirmTOTP(name, codeAt(t, secret, at), at); err != nil {
		t.Fatal(err)
	}
}

func wantEnrolledAdmin(t *testing.T, db *DB, what string, want bool) {
	t.Helper()
	got, err := db.ActiveAdminHasSecondFactor()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	if got != want {
		t.Fatalf("%s: ActiveAdminHasSecondFactor = %v, want %v", what, got, want)
	}
}

// Only an admin that can sign in counts: a suspended or expired admin's
// second factor, an unfinished enrolment and a plain user's second factor
// do not.
func TestActiveAdminHasSecondFactor(t *testing.T) {
	db := openTest(t)
	wantEnrolledAdmin(t, db, "no accounts", false)
	for _, c := range []struct{ name, role string }{{"anna", RoleAdmin}, {"boris", RoleAdmin}, {"carl", RoleUser}} {
		if _, err := db.CreateUser(c.name, "password", c.role, Settings{}); err != nil {
			t.Fatal(err)
		}
	}
	wantEnrolledAdmin(t, db, "admins with no second factor", false)
	enrol(t, db, "carl")
	wantEnrolledAdmin(t, db, "a plain user enrolled", false)
	if _, err := db.StartTOTP("boris"); err != nil {
		t.Fatal(err)
	}
	wantEnrolledAdmin(t, db, "an admin's enrolment unfinished", false)
	enrol(t, db, "boris")
	wantEnrolledAdmin(t, db, "an enrolled admin", true)

	off := true
	if _, err := db.UpdateUser("boris", Settings{Disabled: &off}); err != nil {
		t.Fatal(err)
	}
	wantEnrolledAdmin(t, db, "the enrolled admin suspended", false)
	on, past := false, time.Now().Add(-time.Minute)
	if _, err := db.UpdateUser("boris", Settings{Disabled: &on, AccountExpiresAt: &past}); err != nil {
		t.Fatal(err)
	}
	wantEnrolledAdmin(t, db, "the enrolled admin expired", false)
	later := time.Now().Add(time.Hour)
	if _, err := db.UpdateUser("boris", Settings{AccountExpiresAt: &later}); err != nil {
		t.Fatal(err)
	}
	wantEnrolledAdmin(t, db, "the enrolled admin expiring later", true)
}
