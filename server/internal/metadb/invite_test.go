package metadb

import (
	"database/sql"
	"errors"
	"testing"
	"time"
)

func TestAnInviteSignsInOnceThenIsSpent(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	raw, err := db.MintInvite("alice")
	if err != nil || raw == "" {
		t.Fatalf("mint: %q %v", raw, err)
	}
	now := time.Now()
	u, token, err := db.SpendInvite(raw, "laptop", now)
	if err != nil || u.Username != "alice" || token == "" {
		t.Fatalf("spend: %+v %q %v", u.Username, token, err)
	}
	if got, err := db.UserByToken(token, ClientInfo{}); err != nil || got.Username != "alice" {
		t.Fatalf("the minted token does not sign alice in: %v", err)
	}
	if _, _, err := db.SpendInvite(raw, "phone", now); !errors.Is(err, ErrInviteInvalid) {
		t.Fatalf("second spend: err = %v, want ErrInviteInvalid", err)
	}
}

func TestAnInviteExpiresAndIsOneAnswerForEveryBadOne(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	raw, _ := db.MintInvite("alice")
	late := time.Now().Add(InviteTTL + time.Second)
	if _, _, err := db.SpendInvite(raw, "", late); !errors.Is(err, ErrInviteInvalid) {
		t.Fatalf("expired: err = %v, want ErrInviteInvalid", err)
	}
	if _, _, err := db.SpendInvite("hd_i_nope", "", time.Now()); !errors.Is(err, ErrInviteInvalid) {
		t.Fatalf("unknown: err = %v, want ErrInviteInvalid", err)
	}
}

func TestANewerInviteReplacesTheOlder(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	first, _ := db.MintInvite("alice")
	second, _ := db.MintInvite("alice")
	if _, _, err := db.SpendInvite(first, "", time.Now()); !errors.Is(err, ErrInviteInvalid) {
		t.Fatalf("the replaced invite still spends: %v", err)
	}
	if _, _, err := db.SpendInvite(second, "", time.Now()); err != nil {
		t.Fatalf("the newer invite: %v", err)
	}
}

func TestAPasswordChangeClearsTheInvite(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	raw, _ := db.MintInvite("alice")
	if err := db.SetPassword("alice", "new-password"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.SpendInvite(raw, "", time.Now()); !errors.Is(err, ErrInviteInvalid) {
		t.Fatalf("an invite outlived the password it was sent with: %v", err)
	}
}

// storedInvite is the invite hash alice's row holds, "" when none.
func storedInvite(t *testing.T, db *DB) string {
	t.Helper()
	var hash sql.NullString
	if err := db.read(func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT invite_hash FROM users WHERE username = 'alice'`).Scan(&hash)
	}); err != nil {
		t.Fatal(err)
	}
	return hash.String
}

// Turning a second factor on clears the unspent invite in the same write: a
// link sent before the factor must not outlive it, even after an admin
// clears the factor again.
func TestConfirmingTOTPClearsTheInvite(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	raw, _ := db.MintInvite("alice")
	secret, err := db.StartTOTP("alice")
	if err != nil {
		t.Fatal(err)
	}
	if storedInvite(t, db) == "" {
		t.Fatal("starting an enrolment cleared the invite; the case under test is the confirm")
	}
	now := time.Now()
	if _, err := db.ConfirmTOTP("alice", codeAt(t, secret, now), now); err != nil {
		t.Fatal(err)
	}
	if got := storedInvite(t, db); got != "" {
		t.Fatalf("the invite outlived the confirm: %q", got)
	}
	if err := db.DisableTOTP("alice"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.SpendInvite(raw, "", time.Now()); !errors.Is(err, ErrInviteInvalid) {
		t.Fatalf("the invite spends after the factor was cleared: %v", err)
	}
}

// A sign-in with the password leaves the unspent invite working, whether it
// mints a device token or a web session.
func TestASignInKeepsTheInvite(t *testing.T) {
	for _, mint := range []func(db *DB, hash string) error{
		func(db *DB, hash string) error {
			_, err := db.MintTokenIfPasswordIs("alice", "laptop", hash, "", time.Now())
			return err
		},
		func(db *DB, hash string) error {
			_, err := db.MintWebSessionIfPasswordIs("alice", "browser", hash, "", false, time.Now())
			return err
		},
	} {
		db := openTest(t)
		u := mustUser(t, db, "alice")
		raw, _ := db.MintInvite("alice")
		if err := mint(db, u.PasswordHash); err != nil {
			t.Fatal(err)
		}
		if _, _, err := db.SpendInvite(raw, "", time.Now()); err != nil {
			t.Fatalf("the invite is refused after a sign-in: %v", err)
		}
	}
}

func TestAnInviteNeverBypassesASecondFactor(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	if _, err := db.StartTOTP("alice"); err != nil {
		t.Fatal(err)
	}
	if err := db.write(func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE users SET totp_confirmed_at = ? WHERE username = 'alice'`, toNS(time.Now()))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	raw, _ := db.MintInvite("alice")
	if _, _, err := db.SpendInvite(raw, "", time.Now()); !errors.Is(err, ErrInviteNeedsSecondFactor) {
		t.Fatalf("err = %v, want ErrInviteNeedsSecondFactor", err)
	}
	// Refused, not spent: the person signs in with the password and a code.
	if _, _, err := db.SpendInvite(raw, "", time.Now()); !errors.Is(err, ErrInviteNeedsSecondFactor) {
		t.Fatalf("the refusal spent the invite: %v", err)
	}
}

func TestADisabledAccountsInviteIsRefused(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	raw, _ := db.MintInvite("alice")
	if _, err := db.UpdateUser("alice", Settings{Disabled: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.SpendInvite(raw, "", time.Now()); !errors.Is(err, ErrInactive) {
		t.Fatalf("err = %v, want ErrInactive", err)
	}
}

// confirmedFactor enrols and confirms a second factor for alice.
func confirmedFactor(t *testing.T, db *DB) {
	t.Helper()
	secret, err := db.StartTOTP("alice")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := db.ConfirmTOTP("alice", codeAt(t, secret, now), now); err != nil {
		t.Fatal(err)
	}
}

func TestClearingAConfirmedFactorClearsTheInvite(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	confirmedFactor(t, db)
	raw, _ := db.MintInvite("alice")
	if err := db.DisableTOTP("alice"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.SpendInvite(raw, "", time.Now()); !errors.Is(err, ErrInviteInvalid) {
		t.Fatalf("the invite spends after the confirmed factor was cleared: %v", err)
	}
}

func TestAnAdminClearingAFactorClearsTheInvite(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	confirmedFactor(t, db)
	raw, _ := db.MintInvite("alice")
	if err := db.DisableNonAdminTOTP("alice"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.SpendInvite(raw, "", time.Now()); !errors.Is(err, ErrInviteInvalid) {
		t.Fatalf("the invite spends after the confirmed factor was cleared: %v", err)
	}
}

func TestClearingAPendingEnrollmentKeepsTheInvite(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	if _, err := db.StartTOTP("alice"); err != nil {
		t.Fatal(err)
	}
	raw, _ := db.MintInvite("alice")
	if err := db.DisableTOTP("alice"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.SpendInvite(raw, "", time.Now()); err != nil {
		t.Fatalf("clearing an unconfirmed enrolment killed the invite: %v", err)
	}
}

func TestAnInviteMintedAfterTheFactorIsClearedSpends(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	confirmedFactor(t, db)
	if err := db.DisableTOTP("alice"); err != nil {
		t.Fatal(err)
	}
	raw, _ := db.MintInvite("alice")
	if _, _, err := db.SpendInvite(raw, "", time.Now()); err != nil {
		t.Fatalf("an invite minted after the factor was cleared is refused: %v", err)
	}
}
