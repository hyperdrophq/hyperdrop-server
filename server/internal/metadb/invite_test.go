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
