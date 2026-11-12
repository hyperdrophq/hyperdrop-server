package metadb

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/totp"
)

func codeAt(t *testing.T, secret string, now time.Time) string {
	t.Helper()
	c, err := totp.Code(secret, totp.StepAt(now))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestTOTPEnrolmentConfirmsOnceAndGatesTokenMinting(t *testing.T) {
	db := openTest(t)
	if _, err := db.CreateUser("alice", "pw", RoleUser, Settings{}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ConfirmTOTP("alice", "000000", at); !errors.Is(err, ErrTOTPNotPending) {
		t.Fatalf("confirm before start: %v", err)
	}
	secret, err := db.StartTOTP("alice")
	if err != nil || secret == "" {
		t.Fatal(err)
	}
	u, _ := db.User("alice")
	if u.TwoFactorEnabled() {
		t.Fatal("an unconfirmed enrolment must read as off")
	}
	if _, err := db.ConfirmTOTP("alice", "000000", at); !errors.Is(err, ErrTOTPInvalid) {
		t.Fatalf("wrong code: %v", err)
	}
	codes, err := db.ConfirmTOTP("alice", codeAt(t, secret, at), at)
	if err != nil || len(codes) != 10 {
		t.Fatalf("confirm: %v codes, %v", len(codes), err)
	}
	u, _ = db.User("alice")
	if !u.TwoFactorEnabled() || u.RecoveryCodesLeft != 10 {
		t.Fatalf("after confirm: %+v", u)
	}
	if _, err := db.StartTOTP("alice"); !errors.Is(err, ErrTOTPAlreadyOn) {
		t.Fatalf("second start: %v", err)
	}
	if _, err := db.MintTokenIfPasswordIs("alice", "l", u.PasswordHash, "", at.Add(time.Minute)); !errors.Is(err, ErrTOTPRequired) {
		t.Fatalf("mint without code: %v", err)
	}
	later := at.Add(2 * time.Minute)
	if _, err := db.MintTokenIfPasswordIs("alice", "l", u.PasswordHash, codeAt(t, secret, later), later); err != nil {
		t.Fatalf("mint with code: %v", err)
	}
	if _, err := db.MintTokenIfPasswordIs("alice", "l", u.PasswordHash, codeAt(t, secret, later), later); !errors.Is(err, ErrTOTPInvalid) {
		t.Fatal("a code must not be accepted twice inside its own step")
	}
}

func TestRecoveryCodesAreSingleUseAndResettable(t *testing.T) {
	db := openTest(t)
	if _, err := db.CreateUser("alice", "pw", RoleUser, Settings{}); err != nil {
		t.Fatal(err)
	}
	secret, _ := db.StartTOTP("alice")
	codes, err := db.ConfirmTOTP("alice", codeAt(t, secret, at), at)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.VerifySecondFactor("alice", "  "+codes[0]+" ", at.Add(time.Hour)); err != nil {
		t.Fatalf("recovery code with whitespace: %v", err)
	}
	if err := db.VerifySecondFactor("alice", codes[0], at.Add(time.Hour)); !errors.Is(err, ErrTOTPInvalid) {
		t.Fatal("a spent recovery code must be refused")
	}
	u, _ := db.User("alice")
	if u.RecoveryCodesLeft != 9 {
		t.Fatalf("codes left = %d", u.RecoveryCodesLeft)
	}
	fresh, err := db.ResetRecoveryCodes("alice")
	if err != nil || len(fresh) != 10 || fresh[0] == codes[1] {
		t.Fatalf("reset: %d, %v", len(fresh), err)
	}
	if err := db.VerifySecondFactor("alice", codes[1], at.Add(time.Hour)); !errors.Is(err, ErrTOTPInvalid) {
		t.Fatal("old codes must die on reset")
	}
	if err := db.DisableTOTP("alice"); err != nil {
		t.Fatal(err)
	}
	if err := db.DisableTOTP("alice"); err != nil {
		t.Fatal("disable must be idempotent")
	}
	u, _ = db.User("alice")
	if u.TwoFactorEnabled() || u.RecoveryCodesLeft != 0 || u.TOTPStored != "" {
		t.Fatalf("after disable: %+v", u)
	}
	if _, err := db.ResetRecoveryCodes("alice"); !errors.Is(err, ErrTOTPOff) {
		t.Fatalf("reset while off: %v", err)
	}
	if err := db.VerifySecondFactor("alice", "", at); err != nil {
		t.Fatal("verify with 2FA off must pass")
	}
}

// totpPendingOf is the raw totp_pending column of name's row, "" for NULL.
func totpPendingOf(t *testing.T, db *DB, name string) string {
	t.Helper()
	var v sql.NullString
	if err := db.w.QueryRow(`SELECT totp_pending FROM users WHERE username = ?`, name).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v.String
}

// enrolAt confirms name's second factor at now and returns its secret.
func enrolAt(t *testing.T, db *DB, name string, now time.Time) string {
	t.Helper()
	secret, err := db.StartTOTP(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ConfirmTOTP(name, codeAt(t, secret, now), now); err != nil {
		t.Fatal(err)
	}
	return secret
}

// A replace starts only over a confirmed factor and confirms only what it
// started, and the pending row names the sealed secret it replaces.
func TestTOTPReplaceStartsOverAConfirmedFactorOnly(t *testing.T) {
	db := openTest(t)
	if _, err := db.CreateUser("alice", "pw", RoleUser, Settings{}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.StartTOTPReplace("alice"); !errors.Is(err, ErrTOTPOff) {
		t.Fatalf("replace with no factor: %v", err)
	}
	if _, err := db.StartTOTP("alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.StartTOTPReplace("alice"); !errors.Is(err, ErrTOTPOff) {
		t.Fatalf("replace over an unconfirmed enrolment: %v", err)
	}
	enrolAt(t, db, "alice", at)
	if _, err := db.ConfirmTOTPReplace("alice", "000000", at); !errors.Is(err, ErrTOTPNotPending) {
		t.Fatalf("confirm with nothing pending: %v", err)
	}
	pending, err := db.StartTOTPReplace("alice")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := db.User("alice")
	sum := sha256.Sum256([]byte(u.TOTPStored))
	hash, sealed, ok := strings.Cut(totpPendingOf(t, db, "alice"), ":")
	if !ok || hash != hex.EncodeToString(sum[:]) || !strings.HasPrefix(sealed, sealedTOTPPrefix) {
		t.Fatalf("the pending row = %q, want the active secret's hash and a sealed secret", totpPendingOf(t, db, "alice"))
	}
	if opened, err := openTOTP(db.totpKey, "alice", sealed); err != nil || opened != pending {
		t.Fatalf("the pending secret opens as %q, %v", opened, err)
	}
	later := at.Add(time.Minute)
	if _, err := db.ConfirmTOTPReplace("alice", "000000", later); !errors.Is(err, ErrTOTPInvalid) {
		t.Fatalf("a wrong code: %v", err)
	}
	codes, err := db.ConfirmTOTPReplace("alice", codeAt(t, pending, later), later)
	if err != nil || len(codes) != recoveryCodeCount {
		t.Fatalf("confirm: %d codes, %v", len(codes), err)
	}
	if p := totpPendingOf(t, db, "alice"); p != "" {
		t.Fatalf("the confirm left totp_pending = %q", p)
	}
	u, _ = db.User("alice")
	if !u.TwoFactorEnabled() || u.TOTPLastStep != totp.StepAt(later) || u.RecoveryCodesLeft != recoveryCodeCount {
		t.Fatalf("after the replace: %+v", u)
	}
	if opened, _, err := db.openStoredTOTP(&u); err != nil || opened != pending {
		t.Fatalf("the active secret is %q, %v, want the pending one", opened, err)
	}
}

// Every way a factor is cleared or enrolled afresh clears a pending
// replace: the account's own disable, an admin's reset, the operator's
// reset2fa (DisableTOTP on a volume opened as is), and an enrolment over a
// row the previous release left a pending value on.
func TestDisableAndResetClearThePending(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateUser("alice", "pw", RoleUser, Settings{}); err != nil {
		t.Fatal(err)
	}
	startPending := func(now time.Time) {
		t.Helper()
		enrolAt(t, db, "alice", now)
		if _, err := db.StartTOTPReplace("alice"); err != nil {
			t.Fatal(err)
		}
		if totpPendingOf(t, db, "alice") == "" {
			t.Fatal("the start wrote no pending row")
		}
	}
	for _, c := range []struct {
		what  string
		clear func(string) error
	}{{"DisableTOTP", db.DisableTOTP}, {"DisableNonAdminTOTP", db.DisableNonAdminTOTP}} {
		startPending(at)
		if err := c.clear("alice"); err != nil {
			t.Fatal(err)
		}
		if p := totpPendingOf(t, db, "alice"); p != "" {
			t.Fatalf("%s left totp_pending = %q", c.what, p)
		}
	}

	stale := "0000:" + sealedTOTPPrefix + "AAAA"
	for _, step := range []string{"StartTOTP", "ConfirmTOTP"} {
		if _, err := db.w.Exec(`UPDATE users SET totp_pending = ? WHERE username = ?`, stale, "alice"); err != nil {
			t.Fatal(err)
		}
		secret, err := db.StartTOTP("alice")
		if err != nil {
			t.Fatal(err)
		}
		if step == "ConfirmTOTP" {
			if _, err := db.w.Exec(`UPDATE users SET totp_pending = ? WHERE username = ?`, stale, "alice"); err != nil {
				t.Fatal(err)
			}
			if _, err := db.ConfirmTOTP("alice", codeAt(t, secret, at), at); err != nil {
				t.Fatal(err)
			}
		}
		if p := totpPendingOf(t, db, "alice"); p != "" {
			t.Fatalf("%s left totp_pending = %q", step, p)
		}
	}

	if _, err := db.StartTOTPReplace("alice"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	asIs, err := OpenAsIs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := asIs.DisableTOTP("alice"); err != nil {
		t.Fatalf("reset2fa's DisableTOTP: %v", err)
	}
	if p := totpPendingOf(t, asIs, "alice"); p != "" {
		t.Fatalf("reset2fa left totp_pending = %q", p)
	}
	asIs.Close()
}
