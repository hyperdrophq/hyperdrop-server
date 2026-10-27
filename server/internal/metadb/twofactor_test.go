package metadb

import (
	"errors"
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
