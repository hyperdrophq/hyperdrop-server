package api

import (
	"strings"
	"testing"
)

func TestAPlainUsersPasswordResetVerifiesTheStepUpItCarries(t *testing.T) {
	h, db, _ := newMultiUserAPI(t)
	seedUser(t, db, "alice")
	rec := doReqBare(t, h, "PATCH", "/api/users/alice", testToken,
		`{"resetPassword":true,"currentPassword":"not-the-password"}`)
	if rec.Code != 401 || !strings.Contains(rec.Body.String(), "wrong-password") {
		t.Fatalf("wrong step-up: %d %s", rec.Code, rec.Body)
	}
	if _, err := db.Authenticate("alice", "alice-pw"); err != nil {
		t.Fatalf("the password changed despite the refused step-up: %v", err)
	}
}

func TestAPlainUsersPasswordResetWithoutAStepUpStillWorks(t *testing.T) {
	h, db, _ := newMultiUserAPI(t)
	seedUser(t, db, "alice")
	rec := doReqBare(t, h, "PATCH", "/api/users/alice", testToken, `{"resetPassword":true}`)
	if rec.Code != 200 {
		t.Fatalf("reset without a step-up: %d %s", rec.Code, rec.Body)
	}
	if _, err := db.Authenticate("alice", "alice-pw"); err == nil {
		t.Fatal("the old password still works")
	}
}

func TestAPlainUsersPasswordResetAcceptsTheStepUpItCarries(t *testing.T) {
	h, db, _ := newMultiUserAPI(t)
	seedUser(t, db, "alice")
	rec := doReqBare(t, h, "PATCH", "/api/users/alice", testToken,
		`{"resetPassword":true,"currentPassword":"`+testAdminPassword+`"`+seededAdminTOTP(t)+`}`)
	if rec.Code != 200 {
		t.Fatalf("reset with a step-up: %d %s", rec.Code, rec.Body)
	}
}

func TestAPlainUsersTOTPResetVerifiesTheStepUpItCarries(t *testing.T) {
	h, db, _ := newMultiUserAPI(t)
	token := seedUser(t, db, "alice")
	enableTOTP(t, h, token, "alice-pw")
	rec := doReqBare(t, h, "DELETE", "/api/users/alice/totp", testToken,
		`{"currentPassword":"not-the-password"}`)
	if rec.Code != 401 || !strings.Contains(rec.Body.String(), "wrong-password") {
		t.Fatalf("wrong step-up: %d %s", rec.Code, rec.Body)
	}
	u, err := db.User("alice")
	if err != nil || !u.TwoFactorEnabled() {
		t.Fatalf("the factor was cleared despite the refused step-up: %+v %v", u, err)
	}
}

func TestAPlainUsersTOTPResetWithoutAStepUpStillWorks(t *testing.T) {
	h, db, _ := newMultiUserAPI(t)
	token := seedUser(t, db, "alice")
	enableTOTP(t, h, token, "alice-pw")
	rec := doReqBare(t, h, "DELETE", "/api/users/alice/totp", testToken, ``)
	if rec.Code != 200 {
		t.Fatalf("reset without a step-up: %d %s", rec.Code, rec.Body)
	}
}
