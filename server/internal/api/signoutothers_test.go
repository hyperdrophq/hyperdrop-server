package api

import (
	"strings"
	"testing"
)

// Mass revocation is a CHOICE alongside a password change rather than an
// unavoidable side effect of one, and the choice defaults to revoking: the
// usual reason to change a password is that it may have leaked, and an
// intruder who already logged in holds a token that would otherwise outlive
// the change.
func TestAnUnstatedPasswordChangeStillSignsOtherDevicesOut(t *testing.T) {
	h := newTestAPI(t)
	other := loginWithLabel(t, h, "other-mac")

	rec := doReq(t, h, "PATCH", "/api/me/password", testToken,
		`{"currentPassword":"`+testAdminPassword+`","password":"brand-new"}`)
	if rec.Code != 200 {
		t.Fatalf("password change = %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `"signedOutOthers":true`) {
		t.Fatalf("response did not report the revocation: %s", rec.Body)
	}
	if rec := doReq(t, h, "GET", "/api/me", other, ""); rec.Code != 401 {
		t.Fatalf("the other device answered %d, want 401", rec.Code)
	}
}

// signOutOthers:false keeps every device signed in, INCLUDING the caller's, so
// there is nothing to re-mint and the response carries no token.
func TestKeepingDevicesLeavesEveryTokenWorking(t *testing.T) {
	h := newTestAPI(t)
	other := loginWithLabel(t, h, "other-mac")

	rec := doReq(t, h, "PATCH", "/api/me/password", testToken,
		`{"currentPassword":"`+testAdminPassword+`","password":"brand-new","signOutOthers":false}`)
	if rec.Code != 200 {
		t.Fatalf("password change = %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), `"token"`) {
		t.Fatalf("a kept-devices change minted a replacement token: %s", rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `"signedOutOthers":false`) {
		t.Fatalf("response did not report the choice: %s", rec.Body)
	}
	// Both the other device AND the caller keep working.
	if rec := doReq(t, h, "GET", "/api/me", other, ""); rec.Code != 200 {
		t.Fatalf("the other device answered %d, want 200", rec.Code)
	}
	if rec := doReq(t, h, "GET", "/api/me", testToken, ""); rec.Code != 200 {
		t.Fatalf("the caller's own token answered %d, want 200", rec.Code)
	}
	// The password really did change.
	if _, code := login(t, h, "admin", testAdminPassword); code == 200 {
		t.Fatal("the old password still logs in")
	}
	if _, code := login(t, h, "admin", "brand-new"); code != 200 {
		t.Fatalf("the new password does not log in: %d", code)
	}
}

// The explicit true is the same as saying nothing.
func TestAnExplicitSignOutOthersRevokes(t *testing.T) {
	h := newTestAPI(t)
	other := loginWithLabel(t, h, "other-mac")
	rec := doReq(t, h, "PATCH", "/api/me/password", testToken,
		`{"currentPassword":"`+testAdminPassword+`","password":"brand-new","signOutOthers":true}`)
	if rec.Code != 200 {
		t.Fatalf("password change = %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "GET", "/api/me", other, ""); rec.Code != 401 {
		t.Fatalf("the other device answered %d, want 401", rec.Code)
	}
}

// Keeping devices must not become a way around the current-password check.
func TestKeepingDevicesStillNeedsTheCurrentPassword(t *testing.T) {
	h := newTestAPI(t)
	wantStepUpRequired(t, "no current password", doReq(t, h, "PATCH", "/api/me/password", testToken,
		`{"password":"brand-new","signOutOthers":false}`))
	if rec := doReq(t, h, "PATCH", "/api/me/password", testToken,
		`{"currentPassword":"wrong","password":"brand-new","signOutOthers":false}`); rec.Code != 401 {
		t.Fatalf("wrong current password = %d, want 401", rec.Code)
	}
}
