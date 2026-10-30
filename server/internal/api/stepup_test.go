package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"hyperdrop/server/internal/metadb"
)

// wantStepUpRequired asserts the coded refusal a route that needs the
// caller's own password earns when the request carries none.
func wantStepUpRequired(t *testing.T, what string, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), `"step-up-required"`) {
		t.Fatalf("%s: %d %s, want 403 step-up-required", what, rec.Code, rec.Body)
	}
}

func TestCreatingAnAdminNeedsTheCallersPassword(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	wantStepUpRequired(t, "no password", doReq(t, h, "POST", "/api/users", testToken,
		`{"username":"carol","password":"carol-chosen-pw","role":"admin"}`))
	if rec := doReq(t, h, "POST", "/api/users", testToken,
		`{"username":"carol","password":"carol-chosen-pw","role":"admin","currentPassword":"wrong"}`); rec.Code != 401 || !strings.Contains(rec.Body.String(), `"wrong-password"`) {
		t.Fatalf("wrong password: %d %s, want 401", rec.Code, rec.Body)
	}
	if _, err := um.User("carol"); err == nil {
		t.Fatal("a refused step-up still created the account")
	}
	// A user account needs no step-up: it cannot reach an admin route.
	if rec := doReq(t, h, "POST", "/api/users", testToken, `{"username":"dave","quotaBytes":1}`); rec.Code != 201 {
		t.Fatalf("create user: %d %s", rec.Code, rec.Body)
	}
}

func TestTheStepUpAsksForTheCallersCode(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	secret, _ := enableTOTP(t, h, testToken, testAdminPassword)
	body := `{"username":"carol","role":"admin","currentPassword":"` + testAdminPassword + `"`
	if rec := doReq(t, h, "POST", "/api/users", testToken, body+`}`); rec.Code != 401 || !strings.Contains(rec.Body.String(), "totp-required") {
		t.Fatalf("no code: %d %s, want 401 totp-required", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "POST", "/api/users", testToken, body+`,"totp":"000000"}`); rec.Code != 401 || !strings.Contains(rec.Body.String(), "totp-invalid") {
		t.Fatalf("wrong code: %d %s, want 401 totp-invalid", rec.Code, rec.Body)
	}
	code := nextCode(t, secret)
	if rec := doReq(t, h, "POST", "/api/users", testToken, body+`,"totp":"`+code+`"}`); rec.Code != 201 {
		t.Fatalf("password and code: %d %s, want 201", rec.Code, rec.Body)
	}
	// The accepted code is spent.
	if rec := doReq(t, h, "POST", "/api/users", testToken,
		`{"username":"erin","role":"admin","currentPassword":"`+testAdminPassword+`","totp":"`+code+`"}`); rec.Code != 401 {
		t.Fatalf("replayed code: %d %s, want 401", rec.Code, rec.Body)
	}
}

func TestPromotingAndRecredentialingAnAdminNeedTheStepUp(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	seedUser(t, um, "alice")
	if _, err := um.CreateUser("bob", "bob-pw", metadb.RoleAdmin, metadb.Settings{}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ path, body string }{
		{"/api/users/alice", `{"role":"admin"}`},
		{"/api/users/bob", `{"password":"thief-chosen-pw"}`},
		{"/api/users/bob", `{"resetPassword":true}`},
		// The caller's own password through the admin route, too: the self
		// route asks for the current password, and this one must not be a
		// way around it.
		{"/api/users/admin", `{"password":"thief-chosen-pw"}`},
	} {
		wantStepUpRequired(t, "PATCH "+c.path+" "+c.body, doReq(t, h, "PATCH", c.path, testToken, c.body))
	}
	if u, _ := um.User("alice"); u.IsAdmin() {
		t.Fatal("a refused promotion still promoted")
	}
	if _, err := um.Authenticate("bob", "bob-pw"); err != nil {
		t.Fatal("a refused password change still changed the password")
	}
	// Edits that grant nothing stay a bearer-token matter: a user's password,
	// an admin's limits, and an admin row that keeps its role.
	for _, c := range []struct{ path, body string }{
		{"/api/users/alice", `{"password":"alice-new-pw"}`},
		{"/api/users/bob", `{"quotaBytes":10}`},
		{"/api/users/bob", `{"role":"admin","noEmbed":true}`},
	} {
		if rec := doReq(t, h, "PATCH", c.path, testToken, c.body); rec.Code != 200 {
			t.Fatalf("PATCH %s %s: %d %s", c.path, c.body, rec.Code, rec.Body)
		}
	}
	// With the caller's password, the promotion and the reset go through.
	stepUp := func() string { return `"currentPassword":"` + testAdminPassword + `"` + seededAdminTOTP(t) }
	if rec := doReq(t, h, "PATCH", "/api/users/alice", testToken, `{"role":"admin",`+stepUp()+`}`); rec.Code != 200 {
		t.Fatalf("promotion with step-up: %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "PATCH", "/api/users/bob", testToken, `{"password":"bob-new-pw",`+stepUp()+`}`); rec.Code != 200 {
		t.Fatalf("admin password with step-up: %d %s", rec.Code, rec.Body)
	}
}

func TestClearingAnAdminsFactorNeedsTheStepUp(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	alice := seedUser(t, um, "alice")
	if _, err := um.CreateUser("bob", "bob-pw", metadb.RoleAdmin, metadb.Settings{}); err != nil {
		t.Fatal(err)
	}
	bob, code := login(t, h, "bob", "bob-pw")
	if code != 200 {
		t.Fatalf("login bob: %d", code)
	}
	enableTOTP(t, h, bob, "bob-pw")
	wantStepUpRequired(t, "no body", doReq(t, h, "DELETE", "/api/users/bob/totp", testToken, ""))
	if u, _ := um.User("bob"); !u.TwoFactorEnabled() {
		t.Fatal("a refused reset still cleared the factor")
	}
	if rec := doReq(t, h, "DELETE", "/api/users/bob/totp", testToken,
		`{"currentPassword":"`+testAdminPassword+`"`+seededAdminTOTP(t)+`}`); rec.Code != 200 {
		t.Fatalf("reset with step-up: %d %s", rec.Code, rec.Body)
	}
	// A user's factor is still the lost-phone answer, bearer token alone.
	enableTOTP(t, h, alice, "alice-pw")
	if rec := doReq(t, h, "DELETE", "/api/users/alice/totp", testToken, ""); rec.Code != 200 {
		t.Fatalf("reset a user's factor: %d %s", rec.Code, rec.Body)
	}
}

// TestAStolenAdminTokenCannotReachTheUpdateRoute drives the whole escalation
// the step-up exists to stop: with nothing but an admin's bearer token, mint
// an admin whose password and factor the token holder chose, then stage a
// binary as that admin. The chain has to break at the first step.
func TestAStolenAdminTokenCannotReachTheUpdateRoute(t *testing.T) {
	h, dir := updateAPI(t)
	enableTOTP(t, h, testToken, testAdminPassword)
	stolen := testToken

	rec := doReq(t, h, "POST", "/api/users", stolen, `{"username":"mallory","password":"mallory-pw","role":"admin"}`)
	wantStepUpRequired(t, "mint an admin", rec)
	if _, code := login(t, h, "mallory", "mallory-pw"); code == 200 {
		t.Fatal("the minted admin can sign in")
	}
	// The same token through the other doors: a user promoted, the real
	// admin re-passworded.
	doReq(t, h, "POST", "/api/users", stolen, `{"username":"mallory","password":"mallory-pw","quotaBytes":1}`)
	wantStepUpRequired(t, "promote", doReq(t, h, "PATCH", "/api/users/mallory", stolen, `{"role":"admin"}`))
	wantStepUpRequired(t, "re-password the admin", doReq(t, h, "PATCH", "/api/users/admin", stolen, `{"password":"mallory-pw"}`))

	mallory, code := login(t, h, "mallory", "mallory-pw")
	if code != 200 {
		t.Fatalf("login mallory: %d", code)
	}
	secret, _ := enableTOTP(t, h, mallory, "mallory-pw")
	if rec := postUpdate(t, h, mallory, "mallory-pw", nextCode(t, secret), elfBody(64)); rec.Code != 403 {
		t.Fatalf("a user account on the update route: %d %s, want 403", rec.Code, rec.Body)
	}
	assertNothingStaged(t, dir)
}

// Every route that needs the caller's own password refuses a request without
// one the same way, so a client asks for it the same way everywhere.
func TestEveryRouteRefusesAMissingPasswordAsStepUpRequired(t *testing.T) {
	h := newTestAPI(t)
	wantStepUpRequired(t, "POST /api/me/totp", doReq(t, h, "POST", "/api/me/totp", testToken, `{}`))
	// New recovery codes have something to do only once a factor is on.
	enableTOTP(t, h, testToken, testAdminPassword)
	for _, c := range []struct{ method, path, body string }{
		{"POST", "/api/me/totp/recovery", `{"code":"123456"}`},
		{"PATCH", "/api/me/password", `{"password":"brand-new-pass"}`},
		{"PUT", "/api/connectivity", `{"config":{"mode":"external","domain":"share.example.com"}}`},
		{"POST", "/api/users", `{"username":"carol","role":"admin"}`},
		{"PUT", "/api/ddns", `{"name":"mynas"}`},
		{"PATCH", "/api/server/settings", `{"desktopSignIn":false}`},
	} {
		wantStepUpRequired(t, c.method+" "+c.path, doReqBare(t, h, c.method, c.path, testToken, c.body))
	}
}
