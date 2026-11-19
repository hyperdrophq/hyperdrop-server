package api

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"hyperdrop/server/internal/metadb"
)

// newMultiUserAPI is the fixture for account-aware tests: handler + the
// database (to tweak accounts directly) + the backend it serves from.
func newMultiUserAPI(t *testing.T) (http.Handler, *metadb.DB, Backend) {
	t.Helper()
	b := testBackend(t)
	return New(b, "2.0.0", testDomain(t), nil), b.DB, b
}

func login(t *testing.T, h http.Handler, user, pw string) (string, int) {
	t.Helper()
	rec := doReq(t, h, "POST", "/api/auth/login", "",
		fmt.Sprintf(`{"username":%q,"password":%q}`, user, pw))
	// The seeded admin answers the code question the way an app does.
	if user == metadb.DefaultAdminName && rec.Code == 401 && errCode(t, rec.Body.String()) == "totp-required" {
		rec = doReq(t, h, "POST", "/api/auth/login", "",
			fmt.Sprintf(`{"username":%q,"password":%q%s}`, user, pw, seededAdminTOTP(t)))
	}
	if rec.Code != 200 {
		return "", rec.Code
	}
	var out struct {
		Token string `json:"token"`
	}
	unmarshal(t, rec, &out)
	return out.Token, rec.Code
}

func TestLoginMintsWorkingToken(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	token, code := login(t, h, "admin", testAdminPassword)
	if code != 200 || !strings.HasPrefix(token, "hd_u_") {
		t.Fatalf("login: code=%d token=%q", code, token)
	}
	if rec := doReq(t, h, "GET", "/api/shares", token, ""); rec.Code != 200 {
		t.Fatalf("minted token rejected: %d %s", rec.Code, rec.Body)
	}
}

func TestLoginWrongPassword(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	if _, code := login(t, h, "admin", "nope"); code != 401 {
		t.Fatalf("wrong password: %d, want 401", code)
	}
	if _, code := login(t, h, "ghost", "nope"); code != 401 {
		t.Fatalf("unknown user must look identical: %d, want 401", code)
	}
}

func TestLoginLockout(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	for range 10 {
		login(t, h, "admin", "wrong")
	}
	// Even the CORRECT password is refused while blocked.
	if _, code := login(t, h, "admin", testAdminPassword); code != 429 {
		t.Fatalf("after 10 failures: %d, want 429", code)
	}
}

func TestBadTokenRejected(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	if rec := doReq(t, h, "GET", "/api/shares", "hd_u_bogus", ""); rec.Code != 401 {
		t.Fatalf("bogus token: %d, want 401", rec.Code)
	}
	if rec := doReq(t, h, "GET", "/api/shares", "", ""); rec.Code != 401 {
		t.Fatalf("no token: %d, want 401", rec.Code)
	}
}

func TestDisabledUserTokenRejected(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	tok := seedUser(t, um, "alice")
	yes := true
	if _, err := um.UpdateUser("alice", metadb.Settings{Disabled: &yes}); err != nil {
		t.Fatal(err)
	}
	if rec := doReq(t, h, "GET", "/api/shares", tok, ""); rec.Code != 403 {
		t.Fatalf("disabled user's token: %d, want 403", rec.Code)
	}
	if _, code := login(t, h, "alice", "alice-pw"); code != 403 {
		t.Fatalf("disabled login: %d, want 403", code)
	}
}

func TestMeReportsUsage(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	tok := seedUser(t, um, "alice")
	rec := doReq(t, h, "POST", "/api/shares", tok, `{"name":"mine"}`)
	var created struct {
		ID string `json:"id"`
	}
	unmarshal(t, rec, &created)
	doReq(t, h, "PUT", "/api/shares/"+created.ID+"/files/a.txt", tok, "12345")

	rec = doReq(t, h, "GET", "/api/me", tok, "")
	if rec.Code != 200 {
		t.Fatalf("me: %d %s", rec.Code, rec.Body)
	}
	var me struct {
		Username   string `json:"username"`
		Role       string `json:"role"`
		UsedBytes  int64  `json:"usedBytes"`
		ShareCount int    `json:"shareCount"`
	}
	unmarshal(t, rec, &me)
	if me.Username != "alice" || me.Role != "user" || me.UsedBytes != 5 || me.ShareCount != 1 {
		t.Fatalf("me = %+v", me)
	}
}

// A wrong current password is refused with the code every client words as
// "That is not your password", on each route that asks for it.
func TestAWrongCurrentPasswordIsCodedWrongPassword(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	tok := seedUser(t, um, "alice")
	for _, c := range []struct{ method, path, body string }{
		{"PATCH", "/api/me/password", `{"currentPassword":"nope","password":"brand-new"}`},
		{"POST", "/api/me/totp", `{"currentPassword":"nope"}`},
	} {
		rec := doReq(t, h, c.method, c.path, tok, c.body)
		if rec.Code != 401 || !strings.Contains(rec.Body.String(), `"code":"wrong-password"`) ||
			!strings.Contains(rec.Body.String(), "the current password is wrong") {
			t.Fatalf("%s %s: %d %s", c.method, c.path, rec.Code, rec.Body)
		}
	}
}

func TestChangePasswordRevokesTokens(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	tok := seedUser(t, um, "alice")
	rec := doReq(t, h, "PATCH", "/api/me/password", tok, `{"currentPassword":"alice-pw","password":"brand-new"}`)
	if rec.Code != 200 {
		t.Fatalf("password change: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Token string `json:"token"`
	}
	unmarshal(t, rec, &out)
	if rec := doReq(t, h, "GET", "/api/me", tok, ""); rec.Code != 401 {
		t.Fatalf("old token after password change: %d, want 401", rec.Code)
	}
	if rec := doReq(t, h, "GET", "/api/me", out.Token, ""); rec.Code != 200 {
		t.Fatalf("replacement token: %d", rec.Code)
	}
	if _, code := login(t, h, "alice", "brand-new"); code != 200 {
		t.Fatalf("new password login: %d", code)
	}
}

func TestLogoutRevokesCallingToken(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	tok := seedUser(t, um, "alice")
	if rec := doReq(t, h, "DELETE", "/api/auth/token", tok, ""); rec.Code != 204 {
		t.Fatalf("logout: %d", rec.Code)
	}
	if rec := doReq(t, h, "GET", "/api/me", tok, ""); rec.Code != 401 {
		t.Fatalf("token after logout: %d, want 401", rec.Code)
	}
}

func TestUsageAndDomainAdminOnly(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	tok := seedUser(t, um, "alice")
	if rec := doReq(t, h, "GET", "/api/usage", tok, ""); rec.Code != 403 {
		t.Fatalf("user /api/usage: %d, want 403", rec.Code)
	}
	if rec := doReq(t, h, "GET", "/api/domain", tok, ""); rec.Code != 403 {
		t.Fatalf("user /api/domain: %d, want 403", rec.Code)
	}
	if rec := doReq(t, h, "GET", "/api/usage", testToken, ""); rec.Code != 200 {
		t.Fatalf("admin /api/usage: %d", rec.Code)
	}
}
