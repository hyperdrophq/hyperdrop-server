package api

import (
	"errors"
	"strings"
	"testing"

	"hyperdrop/server/internal/metadb"
)

func TestCreateUserGeneratedPassword(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	rec := doReq(t, h, "POST", "/api/users", testToken, `{"username":"carol","quotaBytes":1024}`)
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Password string `json:"password"`
		User     struct {
			Username   string `json:"username"`
			Role       string `json:"role"`
			QuotaBytes int64  `json:"quotaBytes"`
		} `json:"user"`
	}
	unmarshal(t, rec, &out)
	if len(out.Password) != 16 {
		t.Fatalf("generated password: %q", out.Password)
	}
	if out.User.Role != "user" || out.User.QuotaBytes != 1024 {
		t.Fatalf("user: %+v", out.User)
	}
	if _, code := login(t, h, "carol", out.Password); code != 200 {
		t.Fatalf("login with generated password: %d", code)
	}
}

func TestCreateUserExplicitPassword(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	rec := doReq(t, h, "POST", "/api/users", testToken, `{"username":"carol","password":"chosen-one","quotaBytes":1024}`)
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "chosen-one") {
		t.Fatal("explicit password echoed back")
	}
	if _, code := login(t, h, "carol", "chosen-one"); code != 200 {
		t.Fatalf("login: %d", code)
	}
}

func TestCreateUserValidation(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	if rec := doReq(t, h, "POST", "/api/users", testToken, `{"username":"Bad Name"}`); rec.Code != 400 {
		t.Fatalf("bad name: %d", rec.Code)
	}
	doReq(t, h, "POST", "/api/users", testToken, `{"username":"carol","quotaBytes":1024}`)
	if rec := doReq(t, h, "POST", "/api/users", testToken, `{"username":"carol","quotaBytes":1024}`); rec.Code != 409 {
		t.Fatalf("duplicate: %d, want 409", rec.Code)
	}
	if rec := doReq(t, h, "POST", "/api/users", testToken, `{"username":"neg","quotaBytes":-5}`); rec.Code != 400 {
		t.Fatalf("negative quota: %d", rec.Code)
	}
}

func TestListUsersIncludesUsage(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	alice := seedUser(t, um, "alice")
	id := createShareAs(t, h, alice, `{"name":"x"}`)
	doReq(t, h, "PUT", "/api/shares/"+id+"/files/a.txt", alice, "1234")

	rec := doReq(t, h, "GET", "/api/users", testToken, "")
	var out struct {
		Users []struct {
			Username  string `json:"username"`
			UsedBytes int64  `json:"usedBytes"`
		} `json:"users"`
	}
	unmarshal(t, rec, &out)
	if len(out.Users) != 2 { // admin + alice
		t.Fatalf("users: %+v", out.Users)
	}
	for _, u := range out.Users {
		if u.Username == "alice" && u.UsedBytes != 4 {
			t.Fatalf("alice usage: %+v", u)
		}
	}
}

func TestUserListingReportsTwoFactorEnabled(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	alice := seedUser(t, um, "alice")

	twoFactorOf := func() map[string]bool {
		rec := doReq(t, h, "GET", "/api/users", testToken, "")
		var out struct {
			Users []struct {
				Username         string `json:"username"`
				TwoFactorEnabled bool   `json:"twoFactorEnabled"`
			} `json:"users"`
		}
		unmarshal(t, rec, &out)
		m := map[string]bool{}
		for _, u := range out.Users {
			m[u.Username] = u.TwoFactorEnabled
		}
		return m
	}

	if m := twoFactorOf(); m["alice"] {
		t.Fatalf("alice reports 2FA before enrolling: %+v", m)
	}
	enableTOTP(t, h, alice, "alice-pw")
	if m := twoFactorOf(); !m["alice"] {
		t.Fatalf("alice's confirmed 2FA not reported: %+v", m)
	}
	if m := twoFactorOf(); m["admin"] {
		t.Fatalf("admin reports 2FA without enrolling: %+v", m)
	}
}

func TestAnUnconfirmedEnrollmentListsAsOff(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	alice := seedUser(t, um, "alice")
	if rec := doReq(t, h, "POST", "/api/me/totp", alice, `{"currentPassword":"alice-pw"}`); rec.Code != 200 {
		t.Fatalf("start enrollment: %d %s", rec.Code, rec.Body)
	}
	rec := doReq(t, h, "GET", "/api/users/alice", testToken, "")
	var out struct {
		TwoFactorEnabled bool `json:"twoFactorEnabled"`
	}
	unmarshal(t, rec, &out)
	if out.TwoFactorEnabled {
		t.Fatal("an enrollment the user never confirmed reads as ON")
	}
}

func TestSuspendViaPatchKillsAccess(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	alice := seedUser(t, um, "alice")
	rec := doReq(t, h, "PATCH", "/api/users/alice", testToken, `{"disabled":true}`)
	if rec.Code != 200 {
		t.Fatalf("suspend: %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "GET", "/api/me", alice, ""); rec.Code != 403 {
		t.Fatalf("suspended token: %d, want 403", rec.Code)
	}
	rec = doReq(t, h, "PATCH", "/api/users/alice", testToken, `{"disabled":false}`)
	if rec.Code != 200 {
		t.Fatalf("resume: %d", rec.Code)
	}
	if rec := doReq(t, h, "GET", "/api/me", alice, ""); rec.Code != 200 {
		t.Fatalf("resumed token: %d", rec.Code)
	}
}

func TestResetPassword(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	alice := seedUser(t, um, "alice")
	rec := doReq(t, h, "PATCH", "/api/users/alice", testToken, `{"resetPassword":true}`)
	if rec.Code != 200 {
		t.Fatalf("reset: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Password string `json:"password"`
	}
	unmarshal(t, rec, &out)
	if len(out.Password) != 16 {
		t.Fatalf("no generated password in reset response: %s", rec.Body)
	}
	if rec := doReq(t, h, "GET", "/api/me", alice, ""); rec.Code != 401 {
		t.Fatalf("old token after reset: %d, want 401", rec.Code)
	}
	if _, code := login(t, h, "alice", out.Password); code != 200 {
		t.Fatalf("login with reset password: %d", code)
	}
}

func TestAdminSetsChosenPassword(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	alice := seedUser(t, um, "alice")
	rec := doReq(t, h, "PATCH", "/api/users/alice", testToken, `{"password":"grape-stapler-9"}`)
	if rec.Code != 200 {
		t.Fatalf("set password: %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "grape-stapler-9") {
		t.Fatal("chosen password echoed back")
	}
	if rec := doReq(t, h, "GET", "/api/me", alice, ""); rec.Code != 401 {
		t.Fatalf("old token after password change: %d, want 401", rec.Code)
	}
	if _, code := login(t, h, "alice", "grape-stapler-9"); code != 200 {
		t.Fatalf("login with chosen password: %d", code)
	}
}

func TestChosenPasswordAndResetAreExclusive(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	seedUser(t, um, "alice")
	rec := doReq(t, h, "PATCH", "/api/users/alice", testToken,
		`{"resetPassword":true,"password":"grape-stapler-9"}`)
	if rec.Code != 400 {
		t.Fatalf("both resetPassword and password: %d %s, want 400", rec.Code, rec.Body)
	}
}

func TestAnEmptyPasswordFieldChangesNothing(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	alice := seedUser(t, um, "alice")
	if rec := doReq(t, h, "PATCH", "/api/users/alice", testToken, `{"password":""}`); rec.Code != 200 {
		t.Fatalf("empty password field: %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "GET", "/api/me", alice, ""); rec.Code != 200 {
		t.Fatalf("token revoked by a no-op patch: %d", rec.Code)
	}
	if _, code := login(t, h, "alice", "alice-pw"); code != 200 {
		t.Fatalf("old password after a no-op patch: %d", code)
	}
}

func TestDeleteUserRemovesTheirShares(t *testing.T) {
	h, um, st := newMultiUserAPI(t)
	alice := seedUser(t, um, "alice")
	aliceShare := createShareAs(t, h, alice, `{"name":"hers"}`)
	adminShare := createShareAs(t, h, testToken, `{"name":"mine"}`)

	if rec := doReq(t, h, "DELETE", "/api/users/alice", testToken, ""); rec.Code != 204 {
		t.Fatalf("delete user: %d %s", rec.Code, rec.Body)
	}
	if _, err := st.DB.Share(aliceShare); err == nil {
		t.Fatal("alice's share survived her deletion")
	}
	if _, err := st.DB.Share(adminShare); err != nil {
		t.Fatalf("admin's share deleted too: %v", err)
	}
	if rec := doReq(t, h, "GET", "/api/users/alice", testToken, ""); rec.Code != 404 {
		t.Fatalf("deleted user still listed: %d", rec.Code)
	}
}

func TestUsersRoutesAdminOnly(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	alice := seedUser(t, um, "alice")
	for _, c := range []struct{ method, path string }{
		{"GET", "/api/users"}, {"POST", "/api/users"},
		{"GET", "/api/users/alice"}, {"PATCH", "/api/users/alice"}, {"DELETE", "/api/users/alice"},
	} {
		if rec := doReq(t, h, c.method, c.path, alice, `{}`); rec.Code != 403 {
			t.Errorf("%s %s as user: %d, want 403", c.method, c.path, rec.Code)
		}
	}
}

func TestCreateUserWithRole(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	// An admin needs no quota decision: absent means no limit.
	rec := doReq(t, h, "POST", "/api/users", testToken, `{"username":"carol","role":"admin","currentPassword":"`+testAdminPassword+`"}`)
	if rec.Code != 201 {
		t.Fatalf("create admin: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Password string `json:"password"`
		User     struct {
			Role       string `json:"role"`
			QuotaBytes int64  `json:"quotaBytes"`
		} `json:"user"`
	}
	unmarshal(t, rec, &out)
	if out.User.Role != "admin" || out.User.QuotaBytes != 0 {
		t.Fatalf("admin: %+v", out.User)
	}
	// The new admin reaches an admin-only route.
	tok, code := login(t, h, "carol", out.Password)
	if code != 200 {
		t.Fatalf("login: %d", code)
	}
	if rec := doReq(t, h, "GET", "/api/users", tok, ""); rec.Code != 200 {
		t.Fatalf("new admin on /api/users: %d %s", rec.Code, rec.Body)
	}
	// A user still owes a quota, and an unknown role is refused by code.
	if rec := doReq(t, h, "POST", "/api/users", testToken, `{"username":"dave","role":"user"}`); rec.Code != 400 || !strings.Contains(rec.Body.String(), "quota-required") {
		t.Fatalf("user without quota: %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "POST", "/api/users", testToken, `{"username":"dave","role":"owner","quotaBytes":1}`); rec.Code != 400 || !strings.Contains(rec.Body.String(), "bad-role") {
		t.Fatalf("unknown role: %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "POST", "/api/users", testToken, `{"username":"dave","quotaBytes":1}`); rec.Code != 201 || !strings.Contains(rec.Body.String(), `"role":"user"`) {
		t.Fatalf("default role: %d %s", rec.Code, rec.Body)
	}
}

func TestPatchChangesTheRole(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	alice := seedUser(t, um, "alice")
	if rec := doReq(t, h, "GET", "/api/users", alice, ""); rec.Code != 403 {
		t.Fatalf("user on the admin route before promotion: %d", rec.Code)
	}
	rec := doReq(t, h, "PATCH", "/api/users/alice", testToken, `{"role":"admin","currentPassword":"`+testAdminPassword+`"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"role":"admin"`) {
		t.Fatalf("promote: %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "GET", "/api/users", alice, ""); rec.Code != 200 {
		t.Fatalf("promoted alice on the admin route: %d %s", rec.Code, rec.Body)
	}
	// The original admin is an ordinary account to the promoted one: its
	// limits are editable and it can be demoted by ANOTHER admin.
	rec = doReq(t, h, "PATCH", "/api/users/admin", alice, `{"quotaBytes":5,"role":"user"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"role":"user"`) {
		t.Fatalf("demote the first admin: %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "GET", "/api/users", testToken, ""); rec.Code != 403 {
		t.Fatalf("demoted admin still on the admin route: %d", rec.Code)
	}
	if rec := doReq(t, h, "PATCH", "/api/users/admin", alice, `{"role":"root"}`); rec.Code != 400 || !strings.Contains(rec.Body.String(), "bad-role") {
		t.Fatalf("unknown role on PATCH: %d %s", rec.Code, rec.Body)
	}
}

func TestAnAdminCannotLockThemselvesOut(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	for _, body := range []string{`{"role":"user"}`, `{"disabled":true}`, `{"accountExpiresAt":"2099-01-01T00:00:00Z"}`} {
		rec := doReq(t, h, "PATCH", "/api/users/admin", testToken, body)
		if rec.Code != 403 || !strings.Contains(rec.Body.String(), "self-target") {
			t.Fatalf("PATCH self %s: %d %s", body, rec.Code, rec.Body)
		}
	}
	if rec := doReq(t, h, "DELETE", "/api/users/admin", testToken, ""); rec.Code != 403 || !strings.Contains(rec.Body.String(), "self-target") {
		t.Fatalf("DELETE self: %d %s", rec.Code, rec.Body)
	}
	// Harmless self-edits go through: a limit, keeping the admin role, and
	// clearing an expiry.
	for _, body := range []string{`{"quotaBytes":10}`, `{"role":"admin","disabled":false}`, `{"clearAccountExpiry":true}`} {
		if rec := doReq(t, h, "PATCH", "/api/users/admin", testToken, body); rec.Code != 200 {
			t.Fatalf("PATCH self %s: %d %s", body, rec.Code, rec.Body)
		}
	}
	if rec := doReq(t, h, "GET", "/api/users", testToken, ""); rec.Code != 200 {
		t.Fatalf("admin lost after self-edits: %d", rec.Code)
	}
}

func TestAnotherAdminCanBeDeleted(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	if _, err := um.CreateUser("bob", "bob-pw", metadb.RoleAdmin, metadb.Settings{}); err != nil {
		t.Fatal(err)
	}
	if rec := doReq(t, h, "DELETE", "/api/users/bob", testToken, ""); rec.Code != 204 {
		t.Fatalf("delete another admin: %d %s", rec.Code, rec.Body)
	}
	if _, err := um.User("bob"); !errors.Is(err, metadb.ErrUserNotFound) {
		t.Fatalf("bob survived: %v", err)
	}
}
