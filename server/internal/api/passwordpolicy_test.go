package api

import (
	"net/http"
	"strings"
	"testing"

	"hyperdrop/server/internal/metadb"
)

// A chosen password is 8 to 72 bytes, refused 400 with a code on every route
// a person chooses one.
func TestAChosenPasswordIsEightToSeventyTwoBytes(t *testing.T) {
	h, db, _ := newMultiUserAPI(t)
	seedUser(t, db, "guest")
	long := strings.Repeat("x", 73)
	for _, tc := range []struct{ method, path, body, code string }{
		{"POST", "/api/users", `{"username":"newbie","password":"short","quotaBytes":0}`, "password-too-short"},
		{"POST", "/api/users", `{"username":"newbie","password":"` + long + `","quotaBytes":0}`, "password-too-long"},
		{"PATCH", "/api/users/guest", `{"password":"short"}`, "password-too-short"},
		{"PATCH", "/api/users/guest", `{"password":"` + long + `"}`, "password-too-long"},
		{"PATCH", "/api/me/password", `{"password":"short","currentPassword":"` + testAdminPassword + `"}`, "password-too-short"},
		{"PATCH", "/api/me/password", `{"password":"` + long + `","currentPassword":"` + testAdminPassword + `"}`, "password-too-long"},
	} {
		rec := doReq(t, h, tc.method, tc.path, testToken, tc.body)
		if rec.Code != http.StatusBadRequest || errCode(t, rec.Body.String()) != tc.code {
			t.Errorf("%s %s = %d %s, want 400 %s", tc.method, tc.path, rec.Code, rec.Body, tc.code)
		}
	}
	if _, err := db.User("newbie"); err == nil {
		t.Fatal("a refused create made the account")
	}
	for _, pw := range []string{"eight-ch", strings.Repeat("y", 72)} {
		if rec := doReq(t, h, "PATCH", "/api/users/guest", testToken, `{"password":"`+pw+`"}`); rec.Code != http.StatusOK {
			t.Fatalf("a %d-byte password = %d %s, want 200", len(pw), rec.Code, rec.Body)
		}
	}
}

// An edit that cannot set its password changes nothing else either.
func TestARefusedPasswordLeavesTheRestOfTheEditUnapplied(t *testing.T) {
	h, db, _ := newMultiUserAPI(t)
	seedUser(t, db, "guest")
	rec := doReq(t, h, "PATCH", "/api/users/guest", testToken, `{"password":"`+strings.Repeat("x", 80)+`","quotaBytes":5}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("edit = %d %s, want 400", rec.Code, rec.Body)
	}
	u, err := db.User("guest")
	if err != nil {
		t.Fatal(err)
	}
	if u.QuotaBytes != 0 {
		t.Fatalf("quota = %d after a refused edit, want it unchanged", u.QuotaBytes)
	}
	if rec := tryLogin(t, h, "guest", "guest-pw", ""); rec.Code != http.StatusOK {
		t.Fatalf("the old password after a refused edit = %d, want 200", rec.Code)
	}
}

// A password set before the rule, or by the installer, is never measured:
// the account signs in and changes it as before.
func TestAShortPasswordSetBeforeTheRuleStillSignsIn(t *testing.T) {
	h, db, _ := newMultiUserAPI(t)
	if _, err := db.CreateUser("oldie", "abc", metadb.RoleUser, metadb.Settings{}); err != nil {
		t.Fatal(err)
	}
	rec := tryLogin(t, h, "oldie", "abc", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("login with a short password set before the rule = %d %s", rec.Code, rec.Body)
	}
	var out struct{ Token string }
	unmarshal(t, rec, &out)
	if rec := doReq(t, h, "PATCH", "/api/me/password", out.Token, `{"password":"a-longer-one","currentPassword":"abc"}`); rec.Code != http.StatusOK {
		t.Fatalf("changing it with the short one as the current = %d %s", rec.Code, rec.Body)
	}
}

// A share password longer than bcrypt reads is 400 password-too-long on every
// route that sets one, never a 500; 72 bytes and a short one are accepted,
// since a share password has no minimum.
func TestASharePasswordOverSeventyTwoBytesIsRefused(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	id := createShare(t, h, "kept")
	live := createLiveShare(t, h, testToken, liveShareCreateBodyOne)
	long := strings.Repeat("x", 73)
	for _, tc := range []struct{ method, path, body string }{
		{"POST", "/api/shares", `{"name":"new","password":"` + long + `"}`},
		{"PATCH", "/api/shares/" + id, `{"password":"` + long + `"}`},
		{"POST", "/api/shares/edit", `{"ids":["` + id + `"],"password":"` + long + `"}`},
		{"POST", "/api/live-share", `{"name":"demo","password":"` + long + `","files":[{"path":"a.txt","size":5,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"}]}`},
		{"PATCH", "/api/live-share/" + live.ID, `{"password":"` + long + `"}`},
	} {
		rec := doReq(t, h, tc.method, tc.path, testToken, tc.body)
		if rec.Code != http.StatusBadRequest || errCode(t, rec.Body.String()) != "password-too-long" {
			t.Errorf("%s %s = %d %s, want 400 password-too-long", tc.method, tc.path, rec.Code, rec.Body)
		}
	}
	for _, pw := range []string{"1", strings.Repeat("y", 72)} {
		if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"password":"`+pw+`"}`); rec.Code != http.StatusOK {
			t.Errorf("a %d-byte share password = %d %s, want 200", len(pw), rec.Code, rec.Body)
		}
	}
}
