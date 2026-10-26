package api

import (
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/metadb"
)

// Every /api route registered in api.go has a cookie class, and every class
// names a route that exists. A route left out is refused to a web session
// (the zero class), so the failure this catches is a web feature that cannot
// work, and the stale-entry half keeps a renamed route from leaving a
// decision about a path nothing serves.
func TestEveryAPIRouteIsClassifiedForCookies(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range registeredRoutes(t) {
		if !strings.HasPrefix(r.Pattern, "/api/") {
			continue
		}
		key := r.Method + " " + r.Pattern
		seen[key] = true
		if _, ok := cookieRoutes[key]; !ok {
			t.Errorf("route %q is registered in api.go but has no entry in cookieRoutes (cookieroutes.go): add %q: cookieJSON "+
				"when it answers JSON the web client may call, cookieBytes when it answers file bytes, or cookieNever "+
				"when it mints or answers a bearer token or exists for installed apps alone", key, key)
		}
	}
	for key := range cookieRoutes {
		if !seen[key] {
			t.Errorf("cookieRoutes names %q, which api.go does not register: remove or rename the entry", key)
		}
	}
}

// signInAs signs name in on the web and answers the session cookie's value.
func (f webFixture) signInAs(t *testing.T, name, password string) string {
	t.Helper()
	rec := f.req(t, "POST", "/api/web/session", "", `{"username":"`+name+`","password":"`+password+`"}`)
	if rec.Code != 200 {
		t.Fatalf("web sign-in as %s: %d %s", name, rec.Code, rec.Body)
	}
	return webCookieOf(t, rec)
}

func TestCookieSessionRefusedOnByteRoutes(t *testing.T) {
	f := newWebFixture(t, true)
	raw := f.signIn(t, false)
	for _, key := range []string{
		"GET /api/sources/file",
		"GET /api/shares/{id}/poster",
		"GET /api/shares/{id}/thumbs/{slug}",
		"GET /api/admin/log",
	} {
		if cookieRoutes[key] != cookieBytes {
			t.Errorf("%s is not classified cookieBytes", key)
		}
		method, pattern, _ := strings.Cut(key, " ")
		rec := f.req(t, method, samplePath(pattern), raw, "")
		if rec.Code != 401 || errCode(t, rec.Body.String()) != "web-session-refused" {
			t.Errorf("%s with a web session: %d %s, want 401 web-session-refused", key, rec.Code, rec.Body)
		}
	}
	// The owner's poster: refused to the owner's web session, served to the
	// owner's device token.
	id := createShare(t, f.h, "shot")
	if code := putPoster(t, f.h, id, posterJPEG(t, "frame")); code != 204 {
		t.Fatalf("PUT poster = %d", code)
	}
	admin := f.signInAs(t, metadb.DefaultAdminName, testAdminPassword)
	if rec := f.req(t, "GET", "/api/shares/"+id+"/poster", admin, ""); rec.Code != 401 || errCode(t, rec.Body.String()) != "web-session-refused" {
		t.Errorf("the owner's web session on its poster: %d %s, want 401 web-session-refused", rec.Code, rec.Body)
	}
	rec := doReq(t, f.h, "GET", "/api/shares/"+id+"/poster", testToken, "")
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "image/jpeg" || !strings.Contains(rec.Body.String(), "frame") {
		t.Fatalf("the owner's device token on its poster: %d %q, want 200 and the JPEG", rec.Code, rec.Header().Get("Content-Type"))
	}
}

// The routes that answer no JSON a browser may hold refuse a web session
// before it is looked up. The unauthenticated ones read no cookie at all.
func TestCookieSessionRefusedOnNeverRoutes(t *testing.T) {
	unauthenticated := map[string]bool{
		"POST /api/auth/login":             true,
		"POST /api/auth/invite":            true,
		"POST /api/auth/device-link/claim": true,
		"POST /api/auth/device-link/poll":  true,
	}
	for _, key := range []string{
		"POST /api/me/device-links",
		"GET /api/me/device-links/{id}",
		"POST /api/me/device-links/{id}/renew",
		"POST /api/me/device-links/{id}/approve",
		"POST /api/me/device-links/{id}/deny",
		"GET /api/me/push",
		"PUT /api/me/push",
		"DELETE /api/me/push",
		"PUT /api/me/activity",
		"POST /api/server/update",
		"DELETE /api/auth/token",
	} {
		if cookieRoutes[key] != cookieNever {
			t.Errorf("%s is not classified cookieNever", key)
		}
	}
	f := newWebFixture(t, true)
	user := f.signIn(t, false)
	admin := f.signInAs(t, metadb.DefaultAdminName, testAdminPassword)
	for key, class := range cookieRoutes {
		if class == cookieJSON || unauthenticated[key] {
			continue
		}
		method, pattern, _ := strings.Cut(key, " ")
		for _, raw := range []string{user, admin} {
			rec := f.req(t, method, samplePath(pattern), raw, "")
			if rec.Code != 401 || errCode(t, rec.Body.String()) != "web-session-refused" {
				t.Errorf("%s with a web session: %d %s, want 401 web-session-refused", key, rec.Code, rec.Body)
			}
		}
	}
	// The refusals left both sessions signed in.
	for name, raw := range map[string]string{"user": user, "admin": admin} {
		if rec := f.req(t, "GET", "/api/me", raw, ""); rec.Code != 200 {
			t.Errorf("the %s's session after the refusals: %d %s", name, rec.Code, rec.Body)
		}
	}
}

func TestAdminWriteNeedsElevation(t *testing.T) {
	f := newWebFixture(t, true)
	raw := f.signInAs(t, metadb.DefaultAdminName, testAdminPassword)
	rec := f.req(t, "PATCH", "/api/users/alice", raw, `{}`)
	if rec.Code != 403 || errCode(t, rec.Body.String()) != "web-elevation-required" {
		t.Fatalf("an admin write from an unelevated session: %d %s, want 403 web-elevation-required", rec.Code, rec.Body)
	}
	if rec := f.req(t, "POST", "/api/web/session/elevate", raw, `{"currentPassword":"`+testAdminPassword+`"}`); rec.Code != 200 {
		t.Fatalf("elevate: %d %s", rec.Code, rec.Body)
	}
	if rec := f.req(t, "PATCH", "/api/users/alice", raw, `{}`); rec.Code != 200 {
		t.Fatalf("an admin write from an elevated session: %d %s, want 200", rec.Code, rec.Body)
	}
	// An elevation that has run out asks again.
	execRaw(t, f.dir, `UPDATE tokens SET elevated_until = ? WHERE kind = 'web'`, time.Now().Add(-time.Second).UnixNano())
	if rec := f.req(t, "PATCH", "/api/users/alice", raw, `{}`); rec.Code != 403 || errCode(t, rec.Body.String()) != "web-elevation-required" {
		t.Fatalf("an admin write after the elevation ran out: %d %s, want 403 web-elevation-required", rec.Code, rec.Body)
	}
	// A device token needs no elevation.
	if rec := doReq(t, f.h, "PATCH", "/api/users/alice", testToken, `{}`); rec.Code != 200 {
		t.Fatalf("an admin write with a bearer: %d %s, want 200", rec.Code, rec.Body)
	}
	// A user's session is refused as a non-admin, not asked to elevate.
	user := f.signIn(t, false)
	if rec := f.req(t, "PATCH", "/api/users/alice", user, `{}`); rec.Code != 403 || errCode(t, rec.Body.String()) != "" {
		t.Fatalf("a user's session on an admin write: %d %s, want 403 admin only", rec.Code, rec.Body)
	}
}

// One admin change from the web never needs two codes: an elevated session
// is asked the password alone by a route's own step-up, while a device
// token and a session whose elevation ran out are asked the code.
func TestElevatedWebAdminIsAskedThePasswordAlone(t *testing.T) {
	f := newWebFixture(t, true)
	raw := f.signInAs(t, metadb.DefaultAdminName, testAdminPassword)
	secret, _ := enableTOTP(t, f.h, testToken, testAdminPassword)
	newAdmin := func(name string) string {
		return `{"username":"` + name + `","password":"carol-password-1","role":"admin","currentPassword":"` + testAdminPassword + `"}`
	}
	if rec := f.req(t, "POST", "/api/users", raw, newAdmin("carol")); rec.Code != 403 || errCode(t, rec.Body.String()) != "web-elevation-required" {
		t.Fatalf("an unelevated session: %d %s, want 403 web-elevation-required", rec.Code, rec.Body)
	}
	// The elevation itself asks the code.
	if rec := f.req(t, "POST", "/api/web/session/elevate", raw, `{"currentPassword":"`+testAdminPassword+`"}`); rec.Code != 401 || errCode(t, rec.Body.String()) != "totp-required" {
		t.Fatalf("elevate without the code: %d %s, want 401 totp-required", rec.Code, rec.Body)
	}
	if rec := f.req(t, "POST", "/api/web/session/elevate", raw, `{"currentPassword":"`+testAdminPassword+`","totp":"`+nextCode(t, secret)+`"}`); rec.Code != 200 {
		t.Fatalf("elevate: %d %s", rec.Code, rec.Body)
	}
	if rec := f.req(t, "POST", "/api/users", raw, newAdmin("carol")); rec.Code != 201 {
		t.Fatalf("an elevated session creating an admin with the password alone: %d %s", rec.Code, rec.Body)
	}
	// The password is still checked.
	wrong := `{"username":"dave","password":"dave-password-1","role":"admin","currentPassword":"wrong"}`
	if rec := f.req(t, "POST", "/api/users", raw, wrong); rec.Code != 401 || errCode(t, rec.Body.String()) != "wrong-password" {
		t.Fatalf("an elevated session with a wrong password: %d %s, want 401 wrong-password", rec.Code, rec.Body)
	}
	// Re-elevating an elevated session still asks the code.
	if rec := f.req(t, "POST", "/api/web/session/elevate", raw, `{"currentPassword":"`+testAdminPassword+`"}`); rec.Code != 401 || errCode(t, rec.Body.String()) != "totp-required" {
		t.Fatalf("re-elevating without the code: %d %s, want 401 totp-required", rec.Code, rec.Body)
	}
	// A device token is asked the code.
	if rec := doReq(t, f.h, "POST", "/api/users", testToken, newAdmin("erin")); rec.Code != 401 || errCode(t, rec.Body.String()) != "totp-required" {
		t.Fatalf("a bearer admin without the code: %d %s, want 401 totp-required", rec.Code, rec.Body)
	}
	// Past its ten minutes the session is asked to elevate again, and a
	// route's own step-up asks it the code.
	execRaw(t, f.dir, `UPDATE tokens SET elevated_until = ? WHERE kind = 'web'`, time.Now().Add(-time.Second).UnixNano())
	if rec := f.req(t, "POST", "/api/users", raw, newAdmin("frank")); rec.Code != 403 || errCode(t, rec.Body.String()) != "web-elevation-required" {
		t.Fatalf("an elevation that ran out: %d %s, want 403 web-elevation-required", rec.Code, rec.Body)
	}
	change := `{"password":"admin-new-password-2","currentPassword":"` + testAdminPassword + `","signOutOthers":false}`
	if rec := f.req(t, "PATCH", "/api/me/password", raw, change); rec.Code != 401 || errCode(t, rec.Body.String()) != "totp-required" {
		t.Fatalf("a step-up after the elevation ran out: %d %s, want 401 totp-required", rec.Code, rec.Body)
	}
}

// The elevation spares the code only inside admin routes: an elevated
// session's own-account step-ups still ask it.
func TestElevationSparesTheCodeOnlyOnAdminRoutes(t *testing.T) {
	f := newWebFixture(t, true)
	raw := f.signInAs(t, metadb.DefaultAdminName, testAdminPassword)
	secret, _ := enableTOTP(t, f.h, testToken, testAdminPassword)
	if rec := f.req(t, "POST", "/api/web/session/elevate", raw, `{"currentPassword":"`+testAdminPassword+`","totp":"`+nextCode(t, secret)+`"}`); rec.Code != 200 {
		t.Fatalf("elevate: %d %s", rec.Code, rec.Body)
	}
	pw := `"currentPassword":"` + testAdminPassword + `"`
	for _, c := range []struct{ method, path, body string }{
		{"DELETE", "/api/me/totp", `{` + pw + `}`},
		{"POST", "/api/me/totp/recovery", `{` + pw + `}`},
		{"PATCH", "/api/me/password", `{"password":"admin-new-password-2",` + pw + `,"signOutOthers":false}`},
	} {
		if rec := f.req(t, c.method, c.path, raw, c.body); rec.Code != 401 || errCode(t, rec.Body.String()) != "totp-required" {
			t.Errorf("%s %s from an elevated session without a code: %d %s, want 401 totp-required", c.method, c.path, rec.Code, rec.Body)
		}
	}
	if rec := f.req(t, "GET", "/api/me/totp", raw, ""); !strings.Contains(rec.Body.String(), `"enabled":true`) {
		t.Fatalf("the second factor after the refusals: %s", rec.Body)
	}
	// The same session's admin change takes the password alone.
	body := `{"username":"carol","password":"carol-password-1","role":"admin",` + pw + `}`
	if rec := f.req(t, "POST", "/api/users", raw, body); rec.Code != 201 {
		t.Fatalf("an admin change from the elevated session: %d %s, want 201", rec.Code, rec.Body)
	}
	// The caller's own password never changes through the users route from
	// a web session, elevated or not (TestSelfPasswordFromWebUsersRouteRefused).
	own := `{"password":"admin-new-password-3",` + pw + `}`
	if rec := f.req(t, "PATCH", "/api/users/"+metadb.DefaultAdminName, raw, own); rec.Code != 403 || errCode(t, rec.Body.String()) != "use-change-password" {
		t.Fatalf("the own password through the users route: %d %s, want 403 use-change-password", rec.Code, rec.Body)
	}
	if _, err := f.db.Authenticate(metadb.DefaultAdminName, testAdminPassword); err != nil {
		t.Fatalf("the own password changed: %v", err)
	}
	// Another admin's password takes the elevated session's password alone.
	other := `{"password":"carol-new-password-2",` + pw + `}`
	if rec := f.req(t, "PATCH", "/api/users/carol", raw, other); rec.Code != 200 {
		t.Fatalf("another admin's password from the elevated session: %d %s, want 200", rec.Code, rec.Body)
	}
	if _, err := f.db.Authenticate("carol", "carol-new-password-2"); err != nil {
		t.Fatalf("carol's new password: %v", err)
	}
}

// A web session revoking its own row from the device list is signed out,
// and the answer clears its cookie.
func TestRevokingTheOwnWebSessionClearsTheCookie(t *testing.T) {
	f := newWebFixture(t, true)
	raw := f.signIn(t, false)
	tok, ok := sessionRow(t, f, raw)
	if !ok {
		t.Fatal("no row for the session")
	}
	rec := f.req(t, "DELETE", "/api/me/tokens/"+tok.ID, raw, "")
	if rec.Code != 204 {
		t.Fatalf("revoking the own session: %d %s", rec.Code, rec.Body)
	}
	wantCookieCleared(t, rec)
	if rec := f.req(t, "GET", "/api/me", raw, ""); rec.Code != 401 {
		t.Fatalf("the session after revoking it: %d, want 401", rec.Code)
	}
	// Revoking a device's row leaves the session's cookie alone.
	other := f.signIn(t, true)
	execRaw(t, f.dir, `UPDATE tokens SET created_at = ? WHERE kind = 'web'`, time.Now().Add(-48*time.Hour).UnixNano())
	u, err := f.db.User("alice")
	if err != nil {
		t.Fatal(err)
	}
	device := tokenNamed(u, metadb.TokenHash(f.aliceDevice))
	rec = f.req(t, "DELETE", "/api/me/tokens/"+device.ID, other, "")
	if rec.Code != 204 || len(rec.Header().Values("Set-Cookie")) != 0 {
		t.Fatalf("revoking a device: %d %s %v", rec.Code, rec.Body, rec.Header().Values("Set-Cookie"))
	}
}

func TestAdminReadWithoutElevation(t *testing.T) {
	f := newWebFixture(t, true)
	raw := f.signInAs(t, metadb.DefaultAdminName, testAdminPassword)
	for _, path := range []string{"/api/users", "/api/users/alice", "/api/server/settings", "/api/usage", "/api/domain"} {
		if rec := f.req(t, "GET", path, raw, ""); rec.Code != 200 {
			t.Errorf("GET %s from an unelevated admin session: %d %s, want 200", path, rec.Code, rec.Body)
		}
	}
}

func TestPasswordChangeFromWebAnswersNoToken(t *testing.T) {
	f := newWebFixture(t, true)
	old := f.signIn(t, true)
	signedIn := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
	execRaw(t, f.dir, `UPDATE tokens SET created_at = ? WHERE sha256 = ?`, signedIn.UnixNano(), metadb.WebSessionHash(old))
	const next = "alice-new-password-2"
	rec := f.req(t, "PATCH", "/api/me/password", old, `{"password":"`+next+`","currentPassword":"alice-pw"}`)
	if rec.Code != 200 {
		t.Fatalf("password change: %d %s", rec.Code, rec.Body)
	}
	var out map[string]any
	unmarshal(t, rec, &out)
	if _, ok := out["token"]; ok || out["signedOutOthers"] != true || len(out) != 1 {
		t.Fatalf("answer %s, want {\"signedOutOthers\":true} and no token", rec.Body)
	}
	if strings.Contains(rec.Body.String(), "hd_") {
		t.Fatalf("the answer carries a credential: %s", rec.Body)
	}
	_, attrs := cookieAttributes(t, rec)
	if !containsAttr(attrs, "Max-Age=2592000") {
		t.Fatalf("a kept session's new cookie lacks its lifetime: %v", attrs)
	}
	fresh := webCookieOf(t, rec)
	if fresh == old {
		t.Fatal("the cookie was not re-issued")
	}
	if rec := f.req(t, "GET", "/api/me", old, ""); rec.Code != 401 {
		t.Fatalf("the old session after the change: %d, want 401", rec.Code)
	}
	if rec := doReq(t, f.h, "GET", "/api/me", f.aliceDevice, ""); rec.Code != 401 {
		t.Fatalf("the device token after the change: %d, want 401", rec.Code)
	}
	if rec := f.req(t, "GET", "/api/me", fresh, ""); rec.Code != 200 {
		t.Fatalf("the new session: %d %s", rec.Code, rec.Body)
	}
	tok, ok := sessionRow(t, f, fresh)
	if !ok || !tok.Keep || tok.Label != "Web browser · Chrome on Windows" {
		t.Fatalf("the new session row %+v (found %v)", tok, ok)
	}
	if !tok.CreatedAt.Equal(signedIn) {
		t.Fatalf("the new session signed in at %v, want the old session's %v", tok.CreatedAt, signedIn)
	}

	// Keeping the other devices signed in keeps the session and its cookie.
	rec = f.req(t, "PATCH", "/api/me/password", fresh, `{"password":"alice-new-password-3","currentPassword":"`+next+`","signOutOthers":false}`)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "token") || len(rec.Header().Values("Set-Cookie")) != 0 {
		t.Fatalf("a change keeping the devices: %d %s %v", rec.Code, rec.Body, rec.Header().Values("Set-Cookie"))
	}
	if rec := f.req(t, "GET", "/api/me", fresh, ""); rec.Code != 200 {
		t.Fatalf("the session after a change keeping the devices: %d", rec.Code)
	}
}

func containsAttr(attrs []string, want string) bool {
	for _, a := range attrs {
		if a == want {
			return true
		}
	}
	return false
}

// sessionRow is alice's token row for the web session raw.
func sessionRow(t *testing.T, f webFixture, raw string) (metadb.Token, bool) {
	t.Helper()
	u, err := f.db.User("alice")
	if err != nil {
		t.Fatal(err)
	}
	tok := tokenNamed(u, metadb.WebSessionHash(raw))
	return tok, tok.ID != ""
}

func TestCookieAnswersAreNoStore(t *testing.T) {
	f := newWebFixture(t, true)
	raw := f.signIn(t, false)
	for _, c := range []struct{ method, path string }{
		{"GET", "/api/me"},
		{"GET", "/api/shares"},
		{"GET", "/api/shares/Qx7mK2pR9v"},
		{"GET", "/api/me/tokens"},
		{"GET", "/api/web/session"},
		{"GET", "/api/sources/file"},
	} {
		rec := f.req(t, c.method, c.path, raw, "")
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s %s with a web session (%d): Cache-Control %q, want no-store", c.method, c.path, rec.Code, got)
		}
	}
	// A session that is gone still answers no-store.
	if rec := f.req(t, "GET", "/api/me", "hd_w_unknown", ""); rec.Code != 401 || rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("an unknown session: %d, Cache-Control %q", rec.Code, rec.Header().Get("Cache-Control"))
	}
	// A device token's answers are unchanged.
	if rec := doReq(t, f.h, "GET", "/api/me", f.aliceDevice, ""); rec.Header().Get("Cache-Control") == "no-store" {
		t.Error("a bearer answer carries no-store")
	}
}

// An admin's web session sets its own password through PATCH
// /api/me/password only: the users route would sign the browser out and
// answer an invite for the admin's own account. A bearer caller keeps it.
func TestSelfPasswordFromWebUsersRouteRefused(t *testing.T) {
	f := newWebFixture(t, true)
	raw := f.signInAs(t, metadb.DefaultAdminName, testAdminPassword)
	if rec := f.req(t, "POST", "/api/web/session/elevate", raw, `{"currentPassword":"`+testAdminPassword+`"}`); rec.Code != 200 {
		t.Fatalf("elevate: %d %s", rec.Code, rec.Body)
	}
	self := "/api/users/" + metadb.DefaultAdminName
	for _, body := range []string{
		`{"password":"admin-new-password-1","currentPassword":"` + testAdminPassword + `"}`,
		`{"resetPassword":true,"currentPassword":"` + testAdminPassword + `"}`,
	} {
		rec := f.req(t, "PATCH", self, raw, body)
		if rec.Code != 403 || errCode(t, rec.Body.String()) != "use-change-password" {
			t.Fatalf("%s from the web session: %d %s, want 403 use-change-password", body, rec.Code, rec.Body)
		}
	}
	if rec := f.req(t, "GET", "/api/me", raw, ""); rec.Code != 200 {
		t.Fatalf("the session after the refusals: %d", rec.Code)
	}
	if _, err := f.db.Authenticate(metadb.DefaultAdminName, testAdminPassword); err != nil {
		t.Fatalf("the password after the refusals: %v", err)
	}
	// The session's other edits of its own account, and its password edits
	// of another account, go through.
	if rec := f.req(t, "PATCH", self, raw, `{}`); rec.Code != 200 {
		t.Fatalf("an empty self edit: %d %s", rec.Code, rec.Body)
	}
	if rec := f.req(t, "PATCH", "/api/users/alice", raw, `{"password":"alice-new-password-1","currentPassword":"`+testAdminPassword+`"}`); rec.Code != 200 {
		t.Fatalf("another account's password: %d %s", rec.Code, rec.Body)
	}
	// A bearer sets its own password on this route.
	rec := doReq(t, f.h, "PATCH", self, testToken, `{"password":"admin-new-password-2","currentPassword":"`+testAdminPassword+`"}`)
	if rec.Code != 200 {
		t.Fatalf("a bearer's own password: %d %s", rec.Code, rec.Body)
	}
}
