package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"hyperdrop/server/internal/ddns"
	"hyperdrop/server/internal/metadb"
)

// authRouteRE pulls each mux registration in api.go whose handler starts
// with one of the gates built on h.auth, the routes the second-factor rule
// covers.
var authRouteRE = regexp.MustCompile(`mux\.Handle\("([A-Z]+) (/[^"]*)",\s*h\.(?:auth|read|admin|adminRead|webAuth)\(`)

// authenticatedRoutes is every route in api.go behind h.auth or a gate built
// on it.
func authenticatedRoutes(t *testing.T) []registeredRoute {
	t.Helper()
	src, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatalf("read api.go: %v", err)
	}
	m := authRouteRE.FindAllSubmatch(src, -1)
	if len(m) == 0 {
		t.Fatal("found no authenticated routes in api.go: the regex has drifted from the source")
	}
	out := make([]registeredRoute, 0, len(m))
	for _, g := range m {
		out = append(out, registeredRoute{Method: string(g[1]), Pattern: string(g[2])})
	}
	return out
}

// restrictedAdminAPI is a handler whose seeded admin (testToken) has no
// second factor, and the store behind it.
func restrictedAdminAPI(t *testing.T) (http.Handler, *metadb.DB) {
	t.Helper()
	h, hd := newTestAPIParts(t)
	clearSeededAdminTOTP(t, hd.db)
	if u, err := hd.db.User(metadb.DefaultAdminName); err != nil || u.TwoFactorEnabled() {
		t.Fatalf("seeded admin: err %v, second factor %v, want an admin with none", err, u.TwoFactorEnabled())
	}
	return h, hd.db
}

// restrictedClaimAPI is claimCountingAPI whose seeded admin has no second
// factor.
func restrictedClaimAPI(t *testing.T) (http.Handler, *atomic.Int32) {
	t.Helper()
	b := testBackend(t)
	clearSeededAdminTOTP(t, b.DB)
	return claimCountingAPIOn(t, b)
}

// wantSetupRequired fails t unless rec is the restricted account's refusal.
func wantSetupRequired(t *testing.T, what string, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusForbidden || errCode(t, rec.Body.String()) != "two-factor-setup-required" {
		t.Errorf("%s = %d %s, want 403 two-factor-setup-required", what, rec.Code, rec.Body)
	}
}

// setupRequired reports whether rec is the restricted account's refusal.
func setupRequired(rec *httptest.ResponseRecorder) bool {
	return strings.Contains(rec.Body.String(), `"two-factor-setup-required"`)
}

func TestARestrictedAdminIsRefusedOutsideTheSetupRoutes(t *testing.T) {
	h, _ := restrictedAdminAPI(t)
	for _, c := range []struct{ method, path, body string }{
		{"POST", "/api/shares", `{"name":"x"}`},
		{"GET", "/api/users", ""},
		{"PUT", "/api/domain", `{"domain":"share.example.com"}`},
		{"PATCH", "/api/server/settings", `{"autoUpdate":true}`},
	} {
		rec := doReq(t, h, c.method, c.path, testToken, c.body)
		wantSetupRequired(t, c.method+" "+c.path, rec)
		var e struct {
			Error string `json:"error"`
		}
		unmarshal(t, rec, &e)
		if e.Error != "Set up two-factor for this account first." {
			t.Errorf("%s %s sentence = %q", c.method, c.path, e.Error)
		}
	}
}

func TestTheReadsAnAppDrawsWithStayOpen(t *testing.T) {
	h, _ := restrictedAdminAPI(t)
	for _, key := range []string{
		"GET /api/me",
		"GET /api/me/totp",
		"GET /api/me/tokens",
		"GET /api/web/session",
		"GET /api/usage",
		"GET /api/server/settings",
		"GET /api/local-addresses",
		"GET /api/ddns",
		"GET /api/ddns/available",
	} {
		method, pattern, _ := strings.Cut(key, " ")
		rec := doReq(t, h, method, samplePath(pattern), testToken, "")
		if setupRequired(rec) {
			t.Errorf("%s = %d %s, want it open to an admin owing a second factor", key, rec.Code, rec.Body)
		}
	}
}

func TestAFreshAdminClaimsTheFreeNameAndEnrols(t *testing.T) {
	h, claims := restrictedClaimAPI(t)
	body := fmt.Sprintf(`{"name":"mynas","currentPassword":%q}`, testAdminPassword)
	if rec := doReq(t, h, "PUT", "/api/ddns", testToken, body); rec.Code != http.StatusOK {
		t.Fatalf("first free-name claim = %d %s, want 200", rec.Code, rec.Body)
	}
	if n := claims.Load(); n != 1 {
		t.Fatalf("claims = %d, want 1", n)
	}
	enableTOTP(t, h, testToken, testAdminPassword)
	if rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"after"}`); rec.Code != http.StatusCreated {
		t.Fatalf("share after enrolment = %d %s, want 201", rec.Code, rec.Body)
	}
}

func TestOnceANameIsHeldChangingItNeedsTheSecondFactor(t *testing.T) {
	h, claims := restrictedClaimAPI(t)
	body := fmt.Sprintf(`{"name":"mynas","currentPassword":%q}`, testAdminPassword)
	if rec := doReq(t, h, "PUT", "/api/ddns", testToken, body); rec.Code != http.StatusOK {
		t.Fatalf("first free-name claim = %d %s, want 200", rec.Code, rec.Body)
	}
	if !strings.Contains(doReq(t, h, "GET", "/api/ddns", testToken, "").Body.String(), `"configured":true`) {
		t.Fatal("the claimed name is not held")
	}
	rec := doReq(t, h, "PUT", "/api/ddns", testToken, body)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"name":"mynas"`) {
		t.Fatalf("PUT /api/ddns retrying the held name = %d %s, want 200 with the held name", rec.Code, rec.Body)
	}
	for _, c := range []struct{ what, body string }{
		{"othername", fmt.Sprintf(`{"name":"othername","currentPassword":%q}`, testAdminPassword)},
		{"othername replace", fmt.Sprintf(`{"name":"othername","replace":true,"currentPassword":%q}`, testAdminPassword)},
		{"mynas replace", fmt.Sprintf(`{"name":"mynas","replace":true,"currentPassword":%q}`, testAdminPassword)},
	} {
		rec := doReq(t, h, "PUT", "/api/ddns", testToken, c.body)
		wantSetupRequired(t, "PUT /api/ddns "+c.what+" while a name is held", rec)
	}
	if n := claims.Load(); n != 1 {
		t.Fatalf("claims = %d, want 1", n)
	}
}

// The background updater confirms a pending claim once the owner approves
// it, so the client's "I approved it" retry of the same name meets a held
// name: it is answered as a confirmation, with no call to the names
// service, while any other name is still refused.
func TestARetryAfterTheBackgroundConfirmIsAConfirmation(t *testing.T) {
	upd, hits := testDDNS(t)
	b := testBackend(t)
	clearSeededAdminTOTP(t, b.DB)
	dom := testDomain(t)
	if err := dom.Adopt(ddns.FQDN("mynas")); err != nil {
		t.Fatal(err)
	}
	h := New(b, "2.0.0", dom, upd)
	if err := upd.Store().BeginClaim("mynas", "token", "server"); err != nil {
		t.Fatal(err)
	}
	if err := upd.Store().ConfirmClaim(); err != nil {
		t.Fatal(err)
	}
	before := hits.Load()
	body := fmt.Sprintf(`{"name":"mynas","currentPassword":%q}`, testAdminPassword)
	rec := doReq(t, h, "PUT", "/api/ddns", testToken, body)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"name":"mynas"`) {
		t.Fatalf("retry of the confirmed name = %d %s, want 200 with the held name", rec.Code, rec.Body)
	}
	if n := hits.Load() - before; n != 0 {
		t.Fatalf("the retry reached the names service %d times, want none", n)
	}
	other := fmt.Sprintf(`{"name":"othername","currentPassword":%q}`, testAdminPassword)
	wantSetupRequired(t, "PUT /api/ddns othername after the confirm", doReq(t, h, "PUT", "/api/ddns", testToken, other))
}

// A pending enrolment counts as no name held, so the choice's retry after
// the owner approves it stays open; once the claim is confirmed the same
// name is answered as a confirmation and any other is refused.
func TestAPendingNameStillTakesTheChoice(t *testing.T) {
	upd, _ := testDDNS(t)
	b := testBackend(t)
	clearSeededAdminTOTP(t, b.DB)
	h := New(b, "2.0.0", testDomain(t), upd)
	if err := upd.Store().BeginClaim("mynas", "token", "server"); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"name":"mynas","currentPassword":%q}`, testAdminPassword)
	if rec := doReq(t, h, "PUT", "/api/ddns", testToken, body); setupRequired(rec) {
		t.Fatalf("PUT /api/ddns while the name is pending = %d %s, want it open", rec.Code, rec.Body)
	}
	if err := upd.Store().ConfirmClaim(); err != nil {
		t.Fatal(err)
	}
	if rec := doReq(t, h, "PUT", "/api/ddns", testToken, body); rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/ddns retrying the confirmed name = %d %s, want 200", rec.Code, rec.Body)
	}
	other := fmt.Sprintf(`{"name":"othername","currentPassword":%q}`, testAdminPassword)
	wantSetupRequired(t, "PUT /api/ddns othername once the claim is confirmed", doReq(t, h, "PUT", "/api/ddns", testToken, other))
}

func TestCancellingAPendingNameStaysOpen(t *testing.T) {
	h, _ := restrictedClaimAPI(t)
	rec := doReq(t, h, "DELETE", "/api/ddns?pendingName=mynas", testToken, "")
	if setupRequired(rec) {
		t.Fatalf("cancelling a pending name = %d %s, want it open", rec.Code, rec.Body)
	}
	rec = doReq(t, h, "DELETE", "/api/ddns", testToken, "")
	wantSetupRequired(t, "bare DELETE /api/ddns", rec)
}

func TestAFreeNameChoiceIsRefusedWhereNoUpdaterRuns(t *testing.T) {
	h, _ := restrictedAdminAPI(t)
	body := fmt.Sprintf(`{"name":"mynas","currentPassword":%q}`, testAdminPassword)
	rec := doReq(t, h, "PUT", "/api/ddns", testToken, body)
	wantSetupRequired(t, "PUT /api/ddns with no updater", rec)
}

func TestAnAdminWithASecondFactorIsNotRestricted(t *testing.T) {
	h, _ := restrictedAdminAPI(t)
	enableTOTP(t, h, testToken, testAdminPassword)
	if rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"x"}`); rec.Code != http.StatusCreated {
		t.Fatalf("share = %d %s, want 201", rec.Code, rec.Body)
	}
}

func TestAPlainUserIsNotRestrictedWithoutTheSwitch(t *testing.T) {
	h, db := restrictedAdminAPI(t)
	alice := seedUser(t, db, "alice")
	if rec := doReq(t, h, "POST", "/api/shares", alice, `{"name":"x"}`); rec.Code != http.StatusCreated {
		t.Fatalf("share = %d %s, want 201", rec.Code, rec.Body)
	}
	if body := doReq(t, h, "GET", "/api/me", alice, "").Body.String(); strings.Contains(body, "twoFactorRequired") {
		t.Fatalf("a plain user's /api/me = %s, want no twoFactorRequired", body)
	}
}

func TestMeSaysTwoFactorRequired(t *testing.T) {
	h, _ := restrictedAdminAPI(t)
	if body := doReq(t, h, "GET", "/api/me", testToken, "").Body.String(); !strings.Contains(body, `"twoFactorRequired":true`) {
		t.Fatalf("restricted /api/me = %s, want twoFactorRequired true", body)
	}
	enableTOTP(t, h, testToken, testAdminPassword)
	if body := doReq(t, h, "GET", "/api/me", testToken, "").Body.String(); strings.Contains(body, "twoFactorRequired") {
		t.Fatalf("enrolled /api/me = %s, want no twoFactorRequired", body)
	}
}

func TestOnlyMeSaysTwoFactorRequired(t *testing.T) {
	h, db := restrictedAdminAPI(t)
	if _, err := db.CreateUser("root2", "root2-pw", metadb.RoleAdmin, metadb.Settings{}); err != nil {
		t.Fatal(err)
	}
	enableTOTP(t, h, testToken, testAdminPassword)
	if body := doReq(t, h, "GET", "/api/users", testToken, "").Body.String(); strings.Contains(body, "twoFactorRequired") {
		t.Fatalf("GET /api/users = %s, want no twoFactorRequired on any row", body)
	}
}

func TestARestrictedWebSessionIsRefusedTheSameWay(t *testing.T) {
	f := newWebFixture(t, true)
	clearSeededAdminTOTP(t, f.db)
	raw := f.signInAs(t, metadb.DefaultAdminName, testAdminPassword)
	rec := f.req(t, "GET", "/api/users", raw, "")
	wantSetupRequired(t, "GET /api/users with a web session", rec)
	if rec := f.req(t, "GET", "/api/web/session", raw, ""); rec.Code != http.StatusOK {
		t.Fatalf("GET /api/web/session = %d %s, want 200", rec.Code, rec.Body)
	}
}

func TestEveryAuthenticatedRouteIsRefusedByDefault(t *testing.T) {
	h, _ := restrictedAdminAPI(t)
	for _, rt := range authenticatedRoutes(t) {
		key := rt.Method + " " + rt.Pattern
		if _, ok := twoFactorSetupRoutes[key]; ok {
			continue
		}
		rec := doReq(t, h, rt.Method, samplePath(rt.Pattern), testToken, "")
		wantSetupRequired(t, key, rec)
	}
}

func TestEverySetupRouteIsRegistered(t *testing.T) {
	routes := map[string]bool{}
	for _, rt := range authenticatedRoutes(t) {
		routes[rt.Method+" "+rt.Pattern] = true
	}
	for key := range twoFactorSetupRoutes {
		if !routes[key] {
			t.Errorf("twoFactorSetupRoutes names %q, which api.go does not register behind h.auth", key)
		}
	}
	registered := map[string]bool{}
	for _, rt := range registeredRoutes(t) {
		registered[rt.Method+" "+rt.Pattern] = true
	}
	for key := range routes {
		if !registered[key] {
			t.Errorf("authenticatedRoutes found %q, which registeredRoutes does not: the two readers disagree", key)
		}
	}
}

// The parser finds every gate the rule covers, so a route behind one of
// them cannot fall outside the walk.
func TestAuthenticatedRoutesSeeEveryGate(t *testing.T) {
	seen := map[string]bool{}
	for _, rt := range authenticatedRoutes(t) {
		seen[rt.Method+" "+rt.Pattern] = true
	}
	for _, key := range []string{
		"DELETE /api/auth/token",        // h.auth
		"GET /api/me",                   // h.read
		"POST /api/users",               // h.admin
		"GET /api/users",                // h.adminRead
		"GET /api/web/session",          // h.webAuth
		"GET /api/ddns/available",       // h.admin around h.ddnsOnly
		"POST /api/web/session/elevate", // h.webAuth
	} {
		if !seen[key] {
			t.Errorf("authenticatedRoutes misses %q", key)
		}
	}
}

// A free-name claim moves the server's address, so on a server that serves
// a domain of its own it is no setup step.
func TestAFreeNameClaimOnACustomDomainServerNeedsTheSecondFactor(t *testing.T) {
	upd, _ := testDDNS(t)
	b := testBackend(t)
	clearSeededAdminTOTP(t, b.DB)
	dom := testDomain(t)
	if err := dom.Adopt("share.example.com"); err != nil {
		t.Fatal(err)
	}
	h := New(b, "2.0.0", dom, upd)
	body := fmt.Sprintf(`{"name":"mynas","currentPassword":%q}`, testAdminPassword)
	rec := doReq(t, h, "PUT", "/api/ddns", testToken, body)
	wantSetupRequired(t, "PUT /api/ddns on a server serving share.example.com", rec)
}

// An install that asked for a free name (HYPERDROP_DDNS_NAME) serves it from
// boot whether or not the claim went through, and that is still first
// setup: the choice and its retry stay open until the name is held.
func TestAFreeNameTheInstallAskedForStillTakesTheChoice(t *testing.T) {
	upd, _ := testDDNS(t)
	b := testBackend(t)
	clearSeededAdminTOTP(t, b.DB)
	dom := testDomain(t)
	if err := dom.Adopt(ddns.FQDN("mynas")); err != nil {
		t.Fatal(err)
	}
	if err := upd.Store().BeginClaim("mynas", "token", "server"); err != nil {
		t.Fatal(err)
	}
	h := New(b, "2.0.0", dom, upd)
	body := fmt.Sprintf(`{"name":"mynas","currentPassword":%q}`, testAdminPassword)
	if rec := doReq(t, h, "PUT", "/api/ddns", testToken, body); setupRequired(rec) {
		t.Fatalf("PUT /api/ddns on a server serving its pending free name = %d %s, want it open", rec.Code, rec.Body)
	}
}

// A device's own push registration is housekeeping: push register reads it
// before it writes, and signing out removes it.
func TestARestrictedAccountLooksAfterItsPushRegistration(t *testing.T) {
	h, _ := restrictedAdminAPI(t)
	for _, c := range []struct{ method, body string }{{"GET", ""}, {"PUT", "{}"}, {"DELETE", ""}} {
		if rec := doReq(t, h, c.method, "/api/me/push", testToken, c.body); setupRequired(rec) {
			t.Errorf("%s /api/me/push = %d %s, want it open to an admin owing a second factor", c.method, rec.Code, rec.Body)
		}
	}
}

// Every request an always-rule route admits stays open to a restricted
// account, whatever its method; any other refusal is the route's own.
func TestEveryAlwaysRouteStaysOpen(t *testing.T) {
	h, _ := restrictedAdminAPI(t)
	always := reflect.ValueOf(always).Pointer()
	n := 0
	for key, rule := range twoFactorSetupRoutes {
		if reflect.ValueOf(rule).Pointer() != always {
			continue
		}
		n++
		method, pattern, _ := strings.Cut(key, " ")
		body := ""
		if method != "GET" && method != "DELETE" {
			body = "{}"
		}
		if rec := doReq(t, h, method, samplePath(pattern), testToken, body); setupRequired(rec) {
			t.Errorf("%s = %d %s, want it open to an admin owing a second factor", key, rec.Code, rec.Body)
		}
	}
	if n < 20 {
		t.Fatalf("found %d always routes, want the 20 the setup list names", n)
	}
}

// A restricted owner's bearer is no owner on the public routes either: its
// inbox stays invisible and its protected share asks for the password.
func TestARestrictedOwnersBearerFetchesNothingPublicRoutesHide(t *testing.T) {
	b := testBackend(t)
	h := New(b, "2.0.0", testDomain(t), nil)
	inbox := createInbox(t, h, `{"name":"inbox","receive":true}`)
	if rec := doReq(t, h, "PUT", "/receive/"+inbox+"/files/secret.txt", "", "private"); rec.Code != 201 {
		t.Fatalf("upload = %d %s", rec.Code, rec.Body)
	}
	var sh struct {
		Files []struct {
			Slug string `json:"slug"`
		} `json:"files"`
	}
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+inbox, testToken, ""), &sh)
	inboxSlug := sh.Files[0].Slug
	protected, slug := protectedShareWithFile(t, h)
	if rec := doReq(t, h, "GET", "/download/"+inbox+"/"+inboxSlug, testToken, ""); rec.Code != 200 {
		t.Fatalf("enrolled owner's inbox fetch = %d, want 200", rec.Code)
	}

	clearSeededAdminTOTP(t, b.DB)
	if rec := doReq(t, h, "GET", "/download/"+inbox+"/"+inboxSlug, testToken, ""); rec.Code != http.StatusNotFound {
		t.Errorf("restricted owner's inbox fetch = %d %q, want 404", rec.Code, rec.Body.String())
	}
	rec := doReq(t, h, "GET", "/download/"+protected+"/"+slug, testToken, "")
	if rec.Code == http.StatusOK && rec.Body.String() == "data" {
		t.Errorf("restricted owner's bearer passed the password gate")
	}
	if anon := doReq(t, h, "GET", "/download/"+protected+"/"+slug, "", ""); rec.Code != anon.Code {
		t.Errorf("restricted owner's protected fetch = %d, want the anonymous answer %d", rec.Code, anon.Code)
	}
}
