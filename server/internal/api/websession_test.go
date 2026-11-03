package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/ddns"
	"hyperdrop/server/internal/domain"
	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/webapp"
)

// webAppHost is the app origin of a split web fixture.
const webAppHost = "share.example.com"

// webFixture is a handler over a store holding the admin and alice
// (password alice-pw, a device token in aliceDevice), with the origin split
// live on webAppHost when split, and one host (example.com, httptest's)
// when not. Its web store serves a development directory, so the web
// client is on.
type webFixture struct {
	h           http.Handler
	hd          *handler
	db          *metadb.DB
	dir         string
	split       bool
	appHost     string
	web         *webapp.Store
	aliceDevice string
}

func newWebFixture(t *testing.T, split bool) webFixture {
	t.Helper()
	if split {
		return newWebFixtureOn(t, webAppHost, nil)
	}
	return newWebFixtureOn(t, "", nil)
}

// newWebFixtureOn is newWebFixture with the origin split live on appHost
// (none when it is empty) and upd as the server's ddns updater.
func newWebFixtureOn(t *testing.T, appHost string, upd *ddns.Updater) webFixture {
	t.Helper()
	dir := t.TempDir()
	b := testBackendAt(t, dir)
	dom, err := domain.Load(filepath.Join(t.TempDir(), "domain"), "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	split := appHost != ""
	if split {
		if err := dom.Adopt(appHost); err != nil {
			t.Fatal(err)
		}
	}
	web, err := webapp.Open(dir, []string{webTestPub()}, "2.0.0")
	if err != nil {
		t.Fatal(err)
	}
	dev := t.TempDir()
	if err := os.WriteFile(filepath.Join(dev, "index.html"), []byte("web fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	web.UseDevDir(dev)
	hd := newHandler(b, "2.0.0", dom, upd, Deployment{Web: web})
	return webFixture{h: hd.routes(), hd: hd, db: b.DB, dir: dir, split: split, appHost: appHost, web: web,
		aliceDevice: seedUser(t, b.DB, "alice")}
}

// host and origin are what the web app's own requests carry.
func (f webFixture) host() string {
	if f.split {
		return f.appHost
	}
	return "example.com"
}

func (f webFixture) origin() string {
	if f.split {
		return "https://" + f.appHost
	}
	return "http://example.com"
}

// req is a request as the web app sends it: on the app host, from its own
// origin, with the web client header and the session cookie when cookie is
// set. edit changes it before it is served.
func (f webFixture) req(t *testing.T, method, path, cookie, body string, edit ...func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Host = f.host()
	r.Header.Set("X-HyperDrop-Client", "2.0.0 web")
	r.Header.Set("Origin", f.origin())
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: webCookie, Value: cookie})
	}
	for _, e := range edit {
		e(r)
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)
	return rec
}

func from(addr string) func(*http.Request) {
	return func(r *http.Request) { r.RemoteAddr = addr }
}

func header(name, value string) func(*http.Request) {
	return func(r *http.Request) {
		if value == "" {
			r.Header.Del(name)
		} else {
			r.Header.Set(name, value)
		}
	}
}

// signIn signs alice in on the web and answers the session cookie's value.
func (f webFixture) signIn(t *testing.T, keep bool) string {
	t.Helper()
	rec := f.req(t, "POST", "/api/web/session", "", fmt.Sprintf(`{"username":"alice","password":"alice-pw","keep":%v}`, keep))
	if rec.Code != 200 {
		t.Fatalf("web sign-in: %d %s", rec.Code, rec.Body)
	}
	return webCookieOf(t, rec)
}

// webCookieOf is the value of the session cookie rec sets.
func webCookieOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == webCookie {
			return c.Value
		}
	}
	t.Fatalf("no %s cookie in %v", webCookie, rec.Header().Values("Set-Cookie"))
	return ""
}

// setCookieLines is rec's Set-Cookie lines without a sign-out's hd_clear,
// which accesshop_test.go asserts on its own.
func setCookieLines(rec *httptest.ResponseRecorder) []string {
	var out []string
	for _, line := range rec.Header().Values("Set-Cookie") {
		if !strings.HasPrefix(line, accessClearCookie+"=") {
			out = append(out, line)
		}
	}
	return out
}

// wantSignedOut fails unless rec is a sign-out's answer on f: 200 with the
// file origin's clear on a split server, 204 on one origin.
func wantSignedOut(t *testing.T, f webFixture, rec *httptest.ResponseRecorder, what string) {
	t.Helper()
	if !f.split {
		if rec.Code != http.StatusNoContent {
			t.Fatalf("%s: sign out = %d %s, want 204", what, rec.Code, rec.Body)
		}
		return
	}
	var out map[string]string
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil ||
		!strings.HasPrefix(out["accessClear"], "https://files."+f.appHost+"/access/clear?t=") {
		t.Fatalf("%s: sign out = %d %s, want 200 with the file origin's clear", what, rec.Code, rec.Body)
	}
}

// cookieAttributes is the one Set-Cookie line's attributes, after its
// name=value.
func cookieAttributes(t *testing.T, rec *httptest.ResponseRecorder) (nameValue string, attrs []string) {
	t.Helper()
	lines := setCookieLines(rec)
	if len(lines) != 1 {
		t.Fatalf("Set-Cookie = %q, want one", lines)
	}
	parts := strings.Split(lines[0], "; ")
	attrs = parts[1:]
	slices.Sort(attrs)
	return parts[0], attrs
}

// wantCookieCleared fails unless rec's one Set-Cookie clears the session
// cookie with every attribute the setting cookie carries: a browser ignores
// a clear of a __Host- cookie that lacks Secure.
func wantCookieCleared(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	const want = "__Host-hd_web=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict"
	if got := setCookieLines(rec); len(got) != 1 || got[0] != want {
		t.Fatalf("Set-Cookie = %q, want [%q]", got, want)
	}
}

func TestWebSignInSetsHostOnlyCookie(t *testing.T) {
	f := newWebFixture(t, true)
	start := time.Now()
	rec := f.req(t, "POST", "/api/web/session", "", `{"username":"alice","password":"alice-pw"}`)
	if rec.Code != 200 {
		t.Fatalf("sign-in: %d %s", rec.Code, rec.Body)
	}
	nv, attrs := cookieAttributes(t, rec)
	if !strings.HasPrefix(nv, "__Host-hd_web=hd_w_") {
		t.Fatalf("cookie %q", nv)
	}
	if want := []string{"HttpOnly", "Path=/", "SameSite=Strict", "Secure"}; !slices.Equal(attrs, want) {
		t.Fatalf("public cookie attributes %q, want %q", attrs, want)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
	raw := webCookieOf(t, rec)
	if strings.Contains(rec.Body.String(), raw) {
		t.Fatal("the answer carries the session's value")
	}
	var out map[string]json.RawMessage
	unmarshal(t, rec, &out)
	if _, ok := out["token"]; ok {
		t.Fatalf("a token field in %s", rec.Body)
	}
	var body struct {
		User struct {
			Username string `json:"username"`
		} `json:"user"`
		Session struct {
			Keep        bool      `json:"keep"`
			ExpiresAt   time.Time `json:"expiresAt"`
			IdleSeconds int       `json:"idleSeconds"`
		} `json:"session"`
	}
	unmarshal(t, rec, &body)
	if body.User.Username != "alice" || body.Session.Keep || body.Session.IdleSeconds != 1800 ||
		body.Session.ExpiresAt.Before(start.Add(12*time.Hour-time.Second)) || body.Session.ExpiresAt.After(time.Now().Add(12*time.Hour)) {
		t.Fatalf("answer %s", rec.Body)
	}
	u, err := f.db.User("alice")
	if err != nil {
		t.Fatal(err)
	}
	labelled := false
	for _, tok := range u.Tokens {
		labelled = labelled || (tok.Kind == metadb.TokenKindWeb && tok.Label == "Web browser · Chrome on Windows")
	}
	if !labelled {
		t.Fatalf("tokens %+v, want a web row labelled for Chrome on Windows", u.Tokens)
	}

	rec = f.req(t, "POST", "/api/web/session", "", `{"username":"alice","password":"alice-pw","keep":true}`)
	if rec.Code != 200 {
		t.Fatalf("kept sign-in: %d %s", rec.Code, rec.Body)
	}
	if _, attrs := namedCookieAttributes(t, rec, webCookie); !slices.Equal(attrs, []string{"HttpOnly", "Max-Age=2592000", "Path=/", "SameSite=Strict", "Secure"}) {
		t.Fatalf("kept cookie attributes %q", attrs)
	}
	unmarshal(t, rec, &body)
	if !body.Session.Keep || body.Session.IdleSeconds != 2592000 {
		t.Fatalf("kept answer %s", rec.Body)
	}
}

func TestWebSignInRefusesUnknownFields(t *testing.T) {
	f := newWebFixture(t, true)
	rec := f.req(t, "POST", "/api/web/session", "", `{"username":"alice","password":"alice-pw","label":"x"}`)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "label") {
		t.Fatalf("an unknown field: %d %s", rec.Code, rec.Body)
	}
}

func TestWebSignInIsRefusedOffTheAppOrigin(t *testing.T) {
	f := newWebFixture(t, true)
	for name, edit := range map[string]func(*http.Request){
		"file host":     func(r *http.Request) { r.Host = "files." + webAppHost },
		"no web client": header("X-HyperDrop-Client", ""),
		"an app client": header("X-HyperDrop-Client", "2.0.0 macos"),
		"other origin":  header("Origin", "https://evil.example"),
		"cross-site":    header("Sec-Fetch-Site", "cross-site"),
	} {
		rec := f.req(t, "POST", "/api/web/session", "", `{"username":"alice","password":"alice-pw"}`, edit)
		if rec.Code != 403 || errCode(t, rec.Body.String()) != "web-session-refused" || len(rec.Result().Cookies()) != 0 {
			t.Errorf("%s: %d %s, cookies %v; want 403 web-session-refused", name, rec.Code, rec.Body, rec.Result().Cookies())
		}
	}
}

func TestWebSignInSharesTheLoginLockout(t *testing.T) {
	f := newWebFixture(t, true)
	const a = "198.51.100.1:4000"
	for i := 1; i <= pwFailLimit; i++ {
		rec := f.req(t, "POST", "/api/web/session", "", `{"username":"alice","password":"wrong"}`, from(a))
		want := 401
		if i == pwFailLimit {
			want = 429
		}
		if rec.Code != want {
			t.Fatalf("wrong web sign-in %d: %d %s, want %d", i, rec.Code, rec.Body, want)
		}
	}
	if rec := doReqFrom(t, f.h, "POST", "/api/auth/login", "", loginBody("alice", "alice-pw", ""), a); rec.Code != 429 {
		t.Fatalf("app login from the locked address: %d %s, want 429", rec.Code, rec.Body)
	}

	// The second address guesses at a name no account has, so the wait it
	// meets is its own and not alice's lane.
	const b = "198.51.100.2:4000"
	for range pwFailLimit {
		doReqFrom(t, f.h, "POST", "/api/auth/login", "", loginBody("nobody", "wrong", ""), b)
	}
	rec := f.req(t, "POST", "/api/web/session", "", `{"username":"alice","password":"alice-pw"}`, from(b))
	if rec.Code != 429 || !strings.Contains(rec.Body.String(), "from your address") {
		t.Fatalf("web sign-in from an address app logins locked: %d %s, want 429 with the address's wait", rec.Code, rec.Body)
	}
}

// A name no account has waits like one an account has, so the wait does not
// tell which names exist.
func TestWebSignInCounterDoesNotTellNamesApart(t *testing.T) {
	f := newWebFixture(t, true)
	for i := 1; i <= laneFree+1; i++ {
		if rec := f.req(t, "POST", "/api/web/session", "", `{"username":"nobody","password":"wrong"}`, from("203.0.113."+strconv.Itoa(i)+":4000")); rec.Code != 401 {
			t.Fatalf("wrong web sign-in %d at a name no account has: %d %s, want 401", i, rec.Code, rec.Body)
		}
	}
	rec := f.req(t, "POST", "/api/web/session", "", `{"username":"nobody","password":"wrong"}`, from("203.0.113.99:4000"))
	if rec.Code != 429 || !strings.Contains(rec.Body.String(), accountWait) {
		t.Fatalf("a name no account has: %d %s, want 429 with the account's wait", rec.Code, rec.Body)
	}
	if after, _ := strconv.Atoi(rec.Header().Get("Retry-After")); after < 1 || after > int(laneSpacing/time.Second) {
		t.Fatalf("Retry-After = %q, want 30 s at most", rec.Header().Get("Retry-After"))
	}
}

func TestWebSignInTOTP(t *testing.T) {
	f := newWebFixture(t, true)
	secret, _ := enableTOTP(t, f.h, f.aliceDevice, "alice-pw")
	rec := f.req(t, "POST", "/api/web/session", "", `{"username":"alice","password":"alice-pw"}`)
	if rec.Code != 401 || errCode(t, rec.Body.String()) != "totp-required" || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("no code: %d %s", rec.Code, rec.Body)
	}
	rec = f.req(t, "POST", "/api/web/session", "", `{"username":"alice","password":"alice-pw","totp":"000000"}`)
	if rec.Code != 401 || errCode(t, rec.Body.String()) != "totp-invalid" {
		t.Fatalf("a wrong code: %d %s", rec.Code, rec.Body)
	}
	rec = f.req(t, "POST", "/api/web/session", "", `{"username":"alice","password":"alice-pw","totp":"`+nextCode(t, secret)+`"}`)
	if rec.Code != 200 {
		t.Fatalf("the right code: %d %s", rec.Code, rec.Body)
	}
	webCookieOf(t, rec)
}

// The right password with too many wrong codes blocks the account's codes,
// from every address, so the wait is worded as the account's, never the
// caller's address.
func TestWebSignInCodeLockoutIsTheAccounts(t *testing.T) {
	f := newWebFixture(t, true)
	secret, _ := enableTOTP(t, f.h, f.aliceDevice, "alice-pw")
	addr := func(i int) func(*http.Request) { return from("203.0.113." + strconv.Itoa(i) + ":4000") }
	wrong := `{"username":"alice","password":"alice-pw","totp":"000000"}`
	for i := 1; i < pwFailLimit; i++ {
		if rec := f.req(t, "POST", "/api/web/session", "", wrong, addr(i)); rec.Code != 401 {
			t.Fatalf("wrong code %d: %d %s, want 401", i, rec.Code, rec.Body)
		}
	}
	rec := f.req(t, "POST", "/api/web/session", "", wrong, addr(pwFailLimit))
	if rec.Code != 429 || errCode(t, rec.Body.String()) != "locked-out" || !strings.Contains(rec.Body.String(), accountWait) {
		t.Fatalf("the code that locks: %d %s, want 429 with the account's wait", rec.Code, rec.Body)
	}
	rec = f.req(t, "POST", "/api/web/session", "",
		`{"username":"alice","password":"alice-pw","totp":"`+nextCode(t, secret)+`"}`, addr(pwFailLimit+1))
	if rec.Code != 429 || !strings.Contains(rec.Body.String(), accountWait) {
		t.Fatalf("the right code while the codes wait: %d %s, want 429 with the account's wait", rec.Code, rec.Body)
	}
}

func TestCookieAcceptedOnlyOnAppHost(t *testing.T) {
	f := newWebFixture(t, true)
	raw := f.signIn(t, false)
	if rec := f.req(t, "GET", "/api/web/session", raw, ""); rec.Code != 200 {
		t.Fatalf("on the app host: %d %s", rec.Code, rec.Body)
	}
	for _, host := range []string{"files." + webAppHost, "203.0.113.7", "other.example"} {
		rec := f.req(t, "GET", "/api/shares", raw, "", func(r *http.Request) { r.Host = host })
		if rec.Code != 401 {
			t.Errorf("Host %s: %d %s, want 401", host, rec.Code, rec.Body)
		}
	}
}

// With no domain there is one host, and the request's own origin is the
// app's.
func TestCookieOnTheOneDevHost(t *testing.T) {
	f := newWebFixture(t, false)
	raw := f.signIn(t, false)
	if rec := f.req(t, "GET", "/api/shares", raw, ""); rec.Code != 200 {
		t.Fatalf("on the one host: %d %s", rec.Code, rec.Body)
	}
	if rec := f.req(t, "GET", "/api/shares", raw, "", header("Origin", "http://evil.example")); rec.Code != 401 {
		t.Fatalf("from another origin: %d %s, want 401", rec.Code, rec.Body)
	}
}

func TestCookieNeedsWebClientHeader(t *testing.T) {
	f := newWebFixture(t, true)
	raw := f.signIn(t, false)
	for _, v := range []string{"", "2.0.0 macos", "web", "2.0.0"} {
		if rec := f.req(t, "GET", "/api/shares", raw, "", header("X-HyperDrop-Client", v)); rec.Code != 401 {
			t.Errorf("X-HyperDrop-Client %q: %d %s, want 401", v, rec.Code, rec.Body)
		}
	}
}

func TestCookieRefusedCrossOrigin(t *testing.T) {
	f := newWebFixture(t, true)
	raw := f.signIn(t, false)
	for name, edit := range map[string]func(*http.Request){
		"evil origin":     header("Origin", "https://evil.example"),
		"file origin":     header("Origin", "https://files."+webAppHost),
		"plain http":      header("Origin", "http://"+webAppHost),
		"cross-site":      header("Sec-Fetch-Site", "cross-site"),
		"same-site":       header("Sec-Fetch-Site", "same-site"),
		"no Fetch header": header("Sec-Fetch-Site", ""),
		"no Origin":       header("Origin", ""),
	} {
		want := 401
		if name == "no Fetch header" || name == "no Origin" {
			want = 200
		}
		if rec := f.req(t, "GET", "/api/shares", raw, "", edit); rec.Code != want {
			t.Errorf("%s: %d %s, want %d", name, rec.Code, rec.Body, want)
		}
	}
}

func TestWebSessionIsNotABearerToken(t *testing.T) {
	f := newWebFixture(t, true)
	raw := f.signIn(t, false)
	if rec := doReq(t, f.h, "GET", "/api/shares", raw, ""); rec.Code != 401 {
		t.Fatalf("the session's value as a bearer: %d %s, want 401", rec.Code, rec.Body)
	}
	// A request with an Authorization header is judged by it alone.
	rec := f.req(t, "GET", "/api/shares", raw, "", header("Authorization", "Bearer nope"))
	if rec.Code != 401 {
		t.Fatalf("a bad bearer beside a good cookie: %d %s, want 401", rec.Code, rec.Body)
	}
	// And a device token in the cookie is not a session.
	if rec := f.req(t, "GET", "/api/shares", f.aliceDevice, ""); rec.Code != 401 {
		t.Fatalf("a device token as the cookie: %d %s, want 401", rec.Code, rec.Body)
	}
	// The web routes are for web sessions only.
	rec = doReq(t, f.h, "GET", "/api/web/session", f.aliceDevice, "")
	if rec.Code != 400 || errCode(t, rec.Body.String()) != "web-session-only" {
		t.Fatalf("a device token on the web session route: %d %s", rec.Code, rec.Body)
	}
}

func TestBackgroundRequestsDoNotExtendIdle(t *testing.T) {
	f := newWebFixture(t, true)
	raw := f.signIn(t, false)
	idleUntil := func() time.Time {
		t.Helper()
		_, tok, err := f.db.UserByWebSession(raw, metadb.ClientInfo{}, time.Now(), false)
		if err != nil {
			t.Fatal(err)
		}
		return tok.IdleUntil
	}
	// Move the session's deadline back past the coalescing minute, as if the
	// last action was two minutes ago.
	minted := idleUntil()
	setIdle(t, f, raw, minted.Add(-2*time.Minute))
	if rec := f.req(t, "GET", "/api/shares", raw, "", header("X-HyperDrop-Background", "1")); rec.Code != 200 {
		t.Fatalf("background poll: %d %s", rec.Code, rec.Body)
	}
	if got := idleUntil(); !got.Equal(minted.Add(-2 * time.Minute)) {
		t.Fatalf("a background poll moved the idle limit to %v", got)
	}
	if rec := f.req(t, "GET", "/api/shares", raw, ""); rec.Code != 200 {
		t.Fatalf("user action: %d %s", rec.Code, rec.Body)
	}
	if got := idleUntil(); !got.After(minted.Add(-time.Minute)) {
		t.Fatalf("a user action left the idle limit at %v", got)
	}
}

// setIdle moves the web session raw's idle limit to until.
func setIdle(t *testing.T, f webFixture, raw string, until time.Time) {
	t.Helper()
	execRaw(t, f.dir, `UPDATE tokens SET idle_until = ? WHERE sha256 = ?`, until.UnixNano(), metadb.WebSessionHash(raw))
}

func TestSignOutRevokesServerSide(t *testing.T) {
	f := newWebFixture(t, true)
	raw := f.signIn(t, true)
	rec := f.req(t, "DELETE", "/api/web/session", raw, "")
	wantSignedOut(t, f, rec, "sign out")
	wantCookieCleared(t, rec)
	if rec := f.req(t, "GET", "/api/web/session", raw, ""); rec.Code != 401 {
		t.Fatalf("the cookie replayed after sign out: %d %s, want 401", rec.Code, rec.Body)
	}
	if rec := doReq(t, f.h, "GET", "/api/me", f.aliceDevice, ""); rec.Code != 200 {
		t.Fatalf("the device token after the web sign out: %d", rec.Code)
	}
}

// A sign-out clears every share access cookie the browser sent, each with
// the name, domain and path its unlock set, and nothing that is not one.
func TestSignOutClearsShareAccessCookies(t *testing.T) {
	f := newWebFixture(t, true)
	rec := doReq(t, f.h, "POST", "/api/shares", f.aliceDevice, `{"name":"p","password":"first"}`)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	var made struct{ ID string }
	unmarshal(t, rec, &made)
	uploadGetSlugAs(t, f.h, f.aliceDevice, made.ID, "a.txt", "hello")

	unlock := httptest.NewRequest("POST", "/unlock/"+made.ID, strings.NewReader("password=first&next=/share/"+made.ID))
	unlock.Host = webAppHost
	unlock.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	unlocked := httptest.NewRecorder()
	f.h.ServeHTTP(unlocked, unlock)
	if unlocked.Code != 303 {
		t.Fatalf("unlock = %d %s", unlocked.Code, unlocked.Body)
	}
	var access *http.Cookie
	var setAttrs []string
	for _, line := range unlocked.Header().Values("Set-Cookie") {
		if strings.HasPrefix(line, "hd_"+made.ID+"=") {
			for _, a := range strings.Split(line, "; ")[1:] {
				if !strings.HasPrefix(a, "Expires=") {
					setAttrs = append(setAttrs, a)
				}
			}
		}
	}
	for _, c := range unlocked.Result().Cookies() {
		if c.Name == "hd_"+made.ID {
			access = c
		}
	}
	if access == nil || slices.ContainsFunc(setAttrs, func(a string) bool { return strings.HasPrefix(a, "Domain=") }) {
		t.Fatalf("unlock set %q, want a host-only access cookie", unlocked.Header().Values("Set-Cookie"))
	}

	raw := f.signIn(t, false)
	out := f.req(t, "DELETE", "/api/web/session", raw, "", func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: access.Name, Value: access.Value})
		r.AddCookie(&http.Cookie{Name: access.Name, Value: "a stray same-named cookie"})
		r.AddCookie(&http.Cookie{Name: visitorCookie, Value: "v"})
		r.AddCookie(&http.Cookie{Name: visitorCookieName(made.ID), Value: "v"})
		r.AddCookie(&http.Cookie{Name: "hd_short", Value: "v"})
	})
	wantSignedOut(t, f, out, "sign out")
	var clears []string
	for _, line := range setCookieLines(out) {
		if !strings.HasPrefix(line, webCookie+"=") {
			clears = append(clears, line)
		}
	}
	if len(clears) != 1 {
		t.Fatalf("access clears = %q, want one for hd_%s", clears, made.ID)
	}
	parts := strings.Split(clears[0], "; ")
	if parts[0] != "hd_"+made.ID+"=" {
		t.Fatalf("clear %q", clears[0])
	}
	var clearAttrs []string
	for _, a := range parts[1:] {
		if a != "Max-Age=0" {
			clearAttrs = append(clearAttrs, a)
		}
	}
	if !slices.Contains(parts, "Max-Age=0") {
		t.Fatalf("clear %q has no Max-Age=0", clears[0])
	}
	slices.Sort(setAttrs)
	slices.Sort(clearAttrs)
	if !slices.Equal(setAttrs, clearAttrs) {
		t.Fatalf("clear attributes %q, want the unlock's %q", clearAttrs, setAttrs)
	}
}

func TestWebSessionInfo(t *testing.T) {
	f := newWebFixture(t, true)
	raw := f.signIn(t, true)
	rec := f.req(t, "GET", "/api/web/session", raw, "")
	if rec.Code != 200 {
		t.Fatalf("info: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		User    map[string]any `json:"user"`
		Session map[string]any `json:"session"`
	}
	unmarshal(t, rec, &out)
	if out.User["username"] != "alice" || out.Session["keep"] != true || out.Session["expiresAt"] == nil ||
		out.Session["idleUntil"] == nil {
		t.Fatalf("info %s", rec.Body)
	}
	if _, ok := out.Session["elevatedUntil"]; ok {
		t.Fatalf("an unelevated session reports elevatedUntil: %s", rec.Body)
	}
}

func TestElevate(t *testing.T) {
	f := newWebFixture(t, true)
	raw := f.signIn(t, false)
	if rec := f.req(t, "POST", "/api/web/session/elevate", raw, `{}`); rec.Code != 403 || errCode(t, rec.Body.String()) != "step-up-required" {
		t.Fatalf("no password: %d %s", rec.Code, rec.Body)
	}
	const a = "198.51.100.9:4000"
	rec := f.req(t, "POST", "/api/web/session/elevate", raw, `{"currentPassword":"wrong"}`, from(a))
	if rec.Code != 401 || errCode(t, rec.Body.String()) != "wrong-password" {
		t.Fatalf("a wrong password: %d %s", rec.Code, rec.Body)
	}
	for range pwFailLimit - 1 {
		f.req(t, "POST", "/api/web/session/elevate", raw, `{"currentPassword":"wrong"}`, from(a))
	}
	if rec := f.req(t, "POST", "/api/web/session/elevate", raw, `{"currentPassword":"alice-pw"}`, from(a)); rec.Code != 429 {
		t.Fatalf("the wrong passwords were not counted: %d %s, want 429", rec.Code, rec.Body)
	}

	g := newWebFixture(t, true)
	raw = g.signIn(t, false)
	start := time.Now()
	rec = g.req(t, "POST", "/api/web/session/elevate", raw, `{"currentPassword":"alice-pw"}`)
	if rec.Code != 200 {
		t.Fatalf("the right password: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		ElevatedUntil time.Time `json:"elevatedUntil"`
	}
	unmarshal(t, rec, &out)
	if out.ElevatedUntil.Before(start.Add(10*time.Minute)) || out.ElevatedUntil.After(time.Now().Add(10*time.Minute)) {
		t.Fatalf("elevatedUntil %v, want about ten minutes from now", out.ElevatedUntil)
	}
	rec = g.req(t, "GET", "/api/web/session", raw, "")
	var info struct {
		Session struct {
			ElevatedUntil time.Time `json:"elevatedUntil"`
		} `json:"session"`
	}
	unmarshal(t, rec, &info)
	if !info.Session.ElevatedUntil.Equal(out.ElevatedUntil) {
		t.Fatalf("info elevatedUntil %v, want %v", info.Session.ElevatedUntil, out.ElevatedUntil)
	}
}

func TestElevateAsksTheCodeOfAnAccountWithOne(t *testing.T) {
	f := newWebFixture(t, true)
	secret, _ := enableTOTP(t, f.h, f.aliceDevice, "alice-pw")
	rec := f.req(t, "POST", "/api/web/session", "", `{"username":"alice","password":"alice-pw","totp":"`+nextCode(t, secret)+`"}`)
	if rec.Code != 200 {
		t.Fatalf("sign-in: %d %s", rec.Code, rec.Body)
	}
	raw := webCookieOf(t, rec)
	if rec := f.req(t, "POST", "/api/web/session/elevate", raw, `{"currentPassword":"alice-pw"}`); rec.Code != 401 || errCode(t, rec.Body.String()) != "totp-required" {
		t.Fatalf("no code: %d %s", rec.Code, rec.Body)
	}
}

func TestCallerTokenIsTheWebSession(t *testing.T) {
	f := newWebFixture(t, true)
	raw := f.signIn(t, false)
	rec := f.req(t, "GET", "/api/me/tokens", raw, "")
	if rec.Code != 200 {
		t.Fatalf("tokens: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Tokens []struct {
			Label   string `json:"label"`
			Current bool   `json:"current"`
		} `json:"tokens"`
	}
	unmarshal(t, rec, &out)
	var current []string
	for _, tok := range out.Tokens {
		if tok.Current {
			current = append(current, tok.Label)
		}
	}
	if !slices.Equal(current, []string{"Web browser · Chrome on Windows"}) {
		t.Fatalf("current rows %q in %s", current, rec.Body)
	}
	// The device token is still its own caller.
	rec = doReq(t, f.h, "GET", "/api/me/tokens", f.aliceDevice, "")
	var device struct {
		Tokens []struct {
			Label   string `json:"label"`
			Current bool   `json:"current"`
		} `json:"tokens"`
	}
	unmarshal(t, rec, &device)
	for _, tok := range device.Tokens {
		if tok.Current && tok.Label != "test" {
			t.Fatalf("the device token's current row is %q", tok.Label)
		}
	}
}

// A web session lists with kind "web" and a device token with no kind, so a
// client can name the sessions a revoke takes with it.
func TestTheTokenListMarksAWebSession(t *testing.T) {
	f := newWebFixture(t, true)
	f.signIn(t, false)
	rec := doReq(t, f.h, "GET", "/api/me/tokens", f.aliceDevice, "")
	if rec.Code != 200 {
		t.Fatalf("tokens: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Tokens []map[string]any `json:"tokens"`
	}
	unmarshal(t, rec, &out)
	kinds := map[string]any{}
	for _, row := range out.Tokens {
		kinds[row["label"].(string)] = row["kind"]
	}
	if kinds["Web browser · Chrome on Windows"] != "web" {
		t.Fatalf("the web session's kind is %v in %s", kinds["Web browser · Chrome on Windows"], rec.Body)
	}
	if k, ok := kinds["test"]; !ok || k != nil {
		t.Fatalf("the device token carries kind %v in %s", k, rec.Body)
	}
}

func TestWindowCheckOnWebHeader(t *testing.T) {
	f := newWebFixture(t, true)
	raw := f.signIn(t, false)
	rec := f.req(t, "GET", "/api/shares", raw, "", header("X-HyperDrop-Client", "0.9.0 web"))
	if rec.Code != 409 || errCode(t, rec.Body.String()) != "client-outdated" {
		t.Fatalf("a web bundle outside the window: %d %s, want 409", rec.Code, rec.Body)
	}
	rec = f.req(t, "POST", "/api/web/session", "", `{"username":"alice","password":"alice-pw"}`, header("X-HyperDrop-Client", "0.9.0 web"))
	if rec.Code != 409 {
		t.Fatalf("a sign-in from a web bundle outside the window: %d %s, want 409", rec.Code, rec.Body)
	}
}

func TestUASummary(t *testing.T) {
	for ua, want := range map[string]string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36":                         "Chrome on Windows",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0":           "Edge on Windows",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15":                   "Safari on macOS",
		"Mozilla/5.0 (X11; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0":                                                                  "Firefox on Linux",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1": "Safari on iPhone",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/141.0 Mobile/15E148 Safari/604.1":  "Chrome on iPhone",
		"Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36":                   "Chrome on Android",
		"Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36":                          "Chrome on ChromeOS",
		"curl/8.7.1": "a browser",
		"":           "a browser",
	} {
		if got := uaSummary(ua); got != want {
			t.Errorf("uaSummary(%q) = %q, want %q", ua, got, want)
		}
	}
}

// A use that slides a kept session's row sets the cookie again with a fresh
// 30-day lifetime, so the browser keeps it as long as the server does; a use
// that slides nothing, a background request and a public session set none.
func TestKeptSessionCookieSlides(t *testing.T) {
	f := newWebFixture(t, true)
	kept := f.signIn(t, true)
	if rec := f.req(t, "GET", "/api/me", kept, ""); rec.Code != 200 || len(rec.Header().Values("Set-Cookie")) != 0 {
		t.Fatalf("a use inside the coalescing minute: %d %v, want no Set-Cookie", rec.Code, rec.Header().Values("Set-Cookie"))
	}
	behind := time.Now().Add(metadb.WebKeepFor - time.Hour)
	setIdle(t, f, kept, behind)
	rec := f.req(t, "GET", "/api/shares", kept, "", header("X-HyperDrop-Background", "1"))
	if rec.Code != 200 || len(rec.Header().Values("Set-Cookie")) != 0 {
		t.Fatalf("a background request: %d %v, want no Set-Cookie", rec.Code, rec.Header().Values("Set-Cookie"))
	}
	rec = f.req(t, "GET", "/api/me", kept, "")
	if rec.Code != 200 {
		t.Fatalf("a use: %d %s", rec.Code, rec.Body)
	}
	want := "__Host-hd_web=" + kept + "; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Strict"
	if got := rec.Header().Values("Set-Cookie"); len(got) != 1 || got[0] != want {
		t.Fatalf("Set-Cookie = %q, want [%q]", got, want)
	}

	public := f.signIn(t, false)
	setIdle(t, f, public, time.Now().Add(metadb.WebIdle-10*time.Minute))
	if rec := f.req(t, "GET", "/api/me", public, ""); rec.Code != 200 || len(rec.Header().Values("Set-Cookie")) != 0 {
		t.Fatalf("a public session's use: %d %v, want no Set-Cookie", rec.Code, rec.Header().Values("Set-Cookie"))
	}
}
