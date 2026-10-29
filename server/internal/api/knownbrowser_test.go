package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/volsecret"
)

// knownValueRe is the shape of a known-browser cookie's value.
var knownValueRe = regexp.MustCompile(`^k1\.[A-Za-z0-9_-]{22}\.[0-9]+\.[A-Za-z0-9_-]{43}$`)

// namedCookieAttributes is the attributes, after its name=value, of the one
// Set-Cookie line rec carries for the cookie name.
func namedCookieAttributes(t *testing.T, rec *httptest.ResponseRecorder, name string) (value string, attrs []string) {
	t.Helper()
	var lines []string
	for _, line := range rec.Header().Values("Set-Cookie") {
		if strings.HasPrefix(line, name+"=") {
			lines = append(lines, line)
		}
	}
	if len(lines) != 1 {
		t.Fatalf("Set-Cookie for %s = %q (all: %q), want one", name, lines, rec.Header().Values("Set-Cookie"))
	}
	parts := strings.Split(lines[0], "; ")
	attrs = parts[1:]
	slices.Sort(attrs)
	return strings.TrimPrefix(parts[0], name+"="), attrs
}

// setsKnownCookie reports whether rec sets the known-browser cookie at all.
func setsKnownCookie(rec *httptest.ResponseRecorder) bool {
	for _, line := range rec.Header().Values("Set-Cookie") {
		if strings.HasPrefix(line, knownCookie+"=") {
			return true
		}
	}
	return false
}

// withKnown sends value as the known-browser cookie.
func withKnown(value string) func(*http.Request) {
	return func(r *http.Request) { r.AddCookie(&http.Cookie{Name: knownCookie, Value: value}) }
}

// keptSignIn signs alice in with keep:true from addr and answers the session
// cookie's value and the known-browser cookie's value.
func keptSignIn(t *testing.T, f webFixture, addr string) (session, known string) {
	t.Helper()
	rec := f.req(t, "POST", "/api/web/session", "", `{"username":"alice","password":"alice-pw","keep":true}`, from(addr))
	if rec.Code != 200 {
		t.Fatalf("kept web sign-in: %d %s", rec.Code, rec.Body)
	}
	known, _ = namedCookieAttributes(t, rec, knownCookie)
	return webCookieOf(t, rec), known
}

// knownKeyOf derives the known-browser MAC key from secret as the
// specification names it.
func knownKeyOf(t *testing.T, secret []byte) []byte {
	t.Helper()
	key, err := volsecret.Subkey(secret, "known-browser")
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// knownValueFor builds a known-browser cookie value from the specification
// alone: k1.<id>.<issued>.<mac>, the MAC an HMAC-SHA256 under key of
// "k1|<username>|<created Unix seconds>|<password hash>|<id>|<issued>".
func knownValueFor(key []byte, u metadb.User, id string, issued int64) string {
	is := strconv.FormatInt(issued, 10)
	m := hmac.New(sha256.New, key)
	m.Write([]byte("k1|" + u.Username + "|" + strconv.FormatInt(u.CreatedAt.Unix(), 10) + "|" + u.PasswordHash + "|" + id + "|" + is))
	return "k1." + id + "." + is + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// newKnownID is a fresh cookie id: 16 random bytes, base64url unpadded.
func newKnownID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// laneFails is the failures the login limiter's lane key holds.
func laneFails(f webFixture, key string) int {
	l := f.hd.limits.login
	l.mu.Lock()
	defer l.mu.Unlock()
	if e := l.lanes[key]; e != nil {
		return e.fails
	}
	return 0
}

// knownLanes is the number of known-browser lanes the login limiter holds.
func knownLanes(f webFixture) int {
	l := f.hd.limits.login
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for k := range l.lanes {
		if strings.HasPrefix(k, knownLanePrefix) {
			n++
		}
	}
	return n
}

func TestAKeptWebSignInSetsTheKnownBrowserCookie(t *testing.T) {
	f := newWebFixture(t, true)
	before := time.Now().Unix()
	rec := f.req(t, "POST", "/api/web/session", "", `{"username":"alice","password":"alice-pw","keep":true}`)
	if rec.Code != 200 {
		t.Fatalf("kept web sign-in: %d %s", rec.Code, rec.Body)
	}
	value, attrs := namedCookieAttributes(t, rec, knownCookie)
	if !slices.Equal(attrs, []string{"HttpOnly", "Max-Age=15552000", "Path=/", "SameSite=Strict", "Secure"}) {
		t.Fatalf("known-browser cookie attributes %q", attrs)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == knownCookie && (c.MaxAge != 15552000 || c.Domain != "") {
			t.Fatalf("known-browser cookie MaxAge %d Domain %q, want 15552000 and none", c.MaxAge, c.Domain)
		}
	}
	if !knownValueRe.MatchString(value) {
		t.Fatalf("known-browser cookie value %q, want k1.<id>.<issued>.<mac>", value)
	}
	parts := strings.Split(value, ".")
	issued, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || issued < before || issued > time.Now().Unix() {
		t.Fatalf("issued %q, want the sign-in's time", parts[2])
	}
	u, err := f.db.User("alice")
	if err != nil {
		t.Fatal(err)
	}
	if want := knownValueFor(knownKeyOf(t, f.hd.fs.Secret()), u, parts[1], issued); value != want {
		t.Fatalf("known-browser cookie %q, want the specification's %q", value, want)
	}
}

func TestAPublicWebSignInSetsNoKnownBrowserCookie(t *testing.T) {
	f := newWebFixture(t, true)
	if rec := f.req(t, "POST", "/api/web/session", "", `{"username":"alice","password":"alice-pw"}`); rec.Code != 200 || setsKnownCookie(rec) {
		t.Fatalf("public web sign-in: %d %s %q, want 200 and no known-browser cookie", rec.Code, rec.Body, rec.Header().Values("Set-Cookie"))
	}
	if rec := f.req(t, "POST", "/api/web/session", "", `{"username":"alice","password":"wrong","keep":true}`); rec.Code != 401 || setsKnownCookie(rec) {
		t.Fatalf("wrong kept web sign-in: %d %s %q, want 401 and no known-browser cookie", rec.Code, rec.Body, rec.Header().Values("Set-Cookie"))
	}
}

func TestAKnownBrowserSignsInWhileTheAccountsLaneIsThrottled(t *testing.T) {
	f := newWebFixture(t, true)
	next := laneAddrs(0)
	_, known := keptSignIn(t, f, next())
	throttleAlice(t, f, next)
	rec := f.req(t, "POST", "/api/web/session", "", `{"username":"alice","password":"alice-pw","keep":true}`, from(next()), withKnown(known))
	if rec.Code != 200 {
		t.Fatalf("a known browser's sign-in while alice's lane waits: %d %s, want 200", rec.Code, rec.Body)
	}
	rec = f.req(t, "POST", "/api/web/session", "", `{"username":"alice","password":"alice-pw","keep":true}`, from(next()))
	wantAccountWait(t, rec, "a browser without the cookie")
}

func TestAKnownBrowserHasALaneOfItsOwn(t *testing.T) {
	f := newWebFixture(t, true)
	next := laneAddrs(0)
	_, known := keptSignIn(t, f, next())
	wrong := `{"username":"alice","password":"wrong","keep":true}`
	for i := range laneFree + 1 {
		if rec := f.req(t, "POST", "/api/web/session", "", wrong, from(next()), withKnown(known)); rec.Code != 401 {
			t.Fatalf("wrong sign-in %d with the cookie: %d %s, want 401", i+1, rec.Code, rec.Body)
		}
	}
	rec := f.req(t, "POST", "/api/web/session", "", wrong, from(next()), withKnown(known))
	wantAccountWait(t, rec, "the twelfth wrong sign-in with the cookie")
	if n := laneFails(f, signInLaneKey("alice")); n != 0 {
		t.Fatalf("alice's stranger lane holds %d failures, want 0", n)
	}
	for range laneFree {
		wrongLogin(t, f, "alice", next())
	}
}

func TestAKnownBrowserCookieThatDoesNotHoldIsAStranger(t *testing.T) {
	type fixture struct {
		webFixture
		t     *testing.T
		key   []byte
		alice metadb.User
		now   int64
	}
	valid := func(f fixture) string { return knownValueFor(f.key, f.alice, newKnownID(), f.now) }
	cases := []struct {
		name   string
		user   string
		known  bool
		cookie func(f fixture) string
	}{
		{name: "a cookie made as specified", user: "alice", known: true, cookie: valid},
		{name: "issued 179 days ago", user: "alice", known: true, cookie: func(f fixture) string {
			return knownValueFor(f.key, f.alice, newKnownID(), f.now-179*24*3600)
		}},
		{name: "a flipped MAC byte", user: "alice", cookie: func(f fixture) string {
			v := valid(f)
			i := strings.LastIndex(v, ".") + 1
			mac, err := base64.RawURLEncoding.DecodeString(v[i:])
			if err != nil {
				f.t.Fatal(err)
			}
			mac[7] ^= 0x01
			return v[:i] + base64.RawURLEncoding.EncodeToString(mac)
		}},
		{name: "issued 181 days ago", user: "alice", cookie: func(f fixture) string {
			return knownValueFor(f.key, f.alice, newKnownID(), f.now-181*24*3600)
		}},
		{name: "issued one hour ahead", user: "alice", cookie: func(f fixture) string {
			return knownValueFor(f.key, f.alice, newKnownID(), f.now+3600)
		}},
		{name: "minted under another volume secret", user: "alice", cookie: func(f fixture) string {
			other := make([]byte, 32)
			rand.Read(other)
			return knownValueFor(knownKeyOf(f.t, other), f.alice, newKnownID(), f.now)
		}},
		{name: "alice's cookie at bob's sign-in", user: "bob", cookie: valid},
		{name: "garbage", user: "alice", cookie: func(fixture) string { return "garbage" }},
		{name: "an empty value", user: "alice", cookie: func(fixture) string { return "" }},
		{name: "4 KB of a", user: "alice", cookie: func(fixture) string { return strings.Repeat("a", 4096) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wf := newWebFixture(t, true)
			seedUser(t, wf.db, "bob")
			alice, err := wf.db.User("alice")
			if err != nil {
				t.Fatal(err)
			}
			f := fixture{webFixture: wf, t: t, key: knownKeyOf(t, wf.hd.fs.Secret()), alice: alice, now: time.Now().Unix()}
			cookie := c.cookie(f)
			next := laneAddrs(0)
			wrong := `{"username":"` + c.user + `","password":"wrong","keep":true}`
			if rec := wf.req(t, "POST", "/api/web/session", "", wrong, from(next()), withKnown(cookie)); rec.Code != 401 {
				t.Fatalf("wrong sign-in: %d %s, want 401", rec.Code, rec.Body)
			}
			stranger := laneFails(wf, signInLaneKey(c.user))
			if c.known {
				if stranger != 0 || knownLanes(wf) != 1 {
					t.Fatalf("stranger lane %d failures, %d known lanes; want 0 and the cookie's own lane", stranger, knownLanes(wf))
				}
			} else if stranger != 1 || knownLanes(wf) != 0 {
				t.Fatalf("stranger lane %d failures, %d known lanes; want 1 and none", stranger, knownLanes(wf))
			}
			right := `{"username":"` + c.user + `","password":"` + c.user + `-pw"}`
			if rec := wf.req(t, "POST", "/api/web/session", "", right, from(next()), withKnown(cookie)); rec.Code != 200 {
				t.Fatalf("right sign-in: %d %s, want 200", rec.Code, rec.Body)
			}
		})
	}
}

func TestAKnownBrowserCookieDiesWithItsAccount(t *testing.T) {
	f := newWebFixture(t, true)
	next := laneAddrs(0)
	_, known := keptSignIn(t, f, next())
	old, err := f.db.User("alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.db.DeleteUser("alice"); err != nil {
		t.Fatal(err)
	}
	// An account's creation time is kept to the second, so the new alice is
	// made in a later second than the old one.
	time.Sleep(time.Until(old.CreatedAt.Add(time.Second)))
	if _, err := f.db.CreateUser("alice", "alice-pw", metadb.RoleUser, metadb.Settings{}); err != nil {
		t.Fatal(err)
	}
	if rec := f.req(t, "POST", "/api/web/session", "", `{"username":"alice","password":"wrong"}`, from(next()), withKnown(known)); rec.Code != 401 {
		t.Fatalf("wrong sign-in with the old alice's cookie: %d %s, want 401", rec.Code, rec.Body)
	}
	if n := laneFails(f, signInLaneKey("alice")); n != 1 || knownLanes(f) != 0 {
		t.Fatalf("stranger lane %d failures, %d known lanes; want 1 and none", n, knownLanes(f))
	}
}

// wantKnownLane makes one wrong web sign-in at alice carrying the
// known-browser cookie known and checks which lane counted it: the cookie's
// own when known holds, the stranger lane otherwise.
func wantKnownLane(t *testing.T, f webFixture, known, addr string, holds bool, what string) {
	t.Helper()
	strangerBefore, knownBefore := laneFails(f, signInLaneKey("alice")), knownLanes(f)
	if rec := f.req(t, "POST", "/api/web/session", "", `{"username":"alice","password":"wrong"}`, from(addr), withKnown(known)); rec.Code != 401 {
		t.Fatalf("%s: wrong sign-in with the cookie: %d %s, want 401", what, rec.Code, rec.Body)
	}
	stranger := laneFails(f, signInLaneKey("alice")) - strangerBefore
	if holds && (stranger != 0 || knownLanes(f) == 0) {
		t.Fatalf("%s: the stranger lane counted %d, %d known lanes; want the cookie's own lane", what, stranger, knownLanes(f))
	}
	if !holds && (stranger != 1 || knownLanes(f) != knownBefore) {
		t.Fatalf("%s: the stranger lane counted %d, known lanes %d to %d; want the stranger lane", what, stranger, knownBefore, knownLanes(f))
	}
}

func TestASignOutLeavesTheKnownBrowserCookieHolding(t *testing.T) {
	f := newWebFixture(t, true)
	next := laneAddrs(0)
	session, known := keptSignIn(t, f, next())
	rec := f.req(t, "DELETE", "/api/web/session", session, "", withKnown(known))
	wantSignedOut(t, f, rec, "sign out")
	wantKnownLane(t, f, known, next(), true, "after a sign-out")
}

func TestAPasswordChangeVoidsTheKnownBrowserCookie(t *testing.T) {
	f := newWebFixture(t, true)
	next := laneAddrs(0)
	session, known := keptSignIn(t, f, next())
	wantKnownLane(t, f, known, next(), true, "before the change")
	body := `{"password":"` + strongPassword + `","currentPassword":"alice-pw"}`
	if rec := f.req(t, "PATCH", "/api/me/password", session, body, from(next())); rec.Code != 200 {
		t.Fatalf("password change: %d %s", rec.Code, rec.Body)
	}
	wantKnownLane(t, f, known, next(), false, "after alice changed her password")
}

func TestAnAdminPasswordResetVoidsTheKnownBrowserCookie(t *testing.T) {
	f := newWebFixture(t, true)
	next := laneAddrs(0)
	_, known := keptSignIn(t, f, next())
	wantKnownLane(t, f, known, next(), true, "before the reset")
	if rec := doReqFrom(t, f.h, "PATCH", "/api/users/alice", testToken, `{"password":"`+strongPassword+`"}`, next()); rec.Code != 200 {
		t.Fatalf("the admin setting alice's password: %d %s", rec.Code, rec.Body)
	}
	wantKnownLane(t, f, known, next(), false, "after the admin set alice's password")
}

// A kept sign-in under the new password mints a cookie that holds.
func TestAKeptSignInAfterAPasswordResetMintsACookieThatHolds(t *testing.T) {
	f := newWebFixture(t, true)
	next := laneAddrs(0)
	if rec := doReqFrom(t, f.h, "PATCH", "/api/users/alice", testToken, `{"password":"`+strongPassword+`"}`, next()); rec.Code != 200 {
		t.Fatalf("the admin setting alice's password: %d %s", rec.Code, rec.Body)
	}
	rec := f.req(t, "POST", "/api/web/session", "", `{"username":"alice","password":"`+strongPassword+`","keep":true}`, from(next()))
	if rec.Code != 200 {
		t.Fatalf("kept sign-in under the new password: %d %s", rec.Code, rec.Body)
	}
	known, _ := namedCookieAttributes(t, rec, knownCookie)
	wantKnownLane(t, f, known, next(), true, "the cookie minted under the new password")
}

func TestSignOutAndAPasswordChangeSetNoKnownBrowserCookie(t *testing.T) {
	f := newWebFixture(t, true)
	session, known := keptSignIn(t, f, laneAddrs(0)())
	body := `{"password":"` + strongPassword + `","currentPassword":"alice-pw"}`
	rec := f.req(t, "PATCH", "/api/me/password", session, body, withKnown(known))
	if rec.Code != 200 || setsKnownCookie(rec) {
		t.Fatalf("password change: %d %s %q, want 200 and no known-browser cookie", rec.Code, rec.Body, rec.Header().Values("Set-Cookie"))
	}
	rec = f.req(t, "DELETE", "/api/web/session", webCookieOf(t, rec), "", withKnown(known))
	wantSignedOut(t, f, rec, "sign out")
	if setsKnownCookie(rec) {
		t.Fatalf("sign out set %q, want no known-browser cookie", rec.Header().Values("Set-Cookie"))
	}
}

func TestTheKnownBrowserCookieIsNeverSetOffTheAppHost(t *testing.T) {
	f := newWebFixture(t, true)
	rec := f.req(t, "POST", "/api/web/session", "", `{"username":"alice","password":"alice-pw","keep":true}`,
		func(r *http.Request) { r.Host = "files." + webAppHost })
	if rec.Code != 403 || len(rec.Header().Values("Set-Cookie")) != 0 {
		t.Fatalf("sign-in on the file host: %d %s %q, want 403 and no cookie", rec.Code, rec.Body, rec.Header().Values("Set-Cookie"))
	}
}
