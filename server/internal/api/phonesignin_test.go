package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/metadb"
)

// Signing a browser in with a phone: the browser asks for a request and
// shows its code, the signed-in phone claims it, the browser shows the
// number the phone's owner types there, the phone approves, and the
// browser's next poll collects a public web session.

type webSignInOut struct {
	ID         string    `json:"id"`
	PollSecret string    `json:"pollSecret"`
	Code       string    `json:"code"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

type webSignInClaimOut struct {
	ID          string `json:"id"`
	Browser     string `json:"browser"`
	Address     string `json:"address"`
	SameNetwork bool   `json:"sameNetwork"`
}

type webSignInPollOut struct {
	State    string `json:"state"`
	Number   int    `json:"number"`
	Username string `json:"username"`
}

// browserAddr is where the fixture's browser asks from.
const browserAddr = "203.0.113.50:4000"

// newWebSignIn is the browser asking for a request from addr.
func newWebSignIn(t *testing.T, f webFixture, addr string) webSignInOut {
	t.Helper()
	rec := f.req(t, "POST", "/api/web/phone-sign-in", "", `{}`, from(addr))
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var out webSignInOut
	unmarshal(t, rec, &out)
	return out
}

// pollWebSignIn is the browser's poll.
func pollWebSignIn(t *testing.T, f webFixture, s webSignInOut) (int, webSignInPollOut, string) {
	t.Helper()
	rec := f.req(t, "POST", "/api/web/phone-sign-in/poll", "",
		`{"id":"`+s.ID+`","pollSecret":"`+s.PollSecret+`"}`, from(browserAddr))
	var out webSignInPollOut
	if rec.Code == 202 {
		unmarshal(t, rec, &out)
	}
	cookie := ""
	for _, c := range rec.Result().Cookies() {
		if c.Name == webCookie {
			cookie = c.Value
		}
	}
	return rec.Code, out, cookie
}

// webSignInWire is what a hdweb1 code carries.
type webSignInWire struct {
	S string `json:"s"`
	I string `json:"i"`
	W string `json:"w"`
}

// decodeWebSignInCode reads a hdweb1 code as core/joincode does.
func decodeWebSignInCode(code string) (webSignInWire, error) {
	body, ok := strings.CutPrefix(code, webSignInPrefix)
	if !ok {
		return webSignInWire{}, errors.New("not a hdweb1 code")
	}
	b, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return webSignInWire{}, err
	}
	var w webSignInWire
	err = json.Unmarshal(b, &w)
	return w, err
}

// codeSecret is the one-time secret a hdweb1 code carries, as the phone
// reads it.
func codeSecret(t *testing.T, code string) (server, serverID, secret string) {
	t.Helper()
	w, err := decodeWebSignInCode(code)
	if err != nil {
		t.Fatalf("code %q: %v", code, err)
	}
	return w.S, w.I, w.W
}

// claimWebSignIn is the phone, signed in with token, claiming the code.
func claimWebSignIn(t *testing.T, f webFixture, token, code string) webSignInClaimOut {
	t.Helper()
	_, _, secret := codeSecret(t, code)
	rec := doReq(t, f.h, "POST", "/api/me/web-sign-ins/claim", token, `{"secret":"`+secret+`"}`)
	if rec.Code != 200 {
		t.Fatalf("claim: %d %s", rec.Code, rec.Body)
	}
	var out webSignInClaimOut
	unmarshal(t, rec, &out)
	return out
}

func approveWebSignIn(t *testing.T, f webFixture, token, id string, number int, totp string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"number":` + strconv.Itoa(number) + `}`
	if totp != "" {
		body = `{"number":` + strconv.Itoa(number) + `,"totp":"` + totp + `"}`
	}
	return doReq(t, f.h, "POST", "/api/me/web-sign-ins/"+id+"/approve", token, body)
}

// oldDevice backdates token's sign-in two days, so the fresh-device rule
// passes it.
func oldDevice(t *testing.T, f webFixture, token string) {
	t.Helper()
	execRaw(t, f.dir, `UPDATE tokens SET created_at = ? WHERE sha256 = ?`,
		time.Now().Add(-48*time.Hour).UnixNano(), metadb.TokenHash(token))
}

func wantExpired(t *testing.T, what string, code int, body string) {
	t.Helper()
	if code != 410 || errCode(t, body) != "web-sign-in-expired" {
		t.Fatalf("%s: %d %s, want 410 web-sign-in-expired", what, code, body)
	}
}

func TestPhoneSignInHappyPath(t *testing.T) {
	withFreshDeviceRule(t)
	f := newWebFixture(t, true)
	oldDevice(t, f, f.aliceDevice)
	start := time.Now()
	s := newWebSignIn(t, f, browserAddr)
	if !strings.HasPrefix(s.Code, webSignInPrefix) || s.ID == "" || len(s.PollSecret) != 43 {
		t.Fatalf("created %+v", s)
	}
	if d := s.ExpiresAt.Sub(start); d < 2*time.Minute-5*time.Second || d > 2*time.Minute+5*time.Second {
		t.Fatalf("expiresAt %v is %v from now, want 2 minutes", s.ExpiresAt, d)
	}
	server, serverID, secret := codeSecret(t, s.Code)
	if server != "https://"+webAppHost || serverID != f.hd.fs.ServerID() || len(secret) != 43 {
		t.Fatalf("code carries %q %q %q", server, serverID, secret)
	}
	if code, out, _ := pollWebSignIn(t, f, s); code != 202 || out.State != "waiting" || out.Username != "" {
		t.Fatalf("poll before the claim: %d %+v", code, out)
	}

	claim := claimWebSignIn(t, f, f.aliceDevice, s.Code)
	if claim.ID != s.ID || claim.Browser != "Chrome on Windows" || claim.Address != "203.0.113.50" || claim.SameNetwork {
		t.Fatalf("claim %+v", claim)
	}
	code, out, _ := pollWebSignIn(t, f, s)
	if code != 202 || out.State != "claimed" || out.Number < 10 || out.Number > 99 || out.Username != "alice" {
		t.Fatalf("poll after the claim: %d %+v, want claimed by alice", code, out)
	}
	if rec := approveWebSignIn(t, f, f.aliceDevice, claim.ID, out.Number, ""); rec.Code != 204 {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body)
	}
	code, _, cookie := pollWebSignIn(t, f, s)
	if code != 200 || cookie == "" {
		t.Fatalf("poll after the approval: %d, cookie %q", code, cookie)
	}
	rec := f.req(t, "GET", "/api/me", cookie, "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"username":"alice"`) {
		t.Fatalf("the phone-approved session on /api/me: %d %s", rec.Code, rec.Body)
	}
	u, err := f.db.User("alice")
	if err != nil {
		t.Fatal(err)
	}
	device := tokenNamed(u, metadb.TokenHash(f.aliceDevice))
	var web metadb.Token
	for _, tok := range u.Tokens {
		if tok.Kind == metadb.TokenKindWeb {
			web = tok
		}
	}
	if web.Keep || web.Label != "Web browser · Chrome on Windows" || web.ViaToken != device.ID {
		t.Fatalf("the session row %+v, want a public session approved by %s", web, device.ID)
	}
}

// The poll's 200 is the web sign-in's answer: the account and the
// session's limits, never a token, and the cookie a public one.
func TestPhoneSignInAnswersLikeTheWebSignIn(t *testing.T) {
	f := newWebFixture(t, true)
	s := newWebSignIn(t, f, browserAddr)
	claim := claimWebSignIn(t, f, f.aliceDevice, s.Code)
	_, out, _ := pollWebSignIn(t, f, s)
	approveWebSignIn(t, f, f.aliceDevice, claim.ID, out.Number, "")
	rec := f.req(t, "POST", "/api/web/phone-sign-in/poll", "", `{"id":"`+s.ID+`","pollSecret":"`+s.PollSecret+`"}`)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "token") || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("poll: %d %s %v", rec.Code, rec.Body, rec.Header())
	}
	var body struct {
		User    map[string]any `json:"user"`
		Session struct {
			Keep        bool `json:"keep"`
			IdleSeconds int  `json:"idleSeconds"`
		} `json:"session"`
	}
	unmarshal(t, rec, &body)
	if body.User["username"] != "alice" || body.Session.Keep || body.Session.IdleSeconds != 1800 {
		t.Fatalf("poll body %+v", body)
	}
	_, attrs := cookieAttributes(t, rec)
	for _, a := range attrs {
		if strings.HasPrefix(a, "Max-Age") || strings.HasPrefix(a, "Expires") {
			t.Fatalf("the cookie is kept: %v", attrs)
		}
	}
}

func TestPhoneSignInWrongNumberBurns(t *testing.T) {
	f := newWebFixture(t, true)
	s := newWebSignIn(t, f, browserAddr)
	claim := claimWebSignIn(t, f, f.aliceDevice, s.Code)
	_, out, _ := pollWebSignIn(t, f, s)
	wrong := out.Number%90 + 10
	if wrong == out.Number {
		wrong = out.Number%89 + 11
	}
	rec := approveWebSignIn(t, f, f.aliceDevice, claim.ID, wrong, "")
	if rec.Code != 409 || errCode(t, rec.Body.String()) != "device-link-wrong-number" || !strings.Contains(rec.Body.String(), "the number the browser shows") {
		t.Fatalf("a wrong number: %d %s, want 409 device-link-wrong-number naming the browser", rec.Code, rec.Body)
	}
	rec = approveWebSignIn(t, f, f.aliceDevice, claim.ID, out.Number, "")
	wantExpired(t, "the right number after a wrong one", rec.Code, rec.Body.String())
	code, _, _ := pollWebSignIn(t, f, s)
	if code != 410 {
		t.Fatalf("poll of a burned request: %d, want 410", code)
	}
	if rec := approveWebSignIn(t, f, f.aliceDevice, claim.ID, 9, ""); rec.Code != 400 {
		t.Fatalf("a number that is not two digits: %d, want 400", rec.Code)
	}
}

func TestPhoneSignInNeedsCodeOnTwoFactor(t *testing.T) {
	f := newWebFixture(t, true)
	secret, _ := enableTOTP(t, f.h, f.aliceDevice, "alice-pw")
	s := newWebSignIn(t, f, browserAddr)
	claim := claimWebSignIn(t, f, f.aliceDevice, s.Code)
	_, out, _ := pollWebSignIn(t, f, s)
	rec := approveWebSignIn(t, f, f.aliceDevice, claim.ID, out.Number, "")
	if rec.Code != 401 || errCode(t, rec.Body.String()) != "totp-required" {
		t.Fatalf("no code: %d %s, want 401 totp-required", rec.Code, rec.Body)
	}
	rec = approveWebSignIn(t, f, f.aliceDevice, claim.ID, out.Number, "000000")
	if rec.Code != 401 || errCode(t, rec.Body.String()) != "totp-invalid" {
		t.Fatalf("a wrong code: %d %s, want 401 totp-invalid", rec.Code, rec.Body)
	}
	if code, again, _ := pollWebSignIn(t, f, s); code != 202 || again.State != "claimed" {
		t.Fatalf("after refused codes: %d %+v, want still claimed", code, again)
	}
	if rec := approveWebSignIn(t, f, f.aliceDevice, claim.ID, out.Number, nextCode(t, secret)); rec.Code != 204 {
		t.Fatalf("number and code: %d %s", rec.Code, rec.Body)
	}
	if code, _, cookie := pollWebSignIn(t, f, s); code != 200 || cookie == "" {
		t.Fatalf("poll after the approval: %d", code)
	}
}

func TestPhoneSignInFreshDeviceRefused(t *testing.T) {
	withFreshDeviceRule(t)
	f := newWebFixture(t, true)
	s := newWebSignIn(t, f, browserAddr)
	_, _, secret := codeSecret(t, s.Code)
	rec := doReq(t, f.h, "POST", "/api/me/web-sign-ins/claim", f.aliceDevice, `{"secret":"`+secret+`"}`)
	if rec.Code != 403 || errCode(t, rec.Body.String()) != "device-too-new" {
		t.Fatalf("claim from a fresh device: %d %s, want 403 device-too-new", rec.Code, rec.Body)
	}
	if code, out, _ := pollWebSignIn(t, f, s); code != 202 || out.State != "waiting" {
		t.Fatalf("after the refused claim: %d %+v, want still waiting", code, out)
	}
}

func TestPhoneSignInUnclaimedExpires(t *testing.T) {
	f := newWebFixture(t, true)
	s := newWebSignIn(t, f, browserAddr)
	_, _, secret := codeSecret(t, s.Code)
	f.hd.signIns.clock = func() time.Time { return time.Now().Add(2*time.Minute + time.Second) }
	code, _, _ := pollWebSignIn(t, f, s)
	if code != 410 {
		t.Fatalf("poll after 2 minutes: %d, want 410", code)
	}
	rec := doReq(t, f.h, "POST", "/api/me/web-sign-ins/claim", f.aliceDevice, `{"secret":"`+secret+`"}`)
	wantExpired(t, "claim after 2 minutes", rec.Code, rec.Body.String())
}

func TestPhoneSignInClaimedExpires(t *testing.T) {
	f := newWebFixture(t, true)
	s := newWebSignIn(t, f, browserAddr)
	f.hd.signIns.clock = func() time.Time { return time.Now().Add(time.Minute) }
	claim := claimWebSignIn(t, f, f.aliceDevice, s.Code)
	_, out, _ := pollWebSignIn(t, f, s)
	f.hd.signIns.clock = func() time.Time { return time.Now().Add(6*time.Minute + time.Second) }
	rec := approveWebSignIn(t, f, f.aliceDevice, claim.ID, out.Number, "")
	wantExpired(t, "approve 5 minutes after the claim", rec.Code, rec.Body.String())
}

func TestPhoneSignInSecondClaimBurns(t *testing.T) {
	f := newWebFixture(t, true)
	bob := seedUser(t, f.db, "bob")
	s := newWebSignIn(t, f, browserAddr)
	claim := claimWebSignIn(t, f, f.aliceDevice, s.Code)
	_, _, secret := codeSecret(t, s.Code)
	rec := doReq(t, f.h, "POST", "/api/me/web-sign-ins/claim", bob, `{"secret":"`+secret+`"}`)
	wantExpired(t, "a second claim", rec.Code, rec.Body.String())
	code, _, _ := pollWebSignIn(t, f, s)
	if code != 410 {
		t.Fatalf("poll after a second claim: %d, want 410", code)
	}
	rec = approveWebSignIn(t, f, f.aliceDevice, claim.ID, 42, "")
	wantExpired(t, "approve after a second claim", rec.Code, rec.Body.String())
}

// One account approves one request at a time: claiming a second burns the
// first.
func TestPhoneSignInOneClaimPerAccount(t *testing.T) {
	f := newWebFixture(t, true)
	first := newWebSignIn(t, f, browserAddr)
	second := newWebSignIn(t, f, browserAddr)
	claimWebSignIn(t, f, f.aliceDevice, first.Code)
	claimWebSignIn(t, f, f.aliceDevice, second.Code)
	if code, _, _ := pollWebSignIn(t, f, first); code != 410 {
		t.Fatalf("the first request after a second claim: %d, want 410", code)
	}
	if code, out, _ := pollWebSignIn(t, f, second); code != 202 || out.State != "claimed" {
		t.Fatalf("the second request: %d %+v", code, out)
	}
}

func TestPhoneSignInSingleSession(t *testing.T) {
	f := newWebFixture(t, true)
	s := newWebSignIn(t, f, browserAddr)
	claim := claimWebSignIn(t, f, f.aliceDevice, s.Code)
	_, out, _ := pollWebSignIn(t, f, s)
	approveWebSignIn(t, f, f.aliceDevice, claim.ID, out.Number, "")
	if code, _, cookie := pollWebSignIn(t, f, s); code != 200 || cookie == "" {
		t.Fatalf("first poll after the approval: %d", code)
	}
	if code, _, cookie := pollWebSignIn(t, f, s); code != 410 || cookie != "" {
		t.Fatalf("second poll after the approval: %d cookie %q, want 410 and no cookie", code, cookie)
	}
	u, err := f.db.User("alice")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, tok := range u.Tokens {
		if tok.Kind == metadb.TokenKindWeb {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d web sessions, want 1", n)
	}
	if rec := doReq(t, f.h, "POST", "/api/me/web-sign-ins/"+claim.ID+"/deny", f.aliceDevice, ""); rec.Code != 410 {
		t.Fatalf("deny of a spent request: %d, want 410", rec.Code)
	}
}

// An approving device signed out before the browser's poll mints nothing.
func TestPhoneSignInApproverSignedOut(t *testing.T) {
	f := newWebFixture(t, true)
	s := newWebSignIn(t, f, browserAddr)
	claim := claimWebSignIn(t, f, f.aliceDevice, s.Code)
	_, out, _ := pollWebSignIn(t, f, s)
	approveWebSignIn(t, f, f.aliceDevice, claim.ID, out.Number, "")
	execRaw(t, f.dir, `DELETE FROM tokens WHERE sha256 = ?`, metadb.TokenHash(f.aliceDevice))
	if code, _, cookie := pollWebSignIn(t, f, s); code != 410 || cookie != "" {
		t.Fatalf("poll after the approver signed out: %d cookie %q, want 410", code, cookie)
	}
}

// An account suspended after the approval gets no session: the poll
// answers account-disabled and spends the request; an account deleted
// takes its approving device with it, so the poll answers 410.
func TestPhoneSignInAccountGoneAfterApproval(t *testing.T) {
	f := newWebFixture(t, true)
	approved := func() webSignInOut {
		s := newWebSignIn(t, f, browserAddr)
		claim := claimWebSignIn(t, f, f.aliceDevice, s.Code)
		_, out, _ := pollWebSignIn(t, f, s)
		approveWebSignIn(t, f, f.aliceDevice, claim.ID, out.Number, "")
		return s
	}
	s := approved()
	off, on := true, false
	if _, err := f.db.UpdateUser("alice", metadb.Settings{Disabled: &off}); err != nil {
		t.Fatal(err)
	}
	rec := f.req(t, "POST", "/api/web/phone-sign-in/poll", "", `{"id":"`+s.ID+`","pollSecret":"`+s.PollSecret+`"}`)
	if rec.Code != 403 || errCode(t, rec.Body.String()) != "account-disabled" || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("poll of a suspended account: %d %s, want 403 account-disabled", rec.Code, rec.Body)
	}
	if code, _, _ := pollWebSignIn(t, f, s); code != 410 {
		t.Fatalf("the poll after: %d, want 410", code)
	}
	if _, err := f.db.UpdateUser("alice", metadb.Settings{Disabled: &on}); err != nil {
		t.Fatal(err)
	}
	s = approved()
	if err := f.db.DeleteUser("alice"); err != nil {
		t.Fatal(err)
	}
	if code, _, cookie := pollWebSignIn(t, f, s); code != 410 || cookie != "" {
		t.Fatalf("poll of a deleted account: %d, want 410", code)
	}
}

func TestPhoneSignInDeny(t *testing.T) {
	f := newWebFixture(t, true)
	bob := seedUser(t, f.db, "bob")
	s := newWebSignIn(t, f, browserAddr)
	claim := claimWebSignIn(t, f, f.aliceDevice, s.Code)
	if rec := doReq(t, f.h, "POST", "/api/me/web-sign-ins/"+claim.ID+"/deny", bob, ""); rec.Code != 410 {
		t.Fatalf("another account's deny: %d, want 410", rec.Code)
	}
	if rec := doReq(t, f.h, "POST", "/api/me/web-sign-ins/"+claim.ID+"/deny", f.aliceDevice, ""); rec.Code != 204 {
		t.Fatalf("deny: %d %s", rec.Code, rec.Body)
	}
	if code, _, _ := pollWebSignIn(t, f, s); code != 410 {
		t.Fatalf("poll of a denied request: %d, want 410", code)
	}
}

func TestPhoneSignInPerAddressCap(t *testing.T) {
	f := newWebFixture(t, true)
	for range webSignInPerAddress {
		newWebSignIn(t, f, browserAddr)
	}
	rec := f.req(t, "POST", "/api/web/phone-sign-in", "", `{}`, from(browserAddr))
	if rec.Code != 429 || errCode(t, rec.Body.String()) != "locked-out" || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("a fourth request: %d %s %v, want 429 locked-out with Retry-After", rec.Code, rec.Body, rec.Header())
	}
	// Another address of the same IPv6 /64 is the same address key.
	for range webSignInPerAddress {
		newWebSignIn(t, f, "[2001:db8::1]:4000")
	}
	if rec := f.req(t, "POST", "/api/web/phone-sign-in", "", `{}`, from("[2001:db8::2]:4000")); rec.Code != 429 {
		t.Fatalf("a fourth request from the same /64: %d, want 429", rec.Code)
	}
	newWebSignIn(t, f, "198.51.100.9:4000")
	f.hd.signIns.clock = func() time.Time { return time.Now().Add(2*time.Minute + time.Second) }
	newWebSignIn(t, f, browserAddr)
}

// One IPv6 /48 holds at most webSignInPerNetwork live requests across all
// its /64s, so one allocation cannot fill the server's cap.
func TestPhoneSignInPerNetworkCap(t *testing.T) {
	f := newWebFixture(t, true)
	made := 0
	for sub := 0; made < webSignInPerNetwork; sub++ {
		for range webSignInPerAddress {
			if made == webSignInPerNetwork {
				break
			}
			newWebSignIn(t, f, fmt.Sprintf("[2001:db8:7:%x::1]:4000", sub))
			made++
		}
	}
	rec := f.req(t, "POST", "/api/web/phone-sign-in", "", `{}`, from("[2001:db8:7:ffff::1]:4000"))
	if rec.Code != 429 || errCode(t, rec.Body.String()) != "locked-out" || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("a fresh /64 of a full /48: %d %s, want 429 locked-out with Retry-After", rec.Code, rec.Body)
	}
	newWebSignIn(t, f, "[2001:db8:8::1]:4000")
	newWebSignIn(t, f, "198.51.100.9:4000")
	f.hd.signIns.clock = func() time.Time { return time.Now().Add(2*time.Minute + time.Second) }
	newWebSignIn(t, f, "[2001:db8:7:ffff::1]:4000")
}

func TestPhoneSignInRefusedWhenWebOff(t *testing.T) {
	f := newWebFixture(t, true)
	s := newWebSignIn(t, f, browserAddr)
	if err := f.hd.setWebSwitch(false); err != nil {
		t.Fatal(err)
	}
	rec := f.req(t, "POST", "/api/web/phone-sign-in", "", `{}`, from(browserAddr))
	if rec.Code != 403 || errCode(t, rec.Body.String()) != "web-off" {
		t.Fatalf("create while off: %d %s, want 403 web-off", rec.Code, rec.Body)
	}
	rec = f.req(t, "POST", "/api/web/phone-sign-in/poll", "", `{"id":"`+s.ID+`","pollSecret":"`+s.PollSecret+`"}`)
	if rec.Code != 403 || errCode(t, rec.Body.String()) != "web-off" {
		t.Fatalf("poll while off: %d %s, want 403 web-off", rec.Code, rec.Body)
	}
	if err := f.hd.setWebSwitch(true); err != nil {
		t.Fatal(err)
	}
	// Turning the web client off forgot every request.
	if code, _, _ := pollWebSignIn(t, f, s); code != 410 {
		t.Fatalf("a request from before the switch went off: %d, want 410", code)
	}
	f.web.UseDevDir("")
	rec = f.req(t, "POST", "/api/web/phone-sign-in", "", `{}`, from(browserAddr))
	if rec.Code != 503 || errCode(t, rec.Body.String()) != "web-unavailable" {
		t.Fatalf("create with no bundle: %d %s, want 503 web-unavailable", rec.Code, rec.Body)
	}
}

// The browser's two routes ask what the web sign-in asks of its request:
// the app host, the web client header and the app's own origin.
func TestPhoneSignInRefusedOffTheAppOrigin(t *testing.T) {
	f := newWebFixture(t, true)
	s := newWebSignIn(t, f, browserAddr)
	claim := claimWebSignIn(t, f, f.aliceDevice, s.Code)
	_, out, _ := pollWebSignIn(t, f, s)
	approveWebSignIn(t, f, f.aliceDevice, claim.ID, out.Number, "")
	poll := `{"id":"` + s.ID + `","pollSecret":"` + s.PollSecret + `"}`
	for name, edit := range map[string]func(*http.Request){
		"another origin":    header("Origin", "https://evil.example"),
		"a cross-site page": header("Sec-Fetch-Site", "cross-site"),
		"no web header":     header("X-HyperDrop-Client", ""),
	} {
		for _, path := range []string{"/api/web/phone-sign-in", "/api/web/phone-sign-in/poll"} {
			rec := f.req(t, "POST", path, "", poll, edit)
			if rec.Code != 403 || errCode(t, rec.Body.String()) != "web-session-refused" || len(rec.Result().Cookies()) != 0 {
				t.Fatalf("%s on %s: %d %s, want 403 web-session-refused", name, path, rec.Code, rec.Body)
			}
		}
	}
	// The refused polls spent nothing.
	if code, _, cookie := pollWebSignIn(t, f, s); code != 200 || cookie == "" {
		t.Fatalf("the browser's own poll: %d", code)
	}
}

func TestPhoneSignInPollSecretMustMatch(t *testing.T) {
	f := newWebFixture(t, true)
	s := newWebSignIn(t, f, browserAddr)
	other := newWebSignIn(t, f, browserAddr)
	forged := s
	forged.PollSecret = other.PollSecret
	if code, _, _ := pollWebSignIn(t, f, forged); code != 410 {
		t.Fatalf("a poll with another request's secret: %d, want 410", code)
	}
	if code, out, _ := pollWebSignIn(t, f, s); code != 202 || out.State != "waiting" {
		t.Fatalf("the request after a forged poll: %d %+v", code, out)
	}
}

// The code the server builds is the one core/joincode decodes: this
// fixture is copied verbatim into TestServerWebSignInCodeDecodes there.
func TestWebSignInCodeFixture(t *testing.T) {
	const fixture = "hdweb1.eyJzIjoiaHR0cHM6Ly9zaGFyZS5leGFtcGxlLmNvbSIsImkiOiJzcnYtMSIsInciOiJjMlZqY21WMCJ9"
	if got := webSignInCode("https://share.example.com", "srv-1", "c2VjcmV0"); got != fixture {
		t.Fatalf("webSignInCode = %q, want %q", got, fixture)
	}
}

// The desktop code is the web payload under its own prefix: this fixture is
// copied verbatim into TestServerDesktopSignInCodeDecodes in core/joincode.
func TestDesktopSignInCodeFixture(t *testing.T) {
	const fixture = "hddesk1.eyJzIjoiaHR0cHM6Ly9zaGFyZS5leGFtcGxlLmNvbSIsImkiOiJzcnYtMSIsInciOiJjMlZqY21WMCJ9"
	if got := desktopSignInCode("https://share.example.com", "srv-1", "c2VjcmV0"); got != fixture {
		t.Fatalf("desktopSignInCode = %q, want %q", got, fixture)
	}
}
