package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"hyperdrop/server/internal/metadb"
)

// Signing a desktop app in with a phone: the computer asks for a request
// bound to the username typed there, a signed-in phone of that account
// claims it, the phone's owner types the number the computer shows, and the
// computer's next poll collects a device token stamped as signed in by phone.

type desktopSignInOut struct {
	ID         string    `json:"id"`
	PollSecret string    `json:"pollSecret"`
	Code       string    `json:"code"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

type desktopClaimOut struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Platform    string `json:"platform"`
	Address     string `json:"address"`
	SameNetwork bool   `json:"sameNetwork"`
}

type desktopPollOut struct {
	State  string `json:"state"`
	Number int    `json:"number"`
	Token  string `json:"token"`
	User   struct {
		Username string `json:"username"`
	} `json:"user"`
}

// desktopAddr is where the fixture's computer asks from.
const desktopAddr = "198.51.100.20:5000"

// deskReq is a POST as the desktop app's CLI sends it: the client header
// naming its system, no browser headers, from desktopAddr. edit changes it
// before it is served.
func deskReq(t *testing.T, f webFixture, path, body string, edit ...func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", path, strings.NewReader(body))
	r.Host = f.host()
	r.RemoteAddr = desktopAddr
	r.Header.Set("X-HyperDrop-Client", "2.0.0 macos")
	r.Header.Set("Content-Type", "application/json")
	for _, e := range edit {
		e(r)
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)
	return rec
}

// newDesktopSignIn is the computer asking for a request for username.
func newDesktopSignIn(t *testing.T, f webFixture, username, label string) desktopSignInOut {
	t.Helper()
	rec := deskReq(t, f, "/api/auth/desktop-sign-in", `{"label":`+strconv.Quote(label)+`,"username":`+strconv.Quote(username)+`}`)
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var out desktopSignInOut
	unmarshal(t, rec, &out)
	return out
}

// pollDesktop is the computer's poll.
func pollDesktop(t *testing.T, f webFixture, s desktopSignInOut) (*httptest.ResponseRecorder, desktopPollOut) {
	t.Helper()
	rec := deskReq(t, f, "/api/auth/desktop-sign-in/poll", `{"id":"`+s.ID+`","pollSecret":"`+s.PollSecret+`"}`)
	var out desktopPollOut
	if rec.Code == 200 || rec.Code == 202 {
		unmarshal(t, rec, &out)
	}
	return rec, out
}

// desktopCodeSecret is the one-time secret a hddesk1 code carries.
func desktopCodeSecret(t *testing.T, code string) (server, serverID, secret string) {
	t.Helper()
	body, ok := strings.CutPrefix(code, desktopSignInPrefix)
	if !ok {
		t.Fatalf("code %q is not a hddesk1 code", code)
	}
	b, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		t.Fatal(err)
	}
	var w webSignInWire
	if err := json.Unmarshal(b, &w); err != nil {
		t.Fatal(err)
	}
	return w.S, w.I, w.W
}

// approverReq is a POST as the approving phone's core sends it: the bearer
// token and the client header naming its system. edit changes it before it
// is served.
func approverReq(t *testing.T, f webFixture, path, token, body string, edit ...func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("X-HyperDrop-Client", "2.0.0 ios")
	r.Header.Set("Content-Type", "application/json")
	for _, e := range edit {
		e(r)
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)
	return rec
}

// claimDesktopReq is the phone, signed in with token, claiming the code.
func claimDesktopReq(t *testing.T, f webFixture, token, code string) *httptest.ResponseRecorder {
	t.Helper()
	_, _, secret := desktopCodeSecret(t, code)
	return approverReq(t, f, "/api/me/desktop-sign-ins/claim", token, `{"secret":"`+secret+`"}`)
}

func claimDesktop(t *testing.T, f webFixture, token, code string) desktopClaimOut {
	t.Helper()
	rec := claimDesktopReq(t, f, token, code)
	if rec.Code != 200 {
		t.Fatalf("claim: %d %s", rec.Code, rec.Body)
	}
	var out desktopClaimOut
	unmarshal(t, rec, &out)
	return out
}

func approveDesktop(t *testing.T, f webFixture, token, id string, number int, totp string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"number":` + strconv.Itoa(number) + `}`
	if totp != "" {
		body = `{"number":` + strconv.Itoa(number) + `,"totp":"` + totp + `"}`
	}
	return approverReq(t, f, "/api/me/desktop-sign-ins/"+id+"/approve", token, body)
}

func wantDesktopExpired(t *testing.T, what string, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != 410 || errCode(t, rec.Body.String()) != "desktop-sign-in-expired" {
		t.Fatalf("%s: %d %s, want 410 desktop-sign-in-expired", what, rec.Code, rec.Body)
	}
}

func wantRefusal(t *testing.T, what string, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if rec.Code != status || errCode(t, rec.Body.String()) != code {
		t.Fatalf("%s: %d %s, want %d %s", what, rec.Code, rec.Body, status, code)
	}
}

// wantWaiting asserts the computer's request is still unclaimed.
func wantWaiting(t *testing.T, f webFixture, s desktopSignInOut) {
	t.Helper()
	if rec, out := pollDesktop(t, f, s); rec.Code != 202 || out.State != "waiting" {
		t.Fatalf("the request: %d %s, want still waiting", rec.Code, rec.Body)
	}
}

// approvedDesktop runs a request for alice up to the approval.
func approvedDesktop(t *testing.T, f webFixture) desktopSignInOut {
	t.Helper()
	s := newDesktopSignIn(t, f, "alice", "Work Mac")
	claim := claimDesktop(t, f, f.aliceDevice, s.Code)
	_, out := pollDesktop(t, f, s)
	if rec := approveDesktop(t, f, f.aliceDevice, claim.ID, out.Number, ""); rec.Code != 204 {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body)
	}
	return s
}

// phoneSignedIn mints alice a computer token approved by her device, as a
// finished desktop sign-in leaves one.
func phoneSignedIn(t *testing.T, f webFixture) string {
	t.Helper()
	u, err := f.db.User("alice")
	if err != nil {
		t.Fatal(err)
	}
	approver := tokenNamed(u, metadb.TokenHash(f.aliceDevice))
	_, raw, err := f.db.MintDesktopSignIn("alice", approver.ID, "Phone sign-in: Mac", "macos", "m", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// All five routes answer a request without a well-formed client header
// 400 client-required, before anything else is judged, so every one of them
// is under the version window.
func TestDesktopRoutesNeedTheClientHeader(t *testing.T) {
	f := newWebFixture(t, true)
	s := newDesktopSignIn(t, f, "alice", "Mac")
	claim := claimDesktop(t, f, f.aliceDevice, s.Code)
	_, out := pollDesktop(t, f, s)
	_, _, secret := desktopCodeSecret(t, s.Code)
	for name, value := range map[string]string{"no header": "", "an off-shape header": "HyperDrop"} {
		for _, path := range []string{"/api/auth/desktop-sign-in", "/api/auth/desktop-sign-in/poll"} {
			rec := deskReq(t, f, path, `{}`, header("X-HyperDrop-Client", value))
			wantRefusal(t, name+" on "+path, rec, 400, "client-required")
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("%s on %s: Cache-Control %q", name, path, rec.Header().Get("Cache-Control"))
			}
		}
		for path, body := range map[string]string{
			"/api/me/desktop-sign-ins/claim":                    `{"secret":"` + secret + `"}`,
			"/api/me/desktop-sign-ins/" + claim.ID + "/approve": `{"number":` + strconv.Itoa(out.Number) + `}`,
			"/api/me/desktop-sign-ins/" + claim.ID + "/deny":    `{}`,
		} {
			rec := approverReq(t, f, path, f.aliceDevice, body, header("X-HyperDrop-Client", value))
			wantRefusal(t, name+" on "+path, rec, 400, "client-required")
		}
	}
	// The refused calls left the claim as it was.
	if rec, again := pollDesktop(t, f, s); rec.Code != 202 || again.State != "claimed" || again.Number != out.Number {
		t.Fatalf("after the refusals: %d %s, want still claimed", rec.Code, rec.Body)
	}
}

func TestDesktopCreateRefusesABrowser(t *testing.T) {
	f := newWebFixture(t, true)
	body := `{"label":"Mac","username":"alice"}`
	for name, edit := range map[string]func(*http.Request){
		"an Origin":         header("Origin", "https://evil.example"),
		"a Sec-Fetch-Site":  header("Sec-Fetch-Site", "none"),
		"the web client":    header("X-HyperDrop-Client", "2.0.0 web"),
		"a same-origin app": header("Origin", "https://"+webAppHost),
	} {
		for _, path := range []string{"/api/auth/desktop-sign-in", "/api/auth/desktop-sign-in/poll"} {
			wantRefusal(t, name+" on "+path, deskReq(t, f, path, body, edit), 403, "desktop-sign-in-refused")
		}
	}
}

func TestDesktopCreateRefusesAClientOutsideTheWindow(t *testing.T) {
	f := newWebFixture(t, true)
	rec := deskReq(t, f, "/api/auth/desktop-sign-in", `{"label":"Mac","username":"alice"}`, header("X-HyperDrop-Client", "1.0.0 macos"))
	wantRefusal(t, "an old client", rec, 409, "client-outdated")
}

// An unknown, a suspended and an administrator's username each get a
// request answered exactly as alice's is: only the claim judges the account.
func TestDesktopCreateRevealsNothingAboutTheUser(t *testing.T) {
	f := newWebFixture(t, true)
	seedUser(t, f.db, "sam")
	off := true
	if _, err := f.db.UpdateUser("sam", metadb.Settings{Disabled: &off}); err != nil {
		t.Fatal(err)
	}
	keys := func(rec *httptest.ResponseRecorder) string {
		var m map[string]any
		unmarshal(t, rec, &m)
		var out []string
		for k := range m {
			out = append(out, k)
		}
		slices.Sort(out)
		return strings.Join(out, ",")
	}
	var want string
	for i, name := range []string{"alice", "nobody", "sam", metadb.DefaultAdminName} {
		rec := deskReq(t, f, "/api/auth/desktop-sign-in", `{"label":"Mac","username":"`+name+`"}`, from("198.51.100."+strconv.Itoa(30+i)+":5000"))
		if rec.Code != 201 {
			t.Fatalf("create for %s: %d %s", name, rec.Code, rec.Body)
		}
		if got := keys(rec); i == 0 {
			want = got
		} else if got != want {
			t.Fatalf("create for %s answers %s, alice's %s", name, got, want)
		}
	}
	if want != "code,expiresAt,id,pollSecret" {
		t.Fatalf("the answer's fields: %s", want)
	}
}

func TestDesktopFullFlowMintsAStampedToken(t *testing.T) {
	f := newWebFixture(t, true)
	start := time.Now()
	s := newDesktopSignIn(t, f, "alice", "Work\u202e Mac")
	if s.ID == "" || len(s.PollSecret) != 43 {
		t.Fatalf("created %+v", s)
	}
	if d := s.ExpiresAt.Sub(start); d < 2*time.Minute-5*time.Second || d > 2*time.Minute+5*time.Second {
		t.Fatalf("expiresAt %v is %v from now, want 2 minutes", s.ExpiresAt, d)
	}
	server, serverID, secret := desktopCodeSecret(t, s.Code)
	if server != "https://"+webAppHost || serverID != f.hd.fs.ServerID() || len(secret) != 43 {
		t.Fatalf("code carries %q %q %q", server, serverID, secret)
	}
	wantWaiting(t, f, s)

	claim := claimDesktop(t, f, f.aliceDevice, s.Code)
	if claim.ID != s.ID || claim.Label != "Work Mac" || claim.Platform != "macos" || claim.Address != "198.51.100.20" || claim.SameNetwork {
		t.Fatalf("claim %+v", claim)
	}
	rec, out := pollDesktop(t, f, s)
	if rec.Code != 202 || out.State != "claimed" || out.Number < 10 || out.Number > 99 || strings.Contains(rec.Body.String(), "alice") {
		t.Fatalf("poll after the claim: %d %s, want claimed with no username", rec.Code, rec.Body)
	}
	if rec := approveDesktop(t, f, f.aliceDevice, claim.ID, out.Number, ""); rec.Code != 204 {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body)
	}
	rec, out = pollDesktop(t, f, s)
	if rec.Code != 200 || !strings.HasPrefix(out.Token, "hd_u_") || out.User.Username != "alice" {
		t.Fatalf("poll after the approval: %d %s", rec.Code, rec.Body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("the token's answer: %v", rec.Header())
	}
	if rec := doReq(t, f.h, "GET", "/api/me", out.Token, ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"username":"alice"`) {
		t.Fatalf("the minted token on /api/me: %d %s", rec.Code, rec.Body)
	}
	if again, _ := pollDesktop(t, f, s); again.Code != 410 {
		t.Fatalf("a second poll after the approval: %d, want 410", again.Code)
	}

	list := doReq(t, f.h, "GET", "/api/me/tokens", f.aliceDevice, "")
	var tokens struct {
		Tokens []map[string]any `json:"tokens"`
	}
	unmarshal(t, list, &tokens)
	found := false
	for _, row := range tokens.Tokens {
		switch row["label"] {
		case "Phone sign-in: Work Mac":
			found = true
			if row["method"] != "phone" || row["approvedBy"] != "test" {
				t.Fatalf("the computer's row %v", row)
			}
		default:
			if _, ok := row["method"]; ok {
				t.Fatalf("a row signed in another way carries method: %v", row)
			}
			if _, ok := row["approvedBy"]; ok {
				t.Fatalf("a row signed in another way carries approvedBy: %v", row)
			}
		}
	}
	if !found {
		t.Fatalf("no computer row in %v", tokens.Tokens)
	}
	// The stored row carries the system the computer's request named.
	u, err := f.db.User("alice")
	if err != nil {
		t.Fatal(err)
	}
	if tok := tokenNamed(u, metadb.TokenHash(out.Token)); tok.ClientPlatform != "macos" || tok.SignInMethod != metadb.SignInMethodPhone {
		t.Fatalf("the computer's token row %+v, want platform macos signed in by phone", tok)
	}
}

// Another account's claim answers as an unknown code does and leaves the
// request waiting for the account it was made for.
func TestDesktopClaimRefusesAnotherAccountAndKeepsTheRequest(t *testing.T) {
	f := newWebFixture(t, true)
	bob := seedUser(t, f.db, "bob")
	s := newDesktopSignIn(t, f, "alice", "Mac")
	wantDesktopExpired(t, "bob's claim", claimDesktopReq(t, f, bob, s.Code))
	wantWaiting(t, f, s)
	// A second claim by bob still touches nothing.
	wantDesktopExpired(t, "bob's second claim", claimDesktopReq(t, f, bob, s.Code))
	if claim := claimDesktop(t, f, f.aliceDevice, s.Code); claim.ID != s.ID {
		t.Fatalf("alice's claim %+v", claim)
	}
	// Once alice claimed it, bob's claim does not burn it either.
	wantDesktopExpired(t, "bob's claim of alice's claimed request", claimDesktopReq(t, f, bob, s.Code))
	if rec, out := pollDesktop(t, f, s); rec.Code != 202 || out.State != "claimed" {
		t.Fatalf("after bob's claim: %d %s, want still claimed", rec.Code, rec.Body)
	}
}

func TestDesktopClaimMatchesTheUsernameCasefolded(t *testing.T) {
	f := newWebFixture(t, true)
	s := newDesktopSignIn(t, f, " Alice ", "Mac")
	if claim := claimDesktop(t, f, f.aliceDevice, s.Code); claim.ID != s.ID {
		t.Fatalf("claim %+v", claim)
	}
}

func TestDesktopCreateRefusesAMalformedUsername(t *testing.T) {
	f := newWebFixture(t, true)
	for _, name := range []string{"", "a", "\u212alice", "al ice"} {
		rec := deskReq(t, f, "/api/auth/desktop-sign-in", `{"label":"Mac","username":`+strconv.Quote(name)+`}`)
		if rec.Code != 400 {
			t.Fatalf("username %q: %d %s, want 400", name, rec.Code, rec.Body)
		}
	}
}

func TestDesktopClaimRefusesAFreshDevice(t *testing.T) {
	withFreshDeviceRule(t)
	f := newWebFixture(t, true)
	s := newDesktopSignIn(t, f, "alice", "Mac")
	wantRefusal(t, "a fresh device's claim", claimDesktopReq(t, f, f.aliceDevice, s.Code), 403, "device-too-new")
	wantWaiting(t, f, s)
	oldDevice(t, f, f.aliceDevice)
	claimDesktop(t, f, f.aliceDevice, s.Code)
}

func TestDesktopClaimRefusesAPhoneSignedInToken(t *testing.T) {
	f := newWebFixture(t, true)
	computer := phoneSignedIn(t, f)
	s := newDesktopSignIn(t, f, "alice", "Mac")
	wantRefusal(t, "a computer's claim", claimDesktopReq(t, f, computer, s.Code), 403, "desktop-sign-in-refused")
	wantWaiting(t, f, s)
}

func TestDesktopClaimRefusesAdmin(t *testing.T) {
	f := newWebFixture(t, true)
	s := newDesktopSignIn(t, f, metadb.DefaultAdminName, "Mac")
	wantRefusal(t, "an admin's claim", claimDesktopReq(t, f, testToken, s.Code), 403, "desktop-sign-in-admin")
	wantWaiting(t, f, s)
}

// An approving device that signed in three computers in the last day is
// refused at the claim, before it draws a number.
func TestDesktopClaimRefusesTheFourthInADay(t *testing.T) {
	f := newWebFixture(t, true)
	for range metadb.DesktopSignInsPerDay {
		phoneSignedIn(t, f)
	}
	s := newDesktopSignIn(t, f, "alice", "Mac")
	wantRefusal(t, "a fourth claim", claimDesktopReq(t, f, f.aliceDevice, s.Code), 429, "desktop-sign-in-limit")
	wantWaiting(t, f, s)
}

func TestDesktopPollAfterApproverRevokedMintsNothing(t *testing.T) {
	f := newWebFixture(t, true)
	s := approvedDesktop(t, f)
	execRaw(t, f.dir, `DELETE FROM tokens WHERE sha256 = ?`, metadb.TokenHash(f.aliceDevice))
	rec, out := pollDesktop(t, f, s)
	wantDesktopExpired(t, "poll after the approver signed out", rec)
	if out.Token != "" || strings.Contains(rec.Body.String(), "hd_u_") {
		t.Fatalf("a token in %s", rec.Body)
	}
	u, err := f.db.User("alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(u.Tokens) != 0 {
		t.Fatalf("alice holds %+v", u.Tokens)
	}
}

func TestDesktopPollAfterPasswordChangeMintsNothing(t *testing.T) {
	f := newWebFixture(t, true)
	s := approvedDesktop(t, f)
	rec := doReq(t, f.h, "PATCH", "/api/me/password", f.aliceDevice, `{"password":"a-new-password","currentPassword":"alice-pw"}`)
	if rec.Code != 200 {
		t.Fatalf("password change: %d %s", rec.Code, rec.Body)
	}
	rec, _ = pollDesktop(t, f, s)
	wantDesktopExpired(t, "poll after the password changed", rec)
	u, err := f.db.User("alice")
	if err != nil {
		t.Fatal(err)
	}
	for _, tok := range u.Tokens {
		if tok.SignInMethod == metadb.SignInMethodPhone {
			t.Fatalf("a computer was signed in: %+v", tok)
		}
	}
}

// A suspended account, an administrator's and an approver at its daily
// limit get the mint's own refusal at the poll.
func TestDesktopPollMapsTheMintsRefusals(t *testing.T) {
	f := newWebFixture(t, true)
	s := approvedDesktop(t, f)
	off, on := true, false
	if _, err := f.db.UpdateUser("alice", metadb.Settings{Disabled: &off}); err != nil {
		t.Fatal(err)
	}
	rec, _ := pollDesktop(t, f, s)
	wantDesktopExpired(t, "poll of a suspended account", rec)
	if _, err := f.db.UpdateUser("alice", metadb.Settings{Disabled: &on}); err != nil {
		t.Fatal(err)
	}

	s = approvedDesktop(t, f)
	admin := metadb.RoleAdmin
	if _, err := f.db.UpdateUser("alice", metadb.Settings{Role: &admin}); err != nil {
		t.Fatal(err)
	}
	rec, _ = pollDesktop(t, f, s)
	wantRefusal(t, "poll of a promoted account", rec, 403, "desktop-sign-in-admin")
	user := metadb.RoleUser
	if _, err := f.db.UpdateUser("alice", metadb.Settings{Role: &user}); err != nil {
		t.Fatal(err)
	}

	s = approvedDesktop(t, f)
	for range metadb.DesktopSignInsPerDay {
		phoneSignedIn(t, f)
	}
	rec, _ = pollDesktop(t, f, s)
	wantRefusal(t, "poll past the daily limit", rec, 429, "desktop-sign-in-limit")
}

func TestDesktopPollAtTheDeviceCap(t *testing.T) {
	f := newWebFixture(t, true)
	was := metadb.MaxTokensPerAccount
	metadb.MaxTokensPerAccount = 2
	t.Cleanup(func() { metadb.MaxTokensPerAccount = was })
	s := approvedDesktop(t, f)
	if _, err := f.db.MintToken("alice", "second"); err != nil {
		t.Fatal(err)
	}
	rec, _ := pollDesktop(t, f, s)
	wantRefusal(t, "poll at the device cap", rec, 409, "too-many-devices")
}

func TestDesktopWrongNumberBurns(t *testing.T) {
	f := newWebFixture(t, true)
	s := newDesktopSignIn(t, f, "alice", "Mac")
	claim := claimDesktop(t, f, f.aliceDevice, s.Code)
	_, out := pollDesktop(t, f, s)
	wrong := out.Number%90 + 10
	if wrong == out.Number {
		wrong = out.Number%89 + 11
	}
	rec := approveDesktop(t, f, f.aliceDevice, claim.ID, wrong, "")
	if rec.Code != 409 || errCode(t, rec.Body.String()) != "device-link-wrong-number" ||
		!strings.Contains(rec.Body.String(), "that is not the number the computer shows") {
		t.Fatalf("a wrong number: %d %s", rec.Code, rec.Body)
	}
	wantDesktopExpired(t, "the right number after a wrong one", approveDesktop(t, f, f.aliceDevice, claim.ID, out.Number, ""))
	rec, _ = pollDesktop(t, f, s)
	wantDesktopExpired(t, "poll of a burned request", rec)
}

func TestDesktopWrongTOTPAsksAgain(t *testing.T) {
	f := newWebFixture(t, true)
	secret, _ := enableTOTP(t, f.h, f.aliceDevice, "alice-pw")
	s := newDesktopSignIn(t, f, "alice", "Mac")
	claim := claimDesktop(t, f, f.aliceDevice, s.Code)
	_, out := pollDesktop(t, f, s)
	wantRefusal(t, "no code", approveDesktop(t, f, f.aliceDevice, claim.ID, out.Number, ""), 401, "totp-required")
	wantRefusal(t, "a wrong code", approveDesktop(t, f, f.aliceDevice, claim.ID, out.Number, "000000"), 401, "totp-invalid")
	if rec, again := pollDesktop(t, f, s); rec.Code != 202 || again.State != "claimed" {
		t.Fatalf("after refused codes: %d %s, want still claimed", rec.Code, rec.Body)
	}
	if rec := approveDesktop(t, f, f.aliceDevice, claim.ID, out.Number, nextCode(t, secret)); rec.Code != 204 {
		t.Fatalf("number and code: %d %s", rec.Code, rec.Body)
	}
	if rec, done := pollDesktop(t, f, s); rec.Code != 200 || done.Token == "" {
		t.Fatalf("poll after the approval: %d %s", rec.Code, rec.Body)
	}
}

func TestDesktopDeny(t *testing.T) {
	f := newWebFixture(t, true)
	bob := seedUser(t, f.db, "bob")
	s := newDesktopSignIn(t, f, "alice", "Mac")
	claim := claimDesktop(t, f, f.aliceDevice, s.Code)
	wantDesktopExpired(t, "bob's deny", approverReq(t, f, "/api/me/desktop-sign-ins/"+claim.ID+"/deny", bob, `{}`))
	if rec := approverReq(t, f, "/api/me/desktop-sign-ins/"+claim.ID+"/deny", f.aliceDevice, `{}`); rec.Code != 204 {
		t.Fatalf("deny: %d %s", rec.Code, rec.Body)
	}
	rec, _ := pollDesktop(t, f, s)
	wantDesktopExpired(t, "poll of a denied request", rec)
}

func TestDesktopSwitchOffDropsRequests(t *testing.T) {
	f := newWebFixture(t, true)
	s := newDesktopSignIn(t, f, "alice", "Mac")
	rec := doReq(t, f.h, "PATCH", "/api/server/settings", testToken, `{"desktopSignIn":false}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"desktopSignIn":false`) {
		t.Fatalf("turning it off: %d %s", rec.Code, rec.Body)
	}
	if f.hd.desktopSignInOn() {
		t.Fatal("the switch reads on")
	}
	body := `{"label":"Mac","username":"alice"}`
	wantRefusal(t, "create while off", deskReq(t, f, "/api/auth/desktop-sign-in", body), 403, "desktop-sign-in-off")
	rec, _ = pollDesktop(t, f, s)
	wantRefusal(t, "poll while off", rec, 403, "desktop-sign-in-off")
	wantRefusal(t, "claim while off", claimDesktopReq(t, f, f.aliceDevice, s.Code), 403, "desktop-sign-in-off")

	rec = doReq(t, f.h, "PATCH", "/api/server/settings", testToken, `{"desktopSignIn":true}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"desktopSignIn":true`) {
		t.Fatalf("turning it on: %d %s", rec.Code, rec.Body)
	}
	// Turning it off forgot every request.
	rec, _ = pollDesktop(t, f, s)
	wantDesktopExpired(t, "a request from before the switch went off", rec)
	newDesktopSignIn(t, f, "alice", "Mac")
}

func TestDesktopSwitchDefaultsOn(t *testing.T) {
	f := newWebFixture(t, true)
	if _, ok, err := f.db.Setting(desktopSwitchKey); err != nil || ok {
		t.Fatalf("a fresh server stores the switch: %v %v", ok, err)
	}
	if !f.hd.desktopSignInOn() {
		t.Fatal("a server that never stored the switch reads off")
	}
	rec := doReq(t, f.h, "GET", "/api/server/settings", testToken, "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"desktopSignIn":true`) {
		t.Fatalf("settings: %d %s", rec.Code, rec.Body)
	}
	if err := f.db.SetSetting(desktopSwitchKey, "0"); err != nil {
		t.Fatal(err)
	}
	if f.hd.desktopSignInOn() {
		t.Fatal(`"0" reads on`)
	}
	if err := f.db.SetSetting(desktopSwitchKey, "1"); err != nil {
		t.Fatal(err)
	}
	if !f.hd.desktopSignInOn() {
		t.Fatal(`"1" reads off`)
	}
	rec = doReq(t, f.h, "PATCH", "/api/server/settings", testToken, `{}`)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "desktopSignIn") {
		t.Fatalf("an empty PATCH: %d %s, want 400 naming every key", rec.Code, rec.Body)
	}
	if rec := doReq(t, f.h, "PATCH", "/api/server/settings", f.aliceDevice, `{"desktopSignIn":false}`); rec.Code != 403 {
		t.Fatalf("a user's PATCH: %d %s, want 403", rec.Code, rec.Body)
	}
}

// A browser's request is never claimed or polled as a computer's, nor the
// reverse, and each switch drops only its own book.
func TestWebAndDesktopBooksNeverCross(t *testing.T) {
	f := newWebFixture(t, true)
	web := newWebSignIn(t, f, browserAddr)
	desk := newDesktopSignIn(t, f, "alice", "Mac")
	_, _, webSecret := codeSecret(t, web.Code)
	_, _, deskSecret := desktopCodeSecret(t, desk.Code)

	wantDesktopExpired(t, "a browser's secret on the desktop claim",
		approverReq(t, f, "/api/me/desktop-sign-ins/claim", f.aliceDevice, `{"secret":"`+webSecret+`"}`))
	rec := doReq(t, f.h, "POST", "/api/me/web-sign-ins/claim", f.aliceDevice, `{"secret":"`+deskSecret+`"}`)
	wantExpired(t, "a computer's secret on the browser claim", rec.Code, rec.Body.String())

	rec = deskReq(t, f, "/api/auth/desktop-sign-in/poll", `{"id":"`+web.ID+`","pollSecret":"`+web.PollSecret+`"}`)
	wantDesktopExpired(t, "a browser's request on the desktop poll", rec)
	rec = f.req(t, "POST", "/api/web/phone-sign-in/poll", "", `{"id":"`+desk.ID+`","pollSecret":"`+desk.PollSecret+`"}`)
	wantExpired(t, "a computer's request on the browser poll", rec.Code, rec.Body.String())

	// A claim in one book burns no request of the other.
	webClaim := claimWebSignIn(t, f, f.aliceDevice, web.Code)
	deskClaim := claimDesktop(t, f, f.aliceDevice, desk.Code)
	wantDesktopExpired(t, "the browser's id on the desktop approve", approveDesktop(t, f, f.aliceDevice, webClaim.ID, 42, ""))
	rec = approveWebSignIn(t, f, f.aliceDevice, deskClaim.ID, 42, "")
	wantExpired(t, "the computer's id on the browser approve", rec.Code, rec.Body.String())
	if code, out, _ := pollWebSignIn(t, f, web); code != 202 || out.State != "claimed" {
		t.Fatalf("the browser's request: %d %+v", code, out)
	}
	if rec, out := pollDesktop(t, f, desk); rec.Code != 202 || out.State != "claimed" {
		t.Fatalf("the computer's request: %d %s", rec.Code, rec.Body)
	}

	if err := f.hd.setWebSwitch(false); err != nil {
		t.Fatal(err)
	}
	if rec, out := pollDesktop(t, f, desk); rec.Code != 202 || out.State != "claimed" {
		t.Fatalf("the computer's request after the web switch went off: %d %s", rec.Code, rec.Body)
	}
	if err := f.hd.setWebSwitch(true); err != nil {
		t.Fatal(err)
	}
	web = newWebSignIn(t, f, browserAddr)
	if err := f.hd.setDesktopSwitch(false); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := pollWebSignIn(t, f, web); code != 202 || out.State != "waiting" {
		t.Fatalf("the browser's request after the desktop switch went off: %d %+v", code, out)
	}
}

// A token a phone signed in approves nothing: not a browser, not a phone
// through a device link, not another computer.
func TestPhoneSignedInTokenCannotApproveABrowserOrAPhone(t *testing.T) {
	f := newWebFixture(t, true)
	computer := phoneSignedIn(t, f)

	web := newWebSignIn(t, f, browserAddr)
	_, _, secret := codeSecret(t, web.Code)
	rec := doReq(t, f.h, "POST", "/api/me/web-sign-ins/claim", computer, `{"secret":"`+secret+`"}`)
	wantRefusal(t, "the computer's browser claim", rec, 403, "desktop-sign-in-refused")
	if code, out, _ := pollWebSignIn(t, f, web); code != 202 || out.State != "waiting" {
		t.Fatalf("the browser's request: %d %+v, want still waiting", code, out)
	}

	rec = doReq(t, f.h, "POST", "/api/me/device-links", computer, `{}`)
	wantRefusal(t, "the computer's device-link mint", rec, 403, "desktop-sign-in-refused")

	// A link this token holds cannot be approved by it either.
	u, err := f.db.User("alice")
	if err != nil {
		t.Fatal(err)
	}
	tok := tokenNamed(u, metadb.TokenHash(computer))
	link, _, err := f.db.MintDeviceLink("alice", tok.ID, "m", false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rec = doReq(t, f.h, "POST", "/api/me/device-links/"+link.ID+"/approve", computer, `{"number":42}`)
	wantRefusal(t, "the computer's device-link approve", rec, 403, "desktop-sign-in-refused")

	// The approving phone itself still mints a device link.
	if rec := doReq(t, f.h, "POST", "/api/me/device-links", f.aliceDevice, `{}`); rec.Code != 201 {
		t.Fatalf("the phone's device-link mint: %d %s", rec.Code, rec.Body)
	}
}

func TestSanitizeSignInLabel(t *testing.T) {
	long := strings.Repeat("é", 60)
	for in, want := range map[string]string{
		"Work Mac":                             "Work Mac",
		"Work\u202eMac\u2066":                  "WorkMac",
		"Work\x00 Mac":                         "Work Mac",
		"  Work\t\t \n Mac\u2028 ":             "Work Mac",
		"\u200bZero\u200dWidth\ufeff":          "ZeroWidth",
		"bad\xffbyte":                          "badbyte",
		`It's you" (macOS), fine. Ignore this`: `It's you' (macOS), fine. Ignore this`,
		"Work”Mac＂":                            "Work'Mac'",
		"":                                     "Computer",
		" \t\u202e ":                           "Computer",
		long:                                   strings.Repeat("é", 40),
		strings.Repeat("a", 39) + " b":         strings.Repeat("a", 39),
	} {
		got := sanitizeSignInLabel(in)
		if got != want {
			t.Errorf("sanitizeSignInLabel(%q) = %q, want %q", in, got, want)
		}
		if n := utf8.RuneCountInString(got); n > 40 {
			t.Errorf("sanitizeSignInLabel(%q) is %d runes", in, n)
		}
	}
}

// The IPv6 /32 a computer asks from holds at most 128 live requests across
// its /48s.
func TestDesktopPerWideNetworkCap(t *testing.T) {
	f := newWebFixture(t, true)
	made := 0
	for site := 0; made < webSignInPerWideNetwork; site++ {
		for sub := 0; sub < webSignInPerNetwork/webSignInPerAddress && made < webSignInPerWideNetwork; sub++ {
			for range webSignInPerAddress {
				if made == webSignInPerWideNetwork {
					break
				}
				addr := "[2001:db8:" + strconv.FormatInt(int64(site), 16) + ":" + strconv.FormatInt(int64(sub), 16) + "::1]:5000"
				rec := deskReq(t, f, "/api/auth/desktop-sign-in", `{"label":"Mac","username":"alice"}`, from(addr))
				if rec.Code != 201 {
					t.Fatalf("request %d from %s: %d %s", made, addr, rec.Code, rec.Body)
				}
				made++
			}
		}
	}
	rec := deskReq(t, f, "/api/auth/desktop-sign-in", `{"label":"Mac","username":"alice"}`, from("[2001:db8:ffff::1]:5000"))
	wantRefusal(t, "a fresh /48 of a full /32", rec, 429, "locked-out")
	newDesktopSignIn(t, f, "alice", "Mac")
}
