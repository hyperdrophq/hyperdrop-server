package api

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/metadb"
)

// A signed-in desktop signs a phone in: it mints a link under its password
// and code, follows it while the phone claims it, and approves it with the
// number the phone shows. Every desktop route is scoped to the token that
// minted the link.

type mintedLink struct {
	ID           string    `json:"id"`
	Secret       string    `json:"secret"`
	ExpiresAt    time.Time `json:"expiresAt"`
	WindowEndsAt time.Time `json:"windowEndsAt"`
}

type linkStatus struct {
	State       string    `json:"state"`
	Address     string    `json:"address"`
	ExpiresAt   time.Time `json:"expiresAt"`
	Label       string    `json:"label"`
	Platform    string    `json:"platform"`
	SameNetwork bool      `json:"sameNetwork"`
}

func mintDeviceLink(t *testing.T, h http.Handler, token, password string) mintedLink {
	t.Helper()
	rec := doReq(t, h, "POST", "/api/me/device-links", token, `{"currentPassword":"`+password+`"`+seededAdminTOTP(t)+`}`)
	if rec.Code != 201 {
		t.Fatalf("mint: %d %s", rec.Code, rec.Body)
	}
	var link mintedLink
	unmarshal(t, rec, &link)
	return link
}

func readDeviceLink(t *testing.T, h http.Handler, token, id string) linkStatus {
	t.Helper()
	rec := doReq(t, h, "GET", "/api/me/device-links/"+id, token, "")
	if rec.Code != 200 {
		t.Fatalf("status: %d %s", rec.Code, rec.Body)
	}
	var st linkStatus
	unmarshal(t, rec, &st)
	return st
}

func TestAFreshDeviceCannotMintALink(t *testing.T) {
	withFreshDeviceRule(t)
	h, hd := newTestAPIParts(t)
	for _, body := range []string{
		`{"currentPassword":"` + testAdminPassword + `"}`,
		`{"currentPassword":"wrong"}`,
	} {
		rec := doReq(t, h, "POST", "/api/me/device-links", testToken, body)
		if rec.Code != 403 || errCode(t, rec.Body.String()) != "device-too-new" {
			t.Fatalf("%s: %d %s, want 403 device-too-new", body, rec.Code, rec.Body)
		}
	}
	hd.limits.login.mu.Lock()
	counted := len(hd.limits.login.byKey) + len(hd.limits.login.accounts)
	hd.limits.login.mu.Unlock()
	if counted != 0 {
		t.Fatalf("the refused mints counted %d lockout entries, want none", counted)
	}
}

func TestTheDesktopMintsWithItsPasswordAndCode(t *testing.T) {
	h := newTestAPI(t)
	if rec := doReq(t, h, "POST", "/api/me/device-links", testToken, `{"currentPassword":"wrong"}`); rec.Code != 401 ||
		errCode(t, rec.Body.String()) != "wrong-password" {
		t.Fatalf("wrong password: %d %s, want 401 wrong-password", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "POST", "/api/me/device-links", testToken, `{"currentPassword":"x","extra":1}`); rec.Code != 400 {
		t.Fatalf("unknown field: %d %s, want 400", rec.Code, rec.Body)
	}

	link := mintDeviceLink(t, h, testToken, testAdminPassword)
	if len(link.Secret) != 43 {
		t.Fatalf("secret %q is %d characters, want 43", link.Secret, len(link.Secret))
	}
	if b, err := base64.RawURLEncoding.DecodeString(link.Secret); err != nil || len(b) != 32 {
		t.Fatalf("secret %q is not 32 bytes of unpadded base64url: %v", link.Secret, err)
	}
	if link.ID == "" {
		t.Fatal("the mint answered no id")
	}
	if want := link.WindowEndsAt.Add(-3 * time.Minute).Add(30 * time.Second); !link.ExpiresAt.Equal(want) {
		t.Fatalf("expiresAt %v, want %v (30 s after the mint)", link.ExpiresAt, want)
	}

	secret, _ := enableTOTP(t, h, testToken, testAdminPassword)
	rec := doReq(t, h, "POST", "/api/me/device-links", testToken, `{"currentPassword":"`+testAdminPassword+`"}`)
	if rec.Code != 401 || errCode(t, rec.Body.String()) != "totp-required" {
		t.Fatalf("2FA account without a code: %d %s, want 401 totp-required", rec.Code, rec.Body)
	}
	rec = doReq(t, h, "POST", "/api/me/device-links", testToken,
		`{"currentPassword":"`+testAdminPassword+`","totp":"`+nextCode(t, secret)+`"}`)
	if rec.Code != 201 {
		t.Fatalf("password and code: %d %s, want 201", rec.Code, rec.Body)
	}
}

func TestTheDesktopRenewsAnUnclaimedLink(t *testing.T) {
	h := newTestAPI(t)
	link := mintDeviceLink(t, h, testToken, testAdminPassword)
	rec := doReq(t, h, "POST", "/api/me/device-links/"+link.ID+"/renew", testToken, "")
	if rec.Code != 200 {
		t.Fatalf("renew: %d %s", rec.Code, rec.Body)
	}
	var renewed mintedLink
	unmarshal(t, rec, &renewed)
	if renewed.ID != link.ID || renewed.Secret == link.Secret || len(renewed.Secret) != 43 ||
		!renewed.WindowEndsAt.Equal(link.WindowEndsAt) || renewed.ExpiresAt.Before(link.ExpiresAt) {
		t.Fatalf("renewed %+v from %+v, want the same link with a new secret and a later expiry", renewed, link)
	}
}

func TestTheDesktopFollowsTheLinkToApproval(t *testing.T) {
	h, hd := newTestAPIParts(t)
	link := mintDeviceLink(t, h, testToken, testAdminPassword)
	if st := readDeviceLink(t, h, testToken, link.ID); st.State != "minted" || st.Label != "" {
		t.Fatalf("before the claim: %+v, want minted with no label", st)
	}
	claim, err := hd.db.ClaimDeviceLink(link.Secret, "Pixel 9", "android", addrMarkOf(hd, "192.0.2.1"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	st := readDeviceLink(t, h, testToken, link.ID)
	if st.State != "claimed" || st.Label != "Pixel 9" || st.Platform != "android" || !st.SameNetwork {
		t.Fatalf("after the claim: %+v, want claimed by Pixel 9 (android) on the same network", st)
	}
	if rec := doReq(t, h, "POST", "/api/me/device-links/"+link.ID+"/approve", testToken,
		`{"number":`+strconv.Itoa(claim.Number)+`}`); rec.Code != 204 {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body)
	}
	if st := readDeviceLink(t, h, testToken, link.ID); st.State != "approved" {
		t.Fatalf("after the approve: %+v, want approved", st)
	}
}

func TestAnotherNetworkReadsNoSameNetwork(t *testing.T) {
	h, hd := newTestAPIParts(t)
	link := mintDeviceLink(t, h, testToken, testAdminPassword)
	if _, err := hd.db.ClaimDeviceLink(link.Secret, "Pixel 9", "android", "198.51.100.2", time.Now()); err != nil {
		t.Fatal(err)
	}
	rec := doReq(t, h, "GET", "/api/me/device-links/"+link.ID, testToken, "")
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "sameNetwork") {
		t.Fatalf("status: %d %s, want no sameNetwork", rec.Code, rec.Body)
	}
}

func TestAnotherTokenCannotReadOrApproveTheLink(t *testing.T) {
	h, hd := newTestAPIParts(t)
	other := loginWithLabel(t, h, "mac-b")
	link := mintDeviceLink(t, h, testToken, testAdminPassword)
	claim, err := hd.db.ClaimDeviceLink(link.Secret, "Pixel 9", "android", addrMarkOf(hd, "192.0.2.1"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/api/me/device-links/" + link.ID, ""},
		{"POST", "/api/me/device-links/" + link.ID + "/approve", `{"number":` + strconv.Itoa(claim.Number) + `}`},
		{"POST", "/api/me/device-links/" + link.ID + "/deny", ""},
		{"POST", "/api/me/device-links/" + link.ID + "/renew", ""},
	} {
		rec := doReq(t, h, c.method, c.path, other, c.body)
		if rec.Code != 404 || errCode(t, rec.Body.String()) != "device-link-invalid" {
			t.Fatalf("%s %s by another token: %d %s, want 404 device-link-invalid", c.method, c.path, rec.Code, rec.Body)
		}
	}
	if st := readDeviceLink(t, h, testToken, link.ID); st.State != "claimed" {
		t.Fatalf("after another token's tries: %+v, want claimed", st)
	}
}

func TestAWrongNumberAnswersWrongNumberAndBurns(t *testing.T) {
	h, hd := newTestAPIParts(t)
	link := mintDeviceLink(t, h, testToken, testAdminPassword)
	claim, err := hd.db.ClaimDeviceLink(link.Secret, "Pixel 9", "android", addrMarkOf(hd, "192.0.2.1"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	wrong := 10 + (claim.Number-10+1)%90
	rec := doReq(t, h, "POST", "/api/me/device-links/"+link.ID+"/approve", testToken, `{"number":`+strconv.Itoa(wrong)+`}`)
	if rec.Code != 409 || errCode(t, rec.Body.String()) != "device-link-wrong-number" {
		t.Fatalf("wrong number: %d %s, want 409 device-link-wrong-number", rec.Code, rec.Body)
	}
	if st := readDeviceLink(t, h, testToken, link.ID); st.State != "burned" {
		t.Fatalf("after a wrong number: %+v, want burned", st)
	}
}

func TestTheDesktopDeniesALink(t *testing.T) {
	h := newTestAPI(t)
	link := mintDeviceLink(t, h, testToken, testAdminPassword)
	if rec := doReq(t, h, "POST", "/api/me/device-links/"+link.ID+"/deny", testToken, ""); rec.Code != 204 {
		t.Fatalf("deny: %d %s", rec.Code, rec.Body)
	}
	if st := readDeviceLink(t, h, testToken, link.ID); st.State != "burned" {
		t.Fatalf("after the deny: %+v, want burned", st)
	}
	rec := doReq(t, h, "POST", "/api/me/device-links/"+link.ID+"/deny", testToken, "")
	if rec.Code != 404 || errCode(t, rec.Body.String()) != "device-link-invalid" {
		t.Fatalf("a second deny: %d %s, want 404 device-link-invalid", rec.Code, rec.Body)
	}
}

// The phone's half: it claims the scanned secret, shows its number, and
// polls until the desktop approves and its own token is minted. Both routes
// are unauthenticated and count their failures on the login lockout.

const phoneClient = "1.4.0 ios"

type phoneClaim struct {
	ClaimID    string `json:"claimId"`
	PollSecret string `json:"pollSecret"`
	Number     int    `json:"number"`
	Approver   string `json:"approver"`
	Username   string `json:"username"`
}

// phoneReq is a phone's unauthenticated request from addr.
func phoneReq(t *testing.T, h http.Handler, path, body, addr string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Header.Set("X-HyperDrop-Client", phoneClient)
	req.RemoteAddr = addr
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func claimBody(secret, label string) string {
	return `{"secret":"` + secret + `","label":"` + label + `"}`
}

func pollBody(c phoneClaim) string {
	return `{"claimId":"` + c.ClaimID + `","pollSecret":"` + c.PollSecret + `"}`
}

func claimLink(t *testing.T, h http.Handler, secret, label, addr string) phoneClaim {
	t.Helper()
	rec := phoneReq(t, h, "/api/auth/device-link/claim", claimBody(secret, label), addr)
	if rec.Code != 202 {
		t.Fatalf("claim: %d %s", rec.Code, rec.Body)
	}
	var c phoneClaim
	unmarshal(t, rec, &c)
	return c
}

func randomLinkSecret(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func wantLinkInvalid(t *testing.T, what string, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != 404 || errCode(t, rec.Body.String()) != "device-link-invalid" {
		t.Fatalf("%s: %d %s, want 404 device-link-invalid", what, rec.Code, rec.Body)
	}
}

func TestAPhoneSignsInThroughALink(t *testing.T) {
	h := newTestAPI(t)
	desktop := loginWithLabel(t, h, "MacBook")
	link := mintDeviceLink(t, h, desktop, testAdminPassword)
	const phone = "198.51.100.20:5000"

	claim := claimLink(t, h, link.Secret, "Ana's iPhone", phone)
	if claim.Number < 10 || claim.Number > 99 || claim.Approver != "MacBook" || claim.Username != "admin" ||
		claim.ClaimID == "" || len(claim.PollSecret) != 43 {
		t.Fatalf("claim %+v, want a number 10-99 approved by MacBook for admin", claim)
	}
	rec := phoneReq(t, h, "/api/auth/device-link/poll", pollBody(claim), phone)
	if rec.Code != 202 || strings.TrimSpace(rec.Body.String()) != "{}" || strings.Contains(rec.Body.String(), "token") {
		t.Fatalf("poll before the approve: %d %s, want 202 {}", rec.Code, rec.Body)
	}
	if st := readDeviceLink(t, h, desktop, link.ID); st.State != "claimed" || st.Label != "Ana's iPhone" || st.Platform != "ios" {
		t.Fatalf("desktop status %+v, want claimed by Ana's iPhone (ios)", st)
	}
	if rec := doReq(t, h, "POST", "/api/me/device-links/"+link.ID+"/approve", desktop,
		`{"number":`+strconv.Itoa(claim.Number)+`}`); rec.Code != 204 {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body)
	}

	rec = phoneReq(t, h, "/api/auth/device-link/poll", pollBody(claim), phone)
	if rec.Code != 200 {
		t.Fatalf("poll after the approve: %d %s, want 200", rec.Code, rec.Body)
	}
	var out struct {
		Token string `json:"token"`
		User  struct {
			Username string `json:"username"`
		} `json:"user"`
	}
	unmarshal(t, rec, &out)
	if out.Token == "" || out.User.Username != "admin" {
		t.Fatalf("poll answered %s, want a token for admin", rec.Body)
	}
	// The token list reports a device's system from the client header its
	// authenticated requests carry, so the phone's first request records it.
	me := httptest.NewRequest("GET", "/api/me", nil)
	me.Header.Set("Authorization", "Bearer "+out.Token)
	me.Header.Set("X-HyperDrop-Client", phoneClient)
	meRec := httptest.NewRecorder()
	h.ServeHTTP(meRec, me)
	if meRec.Code != 200 {
		t.Fatalf("GET /api/me with the phone's token: %d %s", meRec.Code, meRec.Body)
	}
	list := doReq(t, h, "GET", "/api/me/tokens", desktop, "")
	var tokens struct {
		Tokens []struct {
			Label          string `json:"label"`
			ClientPlatform string `json:"clientPlatform"`
		} `json:"tokens"`
	}
	unmarshal(t, list, &tokens)
	found := false
	for _, tok := range tokens.Tokens {
		if tok.Label == "Ana's iPhone" {
			found = true
			if tok.ClientPlatform != "ios" {
				t.Fatalf("phone row %+v, want clientPlatform ios", tok)
			}
		}
	}
	if !found {
		t.Fatalf("token list %s has no row labelled Ana's iPhone", list.Body)
	}
	wantLinkInvalid(t, "a second poll after the token", phoneReq(t, h, "/api/auth/device-link/poll", pollBody(claim), phone))
}

func TestAnUnknownSecretCountsOnTheLoginLockout(t *testing.T) {
	h := newTestAPI(t)
	link := mintDeviceLink(t, h, testToken, testAdminPassword)
	const guesser, other = "203.0.113.50:1000", "198.51.100.60:1000"
	var last *httptest.ResponseRecorder
	for i := range pwFailLimit {
		secret := randomLinkSecret(t)
		if i == 0 {
			secret = "not base64url!"
		}
		last = phoneReq(t, h, "/api/auth/device-link/claim", claimBody(secret, "x"), guesser)
		if i < pwFailLimit-1 {
			wantLinkInvalid(t, "a guessed secret", last)
		}
	}
	if last.Code != 429 {
		t.Fatalf("guess %d: %d %s, want 429", pwFailLimit, last.Code, last.Body)
	}
	if rec := phoneReq(t, h, "/api/auth/device-link/claim", claimBody(link.Secret, "x"), guesser); rec.Code != 429 {
		t.Fatalf("the real secret from the locked-out address: %d %s, want 429", rec.Code, rec.Body)
	}
	if st := readDeviceLink(t, h, testToken, link.ID); st.State != "minted" {
		t.Fatalf("after the locked-out claim: %+v, want minted", st)
	}
	claimLink(t, h, link.Secret, "x", other)
}

func TestAWrongPollSecretCountsOnTheLoginLockout(t *testing.T) {
	h := newTestAPI(t)
	link := mintDeviceLink(t, h, testToken, testAdminPassword)
	const phone, guesser = "198.51.100.60:1000", "203.0.113.50:1000"
	claim := claimLink(t, h, link.Secret, "x", phone)
	var last *httptest.ResponseRecorder
	for i := range pwFailLimit {
		guess := claim
		guess.PollSecret = randomLinkSecret(t)
		if i == 0 {
			guess.PollSecret = "%%%"
		}
		last = phoneReq(t, h, "/api/auth/device-link/poll", pollBody(guess), guesser)
		if i < pwFailLimit-1 {
			wantLinkInvalid(t, "a guessed poll secret", last)
		}
	}
	if last.Code != 429 {
		t.Fatalf("guess %d: %d %s, want 429", pwFailLimit, last.Code, last.Body)
	}
	if rec := phoneReq(t, h, "/api/auth/device-link/poll", pollBody(claim), guesser); rec.Code != 429 {
		t.Fatalf("the real poll secret from the locked-out address: %d %s, want 429", rec.Code, rec.Body)
	}
	if rec := phoneReq(t, h, "/api/auth/device-link/poll", pollBody(claim), phone); rec.Code != 202 {
		t.Fatalf("the phone's own poll: %d %s, want 202", rec.Code, rec.Body)
	}
}

func TestAPendingPollCountsNothing(t *testing.T) {
	h, hd := newTestAPIParts(t)
	link := mintDeviceLink(t, h, testToken, testAdminPassword)
	const phone = "198.51.100.60:1000"
	claim := claimLink(t, h, link.Secret, "x", phone)
	for range pwFailLimit + 1 {
		if rec := phoneReq(t, h, "/api/auth/device-link/poll", pollBody(claim), phone); rec.Code != 202 {
			t.Fatalf("pending poll: %d %s, want 202", rec.Code, rec.Body)
		}
	}
	hd.limits.login.mu.Lock()
	counted := len(hd.limits.login.byKey) + len(hd.limits.login.accounts)
	hd.limits.login.mu.Unlock()
	if counted != 0 {
		t.Fatalf("the claim and pending polls counted %d lockout entries, want none", counted)
	}
}

func TestTheSecondPhoneBurnsTheLinkForBoth(t *testing.T) {
	h := newTestAPI(t)
	link := mintDeviceLink(t, h, testToken, testAdminPassword)
	first := claimLink(t, h, link.Secret, "Ana's iPhone", "198.51.100.20:5000")
	wantLinkInvalid(t, "the second claim",
		phoneReq(t, h, "/api/auth/device-link/claim", claimBody(link.Secret, "Other"), "203.0.113.30:5000"))
	wantLinkInvalid(t, "the first phone's poll",
		phoneReq(t, h, "/api/auth/device-link/poll", pollBody(first), "198.51.100.20:5000"))
	if st := readDeviceLink(t, h, testToken, link.ID); st.State != "burned" {
		t.Fatalf("after two claims: %+v, want burned", st)
	}
}

func TestADeniedLinkAnswersTheNextPoll404(t *testing.T) {
	h := newTestAPI(t)
	link := mintDeviceLink(t, h, testToken, testAdminPassword)
	claim := claimLink(t, h, link.Secret, "x", "198.51.100.20:5000")
	if rec := doReq(t, h, "POST", "/api/me/device-links/"+link.ID+"/deny", testToken, ""); rec.Code != 204 {
		t.Fatalf("deny: %d %s", rec.Code, rec.Body)
	}
	wantLinkInvalid(t, "the poll after the deny",
		phoneReq(t, h, "/api/auth/device-link/poll", pollBody(claim), "198.51.100.20:5000"))
}

func TestThePhoneRoutesDecodeStrictly(t *testing.T) {
	h := newTestAPI(t)
	for _, c := range []struct{ path, body string }{
		{"/api/auth/device-link/claim", `{"secret":"x","label":"y","platform":"ios"}`},
		{"/api/auth/device-link/poll", `{"claimId":"x","pollSecret":"y","extra":1}`},
	} {
		if rec := phoneReq(t, h, c.path, c.body, "198.51.100.20:5000"); rec.Code != 400 {
			t.Fatalf("%s with an unknown field: %d %s, want 400", c.path, rec.Code, rec.Body)
		}
	}
}

// unmatchedBearerReq is an authenticated request whose context carries the
// admin while its bearer names none of the admin's tokens.
func unmatchedBearerReq(t *testing.T, hd *handler, method, path, body string) *http.Request {
	t.Helper()
	u, err := hd.db.User("admin")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+randomLinkSecret(t))
	return req.WithContext(context.WithValue(req.Context(), userKey, u))
}

func TestABearerNamingNoTokenIsRefusedOnRevokeAndMint(t *testing.T) {
	h, hd := newTestAPIParts(t)
	other := loginWithLabel(t, h, "mac-b")
	otherID := tokenID(t, h, testToken, "mac-b")

	req := unmatchedBearerReq(t, hd, "DELETE", "/api/me/tokens/"+otherID, "")
	req.SetPathValue("id", otherID)
	rec := httptest.NewRecorder()
	hd.revokeMyToken(rec, req)
	if rec.Code != 401 {
		t.Fatalf("revoke: %d %s, want 401", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "GET", "/api/me", other, ""); rec.Code != 200 {
		t.Fatalf("the device the refused revoke named answers %d, want 200", rec.Code)
	}

	req = unmatchedBearerReq(t, hd, "POST", "/api/me/device-links", `{"currentPassword":"`+testAdminPassword+`"}`)
	rec = httptest.NewRecorder()
	hd.mintDeviceLink(rec, req)
	if rec.Code != 401 {
		t.Fatalf("mint: %d %s, want 401", rec.Code, rec.Body)
	}
}

func TestAPasswordChangeByABearerNamingNoTokenSignsInNow(t *testing.T) {
	_, hd := newTestAPIParts(t)
	req := unmatchedBearerReq(t, hd, "PATCH", "/api/me/password",
		`{"currentPassword":"`+testAdminPassword+`","password":"brand-new-pass"`+seededAdminTOTP(t)+`}`)
	rec := httptest.NewRecorder()
	hd.changeOwnPassword(rec, req)
	if rec.Code != 200 {
		t.Fatalf("passwd: %d %s", rec.Code, rec.Body)
	}
	after, err := hd.db.User("admin")
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Tokens) != 1 || time.Since(after.Tokens[0].CreatedAt) > time.Minute {
		t.Fatalf("tokens after passwd = %+v, want one signed in now", after.Tokens)
	}
}

func TestAMalformedNumberIsRefusedWithoutBurning(t *testing.T) {
	h, hd := newTestAPIParts(t)
	link := mintDeviceLink(t, h, testToken, testAdminPassword)
	claim, err := hd.db.ClaimDeviceLink(link.Secret, "Pixel 9", "android", addrMarkOf(hd, "192.0.2.1"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{}`, `{"number":null}`, `{"number":9}`, `{"number":100}`, `{"number":0}`, `{"number":-50}`} {
		rec := doReq(t, h, "POST", "/api/me/device-links/"+link.ID+"/approve", testToken, body)
		if rec.Code != 400 || !strings.Contains(rec.Body.String(), "the number is two digits, 10 to 99") {
			t.Fatalf("%s: %d %s, want 400", body, rec.Code, rec.Body)
		}
	}
	if st := readDeviceLink(t, h, testToken, link.ID); st.State != "claimed" {
		t.Fatalf("after malformed numbers: %+v, want claimed", st)
	}
	if rec := doReq(t, h, "POST", "/api/me/device-links/"+link.ID+"/approve", testToken,
		`{"number":`+strconv.Itoa(claim.Number)+`}`); rec.Code != 204 {
		t.Fatalf("approve after malformed numbers: %d %s", rec.Code, rec.Body)
	}
}

// addrMarkOf is what a request from ip leaves on a device link.
func addrMarkOf(hd *handler, ip string) string {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = net.JoinHostPort(ip, "1")
	return hd.linkAddrMark(r)
}

// A link keeps a keyed mark of the minting address, never one a copy of the
// database turns back into the address, and a phone on the desktop's IPv6
// network, which holds another address of the same /64, claims from the
// same network.
func TestALinkKeepsAKeyedMarkOfTheAddress(t *testing.T) {
	dir := t.TempDir()
	b := testBackendAt(t, dir)
	hd := newHandler(b, "2.0.0", testDomain(t), nil, Deployment{})
	h := hd.routes()
	req := httptest.NewRequest("POST", "/api/me/device-links", strings.NewReader(`{"currentPassword":"`+testAdminPassword+`"`+seededAdminTOTP(t)+`}`))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.RemoteAddr = "[2001:db8:9:9::10]:1000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 201 {
		t.Fatalf("mint: %d %s", rec.Code, rec.Body)
	}
	var link mintedLink
	unmarshal(t, rec, &link)
	raw, err := sql.Open("sqlite", filepath.Join(dir, metadb.FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var stored string
	if err := raw.QueryRow(`SELECT minted_addr FROM device_links WHERE id = ?`, link.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	for _, guess := range []string{"2001:db8:9:9::10", "2001:db8:9:9::/64"} {
		if stored == metadb.TokenHash(guess) || strings.Contains(stored, guess) {
			t.Fatalf("minted_addr %q can be read back as %s", stored, guess)
		}
	}
	claimLink(t, h, link.Secret, "Pixel 9", "[2001:db8:9:9:aaaa::2]:1000")
	if st := readDeviceLink(t, h, testToken, link.ID); !st.SameNetwork {
		t.Fatalf("a phone in the desktop's /64: %+v, want the same network", st)
	}
}

// Signing a phone in asks no password of the desktop: whoever has the
// signed-in desktop has the account. An account with a second factor gives
// its code at the approval instead, beside the number.

func TestMintNeedsNoPassword(t *testing.T) {
	h := newTestAPI(t)
	for _, body := range []string{`{}`} {
		rec := doReq(t, h, "POST", "/api/me/device-links", testToken, body)
		if rec.Code != 201 {
			t.Fatalf("mint with %q: %d %s, want 201", body, rec.Code, rec.Body)
		}
	}
	enableTOTP(t, h, testToken, testAdminPassword)
	if rec := doReq(t, h, "POST", "/api/me/device-links", testToken, `{}`); rec.Code != 201 {
		t.Fatalf("a 2FA account's mint without a password: %d %s, want 201", rec.Code, rec.Body)
	}
}

// approve posts an approval of link with body and answers the response.
func approve(t *testing.T, h http.Handler, token, id, body string) *httptest.ResponseRecorder {
	t.Helper()
	return doReq(t, h, "POST", "/api/me/device-links/"+id+"/approve", token, body)
}

func numberBody(n int, code string) string {
	if code == "" {
		return `{"number":` + strconv.Itoa(n) + `}`
	}
	return `{"number":` + strconv.Itoa(n) + `,"totp":"` + code + `"}`
}

func TestApproveAsksTheCodeOfATwoFactorAccount(t *testing.T) {
	h := newTestAPI(t)
	secret, _ := enableTOTP(t, h, testToken, testAdminPassword)
	link := mintBare(t, h, testToken)
	const phone = "198.51.100.20:5000"
	claim := claimLink(t, h, link.Secret, "Pixel 9", phone)

	rec := approve(t, h, testToken, link.ID, numberBody(claim.Number, ""))
	if rec.Code != 401 || errCode(t, rec.Body.String()) != "totp-required" {
		t.Fatalf("no code: %d %s, want 401 totp-required", rec.Code, rec.Body)
	}
	if st := readDeviceLink(t, h, testToken, link.ID); st.State != "claimed" {
		t.Fatalf("after a missing code: %+v, want claimed", st)
	}
	rec = approve(t, h, testToken, link.ID, numberBody(claim.Number, "000000"))
	if rec.Code != 401 || errCode(t, rec.Body.String()) != "totp-invalid" {
		t.Fatalf("wrong code: %d %s, want 401 totp-invalid", rec.Code, rec.Body)
	}
	if st := readDeviceLink(t, h, testToken, link.ID); st.State != "claimed" {
		t.Fatalf("after a wrong code: %+v, want claimed", st)
	}
	if rec := approve(t, h, testToken, link.ID, numberBody(claim.Number, nextCode(t, secret))); rec.Code != 204 {
		t.Fatalf("number and code: %d %s, want 204", rec.Code, rec.Body)
	}
	if rec := phoneReq(t, h, "/api/auth/device-link/poll", pollBody(claim), phone); rec.Code != 200 ||
		!strings.Contains(rec.Body.String(), `"token"`) {
		t.Fatalf("the phone's poll after the approval: %d %s, want its token", rec.Code, rec.Body)
	}
}

// mintBare mints a link with no password, as a 1.1 client does.
func mintBare(t *testing.T, h http.Handler, token string) mintedLink {
	t.Helper()
	rec := doReq(t, h, "POST", "/api/me/device-links", token, `{}`)
	if rec.Code != 201 {
		t.Fatalf("mint: %d %s", rec.Code, rec.Body)
	}
	var link mintedLink
	unmarshal(t, rec, &link)
	return link
}

func TestApproveChecksTheNumberBeforeTheCode(t *testing.T) {
	h := newTestAPI(t)
	secret, _ := enableTOTP(t, h, testToken, testAdminPassword)
	link := mintBare(t, h, testToken)
	claim := claimLink(t, h, link.Secret, "Pixel 9", "198.51.100.20:5000")
	wrong := 10 + (claim.Number-10+1)%90
	rec := approve(t, h, testToken, link.ID, numberBody(wrong, nextCode(t, secret)))
	if rec.Code != 409 || errCode(t, rec.Body.String()) != "device-link-wrong-number" {
		t.Fatalf("wrong number with a right code: %d %s, want 409 device-link-wrong-number", rec.Code, rec.Body)
	}
	if st := readDeviceLink(t, h, testToken, link.ID); st.State != "burned" {
		t.Fatalf("after a wrong number: %+v, want burned", st)
	}
}

func TestASteppedUpLinkApprovesWithTheNumberAlone(t *testing.T) {
	h := newTestAPI(t)
	secret, _ := enableTOTP(t, h, testToken, testAdminPassword)
	rec := doReq(t, h, "POST", "/api/me/device-links", testToken,
		`{"currentPassword":"`+testAdminPassword+`","totp":"`+nextCode(t, secret)+`"}`)
	if rec.Code != 201 {
		t.Fatalf("a 1.0 client's mint: %d %s", rec.Code, rec.Body)
	}
	var link mintedLink
	unmarshal(t, rec, &link)
	claim := claimLink(t, h, link.Secret, "Pixel 9", "198.51.100.20:5000")
	if rec := approve(t, h, testToken, link.ID, numberBody(claim.Number, "")); rec.Code != 204 {
		t.Fatalf("a stepped-up link approved with the number alone: %d %s, want 204", rec.Code, rec.Body)
	}
}

func TestAnAccountWithoutAFactorIgnoresTheCode(t *testing.T) {
	h, hd := newTestAPIParts(t)
	alice := seedUser(t, hd.db, "alice")
	link := mintBare(t, h, alice)
	claim := claimLink(t, h, link.Secret, "Pixel 9", "198.51.100.20:5000")
	if rec := approve(t, h, alice, link.ID, numberBody(claim.Number, "123456")); rec.Code != 204 {
		t.Fatalf("number and a code on an account without a factor: %d %s, want 204", rec.Code, rec.Body)
	}
}

func TestWrongApprovalCodesCountOnTheLockout(t *testing.T) {
	h := newTestAPI(t)
	enableTOTP(t, h, testToken, testAdminPassword)
	link := mintBare(t, h, testToken)
	claim := claimLink(t, h, link.Secret, "Pixel 9", "198.51.100.20:5000")
	var rec *httptest.ResponseRecorder
	for i := 0; i < 12; i++ {
		rec = approve(t, h, testToken, link.ID, numberBody(claim.Number, "000000"))
		if rec.Code == 429 {
			break
		}
		if rec.Code != 401 {
			t.Fatalf("wrong code %d: %d %s, want 401", i+1, rec.Code, rec.Body)
		}
	}
	if rec.Code != 429 {
		t.Fatalf("after 12 wrong codes: %d %s, want 429", rec.Code, rec.Body)
	}
	if st := readDeviceLink(t, h, testToken, link.ID); st.State != "claimed" {
		t.Fatalf("after the lockout: %+v, want claimed", st)
	}
}

func TestStatusAnswersTheClaimingAddress(t *testing.T) {
	h, hd := newTestAPIParts(t)
	link := mintBare(t, h, testToken)
	if st := readDeviceLink(t, h, testToken, link.ID); st.Address != "" {
		t.Fatalf("before the claim: address %q, want none", st.Address)
	}
	claim := claimLink(t, h, link.Secret, "Pixel 9", "203.0.113.7:5000")
	if st := readDeviceLink(t, h, testToken, link.ID); st.Address != "203.0.113.7" {
		t.Fatalf("after the claim: address %q, want 203.0.113.7", st.Address)
	}
	// A restart forgets the address; the approval does not need it.
	hd.linkAddrs.forget(link.ID)
	if st := readDeviceLink(t, h, testToken, link.ID); st.Address != "" || st.State != "claimed" {
		t.Fatalf("after a restart: %+v, want claimed with no address", st)
	}
	if rec := approve(t, h, testToken, link.ID, numberBody(claim.Number, seededAdminCode(t))); rec.Code != 204 {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body)
	}
}

func TestTheAddressIsForgottenWhenTheLinkEnds(t *testing.T) {
	h, hd := newTestAPIParts(t)
	denied := mintBare(t, h, testToken)
	claimLink(t, h, denied.Secret, "Pixel 9", "203.0.113.7:5000")
	if rec := doReq(t, h, "POST", "/api/me/device-links/"+denied.ID+"/deny", testToken, ""); rec.Code != 204 {
		t.Fatalf("deny: %d %s", rec.Code, rec.Body)
	}
	if hd.linkAddrs.has(denied.ID) {
		t.Fatal("a denied link's address is still kept")
	}

	spent := mintBare(t, h, testToken)
	claim := claimLink(t, h, spent.Secret, "Pixel 9", "203.0.113.8:5000")
	if rec := approve(t, h, testToken, spent.ID, numberBody(claim.Number, seededAdminCode(t))); rec.Code != 204 {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body)
	}
	if rec := phoneReq(t, h, "/api/auth/device-link/poll", pollBody(claim), "203.0.113.8:5000"); rec.Code != 200 {
		t.Fatalf("poll: %d %s", rec.Code, rec.Body)
	}
	if hd.linkAddrs.has(spent.ID) {
		t.Fatal("a spent link's address is still kept")
	}
	if st := readDeviceLink(t, h, testToken, spent.ID); st.Address != "" {
		t.Fatalf("a spent link answers address %q", st.Address)
	}
}

func TestAKeptAddressRunsOutWithTheClaim(t *testing.T) {
	var b linkAddrBook
	now := time.Now()
	b.keep("a", "c", "203.0.113.7", now)
	if got, ok := b.get("a", now.Add(5*time.Minute-time.Second)); !ok || got != "203.0.113.7" {
		t.Fatalf("at 4:59: %q %v", got, ok)
	}
	if _, ok := b.get("a", now.Add(5*time.Minute)); ok {
		t.Fatal("at 5:00 the address is still answered")
	}
	if b.has("a") {
		t.Fatal("a read past the claim's end kept the entry")
	}
}
