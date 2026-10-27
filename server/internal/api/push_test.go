package api

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/metadb"
)

const testRelay = "https://relay.test"

// pushAPI is a handler whose server pushes through testRelay.
func pushAPI(t *testing.T) (http.Handler, *handler) {
	t.Helper()
	hd := newHandler(testBackend(t), "2.0.0", testDomain(t), nil, Deployment{PushRelay: testRelay})
	return hd.routes(), hd
}

func phoneKey(t *testing.T) (*ecdh.PrivateKey, string) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k, base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
}

func pushBody(relay, handle, key, tag string, muted ...string) string {
	m := `[]`
	if len(muted) > 0 {
		m = `["` + strings.Join(muted, `","`) + `"]`
	}
	return fmt.Sprintf(`{"relay":%q,"handle":%q,"publicKey":%q,"tag":%q,"muted":%s}`, relay, handle, key, tag, m)
}

func TestAPhoneRegistersOnItsOwnTokenRow(t *testing.T) {
	h, hd := pushAPI(t)
	_, key := phoneKey(t)
	handle := strings.Repeat("a", 32)
	rec := doReq(t, h, "PUT", "/api/me/push", testToken, pushBody(testRelay, handle, key, "entry-1", "domain"))
	if rec.Code != 200 {
		t.Fatalf("PUT = %d %s", rec.Code, rec.Body)
	}
	r, ok, _ := hd.db.PushOf(metadb.TokenHash(testToken))
	if !ok || r.Handle != handle || r.Tag != "entry-1" || !r.Mutes("domain") || r.Relay != testRelay {
		t.Fatalf("stored %+v", r)
	}
	rec = doReq(t, h, "GET", "/api/me/push", testToken, "")
	var got struct {
		Relay      string   `json:"relay"`
		Registered bool     `json:"registered"`
		Tag        string   `json:"tag"`
		Muted      []string `json:"muted"`
	}
	unmarshal(t, rec, &got)
	if got.Relay != testRelay || !got.Registered || got.Tag != "entry-1" || !slices.Equal(got.Muted, []string{"domain"}) {
		t.Fatalf("GET = %+v", got)
	}
	if strings.Contains(rec.Body.String(), handle) {
		t.Fatal("GET answered the handle")
	}
	if rec := doReq(t, h, "DELETE", "/api/me/push", testToken, ""); rec.Code != 204 {
		t.Fatalf("DELETE = %d", rec.Code)
	}
	if _, ok, _ := hd.db.PushOf(metadb.TokenHash(testToken)); ok {
		t.Fatal("DELETE left the registration")
	}
}

func TestAClientCannotPointTheServerAtAnotherRelay(t *testing.T) {
	h, hd := pushAPI(t)
	_, key := phoneKey(t)
	for _, relay := range []string{"http://169.254.169.254", "https://relay.test.evil", "https://relay.test/", ""} {
		rec := doReq(t, h, "PUT", "/api/me/push", testToken, pushBody(relay, strings.Repeat("a", 32), key, "e"))
		if rec.Code != 409 || errCode(t, rec.Body.String()) != "relay-mismatch" {
			t.Fatalf("relay %q: %d %s", relay, rec.Code, rec.Body)
		}
	}
	if _, ok, _ := hd.db.PushOf(metadb.TokenHash(testToken)); ok {
		t.Fatal("a mismatched relay was stored")
	}
}

func TestPushOffRefusesRegistrationAndSaysSo(t *testing.T) {
	hd := newHandler(testBackend(t), "2.0.0", testDomain(t), nil, Deployment{})
	h := hd.routes()
	_, key := phoneKey(t)
	rec := doReq(t, h, "PUT", "/api/me/push", testToken, pushBody(testRelay, strings.Repeat("a", 32), key, "e"))
	if rec.Code != 409 || errCode(t, rec.Body.String()) != "push-off" {
		t.Fatalf("PUT with push off = %d %s", rec.Code, rec.Body)
	}
	rec = doReq(t, h, "GET", "/api/me/push", testToken, "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"relay":""`) {
		t.Fatalf("GET with push off = %d %s", rec.Code, rec.Body)
	}
}

func TestARegistrationIsValidatedFieldByField(t *testing.T) {
	h, _ := pushAPI(t)
	_, key := phoneKey(t)
	good := strings.Repeat("a", 32)
	cases := map[string]string{
		"short handle":     pushBody(testRelay, "abc", key, "e"),
		"upper handle":     pushBody(testRelay, strings.Repeat("A", 32), key, "e"),
		"zero key":         pushBody(testRelay, good, base64.StdEncoding.EncodeToString(make([]byte, 32)), "e"),
		"not base64":       pushBody(testRelay, good, "!!", "e"),
		"tag with a slash": pushBody(testRelay, good, key, "a/b"),
		"odd kind":         pushBody(testRelay, good, key, "e", "in box"),
		"unknown field":    `{"relay":"` + testRelay + `","handle":"` + good + `","publicKey":"` + key + `","extra":1}`,
		"not JSON":         `{`,
	}
	for name, body := range cases {
		if rec := doReq(t, h, "PUT", "/api/me/push", testToken, body); rec.Code != 400 {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	many := make([]string, 17)
	for i := range many {
		many[i] = "k"
	}
	if rec := doReq(t, h, "PUT", "/api/me/push", testToken, pushBody(testRelay, good, key, "e", many...)); rec.Code != 400 {
		t.Errorf("17 mutes: %d", rec.Code)
	}
}

// Signing out deletes the token and its registration with it.
func TestSigningOutDropsTheRegistration(t *testing.T) {
	h, hd := pushAPI(t)
	tok := seedUser(t, hd.db, "bob")
	_, key := phoneKey(t)
	doReq(t, h, "PUT", "/api/me/push", tok, pushBody(testRelay, strings.Repeat("b", 32), key, "e"))
	if rec := doReq(t, h, "DELETE", "/api/auth/token", tok, ""); rec.Code != 204 {
		t.Fatalf("sign-out = %d", rec.Code)
	}
	if targets, _ := hd.db.PushTargets("bob"); len(targets) != 0 {
		t.Fatalf("a signed-out phone still receives: %+v", targets)
	}
}

// An admin listing accounts never sees a handle.
func TestTheUsersListNeverCarriesAPushHandle(t *testing.T) {
	h, hd := pushAPI(t)
	tok := seedUser(t, hd.db, "bob")
	_, key := phoneKey(t)
	handle := strings.Repeat("c", 32)
	doReq(t, h, "PUT", "/api/me/push", tok, pushBody(testRelay, handle, key, "e"))
	for _, path := range []string{"/api/users", "/api/users/bob", "/api/me/tokens"} {
		as := testToken
		if path == "/api/me/tokens" {
			as = tok
		}
		if rec := doReq(t, h, "GET", path, as, ""); strings.Contains(rec.Body.String(), handle) {
			t.Fatalf("%s carries the handle", path)
		}
	}
}

func TestAComputerReportsWhetherItsOwnerIsAtIt(t *testing.T) {
	h, hd := pushAPI(t)
	tok := seedUser(t, hd.db, "bob")
	since := time.Now().Add(-desktopIdleLimit)
	put := func(body string) int {
		req := httptest.NewRequest("PUT", "/api/me/activity", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("X-HyperDrop-Client", "2.0.0 macos")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := put(`{"onConsole":true,"idleSeconds":12}`); code != 204 {
		t.Fatalf("PUT = %d", code)
	}
	if active, _ := hd.db.DesktopActiveSince("bob", since); !active {
		t.Fatal("a Mac whose owner is at it is not in use")
	}
	if code := put(`{"onConsole":true,"idleSeconds":900}`); code != 204 {
		t.Fatalf("PUT = %d", code)
	}
	if active, _ := hd.db.DesktopActiveSince("bob", since); active {
		t.Fatal("a Mac idle for fifteen minutes is in use")
	}
	// Bounded before it is multiplied: this would overflow a Duration into a
	// negative idle time, a mark in the future.
	if code := put(`{"onConsole":true,"idleSeconds":9223372036854775807}`); code != 204 {
		t.Fatalf("PUT = %d", code)
	}
	if active, _ := hd.db.DesktopActiveSince("bob", since); active {
		t.Fatal("an idle time past the limit's overflow counted as in use")
	}
	put(`{"onConsole":true,"idleSeconds":0}`)
	put(`{"onConsole":false,"idleSeconds":0}`)
	if active, _ := hd.db.DesktopActiveSince("bob", since); active {
		t.Fatal("a locked Mac is in use")
	}
}

func TestTheRelaySettingIsAnHTTPSOrigin(t *testing.T) {
	good := map[string]string{"": "", "https://api.gethyperdrop.com": "https://api.gethyperdrop.com",
		"https://relay.example/": "https://relay.example", "https://relay.example:8443": "https://relay.example:8443"}
	for in, want := range good {
		if got, err := ParsePushRelay(in, false); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, in := range []string{"http://relay.example", "relay.example", "https://relay.example/v1", "https://u:p@relay.example",
		"https://relay.example?x=1", "ftp://relay.example"} {
		if _, err := ParsePushRelay(in, false); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
	if got, err := ParsePushRelay("http://localhost:8090", true); err != nil || got != "http://localhost:8090" {
		t.Errorf("a development relay over http: %q %v", got, err)
	}
}

// The kinds a registration may mute are metadb.PushKinds, the names the
// pusher's passes send under; deviceSignedIn is sent outside them and is
// never muted (TestDeviceSignedInCannotBeMuted).
func TestThePushKindsAreThePushersKinds(t *testing.T) {
	if want := []string{pushKindInboxReceived, pushKindAccessRevoked, pushKindDomain, pushKindServerUpdate}; !slices.Equal(metadb.PushKinds, want) {
		t.Fatalf("metadb.PushKinds = %v, the pusher sends %v", metadb.PushKinds, want)
	}
}

// A registration stored under a relay this server no longer sends through
// is never pushed to, so the status says unregistered and the phone
// re-registers rather than believing it is reachable.
func TestARegistrationWithAnotherRelayReadsUnregistered(t *testing.T) {
	h, hd := pushAPI(t)
	k, _ := phoneKey(t)
	if err := hd.db.SetPush(metadb.TokenHash(testToken), metadb.PushRegistration{Relay: "https://old-relay.test",
		Handle: strings.Repeat("a", 32), PublicKey: k.PublicKey().Bytes(), Tag: "entry-1", Muted: []string{"domain"}}); err != nil {
		t.Fatal(err)
	}
	rec := doReq(t, h, "GET", "/api/me/push", testToken, "")
	var got struct {
		Relay      string   `json:"relay"`
		Registered bool     `json:"registered"`
		Tag        string   `json:"tag"`
		Muted      []string `json:"muted"`
	}
	unmarshal(t, rec, &got)
	if got.Relay != testRelay || got.Registered || got.Tag != "" || len(got.Muted) != 0 {
		t.Fatalf("GET = %+v, want unregistered on %s", got, testRelay)
	}
	off := newHandler(testBackend(t), "2.0.0", testDomain(t), nil, Deployment{})
	if err := off.db.SetPush(metadb.TokenHash(testToken), metadb.PushRegistration{Relay: testRelay,
		Handle: strings.Repeat("a", 32), PublicKey: k.PublicKey().Bytes()}); err != nil {
		t.Fatal(err)
	}
	if rec := doReq(t, off.routes(), "GET", "/api/me/push", testToken, ""); !strings.Contains(rec.Body.String(), `"registered":false`) {
		t.Fatalf("GET with push off = %s", rec.Body)
	}
}
