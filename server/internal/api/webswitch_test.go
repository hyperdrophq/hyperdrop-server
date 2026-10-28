package api

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"hyperdrop/core/webbundle"
	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/webapp"
)

// webNoErr fails the test on err.
func webNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// webTestKey signs the bundles these tests install; the fixture's store
// trusts its public half.
var webTestKey = func() ed25519.PrivateKey {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	return priv
}()

func webTestPub() string {
	return base64.StdEncoding.EncodeToString(webTestKey.Public().(ed25519.PublicKey))
}

// webArchive is a bundle archive holding files, gzip-compressed tar.
func webArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// installWebBundle installs a signed bundle whose index.html holds index
// into st.
func installWebBundle(t *testing.T, st *webapp.Store, contract, index string) {
	t.Helper()
	archive := webArchive(t, map[string]string{"index.html": index})
	sig, err := webbundle.Sign(webTestKey, "1.0.0", 1, contract, archive)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Install(archive, sig, "1.0.0", 1, contract); err != nil {
		t.Fatal(err)
	}
}

// appGet is a browser's GET of path on host.
func appGet(h http.Handler, host, path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", path, nil)
	r.Host = host
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestAppServedOnAppOrigin(t *testing.T) {
	f := newWebFixture(t, true)
	rec := appGet(f.h, "files."+webAppHost, "/app/shares/x?y=1")
	if rec.Code != http.StatusPermanentRedirect || rec.Header().Get("Location") != "https://"+webAppHost+"/app/shares/x?y=1" {
		t.Fatalf("/app on the file origin: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := appGet(f.h, "files."+webAppHost, "/app"); rec.Code != http.StatusPermanentRedirect ||
		rec.Header().Get("Location") != "https://"+webAppHost+"/app" {
		t.Fatalf("bare /app on the file origin: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	rec = appGet(f.h, webAppHost, "/app/")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "web fixture") {
		t.Fatalf("/app/ on the app origin: %d %s", rec.Code, rec.Body)
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "img-src 'self' blob: data: https://files."+webAppHost) {
		t.Fatalf("the CSP does not name the file origin: %q", csp)
	}
	if rec := appGet(f.h, webAppHost, "/app"); rec.Code != http.StatusPermanentRedirect || rec.Header().Get("Location") != "/app/" {
		t.Fatalf("/app: %d %q", rec.Code, rec.Header().Get("Location"))
	}

	// One origin: the CSP names no file origin.
	one := newWebFixture(t, false)
	rec = appGet(one.h, one.host(), "/app/")
	if csp := rec.Header().Get("Content-Security-Policy"); rec.Code != 200 || strings.Contains(csp, "files.") ||
		!strings.Contains(csp, "img-src 'self' blob: data:;") {
		t.Fatalf("one origin: %d %q", rec.Code, csp)
	}
}

func TestAppStates(t *testing.T) {
	f := newWebFixture(t, true)
	if err := f.db.SetSetting(webSwitchKey, "off"); err != nil {
		t.Fatal(err)
	}
	rec := appGet(f.h, webAppHost, "/app/")
	if rec.Code != 503 || !strings.Contains(rec.Body.String(), "turned off the web version") {
		t.Fatalf("switched off: %d %s", rec.Code, rec.Body)
	}
	if err := f.db.DeleteSetting(webSwitchKey); err != nil {
		t.Fatal(err)
	}
	f.web.UseDevDir("")
	rec = appGet(f.h, webAppHost, "/app/")
	if rec.Code != 503 || !strings.Contains(rec.Body.String(), "installed on this server yet") {
		t.Fatalf("nothing installed: %d %s", rec.Code, rec.Body)
	}

	// A bundle of contract 2.0.0 installed, then the server updated to 3.0.0:
	// the install is kept but no longer served.
	dir := t.TempDir()
	st, err := webapp.Open(dir, []string{webTestPub()}, "2.0.0")
	if err != nil {
		t.Fatal(err)
	}
	installWebBundle(t, st, "2.0.0", "old bundle")
	hd := newHandler(testBackendAt(t, dir), "3.0.0", testDomain(t), nil, Deployment{Web: st})
	if got := hd.webState(); got != webapp.StateUpdating {
		t.Fatalf("webState after the server update = %v, want updating", got)
	}
	rec = appGet(hd.routes(), "example.com", "/app/")
	if rec.Code != 503 || !strings.Contains(rec.Body.String(), "being updated") {
		t.Fatalf("an install the server no longer serves: %d %s", rec.Code, rec.Body)
	}
	// The same install on the server it speaks is on.
	hd = newHandler(testBackendAt(t, t.TempDir()), "2.0.0", testDomain(t), nil, Deployment{Web: st})
	if got := hd.webState(); got != webapp.StateOn {
		t.Fatalf("webState on its own contract = %v, want on", got)
	}
	// No store at all reads as nothing installed.
	if got := newHandler(testBackend(t), "2.0.0", testDomain(t), nil, Deployment{}).webState(); got != webapp.StateMissing {
		t.Fatalf("webState with no store = %v, want missing", got)
	}
}

func TestWebSwitchOffRevokesSessions(t *testing.T) {
	f := newWebFixture(t, true)
	cookie := f.signIn(t, false)
	device := doReq(t, f.h, "GET", "/api/me", f.aliceDevice, "")
	if device.Code != 200 {
		t.Fatalf("alice's device: %d", device.Code)
	}
	rec := doReq(t, f.h, "PATCH", "/api/server/settings", testToken, `{"webApp":false}`)
	if rec.Code != 200 {
		t.Fatalf("switching the web off: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		WebApp struct {
			Enabled   bool `json:"enabled"`
			Installed bool `json:"installed"`
		} `json:"webApp"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.WebApp.Enabled || !out.WebApp.Installed {
		t.Fatalf("the answer: %v %s", err, rec.Body)
	}
	if v, ok, err := f.db.Setting(webSwitchKey); err != nil || !ok || v != "off" {
		t.Fatalf("the stored switch: %q %v %v", v, ok, err)
	}
	if rec := f.req(t, "GET", "/api/me", cookie, ""); rec.Code != 401 {
		t.Fatalf("the web session after the switch: %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, f.h, "GET", "/api/me", f.aliceDevice, ""); rec.Code != 200 {
		t.Fatalf("alice's device after the switch: %d", rec.Code)
	}
	rec = f.req(t, "POST", "/api/web/session", "", `{"username":"alice","password":"alice-pw"}`)
	if rec.Code != 403 || errCode(t, rec.Body.String()) != "web-off" {
		t.Fatalf("signing in with the web off: %d %s", rec.Code, rec.Body)
	}

	// On again: the setting is forgotten and sign-in works.
	rec = doReq(t, f.h, "PATCH", "/api/server/settings", testToken, `{"webApp":true}`)
	if rec.Code != 200 {
		t.Fatalf("switching the web on: %d %s", rec.Code, rec.Body)
	}
	if _, ok, err := f.db.Setting(webSwitchKey); err != nil || ok {
		t.Fatalf("switching on left the setting stored: %v", err)
	}
	f.signIn(t, false)
}

func TestWebRoutesRefuseWithoutABundle(t *testing.T) {
	f := newWebFixture(t, true)
	cookie := f.signIn(t, false)
	f.web.UseDevDir("")
	rec := f.req(t, "POST", "/api/web/session", "", `{"username":"alice","password":"alice-pw"}`)
	if rec.Code != 503 || errCode(t, rec.Body.String()) != "web-unavailable" {
		t.Fatalf("signing in with nothing installed: %d %s", rec.Code, rec.Body)
	}
	if rec := f.req(t, "GET", "/api/web/session", cookie, ""); rec.Code != 503 || errCode(t, rec.Body.String()) != "web-unavailable" {
		t.Fatalf("the session with nothing installed: %d %s", rec.Code, rec.Body)
	}
	if rec := f.req(t, "POST", "/api/web/session/elevate", cookie, `{"currentPassword":"alice-pw"}`); rec.Code != 503 ||
		errCode(t, rec.Body.String()) != "web-unavailable" {
		t.Fatalf("elevating with nothing installed: %d %s", rec.Code, rec.Body)
	}
	// Signing out always works.
	wantSignedOut(t, f, f.req(t, "DELETE", "/api/web/session", cookie, ""), "signing out with nothing installed")
	if rec := f.req(t, "GET", "/api/me", cookie, ""); rec.Code != 401 {
		t.Fatalf("the session after signing out: %d", rec.Code)
	}

}

// A session minted while the switch is off (a sign-in that read the switch
// before an administrator turned it off) is refused as an unknown session.
func TestAWebSessionMintedWhileOffIsRefused(t *testing.T) {
	f := newWebFixture(t, true)
	if rec := doReq(t, f.h, "PATCH", "/api/server/settings", testToken, `{"webApp":false}`); rec.Code != 200 {
		t.Fatalf("switching the web off: %d %s", rec.Code, rec.Body)
	}
	raw, err := f.db.MintWebSession("alice", "Web browser · late", false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	unknown := f.req(t, "GET", "/api/me", metadb.WebTokenPrefix+strings.Repeat("0", 64), "")
	for _, path := range []string{"/api/me", "/api/web/session"} {
		rec := f.req(t, "GET", path, raw, "")
		if rec.Code != 401 || rec.Body.String() != unknown.Body.String() {
			t.Fatalf("%s with a session minted while off: %d %s, want %d %s", path, rec.Code, rec.Body, unknown.Code, unknown.Body)
		}
	}
	// The row still works the moment the switch is on, so it is the switch
	// that refused it.
	if err := f.db.DeleteSetting(webSwitchKey); err != nil {
		t.Fatal(err)
	}
	if rec := f.req(t, "GET", "/api/me", raw, ""); rec.Code != 200 {
		t.Fatalf("the session with the switch on: %d %s", rec.Code, rec.Body)
	}
}

// Signing out answers 204 and clears the cookie whatever the cookie names:
// a session the off switch revoked, one never minted, none at all. A live
// one is deleted.
func TestSignOutIsIdempotent(t *testing.T) {
	f := newWebFixture(t, true)
	revoked := f.signIn(t, false)
	if rec := doReq(t, f.h, "PATCH", "/api/server/settings", testToken, `{"webApp":false}`); rec.Code != 200 {
		t.Fatalf("switching the web off: %d %s", rec.Code, rec.Body)
	}
	late, err := f.db.MintWebSession("alice", "Web browser · late", false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for name, cookie := range map[string]string{
		"revoked by the switch": revoked,
		"minted while off":      late,
		"never minted":          metadb.WebTokenPrefix + strings.Repeat("0", 64),
		"not a session":         "junk",
		"no cookie":             "",
	} {
		rec := f.req(t, "DELETE", "/api/web/session", cookie, "")
		wantSignedOut(t, f, rec, name)
		if nv, attrs := cookieAttributes(t, rec); nv != webCookie+"=" || !slices.Contains(attrs, "Max-Age=0") {
			t.Fatalf("%s: the cookie %q %q", name, nv, attrs)
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: Cache-Control %q", name, rec.Header().Get("Cache-Control"))
		}
	}
	// The session minted while off is gone, not only refused.
	if err := f.db.DeleteSetting(webSwitchKey); err != nil {
		t.Fatal(err)
	}
	if rec := f.req(t, "GET", "/api/me", late, ""); rec.Code != 401 {
		t.Fatalf("the late session after signing out: %d", rec.Code)
	}
	// A bearer is not a web session, and a request the cookie conditions
	// refuse ends nothing.
	if rec := doReq(t, f.h, "DELETE", "/api/web/session", f.aliceDevice, ""); rec.Code != 400 ||
		errCode(t, rec.Body.String()) != "web-session-only" {
		t.Fatalf("a bearer signing out: %d %s", rec.Code, rec.Body)
	}
	live := f.signIn(t, false)
	if rec := f.req(t, "DELETE", "/api/web/session", live, "", header("X-HyperDrop-Client", "")); rec.Code != 401 {
		t.Fatalf("signing out without the web header: %d %s", rec.Code, rec.Body)
	}
	if rec := f.req(t, "GET", "/api/me", live, ""); rec.Code != 200 {
		t.Fatalf("the session after a refused sign-out: %d", rec.Code)
	}
}

func TestWebSwitchOnNudgesTheFetch(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte(`{"releases":[]}`))
	}))
	defer srv.Close()
	dir := t.TempDir()
	st, err := webapp.Open(dir, nil, "2.0.0")
	if err != nil {
		t.Fatal(err)
	}
	fetcher := webapp.NewFetcher(st, srv.URL+"/", srv.Client())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fetcher.Start(ctx)
	hd := newHandler(testBackendAt(t, dir), "2.0.0", testDomain(t), nil, Deployment{Web: st, WebFetcher: fetcher})
	h := hd.routes()
	if rec := doReq(t, h, "PATCH", "/api/server/settings", testToken, `{"webApp":false}`); rec.Code != 200 {
		t.Fatalf("off: %d %s", rec.Code, rec.Body)
	}
	if hits.Load() != 0 {
		t.Fatal("switching off fetched")
	}
	if rec := doReq(t, h, "PATCH", "/api/server/settings", testToken, `{"webApp":true}`); rec.Code != 200 {
		t.Fatalf("on: %d %s", rec.Code, rec.Body)
	}
	deadline := time.Now().Add(5 * time.Second)
	for hits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if hits.Load() == 0 {
		t.Fatal("switching on did not fetch the web manifest")
	}
	deadline = time.Now().Add(5 * time.Second)
	for fetcher.Status().CheckedAt.IsZero() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	var out struct {
		WebApp map[string]any `json:"webApp"`
	}
	rec := doReq(t, h, "GET", "/api/server/settings", testToken, "")
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.WebApp["enabled"] != true || out.WebApp["installed"] != false || out.WebApp["checkedAt"] == nil {
		t.Fatalf("the settings after a fetch: %s", rec.Body)
	}
	if _, ok := out.WebApp["version"]; ok {
		t.Fatalf("a version with nothing installed: %s", rec.Body)
	}
}

func TestPatchSettingsWebOnlyOnSynology(t *testing.T) {
	hd, _ := settingsHandler(t, Deployment{Channel: "synology", Releases: "https://releases.test/"}, false)
	if hd.updates.Unsupported() == "" {
		t.Fatal("the fixture should not support self-update")
	}
	h := hd.routes()
	rec := doReq(t, h, "PATCH", "/api/server/settings", testToken, `{"webApp":false}`)
	if rec.Code != 200 {
		t.Fatalf("the web switch on a NAS: %d %s", rec.Code, rec.Body)
	}
	if v, ok, err := hd.db.Setting(webSwitchKey); err != nil || !ok || v != "off" {
		t.Fatalf("the stored switch: %q %v %v", v, ok, err)
	}
	// autoUpdate is still refused, and the refusal changes nothing.
	rec = doReq(t, h, "PATCH", "/api/server/settings", testToken, `{"webApp":true,"autoUpdate":true}`)
	if rec.Code != 409 || errCode(t, rec.Body.String()) != "self-update-unavailable" {
		t.Fatalf("autoUpdate on a NAS: %d %s", rec.Code, rec.Body)
	}
	if v, ok, err := hd.db.Setting(webSwitchKey); err != nil || !ok || v != "off" {
		t.Fatalf("a refused patch switched the web: %q %v %v", v, ok, err)
	}
}

func TestPatchSettingsNeedsAField(t *testing.T) {
	hd, _ := settingsHandler(t, Deployment{}, false)
	for _, body := range []string{`{}`, `{"webApp":"on"}`, `{"webApp":null}`} {
		rec := doReq(t, hd.routes(), "PATCH", "/api/server/settings", testToken, body)
		if rec.Code != 400 || errCode(t, rec.Body.String()) != "invalid" {
			t.Errorf("%s: %d %s", body, rec.Code, rec.Body)
		}
	}
}

// manualInstall PUTs archive to /api/server/web as the CLI does.
func manualInstall(t *testing.T, h http.Handler, token, query string, archive, sig []byte) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("PUT", "/api/server/web?"+query, bytes.NewReader(archive))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/gzip")
	if sig != nil {
		r.Header.Set("X-HyperDrop-Signature", strings.TrimSpace(string(sig)))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestManualInstall(t *testing.T) {
	dir := t.TempDir()
	st, err := webapp.Open(dir, []string{webTestPub()}, "2.0.0")
	if err != nil {
		t.Fatal(err)
	}
	b := testBackendAt(t, dir)
	user := seedUser(t, b.DB, "bob")
	h := newHandler(b, "2.0.0", testDomain(t), nil, Deployment{Web: st}).routes()

	archive := webArchive(t, map[string]string{"index.html": "manual bundle", "assets/app.js": "1"})
	sig, err := webbundle.Sign(webTestKey, "1.0.0", 4, "2.0.0", archive)
	if err != nil {
		t.Fatal(err)
	}
	const query = "version=1.0.0&build=4&contract=2.0.0"
	if rec := manualInstall(t, h, user, query, archive, sig); rec.Code != 403 {
		t.Fatalf("a user installed a bundle: %d %s", rec.Code, rec.Body)
	}
	if rec := appGet(h, "example.com", "/app/"); rec.Code != 503 {
		t.Fatalf("/app before the install: %d", rec.Code)
	}

	// A signature that does not cover these parameters.
	for _, q := range []string{"version=1.0.0&build=5&contract=2.0.0", "version=1.0.0&build=x&contract=2.0.0", "build=4&contract=2.0.0"} {
		rec := manualInstall(t, h, testToken, q, archive, sig)
		if rec.Code != 400 || errCode(t, rec.Body.String()) != "web-bundle-invalid" {
			t.Errorf("%s: %d %s", q, rec.Code, rec.Body)
		}
	}
	if rec := manualInstall(t, h, testToken, query, archive, nil); rec.Code != 400 || errCode(t, rec.Body.String()) != "web-bundle-invalid" {
		t.Fatalf("no signature: %d %s", rec.Code, rec.Body)
	}
	_, stranger, err := ed25519.GenerateKey(nil)
	webNoErr(t, err)
	strangerSig, err := webbundle.Sign(stranger, "1.0.0", 4, "2.0.0", archive)
	webNoErr(t, err)
	if rec := manualInstall(t, h, testToken, query, archive, strangerSig); rec.Code != 400 || errCode(t, rec.Body.String()) != "web-bundle-invalid" {
		t.Fatalf("an untrusted key: %d %s", rec.Code, rec.Body)
	}
	// Signed, but not a bundle: no index.html.
	bare := webArchive(t, map[string]string{"app.js": "1"})
	bareSig, err := webbundle.Sign(webTestKey, "1.0.0", 4, "2.0.0", bare)
	webNoErr(t, err)
	if rec := manualInstall(t, h, testToken, query, bare, bareSig); rec.Code != 400 || errCode(t, rec.Body.String()) != "web-bundle-invalid" {
		t.Fatalf("an archive without index.html: %d %s", rec.Code, rec.Body)
	}
	// Signed for a contract this server does not serve.
	farSig, err := webbundle.Sign(webTestKey, "1.0.0", 4, "3.0.0", archive)
	webNoErr(t, err)
	if rec := manualInstall(t, h, testToken, "version=1.0.0&build=4&contract=3.0.0", archive, farSig); rec.Code != 409 ||
		errCode(t, rec.Body.String()) != "web-bundle-outside-window" {
		t.Fatalf("a bundle outside the window: %d %s", rec.Code, rec.Body)
	}
	if rec := appGet(h, "example.com", "/app/"); rec.Code != 503 {
		t.Fatalf("/app after the refusals: %d", rec.Code)
	}

	rec := manualInstall(t, h, testToken, query, archive, sig)
	if rec.Code != 200 {
		t.Fatalf("the install: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Version string `json:"version"`
		Build   int    `json:"build"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Version != "1.0.0" || out.Build != 4 {
		t.Fatalf("the answer: %v %s", err, rec.Body)
	}
	if rec := appGet(h, "example.com", "/app/"); rec.Code != 200 || rec.Body.String() != "manual bundle" {
		t.Fatalf("/app after the install: %d %s", rec.Code, rec.Body)
	}
	if _, err := os.Stat(filepath.Join(dir, "web", "1.0.0-4", "assets", "app.js")); err != nil {
		t.Fatalf("the install is not under the data directory: %v", err)
	}
	var settings struct {
		WebApp map[string]any `json:"webApp"`
	}
	webNoErr(t, json.Unmarshal(doReq(t, h, "GET", "/api/server/settings", testToken, "").Body.Bytes(), &settings))
	if settings.WebApp["installed"] != true || settings.WebApp["version"] != "1.0.0" || settings.WebApp["build"] != float64(4) {
		t.Fatalf("the settings after the install: %v", settings.WebApp)
	}

	// Over the size cap.
	big := manualInstall(t, h, testToken, query, make([]byte, webBundleMax+1), sig)
	if big.Code != http.StatusRequestEntityTooLarge || errCode(t, big.Body.String()) != "body-too-large" {
		t.Fatalf("an oversized archive: %d %s", big.Code, big.Body)
	}

	// No store: nothing can be installed.
	none := newHandler(testBackend(t), "2.0.0", testDomain(t), nil, Deployment{}).routes()
	if rec := manualInstall(t, none, testToken, query, archive, sig); rec.Code != 503 || errCode(t, rec.Body.String()) != "web-unavailable" {
		t.Fatalf("no store: %d %s", rec.Code, rec.Body)
	}
}

func TestHealthReportsWeb(t *testing.T) {
	f := newWebFixture(t, false)
	web := func() any {
		var out map[string]any
		rec := doReq(t, f.h, "GET", "/api/health", "", "")
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out["web"]
	}
	if got := web(); got != true {
		t.Fatalf("on with a bundle: web = %v", got)
	}
	webNoErr(t, f.db.SetSetting(webSwitchKey, "off"))
	if got := web(); got != nil {
		t.Fatalf("switched off: web = %v", got)
	}
	webNoErr(t, f.db.DeleteSetting(webSwitchKey))
	f.web.UseDevDir("")
	if got := web(); got != nil {
		t.Fatalf("nothing installed: web = %v", got)
	}
}

func TestJoinPageLinksTheWebApp(t *testing.T) {
	f := newWebFixture(t, true)
	for _, path := range []string{"/", "/join"} {
		rec := appGet(f.h, webAppHost, path)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), `href="/app/"`) ||
			!strings.Contains(rec.Body.String(), "Use HyperDrop in this browser") {
			t.Fatalf("%s with the web on: %d %s", path, rec.Code, rec.Body)
		}
	}
	webNoErr(t, f.db.SetSetting(webSwitchKey, "off"))
	for _, path := range []string{"/", "/join"} {
		if rec := appGet(f.h, webAppHost, path); rec.Code != 200 || strings.Contains(rec.Body.String(), "/app/") {
			t.Fatalf("%s with the web off: %d", path, rec.Code)
		}
	}
	webNoErr(t, f.db.DeleteSetting(webSwitchKey))
	f.web.UseDevDir("")
	if rec := appGet(f.h, webAppHost, "/"); strings.Contains(rec.Body.String(), "/app/") {
		t.Fatal("the front page links a web version that is not installed")
	}
}

// An archive whose upload broke off is the request failing, not the archive
// being too large.
func TestManualInstallBodyThatBrokeOff(t *testing.T) {
	dir := t.TempDir()
	st, err := webapp.Open(dir, []string{webTestPub()}, "2.0.0")
	webNoErr(t, err)
	h := newHandler(testBackendAt(t, dir), "2.0.0", testDomain(t), nil, Deployment{Web: st}).routes()
	r := httptest.NewRequest("PUT", "/api/server/web?version=1.0.0&build=1&contract=2.0.0",
		io.MultiReader(strings.NewReader("partial"), iotest.ErrReader(errors.New("the client hung up"))))
	r.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 400 {
		t.Fatalf("a body that broke off: %d %s", rec.Code, rec.Body)
	}
}

// A store that could not be opened at boot says why in the settings.
func TestSettingsReportAStoreThatFailedToOpen(t *testing.T) {
	const why = "web client: mkdir /data/web: permission denied"
	h := newHandler(testBackend(t), "2.0.0", testDomain(t), nil, Deployment{WebFailed: why}).routes()
	var out struct {
		WebApp map[string]any `json:"webApp"`
	}
	webNoErr(t, json.Unmarshal(doReq(t, h, "GET", "/api/server/settings", testToken, "").Body.Bytes(), &out))
	if out.WebApp["failed"] != why || out.WebApp["installed"] != false || out.WebApp["enabled"] != true {
		t.Fatalf("webApp: %v", out.WebApp)
	}
}
