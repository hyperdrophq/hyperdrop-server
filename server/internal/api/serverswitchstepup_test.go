package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"hyperdrop/core/webbundle"
	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/webapp"
)

func TestAWebBundleInstallVerifiesTheStepUpHeaders(t *testing.T) {
	dir := t.TempDir()
	st, err := webapp.Open(dir, []string{webTestPub()}, "2.0.0")
	webNoErr(t, err)
	b := testBackendAt(t, dir)
	h := newHandler(b, "2.0.0", testDomain(t), nil, Deployment{Web: st}).routes()
	archive := webArchive(t, map[string]string{"index.html": "bundle", "assets/app.js": "1"})
	sig, err := webbundle.Sign(webTestKey, "1.0.0", 4, "2.0.0", archive)
	webNoErr(t, err)
	const query = "version=1.0.0&build=4&contract=2.0.0"
	put := func(password string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("PUT", "/api/server/web?"+query, strings.NewReader(string(archive)))
		r.Header.Set("Authorization", "Bearer "+testToken)
		r.Header.Set("X-HyperDrop-Signature", strings.TrimSpace(string(sig)))
		if password != "" {
			r.Header.Set("X-HyperDrop-Password", password)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}
	rec := put("wrong")
	if rec.Code != http.StatusUnauthorized || errCode(t, rec.Body.String()) != "wrong-password" {
		t.Fatalf("wrong password = %d %s, want 401 wrong-password", rec.Code, rec.Body)
	}
	if _, ok := st.Current(); ok {
		t.Fatal("a bundle was installed after a refused step-up")
	}
	if _, ok := st.Current(); ok {
		t.Fatal("a bundle was installed after a refused step-up")
	}
}

func TestAWebBundleInstallWithoutHeadersIsStepUpRequired(t *testing.T) {
	dir := t.TempDir()
	st, err := webapp.Open(dir, []string{webTestPub()}, "2.0.0")
	webNoErr(t, err)
	b := testBackendAt(t, dir)
	h := newHandler(b, "2.0.0", testDomain(t), nil, Deployment{Web: st}).routes()
	archive := webArchive(t, map[string]string{"index.html": "bundle", "assets/app.js": "1"})
	sig, err := webbundle.Sign(webTestKey, "1.0.0", 4, "2.0.0", archive)
	webNoErr(t, err)
	r := httptest.NewRequest("PUT", "/api/server/web?version=1.0.0&build=4&contract=2.0.0", strings.NewReader(string(archive)))
	r.Header.Set("Authorization", "Bearer "+testToken)
	r.Header.Set("X-HyperDrop-Signature", strings.TrimSpace(string(sig)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	wantStepUpRequired(t, "bare web bundle install", rec)
	if _, ok := st.Current(); ok {
		t.Fatal("a bundle was installed without a step-up")
	}
}

func TestAServerSwitchVerifiesTheStepUpItCarries(t *testing.T) {
	hd, _ := settingsHandler(t, Deployment{Releases: "https://releases.test/", Official: true}, true)
	h := hd.routes()
	rec := doReq(t, h, "PATCH", "/api/server/settings", testToken, `{"autoUpdate":false,"currentPassword":"wrong"}`)
	if rec.Code != http.StatusUnauthorized || errCode(t, rec.Body.String()) != "wrong-password" {
		t.Fatalf("wrong password = %d %s, want 401 wrong-password", rec.Code, rec.Body)
	}
	if d := readSettings(t, doReq(t, h, "GET", "/api/server/settings", testToken, "").Body.Bytes()); !d.AutoUpdate {
		t.Fatalf("a refused step-up moved the switch: %+v", d)
	}
	body := fmt.Sprintf(`{"autoUpdate":false,"currentPassword":%q,"totp":%q}`, testAdminPassword, seededAdminCode(t))
	if rec := doReq(t, h, "PATCH", "/api/server/settings", testToken, body); rec.Code != http.StatusOK {
		t.Fatalf("right password and code = %d %s, want 200", rec.Code, rec.Body)
	}
}

func TestAServerSwitchWithoutAStepUpIsStepUpRequired(t *testing.T) {
	hd, _ := settingsHandler(t, Deployment{}, false)
	wantStepUpRequired(t, "bare switch", doReqBare(t, hd.routes(), "PATCH", "/api/server/settings", testToken, `{"desktopSignIn":false}`))
}

func TestAnElevatedWebSessionSwitchesWithThePasswordAlone(t *testing.T) {
	f := newWebFixture(t, true)
	raw := f.signInAs(t, metadb.DefaultAdminName, testAdminPassword)
	secret, _ := enableTOTP(t, f.h, testToken, testAdminPassword)
	body := `{"desktopSignIn":false,"currentPassword":"` + testAdminPassword + `"}`
	if rec := f.req(t, "PATCH", "/api/server/settings", raw, body); rec.Code != 403 || errCode(t, rec.Body.String()) != "web-elevation-required" {
		t.Fatalf("an unelevated session: %d %s, want 403 web-elevation-required", rec.Code, rec.Body)
	}
	elevate := `{"currentPassword":"` + testAdminPassword + `","totp":"` + nextCode(t, secret) + `"}`
	if rec := f.req(t, "POST", "/api/web/session/elevate", raw, elevate); rec.Code != 200 {
		t.Fatalf("elevate: %d %s", rec.Code, rec.Body)
	}
	if rec := f.req(t, "PATCH", "/api/server/settings", raw, body); rec.Code != 200 {
		t.Fatalf("an elevated session with the password alone: %d %s, want 200", rec.Code, rec.Body)
	}
}

func TestAnUnsupportedAutoUpdateSpendsNoCode(t *testing.T) {
	hd, _ := settingsHandler(t, Deployment{Channel: "synology", Releases: "https://releases.test/"}, false)
	h := hd.routes()
	secret, _ := enableTOTP(t, h, testToken, testAdminPassword)
	code := nextCode(t, secret)
	body := fmt.Sprintf(`{"autoUpdate":true,"currentPassword":%q,"totp":%q}`, testAdminPassword, code)
	rec := doReq(t, h, "PATCH", "/api/server/settings", testToken, body)
	if rec.Code != http.StatusConflict || errCode(t, rec.Body.String()) != "self-update-unavailable" {
		t.Fatalf("unsupported = %d %s, want 409 self-update-unavailable", rec.Code, rec.Body)
	}
	body = fmt.Sprintf(`{"desktopSignIn":false,"currentPassword":%q,"totp":%q}`, testAdminPassword, code)
	if rec := doReq(t, h, "PATCH", "/api/server/settings", testToken, body); rec.Code != http.StatusOK {
		t.Fatalf("same code on a supported switch = %d %s, want 200", rec.Code, rec.Body)
	}
}

func TestASettingsBodyNamingNoSwitchIsInvalidEvenWithAStepUp(t *testing.T) {
	hd, _ := settingsHandler(t, Deployment{}, false)
	rec := doReq(t, hd.routes(), "PATCH", "/api/server/settings", testToken, `{"currentPassword":"wrong"}`)
	if rec.Code != http.StatusBadRequest || errCode(t, rec.Body.String()) != "invalid" {
		t.Fatalf("no switch = %d %s, want 400 invalid", rec.Code, rec.Body)
	}
}

func TestABadWebBundleSpendsNoCode(t *testing.T) {
	dir := t.TempDir()
	st, err := webapp.Open(dir, []string{webTestPub()}, "2.0.0")
	webNoErr(t, err)
	b := testBackendAt(t, dir)
	h := newHandler(b, "2.0.0", testDomain(t), nil, Deployment{Web: st}).routes()
	secret, _ := enableTOTP(t, h, testToken, testAdminPassword)
	code := nextCode(t, secret)
	archive := webArchive(t, map[string]string{"index.html": "bundle", "assets/app.js": "1"})
	put := func(query string, sig []byte) *httptest.ResponseRecorder {
		r := httptest.NewRequest("PUT", "/api/server/web?"+query, strings.NewReader(string(archive)))
		r.Header.Set("Authorization", "Bearer "+testToken)
		r.Header.Set("X-HyperDrop-Signature", strings.TrimSpace(string(sig)))
		r.Header.Set("X-HyperDrop-Password", testAdminPassword)
		r.Header.Set("X-HyperDrop-TOTP", code)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}
	otherBuild, err := webbundle.Sign(webTestKey, "1.0.0", 5, "2.0.0", archive)
	webNoErr(t, err)
	rec := put("version=1.0.0&build=4&contract=2.0.0", otherBuild)
	if rec.Code != http.StatusBadRequest || errCode(t, rec.Body.String()) != "web-bundle-invalid" {
		t.Fatalf("bad signature = %d %s, want 400 web-bundle-invalid", rec.Code, rec.Body)
	}
	outside, err := webbundle.Sign(webTestKey, "1.0.0", 4, "9.0.0", archive)
	webNoErr(t, err)
	rec = put("version=1.0.0&build=4&contract=9.0.0", outside)
	if rec.Code != http.StatusConflict || errCode(t, rec.Body.String()) != "web-bundle-outside-window" {
		t.Fatalf("outside the window = %d %s, want 409 web-bundle-outside-window", rec.Code, rec.Body)
	}
	good, err := webbundle.Sign(webTestKey, "1.0.0", 4, "2.0.0", archive)
	webNoErr(t, err)
	if rec := put("version=1.0.0&build=4&contract=2.0.0", good); rec.Code != http.StatusOK {
		t.Fatalf("the same code on a good bundle = %d %s, want 200", rec.Code, rec.Body)
	}
	if _, ok := st.Current(); !ok {
		t.Fatal("no bundle installed")
	}
}
