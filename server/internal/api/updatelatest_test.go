package api

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"hyperdrop/server/internal/updatesig"
)

// latestAPI is a handler whose staging directory exists and whose manifest
// is a local site offering version newest (signed by the test release key),
// running version 9.9.9.
func latestAPI(t *testing.T, newest string, official bool) (http.Handler, string) {
	t.Helper()
	h := latestHandler(t, newest, Deployment{Official: official})
	return h.routes(), h.dep.UpdateDir
}

// latestHandler is latestAPI's handler, built over dep with Releases set to
// the local site.
func latestHandler(t *testing.T, newest string, dep Deployment) *handler {
	t.Helper()
	raw := append([]byte{0x7f, 'E', 'L', 'F'}, []byte("server "+newest)...)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(raw)
	zw.Close()
	sum := sha256.Sum256(gz.Bytes())
	name := "hyperdrop-server-" + newest + "-linux-" + runtime.GOARCH + ".gz"
	manifest, _ := json.Marshal(map[string]any{"releases": []map[string]any{{
		"version": newest, "date": "2026-11-02",
		"linux": map[string]any{runtime.GOARCH: map[string]any{"length": gz.Len(), "sha256": hex.EncodeToString(sum[:])}},
	}}})
	files := map[string][]byte{
		"releases.json": manifest,
		name:            gz.Bytes(),
		name + ".sig":   testSignature(testReleaseKey, newest, runtime.GOARCH, raw),
	}
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, ok := files[strings.TrimPrefix(r.URL.Path, "/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(site.Close)

	trusted := updatesig.TrustedKeys
	updatesig.TrustedKeys = []string{base64.StdEncoding.EncodeToString(testReleaseKey.Public().(ed25519.PublicKey))}
	t.Cleanup(func() { updatesig.TrustedKeys = trusted })
	dir := t.TempDir()
	dep.Releases = site.URL + "/"
	h := newHandler(testBackend(t), "9.9.9", testDomain(t), nil, dep)
	h.dep.UpdateDir = dir
	return h
}

func postLatest(t *testing.T, h http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	return doReq(t, h, "POST", "/api/server/update/latest", testToken, body)
}

func TestUpdateLatestNeedsTwoFactorAndPassword(t *testing.T) {
	h, dir := latestAPI(t, "9.9.10", true)
	body := func(pw, code string) string {
		return `{"currentPassword":"` + pw + `","totp":"` + code + `"}`
	}
	rec := postLatest(t, h, body(testAdminPassword, ""))
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), "totp-setup-required") {
		t.Fatalf("no second factor = %d %s", rec.Code, rec.Body)
	}
	secret, _ := enableTOTP(t, h, testToken, testAdminPassword)
	wantStepUpRequired(t, "no password", postLatest(t, h, body("", nextCode(t, secret))))
	if rec := postLatest(t, h, body("wrong-password", nextCode(t, secret))); rec.Code != 401 {
		t.Fatalf("wrong password = %d", rec.Code)
	}
	if rec := postLatest(t, h, body(testAdminPassword, "000000")); rec.Code != 401 {
		t.Fatalf("wrong code = %d", rec.Code)
	}
	if rec := postLatest(t, h, `{"currentPassword":"x","extra":1}`); rec.Code != 400 {
		t.Fatalf("unknown field = %d", rec.Code)
	}
	assertNothingStaged(t, dir)

	rec = postLatest(t, h, body(testAdminPassword, nextCode(t, secret)))
	if rec.Code != 202 || !strings.Contains(rec.Body.String(), `"version":"9.9.10"`) {
		t.Fatalf("update = %d %s", rec.Code, rec.Body)
	}
	if _, err := os.Stat(filepath.Join(dir, stagedName)); err != nil {
		t.Fatalf("nothing staged: %v", err)
	}
}

func TestUpdateLatestAlreadyCurrent(t *testing.T) {
	h, dir := latestAPI(t, "9.9.9", true)
	secret, _ := enableTOTP(t, h, testToken, testAdminPassword)
	rec := postLatest(t, h, `{"currentPassword":"`+testAdminPassword+`","totp":"`+nextCode(t, secret)+`"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"reason":"already current"`) ||
		!strings.Contains(rec.Body.String(), `"updated":false`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	assertNothingStaged(t, dir)
}

func TestUpdateLatestUnsupported(t *testing.T) {
	h, _ := latestAPI(t, "9.9.10", false)
	rec := postLatest(t, h, `{}`)
	if rec.Code != 501 || !strings.Contains(rec.Body.String(), "update-unsupported") ||
		!strings.Contains(rec.Body.String(), "not an official HyperDrop build") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}
