package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"hyperdrop/server/internal/ddns"
)

// claimCountingAPI is a handler whose names service accepts every claim and
// counts the claims that reach it.
func claimCountingAPI(t *testing.T) (http.Handler, *atomic.Int32) {
	t.Helper()
	return claimCountingAPIOn(t, testBackend(t))
}

// claimCountingAPIOn is claimCountingAPI over b.
func claimCountingAPIOn(t *testing.T, b Backend) (http.Handler, *atomic.Int32) {
	t.Helper()
	var claims atomic.Int32
	h := newTestAPIWithServiceOn(t, b, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/v1/claim") {
			claims.Add(1)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"name":"mynas","fqdn":"` + ddns.FQDN("mynas") +
				`","token":"claimed-tok","expiresAt":9000}`))
			return
		}
		_, _ = w.Write([]byte(`{"ip":"203.0.113.7","changed":true,"state":"active","expiresAt":0}`))
	}))
	return h, &claims
}

// ddnsAPIParts is claimCountingAPIOn with the handler it serves from.
func ddnsAPIParts(t *testing.T, b Backend) (http.Handler, *handler) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/v1/claim") {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"name":"mynas","fqdn":"` + ddns.FQDN("mynas") +
				`","token":"claimed-tok","expiresAt":9000}`))
			return
		}
		_, _ = w.Write([]byte(`{"ip":"203.0.113.7","changed":true,"state":"active","expiresAt":0}`))
	}))
	t.Cleanup(srv.Close)
	s, err := ddns.Load(filepath.Join(t.TempDir(), "ddns"))
	if err != nil {
		t.Fatal(err)
	}
	addr := func(context.Context) (string, bool) { return "203.0.113.7", true }
	upd := ddns.NewUpdater(s, &ddns.Client{BaseURL: srv.URL}, addr)
	t.Cleanup(upd.Stop)
	hd := newHandler(b, "2.0.0", testDomain(t), upd, Deployment{})
	return hd.routes(), hd
}

func TestAFreeNameChoiceVerifiesTheStepUpItCarries(t *testing.T) {
	h, claims := claimCountingAPI(t)
	rec := doReq(t, h, "PUT", "/api/ddns", testToken, `{"name":"mynas","currentPassword":"wrong"}`)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `"code":"wrong-password"`) {
		t.Fatalf("wrong password = %d %s, want 401 wrong-password", rec.Code, rec.Body)
	}
	if n := claims.Load(); n != 0 {
		t.Fatalf("%d claims reached the names service after a refused step-up", n)
	}
	body := fmt.Sprintf(`{"name":"mynas","currentPassword":%q,"totp":%q}`, testAdminPassword, seededAdminCode(t))
	if rec := doReq(t, h, "PUT", "/api/ddns", testToken, body); rec.Code != http.StatusOK {
		t.Fatalf("right password and code = %d %s, want 200", rec.Code, rec.Body)
	}
	if n := claims.Load(); n != 1 {
		t.Fatalf("claims = %d, want 1", n)
	}
}

func TestAFreeNameChoiceWithoutAStepUpIsStepUpRequired(t *testing.T) {
	h, claims := claimCountingAPI(t)
	wantStepUpRequired(t, "bare PUT", doReqBare(t, h, "PUT", "/api/ddns", testToken, `{"name":"mynas"}`))
	if n := claims.Load(); n != 0 {
		t.Fatalf("claims = %d, want 0", n)
	}
}

func TestAnInvalidFreeNameSpendsNoCode(t *testing.T) {
	h, _ := claimCountingAPI(t)
	secret, _ := enableTOTP(t, h, testToken, testAdminPassword)
	code := nextCode(t, secret)
	bad := fmt.Sprintf(`{"name":"Bad_Name","currentPassword":%q,"totp":%q}`, testAdminPassword, code)
	if rec := doReq(t, h, "PUT", "/api/ddns", testToken, bad); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid name = %d %s, want 400", rec.Code, rec.Body)
	}
	good := fmt.Sprintf(`{"name":"mynas","currentPassword":%q,"totp":%q}`, testAdminPassword, code)
	if rec := doReq(t, h, "PUT", "/api/ddns", testToken, good); rec.Code != http.StatusOK {
		t.Fatalf("same code on a valid name = %d %s, want 200", rec.Code, rec.Body)
	}
}

// claimedMynas claims "mynas" with the seeded admin's step-up.
func claimedMynas(t *testing.T, h http.Handler) {
	t.Helper()
	body := fmt.Sprintf(`{"name":"mynas","currentPassword":%q,"totp":%q}`, testAdminPassword, seededAdminCode(t))
	if rec := doReq(t, h, "PUT", "/api/ddns", testToken, body); rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d %s", rec.Code, rec.Body)
	}
}

func TestClearingTheServedFreeNameNeedsTheStepUp(t *testing.T) {
	b := testBackend(t)
	h, hd := ddnsAPIParts(t, b)
	claimedMynas(t, h)
	if got := hd.dom.Current(); got != ddns.FQDN("mynas") {
		t.Fatalf("the server serves %q, want the claimed name", got)
	}
	wantStepUpRequired(t, "bare clear", doReqBare(t, h, "DELETE", "/api/ddns", testToken, ""))
	rec := doReq(t, h, "DELETE", "/api/ddns", testToken, `{"currentPassword":"wrong"}`)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `"code":"wrong-password"`) {
		t.Fatalf("wrong password = %d %s, want 401 wrong-password", rec.Code, rec.Body)
	}
	if !strings.Contains(doReq(t, h, "GET", "/api/ddns", testToken, "").Body.String(), `"configured":true`) {
		t.Fatal("a refused clear released the name")
	}
	body := fmt.Sprintf(`{"currentPassword":%q,"totp":%q}`, testAdminPassword, seededAdminCode(t))
	if rec := doReq(t, h, "DELETE", "/api/ddns", testToken, body); rec.Code != http.StatusOK {
		t.Fatalf("right step-up = %d %s, want 200", rec.Code, rec.Body)
	}
}

func TestClearingAFreeNameNoLongerServedTakesNoStepUp(t *testing.T) {
	h, hd := ddnsAPIParts(t, testBackend(t))
	claimedMynas(t, h)
	if err := hd.dom.Adopt("share.example.com"); err != nil {
		t.Fatal(err)
	}
	if rec := doReqBare(t, h, "DELETE", "/api/ddns", testToken, ""); rec.Code != http.StatusOK {
		t.Fatalf("bare clear of an unserved name = %d %s, want 200", rec.Code, rec.Body)
	}
	if strings.Contains(doReq(t, h, "GET", "/api/ddns", testToken, "").Body.String(), `"configured":true`) {
		t.Fatal("the name is still held after an accepted clear")
	}
}

func TestClearingTheFreeNameVerifiesTheStepUpItCarries(t *testing.T) {
	h, _ := claimCountingAPI(t)
	claimedMynas(t, h)
	rec := doReq(t, h, "DELETE", "/api/ddns", testToken, `{"currentPassword":"wrong"}`)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `"code":"wrong-password"`) {
		t.Fatalf("wrong password = %d %s, want 401 wrong-password", rec.Code, rec.Body)
	}
	if !strings.Contains(doReq(t, h, "GET", "/api/ddns", testToken, "").Body.String(), `"configured":true`) {
		t.Fatal("a refused clear released the name")
	}
}

// A pending candidate whose name is the one the server serves is cancelled
// without a step-up, while a bare clear of the same name asks for one.
func TestCancellingAPendingNameTakesNoStepUp(t *testing.T) {
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/v1/claim") {
			w.Header().Set("content-type", "application/json")
			_, _ = w.Write([]byte(`{}`))
			return
		}
		w.WriteHeader(http.StatusPreconditionRequired)
		_, _ = fmt.Fprintf(w, `{"code":"account-required","error":"Sign in to approve this free domain","approvalURL":"https://gethyperdrop.com/account/#code=approval","challenge":"bootstrap-nonce","expiresAt":%d}`, time.Now().Add(10*time.Minute).Unix())
	}))
	defer registry.Close()
	ds, err := ddns.Load(filepath.Join(t.TempDir(), "ddns"))
	if err != nil {
		t.Fatal(err)
	}
	upd := ddns.NewUpdater(ds, &ddns.Client{BaseURL: registry.URL}, func(context.Context) (string, bool) { return "203.0.113.7", true })
	defer upd.Stop()
	dom := testDomain(t)
	h := New(testBackend(t), "2.0.0", dom, upd)
	if rec := doReq(t, h, "PUT", "/api/ddns", testToken, `{"name":"mynas"}`); rec.Code != http.StatusAccepted {
		t.Fatalf("pending claim = %d %s, want 202", rec.Code, rec.Body)
	}
	if err := dom.Adopt(ddns.FQDN("mynas")); err != nil {
		t.Fatal(err)
	}
	wantStepUpRequired(t, "bare clear of the served name", doReqBare(t, h, "DELETE", "/api/ddns", testToken, ""))
	if ds.Snapshot().Name != "mynas" {
		t.Fatal("a refused clear released the candidate")
	}
	if rec := doReqBare(t, h, "DELETE", "/api/ddns?pendingName=mynas", testToken, ""); rec.Code != http.StatusOK {
		t.Fatalf("cancel = %d %s, want 200", rec.Code, rec.Body)
	}
	if ds.Snapshot().Name != "" {
		t.Fatalf("the candidate is still held: %+v", ds.Snapshot())
	}
}

func TestADifferentFreeNameWhileOneIsHeldSpendsNoCode(t *testing.T) {
	h, claims := claimCountingAPI(t)
	if rec := doReq(t, h, "PUT", "/api/ddns", testToken, `{"name":"mynas"}`); rec.Code != http.StatusOK {
		t.Fatalf("claiming mynas = %d %s", rec.Code, rec.Body)
	}
	secret, _ := enableTOTP(t, h, testToken, testAdminPassword)
	code := nextCode(t, secret)
	other := fmt.Sprintf(`{"name":"othername","currentPassword":%q,"totp":%q}`, testAdminPassword, code)
	rec := doReq(t, h, "PUT", "/api/ddns", testToken, other)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), `"code":"name-permanent"`) {
		t.Fatalf("another name while mynas is held = %d %s, want 409 name-permanent", rec.Code, rec.Body)
	}
	same := fmt.Sprintf(`{"name":"mynas","currentPassword":%q,"totp":%q}`, testAdminPassword, code)
	if rec := doReq(t, h, "PUT", "/api/ddns", testToken, same); rec.Code != http.StatusOK {
		t.Fatalf("same code on the held name = %d %s, want 200", rec.Code, rec.Body)
	}
	if n := claims.Load(); n != 1 {
		t.Fatalf("claims = %d, want 1", n)
	}
}
