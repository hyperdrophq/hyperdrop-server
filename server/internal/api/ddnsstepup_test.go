package api

import (
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"hyperdrop/server/internal/ddns"
)

// claimCountingAPI is a handler whose names service accepts every claim and
// counts the claims that reach it.
func claimCountingAPI(t *testing.T) (http.Handler, *atomic.Int32) {
	t.Helper()
	var claims atomic.Int32
	h := newTestAPIWithService(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

func TestAFreeNameChoiceVerifiesTheStepUpItCarries(t *testing.T) {
	h, claims := claimCountingAPI(t)
	rec := doReq(t, h, "PUT", "/api/ddns", testToken, `{"name":"mynas","currentPassword":"wrong"}`)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `"code":"wrong-password"`) {
		t.Fatalf("wrong password = %d %s, want 401 wrong-password", rec.Code, rec.Body)
	}
	if n := claims.Load(); n != 0 {
		t.Fatalf("%d claims reached the names service after a refused step-up", n)
	}
	body := fmt.Sprintf(`{"name":"mynas","currentPassword":%q}`, testAdminPassword)
	if rec := doReq(t, h, "PUT", "/api/ddns", testToken, body); rec.Code != http.StatusOK {
		t.Fatalf("right password = %d %s, want 200", rec.Code, rec.Body)
	}
	if n := claims.Load(); n != 1 {
		t.Fatalf("claims = %d, want 1", n)
	}
}

func TestAFreeNameChoiceWithoutAStepUpStillWorks(t *testing.T) {
	h, claims := claimCountingAPI(t)
	if rec := doReq(t, h, "PUT", "/api/ddns", testToken, `{"name":"mynas"}`); rec.Code != http.StatusOK {
		t.Fatalf("bare PUT = %d %s, want 200", rec.Code, rec.Body)
	}
	if n := claims.Load(); n != 1 {
		t.Fatalf("claims = %d, want 1", n)
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

func TestClearingTheFreeNameVerifiesTheStepUpItCarries(t *testing.T) {
	h, _ := claimCountingAPI(t)
	if rec := doReq(t, h, "PUT", "/api/ddns", testToken, `{"name":"mynas"}`); rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d %s", rec.Code, rec.Body)
	}
	rec := doReq(t, h, "DELETE", "/api/ddns", testToken, `{"currentPassword":"wrong"}`)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `"code":"wrong-password"`) {
		t.Fatalf("wrong password = %d %s, want 401 wrong-password", rec.Code, rec.Body)
	}
	if !strings.Contains(doReq(t, h, "GET", "/api/ddns", testToken, "").Body.String(), `"configured":true`) {
		t.Fatal("a refused clear released the name")
	}
	if rec := doReq(t, h, "DELETE", "/api/ddns", testToken, ""); rec.Code != http.StatusOK {
		t.Fatalf("empty body = %d %s, want 200", rec.Code, rec.Body)
	}
	if strings.Contains(doReq(t, h, "GET", "/api/ddns", testToken, "").Body.String(), `"configured":true`) {
		t.Fatal("the name is still held after an accepted clear")
	}
}

func TestCancellingAPendingNameTakesNoStepUp(t *testing.T) {
	h, _ := claimCountingAPI(t)
	if rec := doReq(t, h, "DELETE", "/api/ddns?pendingName=mynas", testToken, ""); rec.Code != http.StatusOK {
		t.Fatalf("cancel = %d %s, want 200", rec.Code, rec.Body)
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
