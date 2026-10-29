package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/ddns"
)

func TestAccountApprovalIsUsableBeforeDomainConfiguration(t *testing.T) {
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	h := New(testBackend(t), "2.0.0", nil, upd)
	response := doReq(t, h, "PUT", "/api/ddns", testToken, `{"name":"myserver"}`)
	if response.Code != http.StatusAccepted || !strings.Contains(response.Body.String(), `"enrollment"`) {
		t.Fatalf("pending account approval is not usable: %d %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "bootstrap-nonce") || strings.Contains(response.Body.String(), ds.Snapshot().Token) {
		t.Fatal("private state leaked in client enrollment status")
	}
	proof := doReq(t, h, "GET", "/.well-known/hyperdrop-names", "", "")
	if proof.Code != http.StatusOK || proof.Body.String() != "{\"challenge\":\"bootstrap-nonce\"}\n" {
		t.Fatalf("bootstrap challenge: %d %s", proof.Code, proof.Body.String())
	}
}

func TestDomainRecoveryCredentialAPIIsRemoved(t *testing.T) {
	h := newTestAPI(t)
	if rec := doReq(t, h, "POST", "/api/ddns/recovery-token", testToken, `{"currentPassword":"wrong"}`); rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("domain credential export still exists: %d", rec.Code)
	}
	if rec := doReq(t, h, "PUT", "/api/ddns", testToken, `{"name":"alice","token":"old-recovery"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("domain credential import still exists: %d", rec.Code)
	}
}
