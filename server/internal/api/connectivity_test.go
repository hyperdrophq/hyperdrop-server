package api

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"hyperdrop/server/internal/ddns"
)

func TestConnectivityIsAdminOnlyAndConfigurationRequiresPassword(t *testing.T) {
	b := testBackend(t)
	um := b.DB
	guest := seedUser(t, um, "guest")
	dom := testDomain(t)
	s, err := ddns.Load(filepath.Join(t.TempDir(), "ddns"))
	if err != nil {
		t.Fatal(err)
	}
	u := ddns.NewUpdater(s, &ddns.Client{}, func(context.Context) (string, bool) { return "8.8.8.8", true })
	u.Domain = func() string { return "share.example.com" }
	u.ProbeHost = func(_ context.Context, host, ip string, _ []byte) ddns.HostStatus {
		return ddns.HostStatus{Host: host, DNS: "current", HTTPS: "valid"}
	}
	t.Cleanup(u.Stop)
	h := New(b, "test", dom, u)
	for _, token := range []string{"", guest} {
		if rec := doReq(t, h, "GET", "/api/connectivity", token, ""); rec.Code == 200 {
			t.Fatal("connectivity exposed to a non-admin")
		}
	}
	config := map[string]any{"mode": "external", "domain": "share.example.com", "secrets": map[string]string{"token": "sensitive-provider-token"}}
	request := map[string]any{"config": config, "currentPassword": "wrong"}
	data, _ := json.Marshal(request)
	if rec := doReq(t, h, "PUT", "/api/connectivity", testToken, string(data)); rec.Code == 200 {
		t.Fatal("wrong step-up password accepted")
	}
	if s.Snapshot().Custom != nil {
		t.Fatal("failed authentication mutated config")
	}
	request["currentPassword"] = testAdminPassword
	data, _ = json.Marshal(request)
	rec := doReq(t, h, "PUT", "/api/connectivity", testToken, string(data))
	if rec.Code != http.StatusOK {
		t.Fatalf("configure: %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "sensitive-provider-token") || strings.Contains(rec.Body.String(), "currentPassword") {
		t.Fatal("configuration secrets leaked")
	}
	if s.Snapshot().Custom.Secrets["token"] != "sensitive-provider-token" {
		t.Fatal("credential was not persisted")
	}
}
