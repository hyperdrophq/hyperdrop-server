package api

import (
	"context"
	"net"
	"path/filepath"
	"slices"
	"testing"

	"hyperdrop/server/internal/domain"
)

// Every address change the app makes runs through the deployment's hook,
// which learns whether it was accepted: an accepted one replaces an address
// change still waiting from DSM.
func TestTheAppsAddressChangesRunThroughTheHook(t *testing.T) {
	dom, err := domain.Load(filepath.Join(t.TempDir(), "domain"), "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	pointing := true
	dom.Lookup = func(context.Context, string) ([]net.IP, error) {
		if pointing {
			return []net.IP{net.ParseIP("203.0.113.7")}, nil
		}
		return []net.IP{net.ParseIP("198.51.100.9")}, nil
	}
	upd, _ := testDDNS(t)
	var got []bool
	h := newHandler(testBackend(t), "2.0.0", dom, upd, Deployment{
		DataDir: t.TempDir(),
		AddressChange: func(change func() bool) {
			got = append(got, change())
		},
	}).routes()

	for _, step := range []struct {
		method, path, body string
		code               int
		want               []bool
	}{
		{"PUT", "/api/domain", `{"domain":"share.example.com"}`, 200, []bool{true}},
		{"PUT", "/api/ddns", `{"name":"x"}`, 400, nil},
		{"PUT", "/api/ddns", `{"name":"alice"}`, 200, []bool{true}},
		{"DELETE", "/api/ddns", "", 200, []bool{true}},
	} {
		got = nil
		rec := doReq(t, h, step.method, step.path, testToken, step.body)
		if rec.Code != step.code || !slices.Equal(got, step.want) {
			t.Fatalf("%s %s: %d %s, hook %v, want %d %v", step.method, step.path, rec.Code, rec.Body, got, step.code, step.want)
		}
	}

	pointing = false
	got = nil
	if rec := doReq(t, h, "PUT", "/api/domain", testToken, `{"domain":"other.example.com"}`); rec.Code != 409 || len(got) != 0 {
		t.Fatalf("a refused domain: %d, hook %v", rec.Code, got)
	}
}
