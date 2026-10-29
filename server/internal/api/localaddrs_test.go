package api

import (
	"encoding/json"
	"net"
	"testing"
)

// The candidates the route reports: private IPv4 only (a public address is
// reachable through BaseURL already, loopback is nobody's LAN), each joined
// with the server's own HTTPS listen port.
func TestLocalAddressCandidates(t *testing.T) {
	addrs := []net.Addr{
		cidr(t, "192.168.1.174/24"),
		cidr(t, "203.0.113.7/24"), // public: dropped
		cidr(t, "127.0.0.1/8"),    // loopback: dropped
		cidr(t, "fe80::1/64"),     // IPv6: dropped (the shortcut is IPv4)
		cidr(t, "10.0.0.4/16"),
	}
	got := localAddressCandidates(addrs, "5443")
	want := []string{"192.168.1.174:5443", "10.0.0.4:5443"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %v, want %v", got, want)
	}
	if out := localAddressCandidates(addrs, ""); out != nil {
		t.Fatalf("plain-HTTP mode must report nothing, got %v", out)
	}
}

func cidr(t *testing.T, s string) net.Addr {
	t.Helper()
	ip, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	n.IP = ip
	return n
}

// The route needs a signed-in account (LAN topology stays off the open
// surface) and answers for ANY role: guests upload too.
func TestLocalAddressesRouteIsAuthenticated(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "GET", "/api/local-addresses", "", "")
	if rec.Code != 401 {
		t.Fatalf("unauthenticated = %d, want 401", rec.Code)
	}
	rec = doReq(t, h, "GET", "/api/local-addresses", testToken, "")
	if rec.Code != 200 {
		t.Fatalf("authenticated = %d body %s", rec.Code, rec.Body)
	}
	var out struct {
		Addresses []string `json:"addresses"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	// The shape is pinned; the contents depend on the handler's localPort
	// (empty via New, so the list is empty here) and the host's interfaces.
}
