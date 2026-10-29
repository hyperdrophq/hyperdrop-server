package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"hyperdrop/server/internal/ddns"
	"hyperdrop/server/internal/domain"
)

type fakeNames struct {
	ports    ddns.PortsObservation
	portsErr error
	gotHost  string
}

func (f *fakeNames) PublicIPv4(context.Context) (string, error) { return "203.0.113.9", nil }
func (f *fakeNames) Ports(_ context.Context, host string) (ddns.PortsObservation, error) {
	f.gotHost = host
	return f.ports, f.portsErr
}

func TestProbeNetworkClassifiesPortsAgainstOwnServerID(t *testing.T) {
	dom, err := domain.Load(filepath.Join(t.TempDir(), "domain"), "")
	if err != nil {
		t.Fatal(err)
	}
	router := func(context.Context) (string, error) { return "203.0.113.9", nil }
	names := &fakeNames{ports: ddns.PortsObservation{
		HTTPS: ddns.PortObservation{Answer: "hyperdrop", ServerID: "me"},
		HTTP:  ddns.PortObservation{Answer: "hyperdrop", ServerID: "old-nas"},
	}}
	probeNetwork(context.Background(), router, names, "me", dom)
	if p, ok := dom.Ports(); !ok || p != (domain.Ports{HTTPS: "ok", HTTP: "taken"}) {
		t.Fatalf("Ports = %+v, %v", p, ok)
	}
	if dom.NAT() != "direct" {
		t.Fatalf("NAT = %q", dom.NAT())
	}

	// A failed check (an older registry, a timeout) is no information: the
	// last verdict stands.
	names.portsErr = errors.New("404")
	names.ports = ddns.PortsObservation{}
	probeNetwork(context.Background(), router, names, "me", dom)
	if p, _ := dom.Ports(); p != (domain.Ports{HTTPS: "ok", HTTP: "taken"}) {
		t.Fatalf("a failed check overwrote the verdict: %+v", p)
	}
}

// withDomain is a Manager already serving d, its lookup answering ips (or
// failing when ips is nil).
func withDomain(t *testing.T, d string, ips ...string) *domain.Manager {
	t.Helper()
	path := filepath.Join(t.TempDir(), "domain")
	if err := os.WriteFile(path, []byte(d+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dom, err := domain.Load(path, "")
	if err != nil {
		t.Fatal(err)
	}
	dom.Lookup = func(context.Context, string) ([]net.IP, error) {
		if ips == nil {
			return nil, errors.New("no such host")
		}
		var out []net.IP
		for _, ip := range ips {
			out = append(out, net.ParseIP(ip))
		}
		return out, nil
	}
	return dom
}

var closedBoth = ddns.PortsObservation{IP: "203.0.113.9",
	HTTPS: ddns.PortObservation{Answer: "none"}, HTTP: ddns.PortObservation{Answer: "none"}}

// The registry dials the address the check LEFT from. A custom domain that
// points there is served through these forwards, so the verdict stands.
func TestProbeNetworkCustomDomainPointingAtTheEgressIsJudged(t *testing.T) {
	dom := withDomain(t, "share.example.com", "203.0.113.9")
	router := func(context.Context) (string, error) { return "192.168.1.1", nil }
	probeNetwork(context.Background(), router, &fakeNames{ports: closedBoth}, "me", dom)
	if p, ok := dom.Ports(); !ok || p != (domain.Ports{HTTPS: "closed", HTTP: "closed"}) {
		t.Fatalf("Ports = %+v, %v", p, ok)
	}
}

// A custom domain that points elsewhere (a NAS egressing through a VPN, a
// homelab published through a VPS reverse proxy) is not served through the
// forwards the registry dialled: any verdict would be a false alarm, and a
// verdict left from before is no longer justified, so it is cleared. A
// failed lookup is no evidence either way: cleared too.
func TestProbeNetworkCustomDomainPointingElsewhereSaysNothing(t *testing.T) {
	for name, ips := range map[string][]string{"elsewhere": {"198.51.100.4"}, "lookup fails": nil} {
		dom := withDomain(t, "share.example.com", ips...)
		dom.SetPorts(domain.Ports{HTTPS: "closed", HTTP: "closed"})
		router := func(context.Context) (string, error) { return "192.168.1.1", nil }
		probeNetwork(context.Background(), router, &fakeNames{ports: closedBoth}, "me", dom)
		if p, ok := dom.Ports(); ok {
			t.Errorf("%s: Ports = %+v, want none recorded", name, p)
		}
	}
}

// The free name is kept on this server's egress address by its own
// heartbeat, so it is judged without a lookup (which may still be cached at
// an old address).
func TestProbeNetworkManagedNameIsJudgedWithoutALookup(t *testing.T) {
	dom := withDomain(t, "nas.hyperdrop.link", "198.51.100.4")
	router := func(context.Context) (string, error) { return "192.168.1.1", nil }
	probeNetwork(context.Background(), router, &fakeNames{ports: closedBoth}, "me", dom)
	if p, ok := dom.Ports(); !ok || p != (domain.Ports{HTTPS: "closed", HTTP: "closed"}) {
		t.Fatalf("Ports = %+v, %v", p, ok)
	}
}
