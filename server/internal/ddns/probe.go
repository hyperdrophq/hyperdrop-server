package ddns

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// Probing a host: the DNS and HTTPS checks a connectivity reading is made of.

// probe checks host at ip, pinned to the leaf this process serves for it,
// and reports whether a pin applied. withDNS selects the full probeHost;
// without it only HTTPS at the address is checked, which is what a check
// before the records move can ask. A certificate renewed while the probe
// ran is read again once, so this server's fresh leaf is never taken for
// another server's.
func (u *Updater) probe(ctx context.Context, host, ip string, withDNS bool, now int64) (HostStatus, bool) {
	run := func(pin []byte) HostStatus {
		switch {
		case u.ProbeHost != nil:
			return u.ProbeHost(ctx, host, ip, pin)
		case withDNS:
			return probeHost(ctx, host, ip, u.serverID(), pin, now)
		}
		out := HostStatus{Host: host, DNS: "unknown", CheckedAt: now}
		out.HTTPS, out.ExpiresAt, out.ForeignLeaf = probeHTTPS(ctx, host, ip, u.serverID(), pin)
		return out
	}
	pin := u.pinFor(host)
	h := run(pin)
	if pin != nil && h.ForeignLeaf {
		if fresh := u.pinFor(host); fresh != nil && !bytes.Equal(fresh, pin) {
			pin = fresh
			h = run(pin)
		}
	}
	return h, pin != nil
}

// addressAnswersElsewhere reports whether a pinned probe of either host at
// ip reaches a server presenting a certificate other than this server's.
// An address where nothing answers, where no pin applies, or where this
// server's own certificate answers without a healthy /api/health, is not
// one.
func (u *Updater) addressAnswersElsewhere(ctx context.Context, ip string) bool {
	now := u.Now().Unix()
	for _, host := range u.hostNames() {
		if h, pinned := u.probe(ctx, host, ip, false, now); pinned && h.ForeignLeaf {
			return true
		}
	}
	return false
}

// addressProvesItself reports whether both hosts answer at ip with this
// server's own certificate.
func (u *Updater) addressProvesItself(ctx context.Context, ip string) bool {
	now := u.Now().Unix()
	hosts := u.hostNames()
	for _, host := range hosts {
		if h, pinned := u.probe(ctx, host, ip, false, now); !pinned || h.HTTPS != "valid" {
			return false
		}
	}
	return len(hosts) > 0
}

// check probes both hosts at ip and records what it found. foreign reports
// a pinned probe that was presented another server's leaf; this server's
// own leaf in front of a failing /api/health is a host not healthy yet,
// which the tick retries. Both hosts valid under a pin
// record ip as the last verified address and end the strict state that a
// refusal or a rollback began.
func (u *Updater) check(ctx context.Context, ip string) (hosts []HostStatus, foreign bool, err error) {
	names := u.hostNames()
	if names == nil {
		return nil, false, nil
	}
	now := u.Now().Unix()
	proven := true
	for _, host := range names {
		h, pinned := u.probe(ctx, host, ip, true, now)
		hosts = append(hosts, h)
		if pinned && h.ForeignLeaf {
			foreign = true
		}
		if !pinned || h.HTTPS != "valid" {
			proven = false
		}
	}
	before := u.store.Snapshot().Connectivity.Hosts
	if err := u.store.change(func(s *State) {
		s.Connectivity.Hosts = hosts
		for i, h := range hosts {
			if i >= len(before) || h.DNS != before[i].DNS || h.HTTPS != before[i].HTTPS {
				addEvent(&s.Connectivity, now, "verification", h.Host+": DNS "+h.DNS+", HTTPS "+h.HTTPS)
			}
		}
		if proven && s.Custom != nil {
			s.VerifiedIP = ip
			s.AddressRefusedAt = 0
		}
	}); err != nil {
		return nil, false, err
	}
	return hosts, foreign, nil
}

// judge turns a check's hosts into the tick's outcome.
func (u *Updater) judge(ctx context.Context, hosts []HostStatus) error {
	if hosts == nil {
		return nil
	}
	now := u.Now().Unix()
	for _, h := range hosts {
		if h.IPv6Present {
			return u.failure(ctx, "AAAA records are present; IPv6 reachability is not verified", now+300, false)
		}
		if h.DNS != "current" && h.DNS != "unknown" {
			return u.failure(ctx, h.Host+": DNS has not reached the observed IPv4", now+300, false)
		}
		if h.HTTPS != "valid" {
			return u.failure(ctx, h.Host+": HTTPS "+h.HTTPS, now+300, false)
		}
		if h.ExpiresAt > 0 && h.ExpiresAt-now < 24*3600 {
			return u.failure(ctx, h.Host+": certificate expires within 24 hours", now+300, true)
		}
	}
	if c := u.store.Snapshot().Custom; c != nil && c.CredentialExpiresAt > 0 && c.CredentialExpiresAt-now < 7*24*3600 {
		return u.failure(ctx, "DDNS credentials expire within 7 days", now+300, true)
	}
	return u.healthy(ctx)
}

// hostLookups are the resolvers probeHost asks, in order, until one answers
// (an address list or a definite "no such name"): two public resolvers, so
// the verdict is what the internet sees rather than a local override, then
// the system's own, for a network that blocks DNS to public resolvers.
var hostLookups = []func(context.Context, string) ([]netip.Addr, error){
	publicLookup("1.1.1.1:53"),
	publicLookup("8.8.8.8:53"),
	func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	},
}

func publicLookup(resolverIP string) func(context.Context, string) ([]netip.Addr, error) {
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, resolverIP)
	}}
	return func(ctx context.Context, host string) ([]netip.Addr, error) {
		return resolver.LookupNetIP(ctx, "ip", host)
	}
}

// probeRoots and probeAddress are the probe's seams for tests: a nil pool
// is the system's roots, and the address dialled for ip is its port 443.
var (
	probeRoots   *x509.CertPool
	probeAddress = func(ip string) string { return net.JoinHostPort(ip, "443") }
)

// This is explicitly a check FROM THE SERVER. It does not claim to prove
// inbound internet reachability through a home router's NAT. A non-nil pin
// is the leaf certificate this server serves for host: HTTPS is "valid"
// only when the address presents that very leaf, and
// "server-identity-mismatch" when it presents another, however trusted.
func probeHost(ctx context.Context, host, ip, serverID string, pin []byte, now int64) HostStatus {
	out := HostStatus{Host: host, DNS: "unknown", HTTPS: "unchecked", CheckedAt: now}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	var addresses []netip.Addr
	answered := false
	for _, lookup := range hostLookups {
		lookupCtx, stop := context.WithTimeout(ctx, 3*time.Second)
		got, err := lookup(lookupCtx, host)
		stop()
		var dnsErr *net.DNSError
		if err == nil || errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			addresses, answered = got, true
			break
		}
	}
	// No resolver answered at all: that says nothing about the records, so
	// DNS stays "unknown" (which verify never counts as a DNS fault) and
	// HTTPS, which dials the address itself, is still checked.
	if answered {
		matched := false
		conflict := false
		for _, a := range addresses {
			out.Addresses = append(out.Addresses, a.String())
			if a.Is6() {
				out.IPv6Present = true
			} else if a.String() == ip {
				matched = true
			} else {
				conflict = true
			}
		}
		if !matched || conflict {
			out.DNS = "pending"
			return out
		}
		out.DNS = "current"
	}
	out.HTTPS, out.ExpiresAt, out.ForeignLeaf = probeHTTPS(ctx, host, ip, serverID, pin)
	return out
}

// probeHTTPS is probeHost's HTTPS half: it dials ip itself, whatever DNS
// says, and answers the HTTPS verdict, the presented leaf's expiry and
// whether a pin was given and the leaf presented is another (foreign). With
// the pinned leaf presented, a /api/health that is not a 200 or does not
// decode is "unreachable-or-untrusted": this server, not answering yet.
func probeHTTPS(ctx context.Context, host, ip, serverID string, pin []byte) (status string, expiresAt int64, foreign bool) {
	tr := &http.Transport{TLSClientConfig: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, RootCAs: probeRoots}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, probeAddress(ip))
	}}
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://"+host+"/api/health", nil)
	res, err := hc.Do(req)
	if err != nil {
		return "unreachable-or-untrusted", 0, false
	}
	defer res.Body.Close()
	if res.TLS == nil || len(res.TLS.PeerCertificates) == 0 {
		return "untrusted", 0, false
	}
	leaf := res.TLS.PeerCertificates[0]
	if pin != nil && !bytes.Equal(leaf.Raw, pin) {
		return "server-identity-mismatch", 0, true
	}
	var health struct {
		ServerID string `json:"serverID"`
	}
	healthy := res.StatusCode == 200 && json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&health) == nil
	switch {
	case !healthy && pin != nil:
		return "unreachable-or-untrusted", leaf.NotAfter.Unix(), false
	case !healthy, serverID != "" && health.ServerID != serverID:
		return "server-identity-mismatch", leaf.NotAfter.Unix(), false
	}
	return "valid", leaf.NotAfter.Unix(), false
}
