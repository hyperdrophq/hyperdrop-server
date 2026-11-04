// Package domain owns the server's optional custom domain: syntax
// validation, the "does this domain actually point at me" pre-check (which
// also protects Let's Encrypt's failed-issuance rate limit), persistence in
// the data directory, and the hookup that puts the domain under certificate
// management. The domain lives in <dataDir>/domain so it survives container
// redeploys and server updates.
package domain

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	ErrNoTLS     = errors.New("server has no public IP: a domain needs the HTTPS (public IPv4) mode")
	ErrBadDomain = errors.New("invalid domain")
)

// ErrNotPointing: the domain's A records don't (yet) include the server's
// public IP: DNS not created or not propagated.
type ErrNotPointing struct {
	Domain, IP string
	Got        []string
}

func (e *ErrNotPointing) Error() string {
	got := "no A records"
	if len(e.Got) > 0 {
		got = "resolves to " + strings.Join(e.Got, ", ")
	}
	return fmt.Sprintf("%s does not point at this server yet (%s, need %s): check the DNS record and allow time to propagate", e.Domain, got, e.IP)
}

// Manager is the domain state machine. Zero value is not usable: construct
// with Load.
type Manager struct {
	Path string // persistence file, <dataDir>/domain
	IP   string // server public IPv4; "" = plain-HTTP mode, domains refused
	// BehindNAT: HTTPS mode with no LOCAL public IP, so the router holds the
	// address and forwards 80/443 here (the Synology package). Adopt works
	// without an IP then; Set cannot (its points-here check needs a
	// reference address), so runtime domain changes go through adopt.
	BehindNAT bool
	// Lookup resolves A/AAAA records; nil uses net.DefaultResolver.
	Lookup func(ctx context.Context, host string) ([]net.IP, error)
	// Manage puts a domain under certificate management; nil = no-op.
	Manage func(domain string) error
	// ReprobeNAT re-runs the NAT classification and the port check; nil =
	// no probe available. Adopt and a freshly issued certificate fire it on
	// its own goroutine so a change re-checks the network it now serves.
	ReprobeNAT func()
	// Changed, when set, is told every domain Set or Adopt commits, while
	// the manager's lock is held, so it sees commits in order and must not
	// call back into the Manager.
	Changed func(domain string)
	// Moved, when set, is told every commit whose domain differs from the
	// current one, with the domain it leaves ("" when there was none), under
	// the same lock and after Changed. It must not call back into the
	// Manager. Loading the stored domain is not a commit.
	Moved func(from, to string)

	mu      sync.Mutex
	current string
	certs   map[string]CertState
	nat     string
	ports   *Ports
}

// CertState is one certificate subject's lifecycle as CertMagic reported it:
// pending (an attempt is running), issued, or failed with the CA's error.
type CertState struct {
	State       string    `json:"state"`
	LastError   string    `json:"lastError,omitempty"`
	LastAttempt time.Time `json:"lastAttempt"`
}

// RecordCertEvent folds one CertMagic event into the per-subject map. Only
// lifecycle events are recorded; a failure or a fresh attempt after issuance
// belongs to a RENEWAL, so the state stays issued (the certificate being
// served still works) and only the error is carried.
func (m *Manager) RecordCertEvent(event string, data map[string]any) {
	if m == nil {
		return
	}
	now := time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.certs == nil {
		m.certs = map[string]CertState{}
	}
	if event == "cached_managed_cert" {
		sans, _ := data["sans"].([]string)
		for _, s := range sans {
			m.certs[s] = CertState{State: "issued", LastAttempt: now}
		}
		return
	}
	subject, _ := data["identifier"].(string)
	if subject == "" {
		return
	}
	issued := m.certs[subject].State == "issued"
	switch event {
	case "cert_obtaining":
		if issued {
			return
		}
		m.certs[subject] = CertState{State: "pending", LastAttempt: now}
	case "cert_obtained":
		m.certs[subject] = CertState{State: "issued", LastAttempt: now}
		// A port check's 443 dial reads "unknown" until a certificate
		// serves, so a fresh one is news for it. Async: it takes m.mu.
		if m.ReprobeNAT != nil {
			go m.ReprobeNAT()
		}
	case "cert_failed":
		msg := ""
		switch e := data["error"].(type) {
		case error:
			msg = e.Error()
		case string:
			msg = e
		}
		st := CertState{State: "failed", LastError: msg, LastAttempt: now}
		if issued {
			st.State = "issued"
		}
		m.certs[subject] = st
	}
}

// CertStatus is a copy of the per-subject certificate map; nil when nothing
// was recorded (or on a nil Manager).
func (m *Manager) CertStatus() map[string]CertState {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.certs) == 0 {
		return nil
	}
	out := make(map[string]CertState, len(m.certs))
	maps.Copy(out, m.certs)
	return out
}

// Load reads the persisted domain (missing file = none configured). An
// invalid persisted value is dropped, not fatal: a corrupted file in the
// data volume must never crash-loop the whole share server at boot.
func Load(path, ip string) (*Manager, error) {
	m := &Manager{Path: path, IP: ip}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	if d := strings.TrimSpace(string(data)); Valid(d) {
		m.current = d
	}
	return m, nil
}

// IsCurrent reports whether a request Host names the configured domain.
// Host comparison is case-insensitive and ignores a trailing dot (both
// legal spellings of the same name); ports are the caller's business.
func (m *Manager) IsCurrent(host string) bool {
	d := m.Current()
	return d != "" && strings.EqualFold(strings.TrimSuffix(host, "."), d)
}

// Current is the domain this server serves, empty when it has none.
//
// A nil Manager answers "" rather than panicking: the API can be constructed
// without one, and "no domain" is the honest answer for a server that has no
// domain manager at all.
func (m *Manager) Current() string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.current
}

// Identity is the name this server is known by in public: its domain, else
// its public IP, else "" (plain-HTTP LAN mode, where it has no canonical
// identity). A nil Manager answers "", like Current.
func (m *Manager) Identity() string {
	if d := m.Current(); d != "" || m == nil {
		return d
	}
	return m.IP
}

// Set runs the full pipeline: normalize → validate → DNS pre-check →
// manage certificate → persist. An error at ANY stage leaves the
// configured state unchanged (an error response never hides a committed
// mutation); a synchronous Manage failure with a fsync'd file would be the
// worse inconsistency, so persistence comes last: if the write itself
// fails, the extra managed cert is inert and vanishes on restart.
func (m *Manager) Set(ctx context.Context, d string) error {
	d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
	if !Valid(d) {
		return fmt.Errorf("%w: %q", ErrBadDomain, d)
	}
	if m.IP == "" {
		return ErrNoTLS
	}
	if err := m.checkPointsHere(ctx, d); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.commitLocked(d)
}

// CheckPointsHere runs Set's validation and points-here check on d, as Set
// normalizes it, without applying anything.
func (m *Manager) CheckPointsHere(ctx context.Context, d string) error {
	d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
	if !Valid(d) {
		return fmt.Errorf("%w: %q", ErrBadDomain, d)
	}
	if m.IP == "" {
		return ErrNoTLS
	}
	return m.checkPointsHere(ctx, d)
}

// Adopt configures the domain WITHOUT the points-here pre-check, for a domain
// the operator has already vouched for: the boot domain from the environment
// and a free name whose registration the names service just confirmed.
//
// Set's check exists so nobody can claim a domain they do not control. Those
// two callers control it by construction, and requiring the record to point
// here first would be a deadlock for a server that must serve the domain
// before its DNS can be pointed at it.
func (m *Manager) Adopt(d string) error {
	d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
	if !Valid(d) {
		return fmt.Errorf("%w: %q", ErrBadDomain, d)
	}
	// Behind NAT there is no LOCAL public IP to hold, but HTTPS mode is on
	// and ACME arbitrates reachability, so a missing IP is no ground for
	// refusal: the Synology package boots exactly this way.
	if m.IP == "" && !m.BehindNAT {
		return ErrNoTLS
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.commitLocked(d); err != nil {
		return err
	}
	if m.ReprobeNAT != nil {
		go m.ReprobeNAT()
	}
	return nil
}

// commitLocked hands d to certificate management, persists it and makes it
// the current domain, stopping at the first failure so an error leaves the
// configured domain unchanged. The caller holds m.mu.
func (m *Manager) commitLocked(d string) error {
	if m.Manage != nil {
		if err := m.Manage(d); err != nil {
			return fmt.Errorf("certificate management for %s: %w", d, err)
		}
	}
	if err := os.WriteFile(m.Path, []byte(d+"\n"), 0o600); err != nil {
		return err
	}
	from := m.current
	m.current = d
	if m.Changed != nil {
		m.Changed(d)
	}
	if m.Moved != nil && from != d {
		m.Moved(from, d)
	}
	return nil
}

// SetNAT records the probe's verdict; NAT reads it ("" = never probed).
func (m *Manager) SetNAT(v string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nat = v
}

// Ports is the names service's dial back to this server's public address:
// one netprobe.PortVerdict per port.
type Ports struct {
	HTTPS string `json:"https"`
	HTTP  string `json:"http"`
}

// SetPorts records the port check's verdicts.
func (m *Manager) SetPorts(p Ports) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ports = &p
}

// ClearPorts forgets the port verdict: a check that cannot speak for how
// visitors reach this server must not leave an older verdict standing.
func (m *Manager) ClearPorts() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ports = nil
}

// Ports answers the last verdict; false = never probed.
func (m *Manager) Ports() (Ports, bool) {
	if m == nil {
		return Ports{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ports == nil {
		return Ports{}, false
	}
	return *m.ports, true
}

func (m *Manager) NAT() string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.nat
}

// resolve looks d up through Lookup (net.DefaultResolver when nil), bounded
// to 10 s.
func (m *Manager) resolve(ctx context.Context, d string) ([]net.IP, error) {
	lookup := m.Lookup
	if lookup == nil {
		lookup = func(ctx context.Context, host string) ([]net.IP, error) {
			addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			ips := make([]net.IP, 0, len(addrs))
			for _, a := range addrs {
				ips = append(ips, a.IP)
			}
			return ips, nil
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return lookup(ctx, d)
}

// PointsAt reports whether d resolves to ip; a failed lookup is false.
func (m *Manager) PointsAt(ctx context.Context, d, ip string) bool {
	if ip == "" {
		return false
	}
	ips, _ := m.resolve(ctx, d)
	for _, got := range ips {
		if got.String() == ip {
			return true
		}
	}
	return false
}

func (m *Manager) checkPointsHere(ctx context.Context, d string) error {
	ips, err := m.resolve(ctx, d)
	var got []string
	for _, ip := range ips {
		if ip.String() == m.IP {
			return nil
		}
		got = append(got, ip.String())
	}
	if err != nil {
		got = append(got, "lookup error: "+err.Error())
	}
	return &ErrNotPointing{Domain: d, IP: m.IP, Got: got}
}

// Valid reports whether d is a plausible FQDN we can put on a certificate:
// 2+ LDH labels, no port/scheme/IP-literal, ≤253 chars. Unicode names must
// arrive already punycoded (clients IDNA-encode).
func Valid(d string) bool {
	if len(d) == 0 || len(d) > 253 || net.ParseIP(d) != nil {
		return false
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			ok := c == '-' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')
			if !ok {
				return false
			}
		}
	}
	return true
}
