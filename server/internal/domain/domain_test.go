package domain

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestValid(t *testing.T) {
	good := []string{"share.example.com", "example.co.uk", "xn--bcher-kva.example",
		"a.b.c.example.com", "1share.example.com"}
	for _, d := range good {
		if !Valid(d) {
			t.Errorf("Valid(%q) = false, want true", d)
		}
	}
	long := "a"
	for len(long) < 64 {
		long += "a"
	}
	bad := []string{"", "example", ".example.com", "example.com.", "example..com",
		"203.0.113.7", "-bad.example.com", "bad-.example.com", "un_der.example.com",
		long + ".example.com", "share.example.com:443", "http://share.example.com"}
	for _, d := range bad {
		if Valid(d) {
			t.Errorf("Valid(%q) = true, want false", d)
		}
	}
}

func lookupReturning(ips ...string) func(context.Context, string) ([]net.IP, error) {
	return func(context.Context, string) ([]net.IP, error) {
		var out []net.IP
		for _, s := range ips {
			out = append(out, net.ParseIP(s))
		}
		return out, nil
	}
}

func newTestManager(t *testing.T, ip string) (*Manager, *[]string) {
	t.Helper()
	managed := &[]string{}
	m, err := Load(filepath.Join(t.TempDir(), "domain"), ip)
	if err != nil {
		t.Fatal(err)
	}
	m.Lookup = lookupReturning(ip)
	m.Manage = func(d string) error { *managed = append(*managed, d); return nil }
	return m, managed
}

func TestLoadMissingFile(t *testing.T) {
	m, err := Load(filepath.Join(t.TempDir(), "domain"), "203.0.113.7")
	if err != nil || m.Current() != "" {
		t.Fatalf("Load missing: err=%v current=%q", err, m.Current())
	}
}

func TestLoadExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domain")
	os.WriteFile(path, []byte("share.example.com\n"), 0o600)
	m, err := Load(path, "203.0.113.7")
	if err != nil || m.Current() != "share.example.com" {
		t.Fatalf("Load existing: err=%v current=%q", err, m.Current())
	}
}

func TestSetPersistsAndManages(t *testing.T) {
	m, managed := newTestManager(t, "203.0.113.7")
	if err := m.Set(context.Background(), "Share.Example.com."); err != nil {
		t.Fatal(err)
	}
	if m.Current() != "share.example.com" {
		t.Fatalf("current = %q, want normalized share.example.com", m.Current())
	}
	data, err := os.ReadFile(m.Path)
	if err != nil || string(data) != "share.example.com\n" {
		t.Fatalf("persisted %q err=%v", data, err)
	}
	if len(*managed) != 1 || (*managed)[0] != "share.example.com" {
		t.Fatalf("managed = %v", *managed)
	}
	// Idempotent re-set.
	if err := m.Set(context.Background(), "share.example.com"); err != nil {
		t.Fatal(err)
	}
}

func TestSetRejectsBadDomain(t *testing.T) {
	m, _ := newTestManager(t, "203.0.113.7")
	if err := m.Set(context.Background(), "not_a_domain"); !errors.Is(err, ErrBadDomain) {
		t.Fatalf("err = %v, want ErrBadDomain", err)
	}
}

func TestSetRequiresPublicIP(t *testing.T) {
	m, _ := newTestManager(t, "")
	if err := m.Set(context.Background(), "share.example.com"); !errors.Is(err, ErrNoTLS) {
		t.Fatalf("err = %v, want ErrNoTLS", err)
	}
}

func TestSetChecksDNSPointsHere(t *testing.T) {
	m, _ := newTestManager(t, "203.0.113.7")
	m.Lookup = lookupReturning("198.51.100.1")
	err := m.Set(context.Background(), "share.example.com")
	var np *ErrNotPointing
	if !errors.As(err, &np) {
		t.Fatalf("err = %v, want ErrNotPointing", err)
	}
	if np.Domain != "share.example.com" || np.IP != "203.0.113.7" {
		t.Fatalf("ErrNotPointing = %+v", np)
	}
	if m.Current() != "" {
		t.Fatalf("failed Set must not record a domain, got %q", m.Current())
	}
}

func TestSetAcceptsMultipleARecordsContainingIP(t *testing.T) {
	m, _ := newTestManager(t, "203.0.113.7")
	m.Lookup = lookupReturning("198.51.100.1", "203.0.113.7")
	if err := m.Set(context.Background(), "share.example.com"); err != nil {
		t.Fatal(err)
	}
}

func TestSetLookupError(t *testing.T) {
	m, _ := newTestManager(t, "203.0.113.7")
	m.Lookup = func(context.Context, string) ([]net.IP, error) {
		return nil, errors.New("SERVFAIL")
	}
	err := m.Set(context.Background(), "share.example.com")
	var np *ErrNotPointing
	if !errors.As(err, &np) {
		t.Fatalf("lookup failure should read as not-pointing, got %v", err)
	}
}

func TestManageErrorLeavesStateUnset(t *testing.T) {
	m, _ := newTestManager(t, "203.0.113.7")
	m.Manage = func(string) error { return errors.New("acme down") }
	err := m.Set(context.Background(), "share.example.com")
	if err == nil {
		t.Fatal("want error from Manage")
	}
	// Error responses never hide a committed mutation.
	if m.Current() != "" {
		t.Fatalf("state must stay unset on Manage error, got %q", m.Current())
	}
	if _, err := os.Stat(m.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("domain file must not be written on Manage error, stat err=%v", err)
	}
}

func TestLoadSharesInvalidPersistedDomain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domain")
	os.WriteFile(path, []byte("not a domain!!\n"), 0o600)
	m, err := Load(path, "203.0.113.7")
	if err != nil || m.Current() != "" {
		t.Fatalf("invalid persisted domain must be dropped: err=%v current=%q", err, m.Current())
	}
}

func TestIsCurrent(t *testing.T) {
	m, _ := newTestManager(t, "203.0.113.7")
	if err := m.Set(context.Background(), "share.example.com"); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"share.example.com", "Share.Example.COM", "share.example.com."} {
		if !m.IsCurrent(host) {
			t.Errorf("IsCurrent(%q) = false, want true", host)
		}
	}
	for _, host := range []string{"other.example.com", "203.0.113.7", ""} {
		if m.IsCurrent(host) {
			t.Errorf("IsCurrent(%q) = true, want false", host)
		}
	}
}

// Adopt must NOT require the record to point here yet: its callers vouch for
// the domain themselves, and a server that must serve a domain before its
// record can be pointed at it would otherwise deadlock on "does not point at
// this server yet".
func TestAdoptSkipsThePointsHereCheck(t *testing.T) {
	m, managed := newTestManager(t, "203.0.113.7")
	// Resolves somewhere else entirely.
	m.Lookup = lookupReturning("198.51.100.1")

	if err := m.Set(context.Background(), "share.example.com"); err == nil {
		t.Fatal("Set accepted a domain pointing elsewhere: its check is the reason Adopt exists")
	}
	if err := m.Adopt("share.example.com"); err != nil {
		t.Fatalf("Adopt refused a handover: %v", err)
	}
	if m.Current() != "share.example.com" {
		t.Fatalf("Current() = %q after Adopt", m.Current())
	}
	if len(*managed) != 1 || (*managed)[0] != "share.example.com" {
		t.Fatalf("certificate not managed after Adopt: %v", *managed)
	}
}

// Behind NAT there IS no local public IP (the router holds it and forwards
// 80/443 here), yet HTTPS mode is exactly what is being configured. Adopt
// must work with an empty IP when the manager knows it is behind NAT (the
// Synology boot: HYPERDROP_BEHIND_NAT=1, found live on DSM 7.3 when boot
// died on ErrNoTLS), while a plain-HTTP manager keeps refusing.
func TestAdoptWorksBehindNATWithNoIP(t *testing.T) {
	m, managed := newTestManager(t, "")
	if err := m.Adopt("share.example.com"); !errors.Is(err, ErrNoTLS) {
		t.Fatalf("plain-HTTP adopt: err = %v, want ErrNoTLS", err)
	}
	m.BehindNAT = true
	if err := m.Adopt("share.example.com"); err != nil {
		t.Fatalf("behind-NAT adopt refused: %v", err)
	}
	if m.Current() != "share.example.com" {
		t.Fatalf("Current() = %q after behind-NAT adopt", m.Current())
	}
	if len(*managed) != 1 || (*managed)[0] != "share.example.com" {
		t.Fatalf("certificate not managed: %v", *managed)
	}
}

// It still refuses nonsense: skipping the DNS check is not skipping validation.
func TestAdoptStillValidates(t *testing.T) {
	m, _ := newTestManager(t, "203.0.113.7")
	for _, bad := range []string{"", "example", "203.0.113.7", "http://share.example.com"} {
		if err := m.Adopt(bad); err == nil {
			t.Fatalf("Adopt accepted %q", bad)
		}
	}
}

// The API can be constructed without a domain manager, and health asks every
// server for its domain.
// A nil Manager answers "no domain" rather than panicking mid-response.
func TestANilManagerHasNoDomain(t *testing.T) {
	var m *Manager
	if got := m.Current(); got != "" {
		t.Fatalf("Current() on a nil Manager = %q, want empty", got)
	}
	if m.IsCurrent("share.example.com") {
		t.Fatal("a nil Manager must not claim any host")
	}
}

func TestCertEventsFoldIntoStatus(t *testing.T) {
	m, err := Load(filepath.Join(t.TempDir(), "domain"), "")
	if err != nil {
		t.Fatal(err)
	}
	m.RecordCertEvent("cert_obtaining", map[string]any{"identifier": "share.example.com"})
	if got := m.CertStatus()["share.example.com"].State; got != "pending" {
		t.Fatalf("after obtaining: %q, want pending", got)
	}
	m.RecordCertEvent("cert_failed", map[string]any{
		"identifier": "share.example.com", "error": errors.New("acme: dial tcp: i/o timeout")})
	st := m.CertStatus()["share.example.com"]
	if st.State != "failed" || !strings.Contains(st.LastError, "timeout") || st.LastAttempt.IsZero() {
		t.Fatalf("after failure: %+v", st)
	}
	m.RecordCertEvent("cert_obtained", map[string]any{"identifier": "share.example.com"})
	if got := m.CertStatus()["share.example.com"].State; got != "issued" {
		t.Fatalf("after obtained: %q, want issued", got)
	}
	// A failure after issuance is a renewal failure: the served cert still
	// works, so the state stays issued and only the error is carried.
	m.RecordCertEvent("cert_failed", map[string]any{
		"identifier": "share.example.com", "error": errors.New("renewal refused")})
	st = m.CertStatus()["share.example.com"]
	if st.State != "issued" || st.LastError != "renewal refused" {
		t.Fatalf("renewal failure: %+v", st)
	}
	// A renewal starting must not un-issue the subject either.
	m.RecordCertEvent("cert_obtaining", map[string]any{"identifier": "share.example.com"})
	if got := m.CertStatus()["share.example.com"].State; got != "issued" {
		t.Fatalf("renewal start: %q, want issued", got)
	}
	// Certs loaded from storage at boot arrive as one event listing all SANs.
	m.RecordCertEvent("cached_managed_cert", map[string]any{
		"sans": []string{"a.example.com", "files.a.example.com"}})
	if got := m.CertStatus()["files.a.example.com"].State; got != "issued" {
		t.Fatalf("cached cert: %q, want issued", got)
	}
	m.RecordCertEvent("tls_get_certificate", map[string]any{"identifier": "x"})
	if _, ok := m.CertStatus()["x"]; ok {
		t.Fatal("unrelated events must not create entries")
	}
	m.RecordCertEvent("cert_obtained", map[string]any{})
	var nilM *Manager
	nilM.RecordCertEvent("cert_obtained", map[string]any{"identifier": "y"})
	if nilM.CertStatus() != nil {
		t.Fatal("nil manager must answer nil")
	}
}

func TestAnIssuedCertificateReprobesTheNetwork(t *testing.T) {
	m := &Manager{}
	fired := make(chan struct{}, 4)
	m.ReprobeNAT = func() { fired <- struct{}{} }
	m.RecordCertEvent("cert_obtaining", map[string]any{"identifier": "203.0.113.9"})
	m.RecordCertEvent("cert_failed", map[string]any{"identifier": "203.0.113.9", "error": "nope"})
	select {
	case <-fired:
		t.Fatal("only an issued certificate is news for the port check")
	case <-time.After(50 * time.Millisecond):
	}
	m.RecordCertEvent("cert_obtained", map[string]any{"identifier": "203.0.113.9"})
	select {
	case <-fired:
	case <-time.After(2 * time.Second):
		t.Fatal("an issued certificate did not re-run the port check")
	}
}

func TestCheckPointsHereNormalizesAsSetDoes(t *testing.T) {
	m, _ := newTestManager(t, "203.0.113.7")
	var asked string
	m.Lookup = func(_ context.Context, host string) ([]net.IP, error) {
		asked = host
		return []net.IP{net.ParseIP("203.0.113.7")}, nil
	}
	if err := m.CheckPointsHere(context.Background(), "Share.Example.com."); err != nil {
		t.Fatalf("CheckPointsHere = %v", err)
	}
	if asked != "share.example.com" {
		t.Fatalf("looked up %q, want share.example.com", asked)
	}
	if err := m.CheckPointsHere(context.Background(), "not a domain"); !errors.Is(err, ErrBadDomain) {
		t.Fatalf("invalid name = %v, want ErrBadDomain", err)
	}
	if m.Current() != "" {
		t.Fatalf("CheckPointsHere applied %q", m.Current())
	}
}

type moveRecorder struct{ moves [][2]string }

func (r *moveRecorder) moved(from, to string) { r.moves = append(r.moves, [2]string{from, to}) }

func TestEveryCommittedDomainChangeIsRecorded(t *testing.T) {
	m, _ := newTestManager(t, "203.0.113.7")
	var r moveRecorder
	m.Moved = r.moved
	if err := m.Set(context.Background(), "a.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := m.Set(context.Background(), "b.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := m.Adopt("c.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := m.Adopt("c.example.com"); err != nil {
		t.Fatal(err)
	}
	want := [][2]string{{"", "a.example.com"}, {"a.example.com", "b.example.com"}, {"b.example.com", "c.example.com"}}
	if !reflect.DeepEqual(r.moves, want) {
		t.Fatalf("Moved saw %v, want %v", r.moves, want)
	}
}

func TestLoadingTheStoredDomainRecordsNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domain")
	if err := os.WriteFile(path, []byte("share.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := Load(path, "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	var r moveRecorder
	m.Moved = r.moved
	if m.Current() != "share.example.com" || len(r.moves) != 0 {
		t.Fatalf("current %q, moves %v", m.Current(), r.moves)
	}
}
