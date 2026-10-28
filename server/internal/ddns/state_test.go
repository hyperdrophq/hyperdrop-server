package ddns

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func tempStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ddns")
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return s, path
}

func TestAnAbsentFileIsNotConfigured(t *testing.T) {
	s, _ := tempStore(t)
	if s.Configured() {
		t.Fatal("a server with no ddns file reports a name")
	}
	if got := s.Snapshot(); got.Name != "" || got.Token != "" {
		t.Fatalf("snapshot %+v, want zero", got)
	}
}

func TestSetPersistsAndReloads(t *testing.T) {
	s, path := tempStore(t)
	if err := s.Set("alice", "tok-123"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	again, err := Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := again.Snapshot(); got.Name != "alice" || got.Token != "tok-123" {
		t.Fatalf("reloaded %+v", got)
	}
	if !again.Configured() {
		t.Fatal("reloaded store reports no name")
	}
}

func TestPendingClaimTokenIsDurableButNotConfigured(t *testing.T) {
	s, path := tempStore(t)
	if err := s.BeginClaim("alice", "durable-token", "server-1"); err != nil {
		t.Fatal(err)
	}
	if s.Configured() {
		t.Fatal("pending claim reported configured")
	}
	again, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := again.Snapshot(); !got.Pending || got.Token != "durable-token" || got.ServerID != "server-1" {
		t.Fatalf("pending state = %+v", got)
	}
	if err := again.ConfirmClaim(); err != nil {
		t.Fatal(err)
	}
	if got := again.Snapshot(); got.Pending || got.ServerID != "" || !again.Configured() {
		t.Fatalf("confirmed state = %+v", got)
	}
}

// The file holds a bearer token that can move the name's address, so it is
// never group or world readable.
func TestTheFileIsOwnerReadableOnly(t *testing.T) {
	s, path := tempStore(t)
	if err := s.Set("alice", "tok-123"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode %o, want 600", perm)
	}
}

func TestRecordKeepsTheLastSuccessAndTheLastFailureApart(t *testing.T) {
	s, _ := tempStore(t)
	if err := s.Set("alice", "tok"); err != nil {
		t.Fatal(err)
	}
	if err := s.Record("203.0.113.7", "203.0.113.7", 1000, ""); err != nil {
		t.Fatal(err)
	}
	if got := s.Snapshot(); got.LastIP != "203.0.113.7" || got.LastProbe != "203.0.113.7" ||
		got.LastUpdate != 1000 || got.LastError != "" {
		t.Fatalf("after success: %+v", got)
	}
	// A failure records itself without disturbing the last success, which is
	// what the app's warning counts down from.
	if err := s.Record("", "", 2000, "the service is unreachable"); err != nil {
		t.Fatal(err)
	}
	got := s.Snapshot()
	if got.LastError != "the service is unreachable" {
		t.Fatalf("lastError %q", got.LastError)
	}
	if got.LastUpdate != 1000 || got.LastIP != "203.0.113.7" || got.LastProbe != "203.0.113.7" {
		t.Fatalf("a failure moved the last success: %+v", got)
	}
}

func TestASuccessClearsAnEarlierFailure(t *testing.T) {
	s, _ := tempStore(t)
	_ = s.Set("alice", "tok")
	_ = s.Record("", "", 1000, "boom")
	_ = s.Record("203.0.113.7", "203.0.113.7", 2000, "")
	if got := s.Snapshot(); got.LastError != "" {
		t.Fatalf("lastError %q, want cleared", got.LastError)
	}
}

func TestClearRemovesTheMachineConnection(t *testing.T) {
	s, path := tempStore(t)
	_ = s.Set("alice", "tok")
	if err := s.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if s.Configured() {
		t.Fatal("still configured after Clear")
	}
	reloaded, err := Load(path)
	if err != nil || reloaded.Snapshot().Name != "" || reloaded.Snapshot().Token != "" {
		t.Fatalf("connection was retained: %v", err)
	}
	// Clearing twice is not an error: the second call has nothing to do.
	if err := s.Clear(); err != nil {
		t.Fatalf("second Clear: %v", err)
	}
}

func TestFQDNComposesTheZone(t *testing.T) {
	if got := FQDN("alice"); got != "alice.hyperdrop.link" {
		t.Fatalf("FQDN = %q", got)
	}
}

// A state file that does not parse is set aside and the server starts with
// no free name rather than refusing to boot.
func TestAnUnreadableStateFileIsSetAside(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ddns")
	if err := os.WriteFile(path, []byte(`{"name":"alice","token":`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if st := s.Snapshot(); st.Name != "" || st.Token != "" {
		t.Fatalf("state = %+v, want none", st)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the unreadable file is still at %s: %v", path, err)
	}
	if b, err := os.ReadFile(path + ".corrupt"); err != nil || string(b) != `{"name":"alice","token":` {
		t.Fatalf("set-aside copy = %q, %v", b, err)
	}
}

// A network that blocks DNS to public resolvers is checked through the
// system's resolver, and one where no resolver answers is no DNS verdict at
// all, rather than a DNS fault that turns into an alert.
func TestProbeHostFallsBackAndNeverBlamesAnUnansweredLookup(t *testing.T) {
	saved := hostLookups
	t.Cleanup(func() { hostLookups = saved })
	blocked := func(context.Context, string) ([]netip.Addr, error) {
		return nil, &net.DNSError{Err: "i/o timeout", IsTimeout: true}
	}
	answer := func(addrs ...string) func(context.Context, string) ([]netip.Addr, error) {
		return func(context.Context, string) ([]netip.Addr, error) {
			var out []netip.Addr
			for _, a := range addrs {
				out = append(out, netip.MustParseAddr(a))
			}
			return out, nil
		}
	}
	noSuchName := func(context.Context, string) ([]netip.Addr, error) {
		return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
	}
	for name, tc := range map[string]struct {
		lookups []func(context.Context, string) ([]netip.Addr, error)
		want    string
	}{
		"the system resolver answers": {[]func(context.Context, string) ([]netip.Addr, error){blocked, blocked, answer("127.0.0.1")}, "current"},
		"a public resolver answers":   {[]func(context.Context, string) ([]netip.Addr, error){answer("127.0.0.1"), blocked, blocked}, "current"},
		"another address":             {[]func(context.Context, string) ([]netip.Addr, error){answer("192.0.2.1"), blocked, blocked}, "pending"},
		"no such name is an answer":   {[]func(context.Context, string) ([]netip.Addr, error){noSuchName, answer("127.0.0.1"), blocked}, "pending"},
		"nothing answers":             {[]func(context.Context, string) ([]netip.Addr, error){blocked, blocked, blocked}, "unknown"},
	} {
		hostLookups = tc.lookups
		got := probeHost(context.Background(), "share.example.com", "127.0.0.1", "", 0)
		if got.DNS != tc.want {
			t.Errorf("%s: DNS = %q, want %q", name, got.DNS, tc.want)
		}
	}

	s, err := Load(filepath.Join(t.TempDir(), "ddns"))
	if err != nil {
		t.Fatal(err)
	}
	u := NewUpdater(s, &Client{}, nil)
	u.ProbeHost = func(_ context.Context, host, _ string) HostStatus {
		return HostStatus{Host: host, DNS: "unknown", HTTPS: "valid"}
	}
	if err := u.verify(context.Background(), "203.0.113.7"); err != nil {
		t.Fatal(err)
	}
	if c := s.Snapshot().Connectivity; c.LastError != "" || c.Failures != 0 {
		t.Fatalf("an unanswered lookup counted as a failure: %+v", c)
	}
}

// An activity message is cut at a character boundary, and a one-nanosecond
// interval still jitters rather than panicking.
func TestActivityMessagesAreCutWholeAndTinyIntervalsJitter(t *testing.T) {
	var c Connectivity
	addEvent(&c, 1, "failure", strings.Repeat("a", 511)+"é tail")
	if m := c.Events[len(c.Events)-1].Message; !utf8.ValidString(m) || len(m) > 512 {
		t.Fatalf("message cut to %d bytes, valid %v", len(m), utf8.ValidString(m))
	}
	u := &Updater{Interval: 1}
	if d := u.jittered(); d < 1 {
		t.Fatalf("jittered = %v", d)
	}
}
