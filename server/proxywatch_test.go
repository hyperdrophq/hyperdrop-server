package main

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	proxyproto "github.com/pires/go-proxyproto"

	"hyperdrop/server/internal/api"
)

// testWatch answers a watch on a settable clock, with its log lines and
// change reports recorded.
func testWatch(t *testing.T) (w *proxyWatch, now *time.Time, logs *[]string, changes *int) {
	t.Helper()
	clock := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	now, logs, changes = &clock, new([]string), new(int)
	w = newProxyWatch(func([]ProxySource, int) { *changes++ })
	w.now = func() time.Time { return *now }
	w.logf = func(format string, args ...any) { *logs = append(*logs, fmt.Sprintf(format, args...)) }
	return w, now, logs, changes
}

func addrs(ps []ProxySource) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.Addr
	}
	return out
}

func TestProxyWatchNamesOnlyPrivateSources(t *testing.T) {
	w, _, _, _ := testWatch(t)
	for i := range 20 {
		w.Observe(netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}), proxyproto.ErrSuperfluousProxyHeader)
	}
	w.Observe(netip.MustParseAddr("10.20.30.40"), proxyproto.ErrSuperfluousProxyHeader)

	private, public := w.Snapshot()
	if public != 20 {
		t.Fatalf("publicCount = %d, want 20", public)
	}
	if len(private) != 1 || private[0].Addr != "10.20.30.40" || private[0].Kind != api.ProxyKindUntrustedHeader || private[0].Count != 1 {
		t.Fatalf("private = %+v, want only 10.20.30.40", private)
	}
	for _, p := range private {
		if strings.HasPrefix(p.Addr, "203.0.113.") {
			t.Fatalf("a public source is named: %+v", private)
		}
	}
}

func TestProxyWatchKeepsPrivateWhenFull(t *testing.T) {
	w, now, _, _ := testWatch(t)
	for i := range proxyWatchMax {
		*now = now.Add(time.Second)
		w.Observe(netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)}), proxyproto.ErrSuperfluousProxyHeader)
	}
	// 10.0.0.1 is seen again, so 10.0.0.2 becomes the least recently seen.
	*now = now.Add(time.Second)
	w.Observe(netip.MustParseAddr("10.0.0.1"), proxyproto.ErrSuperfluousProxyHeader)
	// A flood from the internet pushes nobody out.
	for i := range 100 {
		w.Observe(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), proxyproto.ErrSuperfluousProxyHeader)
	}
	private, public := w.Snapshot()
	if len(private) != proxyWatchMax || public != 100 {
		t.Fatalf("after the public flood: %d private, %d public; want %d and 100", len(private), public, proxyWatchMax)
	}
	// A new private source takes the least recently seen one's place.
	*now = now.Add(time.Second)
	w.Observe(netip.MustParseAddr("fd00::5"), proxyproto.ErrSuperfluousProxyHeader)
	private, _ = w.Snapshot()
	got := addrs(private)
	if len(got) != proxyWatchMax || slices.Contains(got, "10.0.0.2") || !slices.Contains(got, "fd00::5") || !slices.Contains(got, "10.0.0.1") {
		t.Fatalf("private = %v, want 10.0.0.2 evicted for fd00::5", got)
	}
	if got[0] != "fd00::5" {
		t.Fatalf("private = %v, want the most recently seen first", got)
	}
}

func TestProxyWatchClassifiesAddresses(t *testing.T) {
	w, _, _, _ := testWatch(t)
	for _, a := range []string{"::ffff:192.168.1.5", "127.0.0.1", "::1", "169.254.3.4", "fe80::1", "fd12::1", "172.17.0.2"} {
		w.Observe(netip.MustParseAddr(a), proxyproto.ErrSuperfluousProxyHeader)
	}
	for _, a := range []string{"8.8.8.8", "2001:db8::1", "::ffff:8.8.4.4", "100.64.0.1"} {
		w.Observe(netip.MustParseAddr(a), proxyproto.ErrSuperfluousProxyHeader)
	}
	private, public := w.Snapshot()
	got := addrs(private)
	slices.Sort(got)
	want := []string{"127.0.0.1", "169.254.3.4", "172.17.0.2", "192.168.1.5", "::1", "fd12::1", "fe80::1"}
	slices.Sort(want)
	if !slices.Equal(got, want) || public != 4 {
		t.Fatalf("private %v, public %d; want %v and 4", got, public, want)
	}
}

func TestProxyWatchKinds(t *testing.T) {
	w, _, _, _ := testWatch(t)
	w.Observe(netip.MustParseAddr("192.168.1.10"), proxyproto.ErrNoProxyProtocol)
	w.Observe(netip.MustParseAddr("192.168.1.11"), fmt.Errorf("wrapped: %w", proxyproto.ErrSuperfluousProxyHeader))
	w.Observe(netip.MustParseAddr("192.168.1.12"), proxyproto.ErrCantReadVersion1Header)
	w.Observe(netip.MustParseAddr("192.168.1.13"), nil)
	// A listed proxy with a public address that sends no header is not a
	// stranger's header: it is logged and never counted as one.
	w.Observe(netip.MustParseAddr("203.0.113.7"), proxyproto.ErrNoProxyProtocol)

	private, public := w.Snapshot()
	kinds := map[string]string{}
	for _, p := range private {
		kinds[p.Addr] = p.Kind
	}
	want := map[string]string{"192.168.1.10": api.ProxyKindTrustedNoHeader, "192.168.1.11": api.ProxyKindUntrustedHeader}
	if fmt.Sprint(kinds) != fmt.Sprint(want) || public != 0 {
		t.Fatalf("kinds %v, public %d; want %v and 0", kinds, public, want)
	}
}

func TestProxyWatchLogsOncePerSourcePerHour(t *testing.T) {
	w, now, logs, _ := testWatch(t)
	for range 50 {
		w.Observe(netip.MustParseAddr("10.20.30.40"), proxyproto.ErrSuperfluousProxyHeader)
		w.Observe(netip.MustParseAddr("203.0.113.9"), proxyproto.ErrSuperfluousProxyHeader)
	}
	if len(*logs) != 2 {
		t.Fatalf("%d log lines for two sources within an hour, want 2: %q", len(*logs), *logs)
	}
	// The log is the one place a public address is named.
	if !strings.Contains((*logs)[1], "203.0.113.9") || !strings.Contains((*logs)[0], "10.20.30.40") {
		t.Fatalf("log lines do not name their source: %q", *logs)
	}
	*now = now.Add(59 * time.Minute)
	w.Observe(netip.MustParseAddr("10.20.30.40"), proxyproto.ErrSuperfluousProxyHeader)
	if len(*logs) != 2 {
		t.Fatalf("logged again within the hour: %q", *logs)
	}
	*now = now.Add(2 * time.Minute)
	w.Observe(netip.MustParseAddr("10.20.30.40"), proxyproto.ErrSuperfluousProxyHeader)
	if len(*logs) != 3 {
		t.Fatalf("not logged again after the hour: %q", *logs)
	}
	// The record of what was logged stays bounded under a flood.
	for i := range 1000 {
		w.Observe(netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)}), proxyproto.ErrSuperfluousProxyHeader)
	}
	if n := len(w.logged); n > proxyLogMax {
		t.Fatalf("the last-logged map holds %d sources, bound %d", n, proxyLogMax)
	}
}

func TestProxyWatchReportsChangesNotEveryConnection(t *testing.T) {
	w, now, _, changes := testWatch(t)
	w.Observe(netip.MustParseAddr("10.20.30.40"), proxyproto.ErrSuperfluousProxyHeader)
	if *changes != 1 {
		t.Fatalf("a new source made %d reports, want 1", *changes)
	}
	for range 100 {
		w.Observe(netip.MustParseAddr("10.20.30.40"), proxyproto.ErrSuperfluousProxyHeader)
	}
	if *changes != 1 {
		t.Fatalf("repeat connections made %d reports, want 1", *changes)
	}
	// The public count is reported when it reaches proxyPublicMin.
	for range proxyPublicMin {
		w.Observe(netip.MustParseAddr("203.0.113.9"), proxyproto.ErrSuperfluousProxyHeader)
	}
	if *changes != 2 {
		t.Fatalf("the public count made %d reports, want 2", *changes)
	}
	for range 100 - proxyPublicMin {
		w.Observe(netip.MustParseAddr("203.0.113.9"), proxyproto.ErrSuperfluousProxyHeader)
	}
	if *changes != 2 {
		t.Fatalf("counts reported per connection: %d reports", *changes)
	}
	// The minute tick reports the counts once, then nothing while idle.
	*now = now.Add(time.Minute)
	w.Tick()
	w.Tick()
	if *changes != 3 {
		t.Fatalf("ticks made %d reports, want 3", *changes)
	}
	private, public := w.Snapshot()
	if private[0].Count != 101 || public != 100 {
		t.Fatalf("counts %d and %d, want 101 and 100", private[0].Count, public)
	}
}

// One or two stray public headers report nothing; three within an hour do,
// until an hour passes with none.
func TestProxyWatchCountsPublicHeadersOverAnHour(t *testing.T) {
	w, now, _, changes := testWatch(t)
	stray := func() { w.Observe(netip.MustParseAddr("198.51.100.4"), proxyproto.ErrSuperfluousProxyHeader) }
	stray()
	*now = now.Add(20 * time.Minute)
	stray()
	if _, public := w.Snapshot(); public != 0 || *changes != 0 {
		t.Fatalf("two public headers: count %d, %d reports; want none", public, *changes)
	}
	*now = now.Add(20 * time.Minute)
	stray()
	if _, public := w.Snapshot(); public != 3 || *changes != 1 {
		t.Fatalf("three public headers within an hour: count %d, %d reports; want 3 and 1", public, *changes)
	}
	// The first has left the window: two remain, which report nothing.
	*now = now.Add(21 * time.Minute)
	w.Tick()
	if _, public := w.Snapshot(); public != 0 || *changes != 2 {
		t.Fatalf("two left in the window: count %d, %d reports; want 0 and 2", public, *changes)
	}
	// Three spread over more than an hour never report.
	w2, now2, _, changes2 := testWatch(t)
	for range 3 {
		w2.Observe(netip.MustParseAddr("198.51.100.4"), proxyproto.ErrSuperfluousProxyHeader)
		*now2 = now2.Add(31 * time.Minute)
		w2.Tick()
	}
	if _, public := w2.Snapshot(); public != 0 || *changes2 != 0 {
		t.Fatalf("three headers over 93 minutes: count %d, %d reports", public, *changes2)
	}
}

func TestProxyWatchForgetsSilentSources(t *testing.T) {
	w, now, _, changes := testWatch(t)
	w.Observe(netip.MustParseAddr("10.20.30.40"), proxyproto.ErrSuperfluousProxyHeader)
	for range proxyPublicMin {
		w.Observe(netip.MustParseAddr("203.0.113.9"), proxyproto.ErrSuperfluousProxyHeader)
	}
	*now = now.Add(proxyWatchForget - time.Minute)
	w.Observe(netip.MustParseAddr("10.20.30.41"), proxyproto.ErrSuperfluousProxyHeader)
	before := *changes
	*now = now.Add(2 * time.Minute)
	w.Tick()
	private, public := w.Snapshot()
	if got := addrs(private); !slices.Equal(got, []string{"10.20.30.41"}) || public != 0 {
		t.Fatalf("after a silent day: private %v, public %d; want only 10.20.30.41", got, public)
	}
	if *changes != before+1 {
		t.Fatalf("forgetting made %d reports, want 1", *changes-before)
	}
}

// The status file is written outside the watch's lock, newest state last.
func TestProxyWatchReportsOutsideItsLockInOrder(t *testing.T) {
	var w *proxyWatch
	var got []int
	w = newProxyWatch(func(private []ProxySource, _ int) {
		w.Snapshot() // deadlocks if called under the watch's lock
		got = append(got, len(private))
	})
	w.logf = func(string, ...any) {}
	done := make(chan struct{})
	go func() {
		w.Observe(netip.MustParseAddr("192.168.1.1"), proxyproto.ErrSuperfluousProxyHeader)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the report ran under the watch's lock")
	}
	w.deliver(proxyReport{seq: 3, private: make([]ProxySource, 3)})
	w.deliver(proxyReport{seq: 2, private: make([]ProxySource, 2)})
	if !slices.Equal(got, []int{1, 3}) {
		t.Fatalf("delivered %v, want [1 3]: an older snapshot was written after a newer one", got)
	}
}

func TestProxyWatchIsNilSafe(t *testing.T) {
	var w *proxyWatch
	w.Observe(netip.MustParseAddr("192.168.1.1"), proxyproto.ErrSuperfluousProxyHeader)
	w.Tick()
	if p, n := w.Snapshot(); p != nil || n != 0 {
		t.Fatal("a nil watch reported sources")
	}
}
