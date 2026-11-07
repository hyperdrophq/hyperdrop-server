package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testGuard is a guard on a reading the test sets.
func testGuard(perAddress int) (*LoadGuard, *MemoryReading) {
	reading := &MemoryReading{Used: 10, Limit: 100, Total: 1 << 30, Available: 900 << 20}
	g := NewLoadGuard(func() MemoryReading { return *reading })
	g.perAddress = perAddress
	g.alwaysServes = 0
	g.setLimit = func(int64) {}
	g.keepAlives = func(bool) {}
	return g, reading
}

func guardGet(g *LoadGuard, path, addr string) (*httptest.ResponseRecorder, bool) {
	served := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { served = true })
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.RemoteAddr = addr
	w := httptest.NewRecorder()
	g.Wrap(next).ServeHTTP(w, r)
	return w, served
}

func TestTheGuardStandsAsideWithMemoryToSpare(t *testing.T) {
	g, _ := testGuard(10)
	g.Tick()
	if w, served := guardGet(g, "/share/x", "203.0.113.5:1"); !served || w.Code != http.StatusOK {
		t.Fatalf("code %d, served %v", w.Code, served)
	}
}

func TestTheGuardRefusesPastEitherMemoryLine(t *testing.T) {
	for name, set := range map[string]func(*MemoryReading){
		"the Go runtime near its limit": func(m *MemoryReading) { m.Used = 91 },
		"the machine nearly out":        func(m *MemoryReading) { m.Available = 96 << 19 },
	} {
		t.Run(name, func(t *testing.T) {
			g, reading := testGuard(10)
			set(reading)
			g.Tick()
			w, served := guardGet(g, "/share/x", "203.0.113.5:1")
			if served {
				t.Fatal("the request reached the server")
			}
			if w.Code != http.StatusServiceUnavailable {
				t.Errorf("code %d", w.Code)
			}
			if got := w.Header().Get("Retry-After"); got != busyRetryAfter {
				t.Errorf("Retry-After %q", got)
			}
			if got := w.Header().Get("Connection"); got != "close" {
				t.Errorf("Connection %q: a refused connection must not stay held", got)
			}
		})
	}
}

// A guard that let go the moment it dipped below its line would flap on every
// request that crossed it.
func TestTheGuardLetsGoOnlyWellBelowItsLine(t *testing.T) {
	g, reading := testGuard(10)
	reading.Used = 91
	g.Tick()
	reading.Used = 88
	g.Tick()
	if _, served := guardGet(g, "/share/x", "203.0.113.5:1"); served {
		t.Fatal("let go just below the line")
	}
	reading.Used = 80
	g.Tick()
	if _, served := guardGet(g, "/share/x", "203.0.113.5:1"); !served {
		t.Fatal("still refusing well below the line")
	}
}

// An unknown reading must not read as a server out of memory: a system with no
// /proc reports zeroes.
func TestAnUnknownMemoryReadingRefusesNothing(t *testing.T) {
	g, reading := testGuard(10)
	*reading = MemoryReading{}
	g.Tick()
	if _, served := guardGet(g, "/share/x", "203.0.113.5:1"); !served {
		t.Fatal("refused on a reading of nothing")
	}
}

// The provisioner, the self-check and a certificate's challenge must reach the
// server whatever its load, or a busy server looks dead and loses its certificate.
func TestTheGuardNeverRefusesHealthOrACertificateChallenge(t *testing.T) {
	g, reading := testGuard(10)
	reading.Used = 95
	g.Tick()
	for _, path := range []string{"/api/health", "/.well-known/acme-challenge/token"} {
		if _, served := guardGet(g, path, "203.0.113.5:1"); !served {
			t.Errorf("%s was refused", path)
		}
	}
}

func TestAnAPIRefusalIsJSONAndAPageRefusalNamesNothing(t *testing.T) {
	g, reading := testGuard(10)
	reading.Used = 95
	g.Tick()
	api, _ := guardGet(g, "/api/shares", "203.0.113.5:1")
	var body struct{ Code, Error string }
	if err := json.Unmarshal(api.Body.Bytes(), &body); err != nil {
		t.Fatalf("%v: %s", err, api.Body)
	}
	if body.Code != "busy" || body.Error == "" {
		t.Errorf("answer %+v", body)
	}
	page, _ := guardGet(g, "/f/somefilekey", "203.0.113.5:1")
	if ct := page.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type %q", ct)
	}
	if !strings.Contains(page.Body.String(), "busy") {
		t.Errorf("the page does not say the server is busy: %s", page.Body)
	}
	if strings.Contains(page.Body.String(), "somefilekey") {
		t.Error("the page names what was asked for")
	}
	if page.Header().Get("Content-Security-Policy") == "" {
		t.Error("the page carries no CSP")
	}
}

// One address holding every goroutine it can open is what takes a small server down,
// whichever route it asks for.
func TestOneAddressHoldsOnlySoManyRequests(t *testing.T) {
	g, _ := testGuard(2)
	release := make(chan struct{})
	var entered, finished sync.WaitGroup
	next := g.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		entered.Done()
		<-release
	}))
	for range 2 {
		entered.Add(1)
		finished.Add(1)
		go func() {
			defer finished.Done()
			r := httptest.NewRequest(http.MethodGet, "/share/x", nil)
			r.RemoteAddr = "[2001:db8:1:2::5]:1"
			next.ServeHTTP(httptest.NewRecorder(), r)
		}()
	}
	entered.Wait()
	if w, served := guardGet(g, "/share/x", "[2001:db8:1:2::9]:1"); served || w.Code != http.StatusServiceUnavailable {
		t.Fatalf("the same /64 went past its limit: code %d", w.Code)
	}
	if _, served := guardGet(g, "/share/x", "[2001:db8:1:3::5]:1"); !served {
		t.Fatal("another /64 was refused")
	}
	close(release)
	finished.Wait()
	if _, served := guardGet(g, "/share/x", "[2001:db8:1:2::9]:1"); !served {
		t.Fatal("still refused once the requests ended")
	}
	if len(g.inFlight) != 0 {
		t.Errorf("addresses left in the guard's map: %v", g.inFlight)
	}
}

// Memory the runtime has freed and not yet handed back is memory it can use again, so
// it must not hold the guard shut after a flood has gone.
func TestFreedHeapDoesNotCountAsUsed(t *testing.T) {
	const size = 128 << 20
	b := make([]byte, size)
	for i := 0; i < size; i += 4096 {
		b[i] = 1
	}
	before := ReadMemory().Used
	runtime.KeepAlive(b)
	b = nil
	runtime.GC()
	if after := ReadMemory().Used; before-after < size/2 {
		t.Errorf("used %d MiB before freeing %d MiB, %d MiB after", before>>20, size>>20, after>>20)
	}
	_ = b
}

// Nothing allocates while everything is refused, so nothing would ever collect what
// the flood left behind: the guard does, at a pace that costs little.
func TestWhileRefusingTheGuardGivesMemoryBack(t *testing.T) {
	g, reading := testGuard(10)
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	g.now = func() time.Time { return now }
	gave := 0
	g.giveBack = func() { gave++ }
	g.Tick()
	if gave != 0 {
		t.Fatalf("gave memory back %d times with nothing wrong", gave)
	}
	reading.Used = 95
	g.Tick()
	if gave != 1 {
		t.Fatalf("gave back %d times on starting to refuse", gave)
	}
	g.Tick()
	if gave != 1 {
		t.Fatalf("gave back %d times inside one period", gave)
	}
	now = now.Add(guardGiveBackEvery)
	g.Tick()
	if gave != 2 {
		t.Fatalf("gave back %d times after a period", gave)
	}
	reading.Used = 10
	now = now.Add(guardGiveBackEvery)
	g.Tick()
	if gave != 2 {
		t.Fatalf("gave back %d times with memory clear of the line", gave)
	}
}

// Past the line, garbage may be all that put it there: the guard collects and reads
// again before it refuses anyone.
func TestTheGuardRefusesOnlyWhatACollectionLeaves(t *testing.T) {
	g, reading := testGuard(10)
	reading.Used = 95
	g.giveBack = func() { reading.Used = 40 }
	g.Tick()
	if _, served := guardGet(g, "/share/x", "203.0.113.5:1"); !served {
		t.Fatal("refused over garbage a collection cleared")
	}
}

// On a small machine a percentage of the total says little: a 0.5 GB server hangs with
// a tenth of its memory still free. On a very small one the same absolute floor would
// never clear, so it gives way to a share of the total.
func TestTheMemoryFloorIsAbsoluteOnSmallMachines(t *testing.T) {
	for _, c := range []struct {
		total, stop, resume int64
	}{
		{451 << 20, 96 << 20, 128 << 20},
		{200 << 20, 50 << 20, (200 << 20) / 3},
		{8 << 30, (8 << 30) / 10, (8 << 30) * 15 / 100},
	} {
		if got := availableFloor(c.total); got != c.stop {
			t.Errorf("total %d MiB: refuses below %d MiB, want %d", c.total>>20, got>>20, c.stop>>20)
		}
		if got := availableClear(c.total); got != c.resume {
			t.Errorf("total %d MiB: resumes at %d MiB, want %d", c.total>>20, got>>20, c.resume>>20)
		}
	}
}

// A machine short of memory for reasons of its own must keep serving: refusing the
// few requests this server holds frees nothing and would leave it refusing for good.
func TestAFewRequestsAlwaysRun(t *testing.T) {
	g, reading := testGuard(1000)
	g.alwaysServes = 2
	reading.Used = 95
	g.Tick()
	release := make(chan struct{})
	var entered, finished sync.WaitGroup
	next := g.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		entered.Done()
		<-release
	}))
	for range 2 {
		entered.Add(1)
		finished.Add(1)
		go func() {
			defer finished.Done()
			r := httptest.NewRequest(http.MethodGet, "/share/x", nil)
			r.RemoteAddr = "203.0.113.5:1"
			next.ServeHTTP(httptest.NewRecorder(), r)
		}()
	}
	entered.Wait()
	if _, served := guardGet(g, "/share/x", "198.51.100.7:1"); served {
		t.Fatal("past the few, the guard still served")
	}
	close(release)
	finished.Wait()
	if _, served := guardGet(g, "/share/x", "198.51.100.7:1"); !served {
		t.Fatal("refused with nothing running")
	}
}

// Past what the machine's memory pays for, the guard refuses without waiting to see the
// memory go: a reading lags, a count does not.
func TestTheServerHoldsOnlyWhatItsMemoryPaysFor(t *testing.T) {
	g, _ := testGuard(1000)
	g.maxRunning = 1
	release := make(chan struct{})
	entered := make(chan struct{})
	done := make(chan struct{})
	next := g.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(entered)
		<-release
	}))
	go func() {
		defer close(done)
		r := httptest.NewRequest(http.MethodGet, "/share/x", nil)
		r.RemoteAddr = "203.0.113.5:1"
		next.ServeHTTP(httptest.NewRecorder(), r)
	}()
	<-entered
	if _, served := guardGet(g, "/share/x", "198.51.100.7:1"); served {
		t.Fatal("went past what memory pays for")
	}
	close(release)
	<-done
	if _, served := guardGet(g, "/share/x", "198.51.100.7:1"); !served {
		t.Fatal("refused with room")
	}
}

func TestRunningRequestsAreWhatFreeMemoryPaysFor(t *testing.T) {
	total := int64(451 << 20)
	free := int64(232 << 20)
	want := int((free - availableClear(total)) / guardBytesPerRequest)
	if got := freeMemoryPaysFor(MemoryReading{Total: total, Available: free}, guardBytesPerRequest); got != want {
		t.Errorf("got %d, want %d", got, want)
	}
	if got := freeMemoryPaysFor(MemoryReading{}, guardBytesPerRequest); got != 0 {
		t.Errorf("an unknown machine limits to %d, want none", got)
	}
	if got := freeMemoryPaysFor(MemoryReading{Total: total, Available: 1 << 20}, guardBytesPerRequest); got != guardAlwaysServes {
		t.Errorf("a machine already short limits to %d, want the %d that always run", got, guardAlwaysServes)
	}
}

// The runtime may not be allowed more than the machine can give it: a limit above what
// is free lets its heap take the whole machine, which then thrashes without ever
// killing anything.
func TestTheMemoryLimitFitsWhatIsFree(t *testing.T) {
	const mib = 1 << 20
	for _, c := range []struct {
		name string
		r    MemoryReading
		env  int64
		want int64
	}{
		{"a small machine", MemoryReading{Used: 20 * mib, Total: 451 * mib, Available: 232 * mib}, 270 * mib, 156 * mib},
		{"the same under load", MemoryReading{Used: 100 * mib, Total: 451 * mib, Available: 152 * mib}, 270 * mib, 156 * mib},
		{"a limit already lower", MemoryReading{Used: 20 * mib, Total: 451 * mib, Available: 232 * mib}, 100 * mib, 100 * mib},
		{"a machine busy with others", MemoryReading{Used: 20 * mib, Total: 4096 * mib, Available: 100 * mib}, 1 << 62, guardLeastLimit},
		{"nothing to read", MemoryReading{Used: 20 * mib}, 270 * mib, 270 * mib},
	} {
		if got := fittedLimit(c.r, c.env); got != c.want {
			t.Errorf("%s: %d MiB, want %d", c.name, got/mib, c.want/mib)
		}
	}
}

func TestTheGuardRefitsTheLimitNowAndThen(t *testing.T) {
	g, reading := testGuard(10)
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	g.now = func() time.Time { return now }
	var set []int64
	g.setLimit = func(n int64) { set = append(set, n) }
	g.envLimit = 1 << 62
	reading.Total, reading.Available, reading.Used = 451<<20, 232<<20, 20<<20
	g.Tick()
	g.Tick()
	if len(set) != 1 {
		t.Fatalf("set the limit %d times in one period", len(set))
	}
	now = now.Add(guardRefitEvery)
	g.Tick()
	if len(set) != 2 {
		t.Fatalf("set the limit %d times after a period", len(set))
	}
}

// A collection only helps when the runtime's own use put the guard past its line: with
// other programs holding the memory it would stop the world each time for nothing.
func TestTheGuardCollectsOnlyForItsOwnUse(t *testing.T) {
	g, reading := testGuard(10)
	gave := 0
	g.giveBack = func() { gave++ }
	reading.Available = 1 << 20
	g.Tick()
	if gave != 0 {
		t.Errorf("collected %d times for a machine short of memory elsewhere", gave)
	}
}

// Free memory falls under load, and a limit that followed it down would refuse every
// page while a queue of zips held all it allowed.
func TestAFloodDoesNotLowerWhatFreeMemoryPaysFor(t *testing.T) {
	g, reading := testGuard(1000)
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	g.now = func() time.Time { return now }
	reading.Total, reading.Available = 451<<20, 232<<20
	g.Tick()
	calm := g.maxRunning
	if calm <= guardAlwaysServes {
		t.Fatalf("a calm machine pays for %d", calm)
	}
	reading.Available = 100 << 20
	now = now.Add(guardRefitEvery)
	g.Tick()
	if g.maxRunning != calm {
		t.Errorf("under load the limit went from %d to %d", calm, g.maxRunning)
	}
	reading.Available = 300 << 20
	now = now.Add(guardRefitEvery)
	g.Tick()
	if g.maxRunning <= calm {
		t.Errorf("more free memory left the limit at %d", g.maxRunning)
	}
}

// fakeConn is a connection a test opens by hand.
type fakeConn struct {
	net.Conn
	addr   string
	closed bool
}

func (c *fakeConn) RemoteAddr() net.Addr {
	a, _ := net.ResolveTCPAddr("tcp", c.addr)
	return a
}

func (c *fakeConn) Close() error { c.closed = true; return nil }

// A connection that has sent its one request costs memory for as long as it sits
// idle, with no request running for any other limit to count.
func TestOneAddressHoldsOnlySoManyConnections(t *testing.T) {
	g, _ := testGuard(1000)
	g.connsPerAddress = 2
	open := func(addr string) *fakeConn {
		c := &fakeConn{addr: addr}
		g.ConnState(c, http.StateNew)
		g.ConnState(c, http.StateActive)
		return c
	}
	a, b := open("[2001:db8:1:2::5]:1"), open("[2001:db8:1:2::9]:2")
	if a.closed || b.closed {
		t.Fatal("closed inside the address's limit")
	}
	c := open("[2001:db8:1:2::7]:3")
	if !c.closed {
		t.Fatal("the same /64 went past its limit")
	}
	g.ConnState(c, http.StateClosed)
	if other := open("[2001:db8:1:3::5]:1"); other.closed {
		t.Fatal("another /64 was closed")
	}
	g.ConnState(a, http.StateActive)
	if a.closed {
		t.Fatal("a second request on one connection counted twice")
	}
	g.ConnState(a, http.StateClosed)
	if d := open("[2001:db8:1:2::8]:4"); d.closed {
		t.Fatal("a connection freed was not offered again")
	}
}

// The server holds what memory pays for. At that limit a connection that has never said
// anything makes room for the newcomer, the oldest first: a silent flood pushes itself
// out, and a visitor, a health check or a certificate's challenge still gets in.
func TestAtTheLimitTheOldestSilentConnectionMakesRoom(t *testing.T) {
	g, _ := testGuard(1000)
	g.maxConns = 2
	newConn := func() *closeCountingConn {
		c := &closeCountingConn{fakeConn: fakeConn{addr: "203.0.113.1:1"}, closed: make(chan struct{})}
		return c
	}
	a, b, c := newConn(), newConn(), newConn()
	g.ConnState(a, http.StateNew)
	g.ConnState(b, http.StateNew)
	g.ConnState(c, http.StateNew)
	waitUntilBlocked(t, a.isClosed)
	if b.isClosed() || c.isClosed() {
		t.Fatalf("closed %v %v, want only the oldest", b.isClosed(), c.isClosed())
	}
	g.ConnState(a, http.StateClosed)
	if g.openConns != 2 {
		t.Fatalf("%d open", g.openConns)
	}
}

// A connection that has spoken is someone's: at the limit the newcomer is the one refused.
func TestAtTheLimitAConnectionThatSpokeStays(t *testing.T) {
	g, _ := testGuard(1000)
	g.maxConns = 2
	a, b := &fakeConn{addr: "203.0.113.1:1"}, &fakeConn{addr: "203.0.113.2:1"}
	for _, x := range []*fakeConn{a, b} {
		g.ConnState(x, http.StateNew)
		g.ConnState(x, http.StateActive)
	}
	g.ConnState(b, http.StateIdle)
	c := &fakeConn{addr: "203.0.113.3:1"}
	g.ConnState(c, http.StateNew)
	if !c.closed || a.closed || b.closed {
		t.Fatalf("closed a=%v b=%v c=%v, want only the newcomer", a.closed, b.closed, c.closed)
	}
	g.ConnState(c, http.StateClosed)
	g.ConnState(a, http.StateClosed)
	d := &fakeConn{addr: "203.0.113.4:1"}
	g.ConnState(d, http.StateNew)
	if d.closed {
		t.Fatal("a connection closed with room to spare")
	}
}

// A connection that came and went must not stay a candidate.
func TestAClosedConnectionIsNoLongerSilent(t *testing.T) {
	g, _ := testGuard(1000)
	g.maxConns = 1
	a := &closeCountingConn{fakeConn: fakeConn{addr: "203.0.113.1:1"}, closed: make(chan struct{})}
	g.ConnState(a, http.StateNew)
	g.ConnState(a, http.StateClosed)
	b := &closeCountingConn{fakeConn: fakeConn{addr: "203.0.113.2:1"}, closed: make(chan struct{})}
	g.ConnState(b, http.StateNew)
	c := &fakeConn{addr: "203.0.113.3:1"}
	g.ConnState(c, http.StateNew)
	waitUntilBlocked(t, b.isClosed)
	if a.isClosed() || c.closed {
		t.Fatalf("a=%v c=%v", a.isClosed(), c.closed)
	}
}

// One address gets a quarter of what the server holds at most, so on a small box it
// cannot crowd the others out with connections it answers on.
func TestOneAddressTakesAQuarterOfTheConnections(t *testing.T) {
	g, _ := testGuard(1000)
	g.maxConns = 8
	var conns []*peerConn
	for range 3 {
		c := &peerConn{fakeConn{addr: "203.0.113.1:1"}}
		g.ConnState(c, http.StateNew)
		conns = append(conns, c)
	}
	if conns[0].closed || conns[1].closed || !conns[2].closed {
		t.Fatalf("closed %v %v %v, want the third", conns[0].closed, conns[1].closed, conns[2].closed)
	}
}

// A newcomer its own address refuses frees nothing, so it pushes nobody out.
func TestANewcomerItsAddressRefusesMakesNoRoom(t *testing.T) {
	g, _ := testGuard(1000)
	g.maxConns, g.connsPerAddress = 2, 1
	other := &closeCountingConn{fakeConn: fakeConn{addr: "203.0.113.9:1"}, closed: make(chan struct{})}
	g.ConnState(other, http.StateNew)
	first := &peerConn{fakeConn{addr: "203.0.113.1:1"}}
	g.ConnState(first, http.StateNew)
	over := &peerConn{fakeConn{addr: "203.0.113.1:1"}}
	g.ConnState(over, http.StateNew)
	if !over.closed {
		t.Fatal("over its address's limit, and let in")
	}
	time.Sleep(20 * time.Millisecond)
	if other.isClosed() {
		t.Fatal("pushed out someone else's connection to make room for one refused")
	}
}

// Idle connections go first: while memory is short or the connections nearly full,
// each one lasts one request, and those sitting idle are dropped.
func TestKeepAlivesEndWhileMemoryOrConnectionsAreShort(t *testing.T) {
	g, reading := testGuard(1000)
	var told []bool
	g.keepAlives = func(on bool) { told = append(told, on) }
	g.Tick()
	if len(told) != 0 {
		t.Fatalf("told %v with nothing wrong", told)
	}
	reading.Used = 95
	g.Tick()
	if len(told) != 1 || told[0] {
		t.Fatalf("told %v past the memory line", told)
	}
	reading.Used = 10
	g.Tick()
	if len(told) != 2 || !told[1] {
		t.Fatalf("told %v with memory clear", told)
	}
	g.maxConns = 10
	var conns []*fakeConn
	for range 9 {
		c := &fakeConn{addr: "203.0.113.1:1"}
		g.ConnState(c, http.StateNew)
		conns = append(conns, c)
	}
	g.Tick()
	if len(told) != 3 || told[2] {
		t.Fatalf("told %v with connections nearly full", told)
	}
	for _, c := range conns[:6] {
		g.ConnState(c, http.StateClosed)
	}
	g.Tick()
	if len(told) != 4 || !told[3] {
		t.Fatalf("told %v with connections free again", told)
	}
}

// A flood must not lower what free memory pays for here either.
func TestAFloodDoesNotLowerTheConnectionsMemoryPaysFor(t *testing.T) {
	g, reading := testGuard(1000)
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	g.now = func() time.Time { return now }
	reading.Total, reading.Available = 451<<20, 232<<20
	g.Tick()
	calm := g.maxConns
	if want := int((232<<20 - availableClear(451<<20)) / guardBytesPerConn); calm != want {
		t.Fatalf("a calm machine pays for %d, want %d", calm, want)
	}
	reading.Available = 100 << 20
	now = now.Add(guardRefitEvery)
	g.Tick()
	if g.maxConns != calm {
		t.Errorf("under load the limit went from %d to %d", calm, g.maxConns)
	}
}

// A limit below what the runtime holds cannot be met: with other programs holding the
// memory the collector would run against it for nothing, and the guard with it.
func TestTheMemoryLimitStaysAboveWhatTheServerHolds(t *testing.T) {
	const mib = 1 << 20
	r := MemoryReading{Used: 100 * mib, Total: 451 * mib, Available: 50 * mib}
	if got := fittedLimit(r, 1<<62); r.Used*100 >= got*guardUsedPercent {
		t.Errorf("fitted %d MiB holding %d", got/mib, r.Used/mib)
	}
	if got := fittedLimit(r, 80*mib); got != 80*mib {
		t.Errorf("fitted %d MiB, want the 80 it started with", got/mib)
	}
}

func TestOtherProgramsHoldingTheMemoryCostNoCollections(t *testing.T) {
	g, reading := testGuard(10)
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	g.now = func() time.Time { return now }
	gave := 0
	g.giveBack = func() { gave++ }
	g.envLimit = 1 << 62
	g.setLimit = func(n int64) { reading.Limit = n }
	reading.Used, reading.Limit, reading.Total, reading.Available = 100<<20, 270<<20, 451<<20, 50<<20
	for range 300 {
		g.Tick()
		now = now.Add(guardEvery)
	}
	if gave != 0 {
		t.Errorf("collected %d times in %v with other programs holding the memory", gave, 300*guardEvery)
	}
}

// Garbage is no reason to raise the limit: it is collected first, and the limit fits
// what that leaves.
func TestTheLimitFitsWhatACollectionLeaves(t *testing.T) {
	g, reading := testGuard(10)
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	g.now = func() time.Time { return now }
	g.envLimit = 1 << 62
	var set int64
	g.setLimit = func(n int64) { set, reading.Limit = n, n }
	g.giveBack = func() { reading.Used = 60 << 20 }
	reading.Used, reading.Limit, reading.Total, reading.Available = 150<<20, 156<<20, 451<<20, 96<<20
	g.refitAt = now.Add(-guardRefitEvery)
	g.Tick()
	if want := fittedLimit(MemoryReading{Used: 60 << 20, Total: 451 << 20, Available: 96 << 20}, 1<<62); set != want {
		t.Errorf("fitted %d MiB, want %d from what the collection left", set>>20, want>>20)
	}
}

// peerConn is a connection whose address is known as it is accepted.
type peerConn struct{ fakeConn }

func (c *peerConn) AddressAtAccept() net.Addr { return c.RemoteAddr() }

// A connection that never sends a byte never reaches a first request, so one address
// is judged as it connects, or its silent connections would fill what memory pays for
// and every other visitor's would be closed on accept.
func TestOneAddressCannotFillTheServerWithSilentConnections(t *testing.T) {
	g, _ := testGuard(1000)
	g.maxConns, g.connsPerAddress = 8, 2
	for range 10 {
		c := &peerConn{fakeConn{addr: "203.0.113.1:1"}}
		g.ConnState(c, http.StateNew)
		if c.closed {
			g.ConnState(c, http.StateClosed)
		}
	}
	other := &peerConn{fakeConn{addr: "198.51.100.7:1"}}
	g.ConnState(other, http.StateNew)
	if other.closed {
		t.Fatal("one address's silent connections shut another out")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.openConns != 3 {
		t.Fatalf("%d connections open, want the address's 2 and the other", g.openConns)
	}
}

// A plain TCP connection needs nothing else to name its address; this is what reaches
// port 80.
func TestASilentTCPConnectionCountsAgainstItsAddress(t *testing.T) {
	g, _ := testGuard(1000)
	g.connsPerAddress = 2
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.NotFoundHandler()}
	g.AddServer(srv)
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	closedByServer := 0
	for range 5 {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if _, err := c.Read(make([]byte, 1)); err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
			closedByServer++
		}
	}
	if closedByServer != 3 {
		t.Fatalf("%d of 5 silent connections closed, want those past the address's 2", closedByServer)
	}
}

// A connection whose address is not known yet, one through a listed proxy, is judged at
// its first request.
func TestALateAddressIsJudgedAtItsFirstRequest(t *testing.T) {
	g, _ := testGuard(1000)
	g.connsPerAddress = 1
	a, b := &fakeConn{addr: "203.0.113.1:1"}, &fakeConn{addr: "203.0.113.1:2"}
	g.ConnState(a, http.StateNew)
	g.ConnState(b, http.StateNew)
	if a.closed || b.closed {
		t.Fatal("closed before the address was known")
	}
	g.ConnState(a, http.StateActive)
	g.ConnState(b, http.StateActive)
	if a.closed || !b.closed {
		t.Fatalf("closed %v %v at the first request", a.closed, b.closed)
	}
}

// Over HTTP/2 the server's own switch drops no idle connection, and a request's end
// drops the one it ran on only after that request. One that has just been opened reads
// as idle before its first request, so it gets a moment.
func TestIdleConnectionsCloseOnlyWhileKeepAliveIsOff(t *testing.T) {
	g, reading := testGuard(1000)
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	g.now = func() time.Time { return now }
	open := func(state http.ConnState) *closeCountingConn {
		c := &closeCountingConn{closed: make(chan struct{})}
		c.addr = "203.0.113.1:1"
		g.ConnState(c, http.StateNew)
		g.ConnState(c, http.StateActive)
		g.ConnState(c, state)
		return c
	}
	idle, busy := open(http.StateIdle), open(http.StateActive)
	now = now.Add(time.Hour)
	g.Tick()
	if idle.isClosed() {
		t.Fatal("closed an idle connection with keep-alive on")
	}
	reading.Used = 95
	fresh := open(http.StateIdle)
	g.Tick()
	select {
	case <-idle.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("an idle connection stayed open with keep-alive off")
	}
	if busy.isClosed() {
		t.Fatal("closed a connection with a request running")
	}
	if fresh.isClosed() {
		t.Fatal("closed a connection before its first request could arrive")
	}
	now = now.Add(guardIdleGrace)
	g.Tick()
	select {
	case <-fresh.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("a connection that stayed silent past its moment stayed open")
	}
	if busy.isClosed() {
		t.Fatal("closed a connection with a request running")
	}
}

// closeCountingConn reports its Close to a test watching from another goroutine.
type closeCountingConn struct {
	fakeConn
	closed chan struct{}
	once   sync.Once
}

func (c *closeCountingConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *closeCountingConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

// The same over a real HTTP/2 connection, the protocol browsers speak to the HTTPS
// server.
func TestAnIdleHTTP2ConnectionClosesWhileKeepAliveIsOff(t *testing.T) {
	g, reading := testGuard(1000)
	g.keepAlives = g.setKeepAlives
	g.giveBack = func() {}
	var clock atomic.Int64
	start := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	g.now = func() time.Time { return start.Add(time.Duration(clock.Load())) }
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	ts.EnableHTTP2 = true
	g.AddServer(ts.Config)
	ts.StartTLS()
	defer ts.Close()
	res, err := ts.Client().Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.ProtoMajor != 2 {
		t.Fatalf("spoke %s", res.Proto)
	}
	openConns := func() int {
		g.mu.Lock()
		defer g.mu.Unlock()
		return g.openConns
	}
	if n := openConns(); n != 1 {
		t.Fatalf("%d connections open after a request", n)
	}
	reading.Used = 95
	clock.Add(int64(guardIdleGrace))
	g.Tick()
	deadline := time.Now().Add(5 * time.Second)
	for openConns() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the idle HTTP/2 connection stayed open with keep-alive off")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// stuckGuard is a guard on a clock of its own, with connections short enough that
// keep-alive is off, and a connection through it.
func stuckGuard(t *testing.T) (g *LoadGuard, reading *MemoryReading, step func(time.Duration), conn func() (*closeCountingConn, context.Context)) {
	t.Helper()
	g, reading = testGuard(1000)
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	g.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	step = func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	conn = func() (*closeCountingConn, context.Context) {
		c := &closeCountingConn{fakeConn: fakeConn{addr: "203.0.113.1:1"}, closed: make(chan struct{})}
		ctx := g.connContext(context.Background(), c)
		g.ConnState(c, http.StateNew)
		g.ConnState(c, http.StateActive)
		return c, ctx
	}
	return g, reading, step, conn
}

func guardServe(g *LoadGuard, ctx context.Context, w http.ResponseWriter, next http.HandlerFunc) {
	r := httptest.NewRequest(http.MethodGet, "/x", nil).WithContext(ctx)
	r.RemoteAddr = "203.0.113.1:1"
	g.Wrap(next).ServeHTTP(w, r)
}

// A handler that has returned leaves the server flushing its response, with no request
// running for any limit to count and no deadline on the write: while connections are
// short, one whose client takes nothing goes the way an idle one does.
func TestAResponseStuckAfterItsHandlerClosesWhileKeepAliveIsOff(t *testing.T) {
	g, reading, step, conn := stuckGuard(t)
	stuck, ctx := conn()
	guardServe(g, ctx, httptest.NewRecorder(), func(http.ResponseWriter, *http.Request) {})
	step(time.Hour)
	g.Tick()
	if stuck.isClosed() {
		t.Fatal("closed with keep-alive on")
	}
	reading.Used = 95
	g.Tick()
	waitUntilBlocked(t, stuck.isClosed)
}

// A flush that finishes makes the connection idle, and the next request starts clean.
func TestAFinishedResponseIsNotStuck(t *testing.T) {
	g, reading, step, conn := stuckGuard(t)
	c, ctx := conn()
	guardServe(g, ctx, httptest.NewRecorder(), func(http.ResponseWriter, *http.Request) {})
	g.ConnState(c, http.StateIdle)
	g.ConnState(c, http.StateActive) // the next request, its handler running
	reading.Used = 95
	step(time.Hour)
	g.Tick()
	time.Sleep(20 * time.Millisecond)
	if c.isClosed() {
		t.Fatal("closed a connection with a request running")
	}
}

// blockingWriter holds a write until it is let go, a client whose window is shut.
type blockingWriter struct {
	*httptest.ResponseRecorder
	writing chan struct{}
	release chan struct{}
}

func (b *blockingWriter) Write(p []byte) (int, error) {
	close(b.writing)
	<-b.release
	return b.ResponseRecorder.Write(p)
}

// A handler stuck in a write is the same case, and is one a limit does count.
func TestAWriteStuckInItsHandlerClosesWhileKeepAliveIsOff(t *testing.T) {
	g, reading, step, conn := stuckGuard(t)
	stuck, ctx := conn()
	bw := &blockingWriter{ResponseRecorder: httptest.NewRecorder(), writing: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		guardServe(g, ctx, bw, func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("x")) })
		close(done)
	}()
	<-bw.writing
	reading.Used = 95
	g.Tick()
	step(guardIdleGrace - time.Second)
	g.Tick()
	time.Sleep(20 * time.Millisecond)
	if stuck.isClosed() {
		t.Fatal("closed inside its moment")
	}
	step(2 * time.Second)
	g.Tick()
	waitUntilBlocked(t, stuck.isClosed)
	close(bw.release)
	<-done
}

// A write that returns is no stall, however long the response goes on: a download
// moving at all is not stuck, and neither is a handler waiting on something else, an
// upload's body or a long poll.
func TestAHandlerNotWritingIsNotStuck(t *testing.T) {
	g, reading, step, conn := stuckGuard(t)
	running, ctx := conn()
	wrote, finish := make(chan struct{}), make(chan struct{})
	done := make(chan struct{})
	go func() {
		guardServe(g, ctx, httptest.NewRecorder(), func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte("x"))
			close(wrote)
			<-finish
		})
		close(done)
	}()
	<-wrote
	reading.Used = 95
	step(time.Hour)
	g.Tick()
	time.Sleep(20 * time.Millisecond)
	if running.isClosed() {
		t.Fatal("closed a request waiting on something other than its client")
	}
	close(finish)
	<-done
}

// One HTTP/2 connection carries many streams, and one stream's finished or stalled
// response says nothing of the others: its state goes idle when they are all done.
func TestAnHTTP2ResponseDoesNotMarkItsConnection(t *testing.T) {
	g, reading, step, conn := stuckGuard(t)
	c, ctx := conn()
	r := httptest.NewRequest(http.MethodGet, "/x", nil).WithContext(ctx)
	r.RemoteAddr = "203.0.113.1:1"
	r.ProtoMajor = 2
	g.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(httptest.NewRecorder(), r)
	reading.Used = 95
	step(time.Hour)
	g.Tick()
	time.Sleep(20 * time.Millisecond)
	if c.isClosed() {
		t.Fatal("closed an HTTP/2 connection over one stream")
	}
}

// Through the real server: clients that ask and never read fill what an address may
// hold, and once they have sat past the moment a newcomer from it gets in.
func TestClientsThatNeverReadCannotFillTheConnections(t *testing.T) {
	g, reading := testGuard(1000)
	g.maxConns = 12        // a quarter of it, 3, for the one address a test connects from
	g.refitAt = time.Now() // the limit stays where it is for the length of the test
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	big := bytes.Repeat([]byte("x"), 8<<20)
	srv := &http.Server{Handler: g.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/big" {
			w.Write(big)
			return
		}
		w.Write([]byte("ok"))
	}))}
	g.AddServer(srv)
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	var stuck []net.Conn
	t.Cleanup(func() {
		for _, c := range stuck {
			c.Close()
		}
	})
	for range 3 {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		c.(*net.TCPConn).SetReadBuffer(1024)
		fmt.Fprintf(c, "GET /big HTTP/1.1\r\nHost: x\r\n\r\n")
		stuck = append(stuck, c)
	}
	time.Sleep(200 * time.Millisecond)
	reading.Used = 95 // keep-alive off, as connections this full turn it
	g.Tick()
	refused := func() bool {
		cl := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
		resp, err := cl.Get("http://" + ln.Addr().String() + "/small")
		if err != nil {
			return true
		}
		resp.Body.Close()
		return resp.StatusCode != 200
	}
	if !refused() {
		t.Fatal("the connections were not full: the case under test did not arise")
	}
	time.Sleep(guardIdleGrace + 100*time.Millisecond)
	g.Tick()
	reading.Used = 10
	g.Tick()
	deadline := time.Now().Add(5 * time.Second)
	for refused() {
		if time.Now().After(deadline) {
			t.Fatal("a newcomer stayed refused with every other connection stuck past its moment")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
