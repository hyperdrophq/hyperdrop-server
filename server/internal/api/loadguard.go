package api

import (
	"bytes"
	"container/list"
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The load guard stands in front of the whole server, because a request held open
// costs memory on every route, not only the ones with a queue of their own: on a
// 0.5 GB server a few thousand of them leave the kernel reclaiming until nothing
// answers, SSH included. It answers two questions from what it can see before a
// request does any work:
//
//   - is the machine nearly out of memory? New requests are told the server is busy
//     until memory is well clear of the line, and what already runs carries on;
//   - does this address already hold guardPerAddress requests? One address has no
//     honest use for more, whichever route it asks for;
//   - does the server already hold what free memory pays for? A reading of memory lags
//     a burst, and a count does not.
//
// It counts connections the same way, per address and in total, since one that has
// sent its request sits idle for as long as keep-alive lets it. While memory or the
// connections are short keep-alive ends, so a connection lasts one request and the
// idle ones are dropped first.
//
// It also keeps the Go runtime's memory limit within what the machine has free. A limit
// above that lets the heap take the whole machine, where nothing can be reclaimed and
// nothing is killed either: the kernel evicts the program text of everything that runs
// and faults it back in, for good.
//
// A refusal costs a few hundred bytes and ends the connection, so an attacker pays
// for a new one each time and the server holds nothing for it.
const (
	// The Go runtime's use of its limit at which the guard refuses, and below which
	// it stops: apart, so a server at the line does not flap on every request.
	guardUsedPercent      = 90
	guardUsedClearPercent = 85
	// guardAlwaysServes is how many requests run whatever memory says: a machine short
	// of memory for reasons of its own must keep serving, since refusing the little
	// this server holds frees nothing and would leave it refusing for good.
	guardAlwaysServes = 64
	// guardPerAddress is how many requests one address (an IPv4 address, or an IPv6
	// /64) may have running at once. It sits above what a browser opens over HTTP/2
	// to one server, so a household or small office behind one address never meets it.
	guardPerAddress = 128
	// guardEvery is how often memory is read: reading opens files, so a request only
	// ever reads the answer.
	guardEvery = 250 * time.Millisecond
	// guardGiveBackEvery is how often the guard collects past its line.
	guardGiveBackEvery = time.Second
	// guardBytesPerRequest is what one request is allowed for when counting what free
	// memory pays for: a stalled file download on a 0.5 GB server holds about this much
	// between the program and the kernel's buffers for its connection.
	guardBytesPerRequest = 128 << 10
	// guardBytesPerConn is what one open connection is allowed for: an idle one holds
	// its goroutine, its buffers and its TLS state, 30 to 60 KiB.
	guardBytesPerConn = 64 << 10
	// guardConnsPerAddress is how many connections one address may hold, above what
	// the browsers of a small office keep open. guardConnsAddressShare lowers it on a
	// server that holds few: an address gets at most this fraction of them.
	guardConnsPerAddress   = 256
	guardConnsAddressShare = 4
	// guardConnsTightTenths is how full the connections are, in tenths, when keep-alive
	// ends and the idle ones go; it comes back below half.
	guardConnsTightTenths = 9
	// guardIdleGrace is how long a connection may sit idle while keep-alive is off. An
	// HTTP/2 connection reads as idle before its first request, so this is that
	// request's moment to arrive.
	guardIdleGrace = 5 * time.Second
	// guardRefitEvery is how often the limits follow what the machine has free.
	guardRefitEvery = time.Minute
	// guardLeastLimit is the lowest the runtime's memory limit goes, on a machine busy
	// with other programs.
	guardLeastLimit = 64 << 20
	// busyRetryAfter is the seconds a busy answer asks a client to wait.
	busyRetryAfter = "30"
)

// LoadGuard refuses new requests while the server cannot afford them.
type LoadGuard struct {
	read       func() MemoryReading
	perAddress int
	// alwaysServes is how many requests run whatever memory says.
	alwaysServes int
	shedding     atomic.Bool
	now          func() time.Time
	giveBack     func()
	gaveBackAt   time.Time
	// envLimit is the memory limit the server was started with, setLimit how the runtime
	// is told its fitted one, and refitAt when it last was.
	envLimit int64
	setLimit func(int64)
	refitAt  time.Time

	// keepAlives switches keep-alive on every server, and keepAlivesOff is what it was
	// last told.
	keepAlives    func(bool)
	keepAlivesOff bool

	mu              sync.Mutex
	running         int
	maxRunning      int // 0: no limit
	inFlight        map[string]int
	servers         []*http.Server
	openConns       int
	maxConns        int // 0: no limit
	connsPerAddress int
	connAddr        map[net.Conn]string
	addrConns       map[string]int
	idleSince       map[net.Conn]time.Time
	// silent holds the connections that have not yet sent anything, oldest first, and
	// silentAt where each one is in it.
	silent   *list.List
	silentAt map[net.Conn]*list.Element
	// writes holds each open connection's state of its response, read only while
	// connections are short.
	writes map[net.Conn]*guardConn
	// streams holds each HTTP/2 response being written, the same way.
	streams map[*guardStream]struct{}
}

// guardConn says since when a connection's response has been going out to a client
// that may not be taking it, in Unix nanoseconds, 0 when none is: while a write runs,
// and from a handler's return until the server has flushed what it wrote, which happens
// under no deadline and with no request left running for any limit to count.
type guardConn struct{ writingSince atomic.Int64 }

type guardConnKey struct{}

// guardStream is one HTTP/2 response. Its connection carries other streams, so a
// stream whose client takes nothing ends alone: its write deadline is set to now,
// which resets the stream and lets its handler go. The deadline is only set while the
// handler runs, the one time a ResponseController may be used.
type guardStream struct {
	guardConn
	rc   *http.ResponseController
	mu   sync.Mutex
	done bool
}

// end lets the stream's handler go with a write error.
func (s *guardStream) end() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.done {
		s.rc.SetWriteDeadline(time.Now())
	}
}

// finish marks the handler returned.
func (s *guardStream) finish() {
	s.mu.Lock()
	s.done = true
	s.mu.Unlock()
}

// connContext gives a new connection its guardConn.
func (g *LoadGuard) connContext(ctx context.Context, c net.Conn) context.Context {
	gc := &guardConn{}
	g.mu.Lock()
	g.writes[c] = gc
	g.mu.Unlock()
	return context.WithValue(ctx, guardConnKey{}, gc)
}

// guardedWrites marks a response's writes on its connection.
type guardedWrites struct {
	http.ResponseWriter
	gc     *guardConn
	stream *guardStream // an HTTP/2 response's stream, nil on HTTP/1
	now    func() time.Time
}

func (w *guardedWrites) begin() { w.gc.writingSince.Store(w.now().UnixNano()) }
func (w *guardedWrites) end()   { w.gc.writingSince.Store(0) }

func (w *guardedWrites) Write(b []byte) (int, error) {
	w.begin()
	defer w.end()
	return w.ResponseWriter.Write(b)
}

func (w *guardedWrites) Flush() {
	w.begin()
	defer w.end()
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// ReadFrom keeps sendfile: a file response comes through in bounded chunks (stallWriter).
func (w *guardedWrites) ReadFrom(src io.Reader) (int64, error) {
	w.begin()
	defer w.end()
	return readFrom(w.ResponseWriter, src)
}

func (w *guardedWrites) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// NewLoadGuard is a guard that reads memory with read.
func NewLoadGuard(read func() MemoryReading) *LoadGuard {
	g := &LoadGuard{read: read, perAddress: guardPerAddress, alwaysServes: guardAlwaysServes, now: time.Now, giveBack: debug.FreeOSMemory,
		envLimit: debug.SetMemoryLimit(-1), setLimit: func(n int64) { debug.SetMemoryLimit(n) }, inFlight: map[string]int{},
		connsPerAddress: guardConnsPerAddress, connAddr: map[net.Conn]string{}, addrConns: map[string]int{}, idleSince: map[net.Conn]time.Time{},
		silent: list.New(), silentAt: map[net.Conn]*list.Element{}, writes: map[net.Conn]*guardConn{},
		streams: map[*guardStream]struct{}{}}
	g.keepAlives = g.setKeepAlives
	return g
}

// AddServer puts srv under the guard's connection limits.
func (g *LoadGuard) AddServer(srv *http.Server) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.servers = append(g.servers, srv)
	srv.ConnState = g.ConnState
	srv.ConnContext = g.connContext
}

// setKeepAlives switches keep-alive on every server. Switching it off drops the HTTP/1
// connections sitting idle; dropIdleConns drops the HTTP/2 ones, which the server's own
// switch leaves until their idle timeout.
func (g *LoadGuard) setKeepAlives(on bool) {
	g.mu.Lock()
	servers := slices.Clone(g.servers)
	g.mu.Unlock()
	for _, srv := range servers {
		srv.SetKeepAlivesEnabled(on)
	}
}

// ConnState counts connections. A connection costs memory for as long as it is open
// with no request running for any other limit to count, so what free memory pays for is
// all the server holds. At that limit the oldest connection that has never sent anything
// is closed to make room, so a silent flood pushes itself out and a newcomer gets in;
// with none to close, the newcomer is. Past its address's limit a connection is closed as
// soon as its address is known: as it is accepted, or through a listed proxy, whose header
// is read from the connection, at its first request.
func (g *LoadGuard) ConnState(c net.Conn, state http.ConnState) {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch state {
	case http.StateNew:
		g.openConns++
		if addr := addressAtAccept(c); addr != nil && g.countConnLocked(c, addr) {
			return
		}
		if g.maxConns > 0 && g.openConns > g.maxConns && !g.closeOldestSilentLocked() {
			_ = c.Close()
			return
		}
		g.silentAt[c] = g.silent.PushBack(c)
	case http.StateActive:
		g.forgetSilentLocked(c)
		g.responseDoneLocked(c)
		delete(g.idleSince, c)
		if _, seen := g.connAddr[c]; !seen {
			g.countConnLocked(c, c.RemoteAddr())
		}
	case http.StateIdle:
		g.forgetSilentLocked(c)
		g.responseDoneLocked(c)
		g.idleSince[c] = g.now()
	case http.StateClosed, http.StateHijacked:
		g.forgetSilentLocked(c)
		delete(g.writes, c)
		delete(g.idleSince, c)
		g.openConns--
		if addr, seen := g.connAddr[c]; seen {
			delete(g.connAddr, c)
			if g.addrConns[addr]--; g.addrConns[addr] == 0 {
				delete(g.addrConns, addr)
			}
		}
	}
}

// responseDoneLocked notes that c's last response has gone out: the server reports a
// connection idle or active again only once it has flushed.
func (g *LoadGuard) responseDoneLocked(c net.Conn) {
	if gc := g.writes[c]; gc != nil {
		gc.writingSince.Store(0)
	}
}

func (g *LoadGuard) forgetSilentLocked(c net.Conn) {
	if e, ok := g.silentAt[c]; ok {
		g.silent.Remove(e)
		delete(g.silentAt, c)
	}
}

// closeOldestSilentLocked closes the connection silent longest and reports whether there
// was one. Closing a TLS connection can wait seconds on a peer that stopped reading, so
// that runs apart from the lock; the count falls when it reports closed.
func (g *LoadGuard) closeOldestSilentLocked() bool {
	e := g.silent.Front()
	if e == nil {
		return false
	}
	c := e.Value.(net.Conn)
	g.forgetSilentLocked(c)
	go c.Close()
	return true
}

// countConnLocked counts c against its address and closes it past the address's limit,
// reporting whether it did.
func (g *LoadGuard) countConnLocked(c net.Conn, remote net.Addr) bool {
	addr := connAddrKey(remote)
	g.connAddr[c] = addr
	g.addrConns[addr]++
	limit := g.connsPerAddress
	if g.maxConns > 0 {
		limit = min(limit, max(1, g.maxConns/guardConnsAddressShare))
	}
	if g.addrConns[addr] > limit {
		_ = c.Close()
		return true
	}
	return false
}

// addressAtAccept is the address c came from when naming it reads nothing from c: a
// plain TCP connection's, or what a listener that takes PROXY headers says of a peer it
// holds to none. It is nil for one whose address only its first bytes can tell.
func addressAtAccept(c net.Conn) net.Addr {
	if t, ok := c.(interface{ NetConn() net.Conn }); ok {
		c = t.NetConn()
	}
	switch p := c.(type) {
	case *net.TCPConn:
		return p.RemoteAddr()
	case interface{ AddressAtAccept() net.Addr }:
		return p.AddressAtAccept()
	}
	return nil
}

func connAddrKey(remote net.Addr) string {
	s := remote.String()
	if host, _, err := net.SplitHostPort(s); err == nil {
		return addrKey(host)
	}
	return s
}

// Run reads memory until ctx ends.
func (g *LoadGuard) Run(ctx context.Context) {
	g.Tick()
	t := time.NewTicker(guardEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			g.Tick()
		}
	}
}

// Tick reads memory and decides whether new requests are refused. Past the runtime's
// line it collects and reads again, at most once a guardGiveBackEvery: garbage may be
// all that put it there, and while requests are refused nothing else would collect it.
// With other programs holding the memory a collection would stop the world for nothing.
// A field the system cannot report never reads as a server out of memory.
func (g *LoadGuard) Tick() {
	now := g.now()
	r := g.read()
	if r.overItsOwnLimit() && now.Sub(g.gaveBackAt) >= guardGiveBackEvery {
		g.gaveBackAt = now
		g.giveBack()
		r = g.read()
	}
	if now.Sub(g.refitAt) >= guardRefitEvery {
		g.refitAt = now
		g.setLimit(fittedLimit(r, g.envLimit))
		g.mu.Lock()
		g.maxRunning = max(g.maxRunning, freeMemoryPaysFor(r, guardBytesPerRequest))
		g.maxConns = max(g.maxConns, freeMemoryPaysFor(r, guardBytesPerConn))
		g.mu.Unlock()
		r = g.read()
	}
	switch {
	case r.over() && !g.shedding.Swap(true):
		log.Printf("load guard: refusing new requests, %d MiB used of %d, %d MiB of %d free on the machine",
			r.Used>>20, r.Limit>>20, r.Available>>20, r.Total>>20)
	case r.clear() && g.shedding.Swap(false):
		log.Printf("load guard: taking requests again, %d MiB used of %d, %d MiB of %d free on the machine",
			r.Used>>20, r.Limit>>20, r.Available>>20, r.Total>>20)
	}
	g.mu.Lock()
	full := g.maxConns > 0 && g.openConns*10 >= g.maxConns*guardConnsTightTenths
	roomy := g.maxConns == 0 || g.openConns*2 < g.maxConns
	g.mu.Unlock()
	shedding := g.shedding.Load()
	switch {
	case (shedding || full) && !g.keepAlivesOff:
		g.keepAlivesOff = true
		g.keepAlives(false)
	case !shedding && roomy && g.keepAlivesOff:
		g.keepAlivesOff = false
		g.keepAlives(true)
	}
	if g.keepAlivesOff {
		g.dropIdleConns(now)
	}
}

// dropIdleConns closes the connections idle past guardIdleGrace, and those whose client
// has taken nothing of a response for as long: to them the server's write has no deadline,
// and nothing else would ever end it. An HTTP/2 stream in that state is reset alone. Closing a TLS connection can wait seconds on a peer
// that stopped reading, so none of that runs here or under the lock.
func (g *LoadGuard) dropIdleConns(now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for c, since := range g.idleSince {
		if now.Sub(since) >= guardIdleGrace {
			delete(g.idleSince, c)
			go c.Close()
		}
	}
	for c, gc := range g.writes {
		since := gc.writingSince.Load()
		if since != 0 && now.UnixNano()-since >= int64(guardIdleGrace) {
			gc.writingSince.Store(0)
			go c.Close()
		}
	}
	for s := range g.streams {
		since := s.writingSince.Load()
		if since != 0 && now.UnixNano()-since >= int64(guardIdleGrace) {
			s.writingSince.Store(0)
			go s.end()
		}
	}
}

// over reports a reading past the guard's line.
func (r MemoryReading) over() bool {
	return r.overItsOwnLimit() || (r.Total > 0 && r.Available < availableFloor(r.Total))
}

// overItsOwnLimit reports the Go runtime past its line.
func (r MemoryReading) overItsOwnLimit() bool {
	return r.Limit > 0 && r.Used*100 >= r.Limit*guardUsedPercent
}

// clear reports a reading well below it.
func (r MemoryReading) clear() bool {
	return (r.Limit == 0 || r.Used*100 < r.Limit*guardUsedClearPercent) &&
		(r.Total == 0 || r.Available >= availableClear(r.Total))
}

// availableFloor is the machine's free memory below which new requests are refused: a
// tenth of it, and on a small machine 96 MiB, or a quarter on one too small to have
// that. A 0.5 GB server loses SSH with about 20 MiB free and a burst covers tens of
// MiB between two readings, so a share of its total stops too late.
func availableFloor(total int64) int64 {
	return max(total/10, min(96<<20, total/4))
}

// availableClear is the free memory above which requests are taken again, and which
// a new zip leaves untouched, so zips stop before anything is refused.
func availableClear(total int64) int64 {
	return max(total*15/100, min(128<<20, total/3))
}

// fittedLimit is the most the Go runtime may hold: what it holds now and what the
// machine could still give it, short of the line where requests are refused, and never
// above the limit it was started with. Its own use and the machine's free memory move
// together, so this stays put under load and moves only with other programs. It stays
// clear of what the runtime holds, read after a collection when that was near the line:
// the runtime cannot go below what is live, and a limit under it would leave the
// collector and the guard's give-back running for nothing while others hold the memory.
func fittedLimit(r MemoryReading, env int64) int64 {
	if r.Total == 0 {
		return env
	}
	return min(env, max(r.Used+r.Available-availableFloor(r.Total), r.Used*100/guardUsedClearPercent, guardLeastLimit))
}

// freeMemoryPaysFor is how many of something costing each bytes the machine's free
// memory pays for, down to the few that always run; 0, no limit, on a system that
// cannot report it. The guard keeps the highest it has read: free memory falls under
// load, and a limit that followed it down would refuse every page while a queue of
// zips held all it allowed.
func freeMemoryPaysFor(r MemoryReading, each int64) int {
	if r.Total == 0 {
		return 0
	}
	return max(guardAlwaysServes, int((r.Available-availableClear(r.Total))/each))
}

// Wrap puts the guard in front of next.
func (g *LoadGuard) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// One HTTP/2 connection carries many streams, so one stream's response says
		// nothing of the connection: the server's own idle state speaks for it.
		if gc, ok := r.Context().Value(guardConnKey{}).(*guardConn); ok {
			if r.ProtoMajor == 1 {
				gw := &guardedWrites{ResponseWriter: w, gc: gc, now: g.now}
				w = gw
				defer gw.begin() // the server flushes after the handler returns
			} else {
				gw := g.guardStream(w)
				w = gw
				defer g.streamDone(gw)
			}
		}
		if guardExempt(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		addr := addrKey(clientIP(r))
		if !g.enter(addr) {
			writeBusy(w, r)
			return
		}
		defer g.leave(addr)
		next.ServeHTTP(w, r)
	})
}

// guardStream puts an HTTP/2 response's writes under the guard.
func (g *LoadGuard) guardStream(w http.ResponseWriter) *guardedWrites {
	s := &guardStream{rc: http.NewResponseController(w)}
	g.mu.Lock()
	g.streams[s] = struct{}{}
	g.mu.Unlock()
	return &guardedWrites{ResponseWriter: w, gc: &s.guardConn, stream: s, now: g.now}
}

// streamDone ends a stream's watch. The server flushes what is left after the handler
// returns, under no deadline, so while connections are short that flush happens here,
// where a client taking nothing still ends the stream; with connections to spare the
// server keeps its own flush, which sets the length of a short response.
func (g *LoadGuard) streamDone(w *guardedWrites) {
	g.mu.Lock()
	short := g.keepAlivesOff
	g.mu.Unlock()
	if short {
		w.Flush()
	}
	w.stream.finish()
	g.mu.Lock()
	delete(g.streams, w.stream)
	g.mu.Unlock()
}

// guardExempt names what must answer whatever the load: a provisioner and the boot
// self-check read health to decide whether the server is alive, and a certificate
// missing its challenge is a server that stays down long after the load has gone.
// Neither holds anything open.
func guardExempt(path string) bool {
	return path == "/api/health" || strings.HasPrefix(path, "/.well-known/acme-challenge/")
}

func (g *LoadGuard) enter(addr string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.shedding.Load() && g.running >= g.alwaysServes {
		return false
	}
	if g.maxRunning > 0 && g.running >= g.maxRunning {
		return false
	}
	if g.inFlight[addr] >= g.perAddress {
		return false
	}
	g.running++
	g.inFlight[addr]++
	return true
}

func (g *LoadGuard) leave(addr string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.running--
	if g.inFlight[addr]--; g.inFlight[addr] == 0 {
		delete(g.inFlight, addr)
	}
}

// busyPageFor renders one busy page. Each is rendered once: a refusal must cost next to
// nothing, and the pages name no share. Retry, on a page answering a zip, is the seconds
// after which the browser asks for that zip again: a zip's download starts by itself once
// there is room, and leaves the page where it is, so the asking stops there.
func busyPageFor(title, note, retry string) []byte {
	var b bytes.Buffer
	if err := page("busy", "busy.html").Execute(&b, struct{ Title, Note, Retry string }{title, note, retry}); err != nil {
		panic("busy page: " + err.Error())
	}
	return b.Bytes()
}

var (
	busyPage = busyPageFor("This server is busy",
		"It is handling more than it can right now. Try again in a minute.", "")
	zipBusyPage = busyPageFor("This server is overloaded",
		"It can't start your zip right now. Leave this page open: the download starts by itself when there is room.", busyRetryAfter)
	zipAddressPage = busyPageFor("Already downloading from your connection",
		"Only "+strconv.Itoa(zipsPerAddress)+" zips at a time can run from one internet connection, and that many are running from yours. Leave this page open: this one starts by itself when one finishes.", busyRetryAfter)
)

// busyPageCSP is the page's own policy, since a refusal has no request context to
// compose the others from.
const busyPageCSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// writeBusy tells a client the server cannot take its request now: code busy on an
// API route, a page on any other, on a connection that then closes.
func writeBusy(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/zip/") {
		writeBusyPage(w, r, zipBusyPage)
		return
	}
	writeBusyPage(w, r, busyPage)
}

func writeBusyPage(w http.ResponseWriter, r *http.Request, busy []byte) {
	w.Header().Set("Retry-After", busyRetryAfter)
	w.Header().Set("Connection", "close")
	w.Header().Set("Cache-Control", "no-store")
	if strings.HasPrefix(r.URL.Path, "/api/") {
		writeErrorCode(w, http.StatusServiceUnavailable, "busy", "The server is busy, try again in a minute.")
		return
	}
	noIndex(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", busyPageCSP)
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write(busy)
}

// busyUnlessGone answers a wait that ended: the client's own leaving needs no answer,
// and a wait past its limit is told the server is busy.
func busyUnlessGone(w http.ResponseWriter, r *http.Request) {
	if r.Context().Err() == nil {
		writeBusy(w, r)
	}
}
