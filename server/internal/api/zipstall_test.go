package api

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"hyperdrop/server/internal/metadb"
)

// pacedWriter takes bytes at a set rate on a clock of its own, so a test
// reads a stream at any speed without waiting for it.
type pacedWriter struct {
	clock time.Time
	rate  float64 // bytes a second
	took  int64
}

func (p *pacedWriter) now() time.Time { return p.clock }

func (p *pacedWriter) Write(b []byte) (int, error) {
	p.clock = p.clock.Add(time.Duration(float64(len(b)) / p.rate * float64(time.Second)))
	p.took += int64(len(b))
	return len(b), nil
}

// A zip stream read below zipMinRate over a zipRateWindow ends, however
// fast it was read before: a client that trickles cannot hold one of
// a place in line for as long as it likes.
func TestZipEndsAStreamReadBelowTheMinimumRate(t *testing.T) {
	stream := func(p *pacedWriter, then func(), total int) error {
		sw := newStallWriter(p, http.NewResponseController(httptest.NewRecorder()), zipStallTimeout, zipMinRate)
		sw.now = p.now
		sw.since = p.now()
		buf := make([]byte, 64<<10)
		for sent := 0; sent < total; sent += len(buf) {
			if sent == 1<<20 && then != nil {
				then()
			}
			if _, err := sw.Write(buf); err != nil {
				return err
			}
		}
		return nil
	}
	start := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

	slow := &pacedWriter{clock: start, rate: zipMinRate * 0.6}
	if err := stream(slow, nil, 8<<20); !errors.Is(err, errZipTooSlow) {
		t.Fatalf("a stream read at 60%% of the floor: %v, want errZipTooSlow", err)
	}
	if limit := int64(float64(zipMinRate) * 2 * zipRateWindow.Seconds()); slow.took > limit {
		t.Fatalf("the slow stream sent %d bytes before it ended, want at most %d", slow.took, limit)
	}

	fast := &pacedWriter{clock: start, rate: zipMinRate * 1.5}
	if err := stream(fast, nil, 4<<20); err != nil {
		t.Fatalf("a stream read above the floor: %v", err)
	}

	burst := &pacedWriter{clock: start, rate: 1 << 20}
	err := stream(burst, func() { burst.rate = zipMinRate / 2 }, 64<<20)
	if !errors.Is(err, errZipTooSlow) {
		t.Fatalf("a fast start then a trickle: %v, want errZipTooSlow", err)
	}
}

// gatedRecorder holds a response's first write until gate closes, so a
// stream stays in flight for as long as a test needs it to.
type gatedRecorder struct {
	*httptest.ResponseRecorder
	started chan struct{}
	gate    chan struct{}
	once    sync.Once
}

func (g *gatedRecorder) Write(p []byte) (int, error) {
	g.once.Do(func() { close(g.started) })
	<-g.gate
	return g.ResponseRecorder.Write(p)
}

// Three zips run per client address (an IPv6 address by its /64) at a time: a home or
// a small office downloads side by side, and one address cannot take all of zipFloor's
// places. A fourth waits behind its own, while another address's stream goes ahead.
func TestThreeZipsRunPerAddress(t *testing.T) {
	saved := zipSlots
	zipSlots = newZipGate(func(int64) bool { return true })
	t.Cleanup(func() { zipSlots = saved })
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "pair", map[string]string{"a.txt": "alpha"})
	get := func(addr string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/zip/"+id, nil)
		r.RemoteAddr = addr
		return r
	}
	for _, c := range []struct{ name, same, other string }{
		{"ipv4", "203.0.113.5:1000", "203.0.113.6:1000"},
		{"ipv6 /64", "[2001:db8:0:1::1]:1000", "[2001:db8:0:2::1]:1000"},
	} {
		same := c.same
		if host, _, _ := net.SplitHostPort(same); strings.Contains(host, ":") {
			same = "[2001:db8:0:1::2]:1000" // the same /64, another address in it
		}
		gate := make(chan struct{})
		var running []chan struct{}
		for i := range zipsPerAddress {
			addr := c.same
			if i > 0 {
				addr = same
			}
			rec := &gatedRecorder{ResponseRecorder: httptest.NewRecorder(), started: make(chan struct{}), gate: gate}
			done := make(chan struct{})
			go func() { h.ServeHTTP(rec, get(addr)); close(done) }()
			select {
			case <-rec.started:
			case <-time.After(5 * time.Second):
				t.Fatalf("%s: stream %d of %d did not start", c.name, i+1, zipsPerAddress)
			}
			running = append(running, done)
		}

		over := httptest.NewRecorder()
		overDone := make(chan struct{})
		go func() { h.ServeHTTP(over, get(same)); close(overDone) }()
		select {
		case <-overDone:
			t.Fatalf("%s: one zip too many from the same address ran beside the others", c.name)
		case <-time.After(200 * time.Millisecond):
		}

		other := httptest.NewRecorder()
		otherDone := make(chan struct{})
		go func() { h.ServeHTTP(other, get(c.other)); close(otherDone) }()
		select {
		case <-otherDone:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: another address's zip waited behind them", c.name)
		}
		if other.Code != http.StatusOK {
			t.Fatalf("another address's zip = %d", other.Code)
		}

		close(gate)
		for _, done := range append(running, overDone) {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("a stream never finished once they were let go")
			}
		}
		if over.Code != http.StatusOK {
			t.Fatalf("the zip behind its own address = %d", over.Code)
		}
	}
	zipAddrs.mu.Lock()
	defer zipAddrs.mu.Unlock()
	if n := len(zipAddrs.keys); n != 0 {
		t.Fatalf("%d addresses still held after every stream ended", n)
	}
}

// A client that stops reading a zip must not keep the stream's place: zipSlots
// has two for the whole server and one per owner, so a stalled reader would
// queue every other zip of that owner's shares behind it for as long as the
// connection stays open.
func TestAStalledZipReaderGivesUpItsSlot(t *testing.T) {
	saved := zipStallTimeout
	zipStallTimeout = 300 * time.Millisecond
	t.Cleanup(func() { zipStallTimeout = saved })

	h := newTestAPI(t)
	// Far more than the loopback socket buffers hold, so the stream blocks on
	// the client rather than finishing into the kernel.
	id, _ := shareWithFiles(t, h, "big", map[string]string{
		"big.bin": strings.Repeat("x", 32<<20),
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetReadBuffer(4096)
	}
	if _, err := io.WriteString(conn, "GET /zip/"+id+" HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	// The status line proves the stream started, so the slot is held by it
	// and not by this test. Nothing past it is ever read.
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || !strings.Contains(line, "200") {
		t.Fatalf("status line = %q, %v", line, err)
	}

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		zipSlots.mu.Lock()
		running := zipSlots.running[metadb.DefaultAdminName]
		zipSlots.mu.Unlock()
		if running == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the stalled stream still holds its place")
}

// deadlineRecorder is a ResponseWriter that records every write deadline a
// handler sets through http.ResponseController.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
	writes    []int
}

func (d *deadlineRecorder) SetWriteDeadline(t time.Time) error {
	d.deadlines = append(d.deadlines, t)
	return nil
}

func (d *deadlineRecorder) Write(p []byte) (int, error) {
	d.writes = append(d.writes, len(p))
	return d.ResponseRecorder.Write(p)
}

// Each deadline covers one bounded chunk, so a slow client that keeps
// reading keeps its stream, and the deadline is cleared when the stream ends:
// the connection carries the next request too.
func TestAZipStreamSetsADeadlinePerChunkAndClearsIt(t *testing.T) {
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "chunks", map[string]string{
		"a.bin": strings.Repeat("y", 3*zipStallChunk+5),
	})
	rec := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/zip/"+id, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	for _, n := range rec.writes {
		if n > zipStallChunk {
			t.Fatalf("a write of %d bytes, past the %d one deadline covers", n, zipStallChunk)
		}
	}
	if len(rec.deadlines) < 4 {
		t.Fatalf("%d deadlines for a 3-chunk file", len(rec.deadlines))
	}
	if last := rec.deadlines[len(rec.deadlines)-1]; !last.IsZero() {
		t.Fatalf("the last deadline is %v, want cleared", last)
	}
}

// A zip that declared its exact length cannot skip a file whose bytes are
// gone: the body would end short of the length it promised. It stops at that
// file instead of streaming the rest of an archive the client will discard.
func TestADeclaredZipStopsAtAMissingFile(t *testing.T) {
	h, b := newTestAPIBackend(t)
	id, _ := shareWithFiles(t, h, "gone", map[string]string{
		"a.txt": "ALPHA-CONTENT", "b.txt": "BRAVO-CONTENT",
	})
	p, err := b.FS.FilePath(id, "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	serveUntilAborted(t, h, rec, httptest.NewRequest(http.MethodGet, "/zip/"+id, nil))
	if rec.Header().Get("Content-Length") == "" {
		t.Fatal("the archive declared no length; the case under test is the declared one")
	}
	if strings.Contains(rec.Body.String(), "BRAVO-CONTENT") {
		t.Fatal("the stream went on past the missing file")
	}
}

// Holding a place in line past the wait limit ends in the same busy answer as a full
// line: a request has no business waiting for good on a client's say-so.
func TestAZipThatWaitsTooLongIsToldTheServerIsBusy(t *testing.T) {
	savedSlots, savedLimit := zipSlots, zipWaitLimit
	zipSlots = newZipGate(func(int64) bool { return false })
	zipWaitLimit = 100 * time.Millisecond
	t.Cleanup(func() { zipSlots, zipWaitLimit = savedSlots, savedLimit })
	for range zipFloor {
		zipSlots.acquire(context.Background(), oneShare("someone-else"), 0)
	}
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "pair", map[string]string{"a.txt": "alpha"})
	r := httptest.NewRequest(http.MethodGet, "/zip/"+id, nil)
	r.RemoteAddr = "203.0.113.5:1000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("code %d", w.Code)
	}
	if w.Header().Get("Retry-After") != busyRetryAfter {
		t.Errorf("Retry-After %q", w.Header().Get("Retry-After"))
	}
	if strings.Contains(w.Body.String(), id) {
		t.Error("the busy page names the share")
	}
}

// A full line refuses at once rather than holding the request.
func TestAFullLineAnswersBusyAtOnce(t *testing.T) {
	saved := zipWaiting
	zipWaiting = newZipLine(func() int { return 0 })
	t.Cleanup(func() { zipWaiting = saved })
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "pair", map[string]string{"a.txt": "alpha"})
	r := httptest.NewRequest(http.MethodGet, "/zip/"+id, nil)
	r.RemoteAddr = "203.0.113.5:1000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("code %d", w.Code)
	}
}

// A flood on one share fills only that share's part of the line. Its next request is
// refused at once, while a visitor of another share of the same account gets a place,
// and starts ahead of the flood's older waiters when a place to run comes free.
func TestAFloodOnOneShareLeavesTheLineOpenForAnother(t *testing.T) {
	savedLine, savedSlots, savedLimit := zipWaiting, zipSlots, zipWaitLimit
	zipWaiting = newZipLine(func() int { return 2 * zipLineShareParts })
	zipSlots = newZipGate(func(int64) bool { return false })
	zipWaitLimit = time.Minute
	t.Cleanup(func() { zipWaiting, zipSlots, zipWaitLimit = savedLine, savedSlots, savedLimit })
	h := newTestAPI(t)
	flooded, _ := shareWithFiles(t, h, "flooded", map[string]string{"a.txt": "alpha"})
	quiet, _ := shareWithFiles(t, h, "quiet", map[string]string{"b.txt": "bravo"})
	floodTurn := zipTurn{owner: metadb.DefaultAdminName, share: flooded}
	for range zipFloor {
		if !zipSlots.acquire(context.Background(), floodTurn, 0) {
			t.Fatal("could not fill the places that run")
		}
	}
	get := func(ctx context.Context, id, addr string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/zip/"+id, nil).WithContext(ctx)
		r.RemoteAddr = addr
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	ctx, cancelFlood := context.WithCancel(context.Background())
	var flood sync.WaitGroup
	for i := range 2 {
		flood.Add(1)
		go func() {
			defer flood.Done()
			// A waiter that starts as the test ends drops its stream on the cancelled request.
			defer func() {
				if got := recover(); got != nil && got != http.ErrAbortHandler {
					t.Errorf("recovered %v", got)
				}
			}()
			get(ctx, flooded, fmt.Sprintf("203.0.113.%d:1000", i+1))
		}()
	}
	defer func() { cancelFlood(); flood.Wait() }()
	waitUntilBlocked(t, func() bool {
		zipWaiting.mu.Lock()
		defer zipWaiting.mu.Unlock()
		return zipWaiting.waiting == 2
	})
	if w := get(context.Background(), flooded, "203.0.113.50:1000"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("the flood's next request answered %d", w.Code)
	}
	answer := make(chan *httptest.ResponseRecorder, 1)
	go func() { answer <- get(context.Background(), quiet, "198.51.100.7:1000") }()
	waitUntilBlocked(t, func() bool {
		zipWaiting.mu.Lock()
		defer zipWaiting.mu.Unlock()
		return zipWaiting.waiting == 3
	})
	zipSlots.release(floodTurn, 0)
	select {
	case w := <-answer:
		if w.Code != http.StatusOK {
			t.Fatalf("the other share answered %d", w.Code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the other share never got its turn")
	}
}

// A zip once running holds no place in line: the line bounds who waits.
func TestARunningZipHoldsNoPlaceInLine(t *testing.T) {
	saved := zipWaiting
	zipWaiting = newZipLine(func() int { return 1 })
	t.Cleanup(func() { zipWaiting = saved })
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "pair", map[string]string{"a.txt": "alpha"})
	running := &gatedRecorder{ResponseRecorder: httptest.NewRecorder(), started: make(chan struct{}), gate: make(chan struct{})}
	done := make(chan struct{})
	r := httptest.NewRequest(http.MethodGet, "/zip/"+id, nil)
	r.RemoteAddr = "203.0.113.5:1000"
	go func() { h.ServeHTTP(running, r); close(done) }()
	defer func() { close(running.gate); <-done }()
	select {
	case <-running.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the stream never started")
	}
	leave, ok := zipWaiting.enter("198.51.100.7", "one-share")
	if !ok {
		t.Fatal("a running zip is still holding its place in line")
	}
	leave()
}

// zipFullAddress runs zipsPerAddress streams from addr until the returned call lets
// them finish.
func zipFullAddress(t *testing.T, h http.Handler, id, addr string) (finish func()) {
	t.Helper()
	gate := make(chan struct{})
	var dones []chan struct{}
	for range zipsPerAddress {
		rec := &gatedRecorder{ResponseRecorder: httptest.NewRecorder(), started: make(chan struct{}), gate: gate}
		r := httptest.NewRequest(http.MethodGet, "/zip/"+id, nil)
		r.RemoteAddr = addr
		done := make(chan struct{})
		go func() { h.ServeHTTP(rec, r); close(done) }()
		select {
		case <-rec.started:
		case <-time.After(5 * time.Second):
			t.Fatal("a stream never started")
		}
		dones = append(dones, done)
	}
	var once sync.Once
	finish = func() {
		once.Do(func() {
			close(gate)
			for _, d := range dones {
				<-d
			}
		})
	}
	t.Cleanup(finish)
	return finish
}

func zipPageRequest(id, addr string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/zip/"+id, nil)
	r.RemoteAddr = addr
	r.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	return r
}

// A person clicking Download sees why nothing is happening within seconds, and the
// page keeps trying for them: a browser spinning for minutes says nothing.
func TestABrowserWaitsBrieflyThenGetsAPageThatRetries(t *testing.T) {
	savedSlots, savedFresh, savedLimit := zipSlots, zipFreshWait, zipWaitLimit
	zipSlots = newZipGate(func(int64) bool { return false })
	zipFreshWait, zipWaitLimit = 50*time.Millisecond, time.Hour
	t.Cleanup(func() { zipSlots, zipFreshWait, zipWaitLimit = savedSlots, savedFresh, savedLimit })
	for range zipFloor {
		zipSlots.acquire(context.Background(), oneShare("someone-else"), 0)
	}
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "pair", map[string]string{"a.txt": "alpha"})
	w := httptest.NewRecorder()
	began := time.Now()
	h.ServeHTTP(w, zipPageRequest(id, "203.0.113.5:1000"))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("code %d", w.Code)
	}
	if time.Since(began) > 10*time.Second {
		t.Fatal("the browser waited past its brief wait")
	}
	body := w.Body.String()
	if !strings.Contains(body, `http-equiv="refresh" content="`+busyRetryAfter+`"`) {
		t.Errorf("the page does not retry: %s", body)
	}
	if !strings.Contains(body, "overloaded") || !strings.Contains(body, "starts by itself") {
		t.Errorf("the page does not say what is happening: %s", body)
	}
	if strings.Contains(body, id) {
		t.Error("the page names the share")
	}
	if w.Header().Get("Retry-After") != busyRetryAfter {
		t.Errorf("Retry-After %q", w.Header().Get("Retry-After"))
	}
}

// The wait behind an address's own streams is bounded the same way, and its page says
// what the visitor can do about it: the server is not overloaded.
func TestAFourthZipFromAnAddressIsToldWhy(t *testing.T) {
	savedSlots, savedFresh := zipSlots, zipFreshWait
	zipSlots = newZipGate(func(int64) bool { return true })
	zipFreshWait = 50 * time.Millisecond
	t.Cleanup(func() { zipSlots, zipFreshWait = savedSlots, savedFresh })
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "pair", map[string]string{"a.txt": "alpha"})
	zipFullAddress(t, h, id, "203.0.113.5:1000")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, zipPageRequest(id, "203.0.113.5:2000"))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("code %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "your connection") || !strings.Contains(body, strconv.Itoa(zipsPerAddress)) {
		t.Errorf("the page does not say why: %s", body)
	}
	if strings.Contains(body, "overloaded") {
		t.Error("the page blames the server")
	}
	if !strings.Contains(body, `http-equiv="refresh"`) {
		t.Error("the page does not retry")
	}
}

// A resume is a download the browser runs itself: no page can show, so it keeps waiting
// for its turn, up to the wait limit, behind its own address and in the gate alike.
func TestAResumeKeepsWaitingForItsTurn(t *testing.T) {
	savedSlots, savedFresh := zipSlots, zipFreshWait
	zipSlots = newZipGate(func(int64) bool { return true })
	zipFreshWait = 20 * time.Millisecond
	t.Cleanup(func() { zipSlots, zipFreshWait = savedSlots, savedFresh })
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "pair", map[string]string{"a.txt": "alpha"})
	finish := zipFullAddress(t, h, id, "203.0.113.5:1000")
	r := zipPageRequest(id, "203.0.113.5:2000")
	r.Header.Set("Range", "bytes=5-")
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { h.ServeHTTP(w, r); close(done) }()
	select {
	case <-done:
		t.Fatalf("a resume stopped waiting: %d", w.Code)
	case <-time.After(10 * zipFreshWait):
	}
	finish()
	<-done
	if w.Code != http.StatusPartialContent {
		t.Fatalf("code %d", w.Code)
	}
}

// So does a client that would save a page as the zip it asked for.
func TestAClientThatCannotShowAPageKeepsWaiting(t *testing.T) {
	savedSlots, savedFresh := zipSlots, zipFreshWait
	zipSlots = newZipGate(func(int64) bool { return true })
	zipFreshWait = 20 * time.Millisecond
	t.Cleanup(func() { zipSlots, zipFreshWait = savedSlots, savedFresh })
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "pair", map[string]string{"a.txt": "alpha"})
	finish := zipFullAddress(t, h, id, "203.0.113.5:1000")
	r := httptest.NewRequest(http.MethodGet, "/zip/"+id, nil)
	r.RemoteAddr = "203.0.113.5:2000"
	r.Header.Set("Accept", "*/*")
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { h.ServeHTTP(w, r); close(done) }()
	select {
	case <-done:
		t.Fatalf("it stopped waiting: %d", w.Code)
	case <-time.After(10 * zipFreshWait):
	}
	finish()
	<-done
	if w.Code != http.StatusOK {
		t.Fatalf("code %d", w.Code)
	}
}

// Even a resume's wait has an end, behind its own address too: a stream has no time
// bound, and a place in line must not be held for good.
func TestAResumeBehindItsOwnAddressStopsAtTheWaitLimit(t *testing.T) {
	savedSlots, savedLimit := zipSlots, zipWaitLimit
	zipSlots = newZipGate(func(int64) bool { return true })
	zipWaitLimit = 50 * time.Millisecond
	t.Cleanup(func() { zipSlots, zipWaitLimit = savedSlots, savedLimit })
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "pair", map[string]string{"a.txt": "alpha"})
	zipFullAddress(t, h, id, "203.0.113.5:1000")
	r := httptest.NewRequest(http.MethodGet, "/zip/"+id, nil)
	r.RemoteAddr = "203.0.113.5:2000"
	r.Header.Set("Range", "bytes=5-")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("code %d", w.Code)
	}
}

// A HEAD has nothing to wait for that a person is watching.
func TestAHeadWaitsBriefly(t *testing.T) {
	savedSlots, savedFresh, savedLimit := zipSlots, zipFreshWait, zipWaitLimit
	zipSlots = newZipGate(func(int64) bool { return false })
	zipFreshWait, zipWaitLimit = 50*time.Millisecond, time.Hour
	t.Cleanup(func() { zipSlots, zipFreshWait, zipWaitLimit = savedSlots, savedFresh, savedLimit })
	for range zipFloor {
		zipSlots.acquire(context.Background(), oneShare("someone-else"), 0)
	}
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "pair", map[string]string{"a.txt": "alpha"})
	r := httptest.NewRequest(http.MethodHead, "/zip/"+id, nil)
	r.RemoteAddr = "203.0.113.5:1000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("code %d", w.Code)
	}
}

// The load guard's refusal of a zip is the same page: it comes first, and the visitor
// waiting on the page may meet it on any retry.
func TestTheGuardsRefusalOfAZipRetriesToo(t *testing.T) {
	w := httptest.NewRecorder()
	writeBusy(w, httptest.NewRequest(http.MethodGet, "/zip/abc", nil))
	if !strings.Contains(w.Body.String(), `http-equiv="refresh"`) {
		t.Error("a refused zip does not retry")
	}
	w = httptest.NewRecorder()
	writeBusy(w, httptest.NewRequest(http.MethodGet, "/share/abc", nil))
	if strings.Contains(w.Body.String(), `http-equiv="refresh"`) {
		t.Error("a refused page reloads itself")
	}
}
