package api

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
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
// zipSem's slots for as long as it likes.
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

// One zip runs per client address (an IPv6 address by its /64) at a time:
// a second from the same address waits behind its own first, while another
// address's stream goes ahead.
func TestZipOneStreamPerAddress(t *testing.T) {
	saved := zipSem
	zipSem = newFairSem(2, 2)
	t.Cleanup(func() { zipSem = saved })
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "pair", map[string]string{"a.txt": "alpha"})
	get := func(addr string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/zip/"+id, nil)
		r.RemoteAddr = addr
		return r
	}
	for _, c := range []struct{ first, same, other string }{
		{"203.0.113.5:1000", "203.0.113.5:2000", "198.51.100.7:1000"},
		{"[2001:db8:1:2::5]:1000", "[2001:db8:1:2::9]:1000", "[2001:db8:1:3::5]:1000"},
	} {
		first := &gatedRecorder{ResponseRecorder: httptest.NewRecorder(),
			started: make(chan struct{}), gate: make(chan struct{})}
		var once sync.Once
		open := func() { once.Do(func() { close(first.gate) }) }
		t.Cleanup(open)
		firstDone := make(chan struct{})
		go func() { h.ServeHTTP(first, get(c.first)); close(firstDone) }()
		select {
		case <-first.started:
		case <-time.After(5 * time.Second):
			t.Fatal("the first stream never started")
		}

		same := httptest.NewRecorder()
		sameDone := make(chan struct{})
		go func() { h.ServeHTTP(same, get(c.same)); close(sameDone) }()
		select {
		case <-sameDone:
			t.Fatalf("%s: a second zip from the same address ran beside the first", c.same)
		case <-time.After(200 * time.Millisecond):
		}

		other := httptest.NewRecorder()
		otherDone := make(chan struct{})
		go func() { h.ServeHTTP(other, get(c.other)); close(otherDone) }()
		select {
		case <-otherDone:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: another address's zip waited behind the first", c.other)
		}
		if other.Code != http.StatusOK {
			t.Fatalf("another address's zip = %d", other.Code)
		}

		open()
		for _, done := range []chan struct{}{firstDone, sameDone} {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("a stream never finished once the first was let go")
			}
		}
		if same.Code != http.StatusOK {
			t.Fatalf("the same address's second zip = %d", same.Code)
		}
	}
	zipAddrs.mu.Lock()
	defer zipAddrs.mu.Unlock()
	if n := len(zipAddrs.keys); n != 0 {
		t.Fatalf("%d addresses still held after every stream ended", n)
	}
}

// A client that stops reading a zip must not keep the stream's slot: zipSem
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

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if !zipSem.acquire(ctx, metadb.DefaultAdminName) {
		t.Fatal("the stalled stream still holds the owner's zip slot")
	}
	zipSem.release(metadb.DefaultAdminName)
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
	rec := doReq(t, h, "GET", "/zip/"+id, "", "")
	if rec.Header().Get("Content-Length") == "" {
		t.Fatal("the archive declared no length; the case under test is the declared one")
	}
	if strings.Contains(rec.Body.String(), "BRAVO-CONTENT") {
		t.Fatal("the stream went on past the missing file")
	}
}
