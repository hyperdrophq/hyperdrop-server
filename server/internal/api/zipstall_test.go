package api

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/metadb"
)

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
