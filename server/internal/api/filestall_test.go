package api

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/metadb"
)

// A reader of /view, /download or /site that stops taking bytes is dropped
// once one chunk has waited fileStallTimeout on it, rather than holding the
// connection and the open file for as long as it stays connected.
func TestFileRoutesDropAStalledReader(t *testing.T) {
	saved := fileStallTimeout
	fileStallTimeout = 300 * time.Millisecond
	t.Cleanup(func() { fileStallTimeout = saved })

	h := newTestAPI(t)
	// Far more than the loopback socket buffers hold, so the response blocks
	// on the client rather than finishing into the kernel.
	const size = 32 << 20
	id, slugs := shareWithFiles(t, h, "big", map[string]string{
		"big.bin": strings.Repeat("x", size),
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	for _, path := range []string{
		"/download/" + id + "/" + slugs["big.bin"],
		"/view/" + id + "/" + slugs["big.bin"],
		"/site/" + id + "/big.bin",
	} {
		conn, err := net.Dial("tcp", srv.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetReadBuffer(4096)
		}
		if _, err := io.WriteString(conn, "GET "+path+" HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		br := bufio.NewReader(conn)
		line, err := br.ReadString('\n')
		if err != nil || !strings.Contains(line, "200") {
			t.Fatalf("%s: status line = %q, %v", path, line, err)
		}
		// Nothing more is read for several stall timeouts; then whatever the
		// server sent before it gave up is drained.
		time.Sleep(5 * fileStallTimeout)
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		got, _ := io.Copy(io.Discard, br)
		if got >= size {
			t.Fatalf("%s: the stalled reader was sent all %d bytes, want it dropped", path, got)
		}
	}
}

// On a live share the stall measures the visitor alone: a sharer whose
// uplink trickles the bytes in keeps a visitor who takes them at once, and
// a visitor who stops taking them is still dropped.
func TestALiveFileStallMeasuresTheVisitorNotTheSharer(t *testing.T) {
	saved := fileStallTimeout
	fileStallTimeout = 300 * time.Millisecond
	t.Cleanup(func() { fileStallTimeout = saved })

	h := newTestLiveShareHandler(t)
	mux := h.routes()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// A sharer sending 1 KiB in 64-byte pieces 50 ms apart: 800 ms in all,
	// well past one stall timeout.
	slow := strings.Repeat("s", 1<<10)
	sh := createLiveShare(t, mux, testToken, fmt.Sprintf(`{"name":"slow","files":[`+
		`{"path":"f.txt","size":%d,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"}]}`, len(slow)))
	go func() {
		for ctx.Err() == nil {
			offers, err := h.liveShareReg.Poll(ctx, sh.ID, metadb.DefaultAdminName, time.Second)
			if err != nil {
				return
			}
			for _, o := range offers {
				c, ok := h.liveShareReg.Claim(metadb.DefaultAdminName, o.Job)
				if !ok {
					continue
				}
				for i := 0; i < len(slow); i += 64 {
					io.WriteString(c, slow[i:i+64])
					time.Sleep(50 * time.Millisecond)
				}
				c.Close()
			}
		}
	}()
	res, err := http.Get(srv.URL + "/download/" + sh.ID + "/" + sh.Files[0].Slug)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil || string(body) != slow {
		t.Fatalf("a visitor of a slow sharer got %d of %d bytes: %v", len(body), len(slow), err)
	}

	const size = 32 << 20
	big := createLiveShare(t, mux, testToken, fmt.Sprintf(`{"name":"big","files":[`+
		`{"path":"big.bin","size":%d,"mime":"application/octet-stream","mtime":"2026-08-06T10:00:00Z"}]}`, size))
	serveLiveShareBody(t, h, big.ID, metadb.DefaultAdminName, strings.Repeat("x", size))
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetReadBuffer(4096)
	}
	if _, err := io.WriteString(conn, "GET /download/"+big.ID+"/"+big.Files[0].Slug+" HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	if line, err := br.ReadString('\n'); err != nil || !strings.Contains(line, "200") {
		t.Fatalf("status line = %q, %v", line, err)
	}
	time.Sleep(5 * fileStallTimeout)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if got, _ := io.Copy(io.Discard, br); got >= size {
		t.Fatalf("the stalled visitor of a live share was sent all %d bytes, want it dropped", got)
	}
}

// Over HTTP/2 a write deadline left armed resets the stream when it fires,
// even with no write pending, so the deadline is armed only while a chunk
// is being written: a sharer silent for longer than fileStallTimeout keeps
// a visitor who reads at once, and a visitor who stops reading is still
// dropped.
func TestALiveFileOverHTTP2SurvivesASilentSharer(t *testing.T) {
	saved := fileStallTimeout
	fileStallTimeout = 300 * time.Millisecond
	t.Cleanup(func() { fileStallTimeout = saved })

	h := newTestLiveShareHandler(t)
	mux := h.routes()
	srv := httptest.NewUnstartedServer(mux)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// A sharer sending half the file, falling silent for three stall
	// timeouts, then sending the rest.
	content := strings.Repeat("p", 64<<10)
	sh := createLiveShare(t, mux, testToken, fmt.Sprintf(`{"name":"paused","files":[`+
		`{"path":"f.bin","size":%d,"mime":"application/octet-stream","mtime":"2026-08-06T10:00:00Z"}]}`, len(content)))
	go func() {
		for ctx.Err() == nil {
			offers, err := h.liveShareReg.Poll(ctx, sh.ID, metadb.DefaultAdminName, time.Second)
			if err != nil {
				return
			}
			for _, o := range offers {
				c, ok := h.liveShareReg.Claim(metadb.DefaultAdminName, o.Job)
				if !ok {
					continue
				}
				half := len(content) / 2
				io.WriteString(c, content[:half])
				time.Sleep(3 * fileStallTimeout)
				io.WriteString(c, content[half:])
				c.Close()
			}
		}
	}()
	client := srv.Client()
	res, err := client.Get(srv.URL + "/download/" + sh.ID + "/" + sh.Files[0].Slug)
	if err != nil {
		t.Fatal(err)
	}
	if res.ProtoMajor != 2 {
		t.Fatalf("the visitor's request went over %s, want HTTP/2", res.Proto)
	}
	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil || string(body) != content {
		t.Fatalf("a visitor of a silent sharer got %d of %d bytes: %v", len(body), len(content), err)
	}

	// Far more than the client's stream window, so the response blocks on
	// the visitor.
	const size = 32 << 20
	big := createLiveShare(t, mux, testToken, fmt.Sprintf(`{"name":"big","files":[`+
		`{"path":"big.bin","size":%d,"mime":"application/octet-stream","mtime":"2026-08-06T10:00:00Z"}]}`, size))
	serveLiveShareBody(t, h, big.ID, metadb.DefaultAdminName, strings.Repeat("x", size))
	res, err = client.Get(srv.URL + "/download/" + big.ID + "/" + big.Files[0].Slug)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.ProtoMajor != 2 || res.StatusCode != http.StatusOK {
		t.Fatalf("the stalled visitor's response = %d over %s", res.StatusCode, res.Proto)
	}
	time.Sleep(5 * fileStallTimeout)
	got, err := io.Copy(io.Discard, res.Body)
	if err == nil || got >= size {
		t.Fatalf("the stalled HTTP/2 visitor read %d of %d bytes (%v), want the stream reset", got, size, err)
	}
}
