package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"hyperdrop/server/internal/api"
)

// The HTTPS server opens wide receive windows: the SETTINGS it sends first
// carry the per-stream window, and a WINDOW_UPDATE on stream 0 raises the
// connection's from the protocol's 64 KiB to h2ConnWindow, so the uploads
// sharing one connection are not held to Go's 1 MiB default per round trip.
func TestTheHTTPSServerOpensWideReceiveWindows(t *testing.T) {
	certPEM, keyPEM := testLeafPEM(t, "share.example.com", []string{"share.example.com"},
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := tls.NewListener(tcp, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}})
	srv := newServer("", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	conn, err := tls.Dial("tcp", tcp.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if p := conn.ConnectionState().NegotiatedProtocol; p != "h2" {
		t.Fatalf("negotiated %q, want h2", p)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		t.Fatal(err)
	}
	fr := http2.NewFramer(conn, conn)
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	var connWindow uint32 = 65535
	settings := false
	for !settings || connWindow < h2ConnWindow {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("reading the server's opening frames: %v (settings seen %v, connection window %d)", err, settings, connWindow)
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if f.IsAck() {
				continue
			}
			settings = true
			v, ok := f.Value(http2.SettingInitialWindowSize)
			if !ok || v != h2StreamWindow {
				t.Fatalf("stream window = %d (sent: %v), want %d", v, ok, h2StreamWindow)
			}
		case *http2.WindowUpdateFrame:
			if f.StreamID == 0 {
				connWindow += f.Increment
			}
		}
	}
	if connWindow != h2ConnWindow {
		t.Fatalf("connection window = %d, want %d", connWindow, h2ConnWindow)
	}
}

// Each HTTP/2 stream holds a goroutine, so what one connection may open is what it
// can make the server hold: the most RFC 9113 recommends a server not go below.
func TestOneConnectionOpensAHundredStreams(t *testing.T) {
	srv := newServer("", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if srv.HTTP2 == nil || srv.HTTP2.MaxConcurrentStreams != 100 {
		t.Fatalf("HTTP2 config %+v", srv.HTTP2)
	}
}

// The guard stands in front of every server this binary starts: past the few that
// always run, a server out of memory refuses.
func TestEveryServerStandsBehindTheLoadGuard(t *testing.T) {
	saved := serverGuard
	t.Cleanup(func() { serverGuard = saved })
	serverGuard = api.NewLoadGuard(func() api.MemoryReading { return api.MemoryReading{Used: 99, Limit: 100} })
	serverGuard.Tick()
	release := make(chan struct{})
	var entered, finished sync.WaitGroup
	srv := newServer("", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		entered.Done()
		<-release
	}))
	get := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		srv.Handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/share/x", nil))
		return w
	}
	for range 64 {
		entered.Add(1)
		finished.Add(1)
		go func() { defer finished.Done(); get() }()
	}
	entered.Wait()
	if w := get(); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("code %d past the few that always run", w.Code)
	}
	close(release)
	finished.Wait()
}

// A connection sitting idle after its one request is dropped when the guard starts
// refusing, on a real server: it holds memory no request limit can see.
func TestAnIdleConnectionIsDroppedWhenTheGuardRefuses(t *testing.T) {
	saved := serverGuard
	t.Cleanup(func() { serverGuard = saved })
	var used atomic.Int64
	used.Store(10)
	serverGuard = api.NewLoadGuard(func() api.MemoryReading { return api.MemoryReading{Used: used.Load(), Limit: 100} })
	srv := newServer("", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(conn)
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	used.Store(99)
	serverGuard.Tick()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := r.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("the idle connection stayed: %v", err)
	}
}
