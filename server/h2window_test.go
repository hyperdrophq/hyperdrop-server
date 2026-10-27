package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/http2"
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
