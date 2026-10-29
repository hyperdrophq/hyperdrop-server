package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// bodyResult is what a test handler saw of its request body.
type bodyResult struct {
	n      int
	err    error
	proto  int
	remote string
	ctxErr error
}

// readingHandler reads the whole body, then waits hold before answering, and
// reports what it saw.
func readingHandler(out chan<- bodyResult, hold time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if hold > 0 {
			time.Sleep(hold)
		}
		out <- bodyResult{n: len(b), err: err, proto: r.ProtoMajor, remote: r.RemoteAddr, ctxErr: r.Context().Err()}
		if err != nil {
			http.Error(w, "body", http.StatusBadRequest)
			return
		}
		fmt.Fprint(w, len(b))
	})
}

func serveBodyTest(t *testing.T, ln net.Listener, d bodyDeadline, h http.Handler) {
	t.Helper()
	srv := &http.Server{Handler: d.wrap(h), ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
}

func awaitBody(t *testing.T, out <-chan bodyResult, within time.Duration) bodyResult {
	t.Helper()
	select {
	case res := <-out:
		return res
	case <-time.After(within):
		t.Fatalf("the handler was still reading its body after %v", within)
		return bodyResult{}
	}
}

func tlsTestConfig(t *testing.T, protos ...string) *tls.Config {
	t.Helper()
	certPEM, keyPEM := testLeafPEM(t, "share.example.com", []string{"share.example.com"},
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: protos}
}

// A client that sends its headers and part of its body and then goes quiet
// loses the request after the idle limit, over plain HTTP/1.1.
func TestAStalledBodyFailsOverHTTP1(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	out := make(chan bodyResult, 1)
	serveBodyTest(t, ln, bodyDeadline{idle: 200 * time.Millisecond, grace: time.Hour}, readingHandler(out, 0))

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "POST / HTTP/1.1\r\nHost: share.example.com\r\nContent-Length: 100\r\n\r\nabc")
	res := awaitBody(t, out, 5*time.Second)
	if !errors.Is(res.err, errBodyStalled) || res.n != 3 {
		t.Fatalf("read %d bytes, err %v: want the 3 sent and then the stall", res.n, res.err)
	}
}

// A body that keeps arriving, however slowly, is read to the end: no single
// wait reaches the idle limit, and with no floor the total never matters.
func TestABodyThatKeepsArrivingIsReadToTheEnd(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	out := make(chan bodyResult, 1)
	serveBodyTest(t, ln, bodyDeadline{idle: 300 * time.Millisecond, grace: time.Hour}, readingHandler(out, 0))

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	const parts = 8
	fmt.Fprintf(conn, "POST / HTTP/1.1\r\nHost: share.example.com\r\nContent-Length: %d\r\n\r\n", parts)
	for range parts {
		time.Sleep(100 * time.Millisecond)
		if _, err := conn.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	res := awaitBody(t, out, 5*time.Second)
	if res.err != nil || res.n != parts {
		t.Fatalf("read %d bytes, err %v: want all %d", res.n, res.err, parts)
	}
}

// A body that keeps arriving below the floor fails once its grace is spent,
// although no single wait reaches the idle limit.
func TestATricklingBodyFallsBelowTheFloor(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	out := make(chan bodyResult, 1)
	// 100 bytes a second earns 10 ms a byte; the client makes the server wait
	// about 50 ms for each.
	serveBodyTest(t, ln, bodyDeadline{idle: time.Second, grace: 300 * time.Millisecond, floor: 100}, readingHandler(out, 0))

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "POST / HTTP/1.1\r\nHost: share.example.com\r\nContent-Length: 1000\r\n\r\n")
	go func() {
		for range 1000 {
			time.Sleep(50 * time.Millisecond)
			if _, err := conn.Write([]byte("x")); err != nil {
				return
			}
		}
	}()
	res := awaitBody(t, out, 10*time.Second)
	if res.err == nil || res.n >= 100 {
		t.Fatalf("read %d bytes, err %v: want a failure within the first few bytes past the grace", res.n, res.err)
	}
}

// Once the body is read, a handler that keeps working longer than the idle
// limit keeps its request: no deadline is left on the connection for the
// HTTP/1.1 server's background read to trip over, which would cancel the
// request's context.
func TestAHandlerOutlivesTheIdleLimitAfterItsBody(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	out := make(chan bodyResult, 1)
	serveBodyTest(t, ln, bodyDeadline{idle: 100 * time.Millisecond, grace: 100 * time.Millisecond, floor: 1}, readingHandler(out, 600*time.Millisecond))

	resp, err := http.Post("http://"+ln.Addr().String()+"/", "text/plain", strings.NewReader("hello"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	res := awaitBody(t, out, 5*time.Second)
	if res.err != nil || res.n != 5 || res.ctxErr != nil {
		t.Fatalf("read %d bytes, err %v, context %v: want the body and a live request", res.n, res.err, res.ctxErr)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

// Over HTTP/2 the limit fails the one stream whose body stalled.
func TestAStalledBodyFailsOverHTTP2(t *testing.T) {
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	out := make(chan bodyResult, 1)
	serveBodyTest(t, tls.NewListener(tcp, tlsTestConfig(t, "h2", "http/1.1")),
		bodyDeadline{idle: 200 * time.Millisecond, grace: time.Hour}, readingHandler(out, 0))

	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: true}
	defer tr.CloseIdleConnections()
	pr, pw := io.Pipe()
	defer pw.Close()
	go func() {
		pw.Write([]byte("abc"))
	}()
	req, err := http.NewRequest("POST", "https://"+tcp.Addr().String()+"/", pr)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		if resp, err := tr.RoundTrip(req); err == nil {
			resp.Body.Close()
		}
	}()
	res := awaitBody(t, out, 5*time.Second)
	if res.proto != 2 {
		t.Fatalf("the request arrived over HTTP/%d, want 2", res.proto)
	}
	if !errors.Is(res.err, errBodyStalled) || res.n != 3 {
		t.Fatalf("read %d bytes, err %v: want the 3 sent and then the stall", res.n, res.err)
	}
}

// Behind a listed proxy the HTTPS listener is TCP, then PROXY, then TLS, and
// the abort still reaches the connection's pending read through both layers.
func TestAStalledBodyFailsBehindTheProxyListener(t *testing.T) {
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	trusted := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	out := make(chan bodyResult, 1)
	serveBodyTest(t, tls.NewListener(wrapProxyListener(tcp, trusted, nil), tlsTestConfig(t, "http/1.1")),
		bodyDeadline{idle: 200 * time.Millisecond, grace: time.Hour}, readingHandler(out, 0))

	raw, err := net.Dial("tcp", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	fmt.Fprint(raw, "PROXY TCP4 203.0.113.9 127.0.0.1 40000 443\r\n")
	conn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	fmt.Fprint(conn, "POST / HTTP/1.1\r\nHost: share.example.com\r\nContent-Length: 100\r\n\r\nabc")
	res := awaitBody(t, out, 5*time.Second)
	if !strings.HasPrefix(res.remote, "203.0.113.9:") {
		t.Fatalf("remote %q: the PROXY header was not applied", res.remote)
	}
	if !errors.Is(res.err, errBodyStalled) || res.n != 3 {
		t.Fatalf("read %d bytes, err %v: want the 3 sent and then the stall", res.n, res.err)
	}
	// The handler's answer still reaches the client.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("reading the answer: %v", err)
	}
	if resp != nil && resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want the handler's 400", resp.StatusCode)
	}
}

// The server built for both listeners reads every body under the limits.
func TestNewServerReadsBodiesUnderTheDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan bool, 1)
	srv := newServer("", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok := r.Body.(*deadlineBody)
		seen <- ok
	}))
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	resp, err := http.Post("http://"+ln.Addr().String()+"/", "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !<-seen {
		t.Fatal("newServer handed the handler an unwrapped body")
	}
}
