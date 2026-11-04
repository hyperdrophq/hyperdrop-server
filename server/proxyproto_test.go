package main

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"hyperdrop/server/internal/api"
	"hyperdrop/server/internal/conffile"
)

func TestResolveBootParsesTrustedProxies(t *testing.T) {
	env := map[string]string{"HYPERDROP_ALLOW_PRIVATE": "1"}
	bc, err := resolveBoot(func(k string) string { return env[k] })
	if err != nil || len(bc.TrustedProxies) != 0 {
		t.Fatalf("unset variable: TrustedProxies = %v, %v; want none", bc.TrustedProxies, err)
	}
	env["HYPERDROP_TRUSTED_PROXIES"] = "192.168.1.30"
	bc, err = resolveBoot(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if !proxyTrusted(bc.TrustedProxies, netip.MustParseAddr("192.168.1.30")) {
		t.Fatalf("TrustedProxies = %v, want 192.168.1.30 in it", bc.TrustedProxies)
	}
	for _, bad := range []string{"192.168.1.30, nope", "0.0.0.0/0"} {
		env["HYPERDROP_TRUSTED_PROXIES"] = bad
		entry := strings.TrimSpace(bad[strings.LastIndex(bad, ",")+1:])
		if _, err := resolveBoot(func(k string) string { return env[k] }); err == nil || !strings.Contains(err.Error(), entry) {
			t.Fatalf("%q must refuse to boot naming %q, got %v", bad, entry, err)
		}
	}
}

func TestProxyTrustedUnmapsAndTrustsNothingImplicitly(t *testing.T) {
	trusted, _ := conffile.ParseTrustedProxies("192.168.1.30")
	if !proxyTrusted(trusted, netip.MustParseAddr("::ffff:192.168.1.30")) {
		t.Fatal("an IPv4-mapped peer must match its IPv4 entry")
	}
	if proxyTrusted(trusted, netip.MustParseAddr("192.168.1.31")) {
		t.Fatal("a neighbouring address must not be trusted")
	}
	for _, lo := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1"} {
		if proxyTrusted(trusted, netip.MustParseAddr(lo)) {
			t.Fatalf("%s is trusted without being listed", lo)
		}
	}
}

// startEchoServer serves r.RemoteAddr over a proxy-wrapped listener on
// 127.0.0.1, the same http.Server shape main uses.
func startEchoServer(t *testing.T, wrap func(net.Listener) net.Listener) (addr string, hits *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hits = new(atomic.Int32)
	srv := newServer("", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.WriteString(w, r.RemoteAddr)
	}))
	go srv.Serve(wrap(ln))
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String(), hits
}

func proxyV1(src string) []byte {
	ap := netip.MustParseAddrPort(src)
	return fmt.Appendf(nil, "PROXY TCP4 %s 127.0.0.1 %d 80\r\n", ap.Addr(), ap.Port())
}

func proxyV2(src string) []byte {
	ap := netip.MustParseAddrPort(src)
	b := []byte("\r\n\r\n\x00\r\nQUIT\n")
	b = append(b, 0x21, 0x11) // v2 PROXY, TCP over IPv4
	b = binary.BigEndian.AppendUint16(b, 12)
	a := ap.Addr().As4()
	b = append(b, a[:]...)
	b = append(b, 127, 0, 0, 1)
	b = binary.BigEndian.AppendUint16(b, ap.Port())
	b = binary.BigEndian.AppendUint16(b, 80)
	return b
}

// proxyV2Local is a v2 LOCAL header (a proxy's own health check).
func proxyV2Local() []byte {
	b := []byte("\r\n\r\n\x00\r\nQUIT\n")
	return append(b, 0x20, 0x00, 0x00, 0x00)
}

// proxyV2Unix is a v2 PROXY header whose source is an AF_UNIX socket.
func proxyV2Unix() []byte {
	b := []byte("\r\n\r\n\x00\r\nQUIT\n")
	b = append(b, 0x21, 0x31) // v2 PROXY, UNIX stream
	b = binary.BigEndian.AppendUint16(b, 216)
	src := make([]byte, 108)
	copy(src, "/tmp/forged.sock")
	return append(append(b, src...), make([]byte, 108)...)
}

// rawGet sends prefix then a GET over one fresh connection and answers the
// response body, or an error when the server closed the connection instead.
func rawGet(addr string, prefix []byte) (string, error) {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(append(append([]byte{}, prefix...), "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"...)); err != nil {
		return "", err
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return string(body), err
}

func listed(t *testing.T, s string) func(net.Listener) net.Listener {
	trusted, err := conffile.ParseTrustedProxies(s)
	if err != nil {
		t.Fatal(err)
	}
	return func(ln net.Listener) net.Listener { return wrapProxyListener(ln, trusted, nil) }
}

func TestProxyListenerListedPeer(t *testing.T) {
	addr, hits := startEchoServer(t, listed(t, "127.0.0.1"))

	for name, hdr := range map[string][]byte{"v2": proxyV2("203.0.113.9:4444"), "v1": proxyV1("203.0.113.9:4444")} {
		got, err := rawGet(addr, hdr)
		if err != nil || got != "203.0.113.9:4444" {
			t.Errorf("listed peer, %s header: got %q, %v; want 203.0.113.9:4444", name, got, err)
		}
	}
	// A LOCAL header carries no client: the address is the proxy's own.
	if got, err := rawGet(addr, proxyV2Local()); err != nil || !strings.HasPrefix(got, "127.0.0.1:") {
		t.Errorf("listed peer, LOCAL header: got %q, %v; want 127.0.0.1:…", got, err)
	}
	before := hits.Load()
	// A listed proxy that forgot send-proxy-v2 must fail loudly, or a
	// client's own leading header would be believed through it.
	if got, err := rawGet(addr, nil); err == nil {
		t.Errorf("listed peer without a header was served: %q", got)
	}
	// A non-TCP source would make RemoteAddr a socket path.
	if got, err := rawGet(addr, proxyV2Unix()); err == nil {
		t.Errorf("listed peer, AF_UNIX source was served: %q", got)
	}
	if got, err := rawGet(addr, []byte("PROXY UNKNOWN\r\n")); err == nil {
		t.Errorf("listed peer, PROXY UNKNOWN was served: %q", got)
	}
	if n := hits.Load() - before; n != 0 {
		t.Fatalf("the handler ran %d times for refused connections", n)
	}
}

func TestProxyListenerUnlistedPeer(t *testing.T) {
	// Loopback is NOT trusted unless listed: dial from 127.0.0.1 against a
	// list that names someone else.
	addr, hits := startEchoServer(t, listed(t, "192.0.2.1"))

	if got, err := rawGet(addr, proxyV2("203.0.113.9:4444")); err == nil {
		t.Errorf("unlisted peer with a v2 header was served: %q", got)
	}
	if got, err := rawGet(addr, proxyV1("203.0.113.9:4444")); err == nil {
		t.Errorf("unlisted peer with a v1 header was served: %q", got)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the handler ran %d times for a forged header", n)
	}
	got, err := rawGet(addr, nil)
	if err != nil || !strings.HasPrefix(got, "127.0.0.1:") {
		t.Errorf("unlisted peer without a header: got %q, %v; want 127.0.0.1:…", got, err)
	}
}

func TestProxyListenerRefusesHeadersWhenNothingIsListed(t *testing.T) {
	addr, hits := startEchoServer(t, listed(t, ""))
	if got, err := rawGet(addr, proxyV2("203.0.113.9:4444")); err == nil {
		t.Fatalf("a header was served with nothing listed: %q", got)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the handler ran %d times for a header-prefixed request", n)
	}
	if got, err := rawGet(addr, nil); err != nil || !strings.HasPrefix(got, "127.0.0.1:") {
		t.Errorf("no header: got %q, %v; want 127.0.0.1:…", got, err)
	}
}

// startTLSWatched serves "ok" over TCP, then the proxy listener with a
// watch, then TLS, the order main uses.
func startTLSWatched(t *testing.T, list string) (addr string, w *proxyWatch) {
	t.Helper()
	trusted, err := conffile.ParseTrustedProxies(list)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	w = newProxyWatch(nil)
	w.logf = func(string, ...any) {}
	srv := newServer("", http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) { io.WriteString(rw, "ok") }))
	srv.ErrorLog = log.New(io.Discard, "", 0)
	go srv.Serve(tls.NewListener(wrapProxyListener(ln, trusted, w), tlsTestConfig(t, "http/1.1")))
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String(), w
}

// tlsGet sends prefix, then a TLS GET, over one fresh connection.
func tlsGet(addr string, prefix []byte) (string, error) {
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := raw.Write(prefix); err != nil {
		return "", err
	}
	c := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	if _, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: share.example.com\r\nConnection: close\r\n\r\n"); err != nil {
		return "", err
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return string(body), err
}

// awaitSources waits for the watch to hold n private sources: the server
// observes on its own goroutine.
func awaitSources(t *testing.T, w *proxyWatch, n int) []ProxySource {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		private, _ := w.Snapshot()
		if len(private) >= n || time.Now().After(deadline) {
			return private
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPlainTLSHandshakeWithNothingListedSucceeds(t *testing.T) {
	addr, w := startTLSWatched(t, "")
	start := time.Now()
	if got, err := tlsGet(addr, nil); err != nil || got != "ok" {
		t.Fatalf("plain TLS with nothing listed: %q, %v", got, err)
	}
	// The header check reads what TLS reads first and waits for nothing.
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("a plain TLS request took %v", d)
	}
	if private, public := w.Snapshot(); len(private) != 0 || public != 0 {
		t.Fatalf("a plain connection was observed: %+v, %d", private, public)
	}
}

func TestUntrustedHeaderIsObservedWithNoProxyListed(t *testing.T) {
	addr, w := startTLSWatched(t, "")
	if got, err := tlsGet(addr, proxyV2("203.0.113.9:4444")); err == nil {
		t.Fatalf("a PROXY header from an unlisted peer was served: %q", got)
	}
	private := awaitSources(t, w, 1)
	if len(private) != 1 || private[0].Addr != "127.0.0.1" || private[0].Kind != api.ProxyKindUntrustedHeader {
		t.Fatalf("observed %+v, want the loopback peer as untrusted-header", private)
	}
}

func TestTrustedPeerWithoutHeaderIsObserved(t *testing.T) {
	addr, w := startTLSWatched(t, "127.0.0.1")
	if got, err := tlsGet(addr, nil); err == nil {
		t.Fatalf("a listed peer without a header was served: %q", got)
	}
	private := awaitSources(t, w, 1)
	if len(private) != 1 || private[0].Addr != "127.0.0.1" || private[0].Kind != api.ProxyKindTrustedNoHeader {
		t.Fatalf("observed %+v, want the loopback peer as trusted-no-header", private)
	}
	// A listed proxy's header still serves, and is not observed.
	if got, err := tlsGet(addr, proxyV2("203.0.113.9:4444")); err != nil || got != "ok" {
		t.Fatalf("listed peer with a header: %q, %v", got, err)
	}
	if private, _ := w.Snapshot(); private[0].Count != 1 {
		t.Fatalf("a good connection was counted: %+v", private)
	}
}

// A proxy's TCP health check connects and closes without a byte: that is no
// missing header, and it must not raise the warning.
func TestTrustedPeerThatSendsNothingIsNotObserved(t *testing.T) {
	addr, w := startTLSWatched(t, "127.0.0.1")
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	// A request after it shows the server got past the empty connection.
	if _, err := tlsGet(addr, proxyV2("203.0.113.9:4444")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if private, public := w.Snapshot(); len(private) != 0 || public != 0 {
		t.Fatalf("an empty connection was observed: %+v, %d", private, public)
	}
}

func TestProxyListenerSilentClientDoesNotBlockOthers(t *testing.T) {
	addr, _ := startEchoServer(t, listed(t, "127.0.0.1"))

	silent, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	time.Sleep(100 * time.Millisecond) // let the server accept it first

	done := make(chan error, 1)
	go func() {
		got, err := rawGet(addr, proxyV2("203.0.113.9:4444"))
		if err == nil && got != "203.0.113.9:4444" {
			err = fmt.Errorf("got %q", got)
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a silent client blocked another client's request")
	}
}
