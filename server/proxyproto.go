package main

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

// Behind a TCP pass-through proxy (HAProxy, nginx stream, Traefik TCP, the
// guide at /downloads/server/proxy/) every visitor arrives from the proxy's
// address, so the per-IP lockout and visitor counting would be shared by
// everyone. A proxy that speaks the PROXY protocol prepends the real source,
// and the HTTPS listener believes it from the peers the operator LISTED in
// HYPERDROP_TRUSTED_PROXIES and from nobody else. The listener is always
// wrapped, whether or not anything is listed:
//
//   - listed peer: the header is REQUIRED (v1 or v2). A listed proxy that
//     forgot send-proxy-v2 fails loudly rather than forwarding raw TCP, in
//     which a client's OWN leading header would be believed;
//   - any other peer, every peer when nothing is listed: a header refuses
//     the connection, and a connection without one is served as an ordinary
//     TLS connection.
//
// Both refusals are handed to the proxyWatch (proxywatch.go) with the TCP
// peer, so a wrong proxy setting, which fails every TLS handshake from that
// source, is reported in the health verdict and the status file rather than
// only in the server log. A listed peer that closes without sending a byte
// (a proxy's TCP health check) is refused like any header-less connection
// and not reported.
//
// Nothing is trusted implicitly, loopback included: an on-box forwarder
// (SSH tunnel, docker-proxy, a proxy without send-proxy) would otherwise let
// any client forge its address. An on-box proxy is listed as 127.0.0.1 or ::1.
//
// Only the HTTPS listener is wrapped. Port 80 holds no lockout (redirects,
// health, ACME, well-known), and the boot self-check and the provisioner dial
// its health route over loopback with no header, which REQUIRE would refuse.
//
// Each connection is a go-proxyproto v0.15 Conn with REQUIRE for a listed
// upstream (a missing header fails the first Read with ErrNoProxyProtocol)
// and REJECT for the rest (a present header fails it with
// ErrSuperfluousProxyHeader; a header-less connection passes untouched, its
// first bytes served from the buffer the check peeked into). The header is
// read lazily on the connection's first Read or RemoteAddr, which net/http
// does on the connection's own goroutine, so a silent client never stalls
// Accept, and the header timeout bounds how long it can sit there.

// errProxySource refuses a header whose source is not a TCP address.
var errProxySource = errors.New("PROXY header source is not TCP over IPv4 or IPv6")

// proxyTrusted reports whether a peer is a listed proxy.
func proxyTrusted(trusted []netip.Prefix, a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// validateProxyHeader keeps RemoteAddr a client's host:port, refusing the
// connection otherwise (never falling back to the proxy's address, which
// would share the lockout again):
//
//   - a v2 LOCAL command is a proxy's own connection (its health check),
//     with no client in it; the library then answers the TCP peer, the
//     listed proxy itself, which only that proxy can produce. Accepted;
//   - v1 "PROXY UNKNOWN" (which the library also reports as LOCAL) is what a
//     proxy sends for a client it cannot name, an AF_UNIX one among them, so
//     it is ambiguous between "the proxy itself" and "some client": refused;
//   - a PROXY command must name a TCP source over IPv4 or IPv6: an AF_UNIX
//     or UNSPEC source would make RemoteAddr a socket path or the proxy's
//     own address. Refused.
func validateProxyHeader(h *proxyproto.Header) error {
	if h.Command.IsLocal() {
		if h.Version == 2 {
			return nil
		}
		return errProxySource
	}
	if h.TransportProtocol != proxyproto.TCPv4 && h.TransportProtocol != proxyproto.TCPv6 {
		return errProxySource
	}
	if _, ok := h.SourceAddr.(*net.TCPAddr); !ok {
		return errProxySource
	}
	return nil
}

// proxyHeaderTimeout bounds how long a connection may take to show whether
// it starts with a PROXY header.
const proxyHeaderTimeout = 10 * time.Second

// proxyListener is the HTTPS listener's PROXY layer (the raw TCP listener
// under TLS: net.Listen, then this, then tls.NewListener, because the header
// precedes the ClientHello). It takes the visitor's address from a listed
// proxy's header and reports refused headers to watch.
type proxyListener struct {
	net.Listener
	trusted atomic.Pointer[[]netip.Prefix]
	watch   *proxyWatch
}

// wrapProxyListener wraps ln for the listed proxies, reporting to watch
// (nil: nothing is reported).
func wrapProxyListener(ln net.Listener, trusted []netip.Prefix, watch *proxyWatch) *proxyListener {
	l := &proxyListener{Listener: ln, watch: watch}
	l.trusted.Store(&trusted)
	return l
}

// Accept chooses each connection's policy from its TCP peer.
func (l *proxyListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	var peer netip.Addr
	if tcp, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		peer, _ = netip.AddrFromSlice(tcp.IP)
		peer = peer.Unmap()
	}
	policy, raw := proxyproto.REJECT, c
	var sent *sentConn
	if peer.IsValid() && proxyTrusted(*l.trusted.Load(), peer) {
		policy = proxyproto.REQUIRE
		sent = &sentConn{Conn: c}
		raw = sent
	}
	pc := proxyproto.NewConn(raw,
		proxyproto.WithPolicy(policy),
		proxyproto.ValidateHeader(validateProxyHeader),
		proxyproto.SetReadHeaderTimeout(proxyHeaderTimeout))
	if l.watch == nil {
		return pc, nil
	}
	return &watchedConn{Conn: pc, peer: peer, sent: sent, watch: l.watch}, nil
}

// sentConn notes whether a listed peer sent any byte, which tells a proxy
// that sent something other than a header from one that connected and
// closed: both fail with ErrNoProxyProtocol.
type sentConn struct {
	net.Conn
	got atomic.Bool
}

func (c *sentConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 && !c.got.Load() {
		c.got.Store(true)
	}
	return n, err
}

// watchedConn hands the first Read's PROXY refusal to the watch with the
// TCP peer. The header check runs once, on that Read or an earlier
// RemoteAddr, and every Read after a refusal repeats its error, so the first
// Read is the one that sees it.
type watchedConn struct {
	net.Conn
	peer  netip.Addr
	sent  *sentConn // nil unless the peer is listed
	watch *proxyWatch
	read  atomic.Bool
}

func (c *watchedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if !c.read.Load() && c.read.CompareAndSwap(false, true) {
		switch {
		case err == nil:
		case errors.Is(err, proxyproto.ErrSuperfluousProxyHeader):
			c.watch.Observe(c.peer, err)
		case errors.Is(err, proxyproto.ErrNoProxyProtocol) && c.sent != nil && c.sent.got.Load():
			c.watch.Observe(c.peer, err)
		}
	}
	return n, err
}

// joinPrefixes names the listed proxies for the boot log line.
func joinPrefixes(ps []netip.Prefix) string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return strings.Join(out, ", ")
}
