package main

import (
	"bytes"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

// bytesConn is a connection whose peer sent data and closed.
type bytesConn struct {
	r    *bytes.Reader
	peer net.Addr
}

func (c *bytesConn) Read(b []byte) (int, error)       { return c.r.Read(b) }
func (c *bytesConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *bytesConn) Close() error                     { return nil }
func (c *bytesConn) LocalAddr() net.Addr              { return &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443} }
func (c *bytesConn) RemoteAddr() net.Addr             { return c.peer }
func (c *bytesConn) SetDeadline(time.Time) error      { return nil }
func (c *bytesConn) SetReadDeadline(time.Time) error  { return nil }
func (c *bytesConn) SetWriteDeadline(time.Time) error { return nil }

// oneConnListener accepts c once.
type oneConnListener struct{ c net.Conn }

func (l *oneConnListener) Accept() (net.Conn, error) {
	if l.c == nil {
		return nil, io.EOF
	}
	c := l.c
	l.c = nil
	return c, nil
}
func (l *oneConnListener) Close() error   { return nil }
func (l *oneConnListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443} }

// A connection's first bytes are the peer's. From a listed proxy, a connection
// that reads at all names a TCP address; from anyone else it keeps the TCP
// peer's address and its bytes arrive untouched.
func FuzzProxyHeader(f *testing.F) {
	f.Add(proxyV1("203.0.113.9:5000"))
	f.Add(append(proxyV1("203.0.113.9:5000"), "GET / HTTP/1.1\r\n\r\n"...))
	f.Add(append(proxyV2("203.0.113.9:5000"), 0x16, 0x03, 0x01))
	f.Add(proxyV2Local())
	f.Add(proxyV2Unix())
	f.Add([]byte("PROXY UNKNOWN\r\n"))
	f.Add([]byte("PROXY TCP4 203.0.113.9 192.0.2.1 65536 443\r\n"))
	f.Add([]byte{0x16, 0x03, 0x01, 0x02, 0x00})
	f.Add([]byte{})

	peer := &net.TCPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 40000}
	lists := map[bool][]netip.Prefix{
		true:  {netip.MustParsePrefix("198.51.100.0/24")},
		false: nil,
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		for listed, trusted := range lists {
			ln := wrapProxyListener(&oneConnListener{c: &bytesConn{r: bytes.NewReader(data), peer: peer}}, trusted, nil)
			conn, err := ln.Accept()
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(conn)
			remote := conn.RemoteAddr()
			if listed {
				if err != nil {
					continue
				}
				if _, ok := remote.(*net.TCPAddr); !ok {
					t.Fatalf("a listed proxy's connection is from %T %v", remote, remote)
				}
				if len(got) >= len(data) && len(data) > 0 {
					t.Fatalf("a listed proxy's connection was served without a header: %q", data)
				}
				continue
			}
			if remote.String() != peer.String() {
				t.Fatalf("an unlisted peer became %v", remote)
			}
			if err == nil && !bytes.Equal(got, data) {
				t.Fatalf("an unlisted peer's bytes changed: sent %q, read %q", data, got)
			}
		}
	})
}
