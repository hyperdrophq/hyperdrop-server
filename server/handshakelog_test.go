package main

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"
)

func captureStdLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev, flags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prev); log.SetFlags(flags) })
	return &buf
}

// A handshake the client abandoned (EOF, a reset) is noise when it repeats
// all day from a LAN client: it is logged once an hour per address, the
// next line counting the ones in between.
func TestAbandonedHandshakesAreCountedPerAddressAndHour(t *testing.T) {
	buf := captureStdLog(t)
	now := time.Date(2026, 10, 22, 8, 0, 0, 0, time.UTC)
	f := newHandshakeLog(func() time.Time { return now })
	l := log.New(f, "", 0)
	l.Print("http: TLS handshake error from 192.168.1.29:57758: EOF")
	l.Print("http: TLS handshake error from 192.168.1.29:57759: EOF")
	l.Print("http: TLS handshake error from 192.168.1.29:57760: read tcp 192.168.1.10:5443->192.168.1.29:57760: read: connection reset by peer")
	l.Print("http: TLS handshake error from 192.168.1.68:61000: EOF")
	l.Print("http: TLS handshake error from 66.132.172.136:35448: tls: client offered only unsupported versions: [302 301]")
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("%d lines, want 3 (one per LAN address, the unsupported-version line):\n%s", len(lines), buf.String())
	}
	now = now.Add(61 * time.Minute)
	l.Print("http: TLS handshake error from 192.168.1.29:58000: EOF")
	if !strings.Contains(buf.String(), "192.168.1.29:58000: EOF (2 more from 192.168.1.29 since 08:00 UTC)") {
		t.Fatalf("the next hour's line does not count the ones in between:\n%s", buf.String())
	}
	l.Print("http: some other server error")
	if !strings.Contains(buf.String(), "http: some other server error") {
		t.Fatal("another error was swallowed")
	}
}

// A failed handshake costs the client almost nothing and its server name is the
// client's own text, so a stranger must not be able to fill the log with them
// and rotate the history away: each address logs one per class per hour, cut
// short, and the two classes never hide each other.
func TestEveryFailedHandshakeIsCountedAndCutShort(t *testing.T) {
	buf := captureStdLog(t)
	now := time.Date(2026, 10, 22, 8, 0, 0, 0, time.UTC)
	f := newHandshakeLog(func() time.Time { return now })
	l := log.New(f, "", 0)
	sni := strings.Repeat("a", 60_000)
	for i := range 200 {
		l.Printf("http: TLS handshake error from 203.0.113.9:%d: no certificate available for '%s'", 1000+i, sni)
	}
	l.Print("http: TLS handshake error from 203.0.113.9:5: EOF")
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("%d lines, want one per class", len(lines))
	}
	if len(lines[0]) > handshakeLogLineMax {
		t.Fatalf("a line of %d bytes", len(lines[0]))
	}
	now = now.Add(61 * time.Minute)
	l.Print("http: TLS handshake error from 203.0.113.9:6: no certificate available for 'x'")
	if !strings.Contains(buf.String(), "(199 more from 203.0.113.9 since 08:00 UTC)") {
		t.Fatalf("the next hour's line does not count the ones in between:\n%.400s", buf.String())
	}
}

// A host holds a whole IPv6 /64, so its addresses count as one source.
func TestAnIPv6PrefixIsOneHandshakeSource(t *testing.T) {
	buf := captureStdLog(t)
	f := newHandshakeLog(time.Now)
	l := log.New(f, "", 0)
	l.Print("http: TLS handshake error from [2001:db8:1:2::1]:443: remote error: tls: bad certificate")
	l.Print("http: TLS handshake error from [2001:db8:1:2::2]:443: remote error: tls: bad certificate")
	l.Print("http: TLS handshake error from [2001:db8:1:3::1]:443: remote error: tls: bad certificate")
	if got := strings.Count(strings.TrimSpace(buf.String()), "\n") + 1; got != 2 {
		t.Fatalf("%d lines, want one per /64:\n%s", got, buf.String())
	}
}
