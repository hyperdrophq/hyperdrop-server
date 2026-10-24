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
// next line counting the ones in between. Every other handshake error is
// logged as it comes.
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
	l.Print("http: TLS handshake error from 66.132.172.136:35449: tls: client offered only unsupported versions: [301]")
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("%d lines, want 4 (one per LAN address, both unsupported-version lines):\n%s", len(lines), buf.String())
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
