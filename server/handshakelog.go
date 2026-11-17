package main

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"
)

// handshakeLogWindow is how long an address's failed handshakes are counted
// rather than logged.
const handshakeLogWindow = time.Hour

// handshakeLogSourcesMax bounds the addresses remembered at once; past it
// the expired windows are forgotten and a new address is logged uncounted.
const handshakeLogSourcesMax = 1024

// handshakeLogLineMax is the most of a line a failed handshake logs. The rest
// of it can be the client's own text: a certificate lookup's error quotes the
// server name the client sent, up to tens of kilobytes of it.
const handshakeLogLineMax = 256

// failedHandshake matches net/http's line for any TLS handshake that failed,
// with the client's address and the error.
var failedHandshake = regexp.MustCompile(`(?s)^http: TLS handshake error from ([^ ]+): (.*)$`)

// abandonedError matches the error of a handshake the client gave up on before
// it finished: the connection closed (EOF) or was reset. A LAN client's
// reachability check that times out writes one of these on every run.
var abandonedError = regexp.MustCompile(`^(EOF|read tcp .*: connection reset by peer)$`)

// handshakeLog is the HTTP servers' error log. It writes every line through
// the standard logger, except a failed handshake: anyone who can reach the
// port can fail one cheaply, so each client address logs one per hour, the next
// line counting the ones in between, and at most handshakeLogLineMax bytes of
// it. An abandoned handshake is counted apart from every other failure, so a
// LAN client's noise never hides the error that says why a real client failed.
type handshakeLog struct {
	mu      sync.Mutex
	now     func() time.Time
	sources map[string]*handshakeSource
}

type handshakeSource struct {
	since      time.Time
	suppressed int
}

func newHandshakeLog(now func() time.Time) *handshakeLog {
	return &handshakeLog{now: now, sources: map[string]*handshakeSource{}}
}

// handshakeSourceOf names the address a handshake is counted under: the host,
// or for IPv6 its /64, every address of which one host can hold.
func handshakeSourceOf(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.Is6() && !ip.Is4In6() {
		if p, err := ip.Prefix(64); err == nil {
			return p.String()
		}
	}
	return host
}

// Write takes one line the server's error logger formatted.
func (l *handshakeLog) Write(p []byte) (int, error) {
	line := strings.TrimRight(string(p), "\n")
	m := failedHandshake.FindStringSubmatch(line)
	if m == nil {
		log.Print(line)
		return len(p), nil
	}
	if len(line) > handshakeLogLineMax {
		line = strings.ToValidUTF8(line[:handshakeLogLineMax], "")
	}
	host := handshakeSourceOf(m[1])
	key := host
	if !abandonedError.MatchString(m[2]) {
		key = "failed " + host
	}
	l.mu.Lock()
	now := l.now()
	src := l.sources[key]
	if src != nil && now.Sub(src.since) < handshakeLogWindow {
		src.suppressed++
		l.mu.Unlock()
		return len(p), nil
	}
	if src != nil && src.suppressed > 0 {
		line += fmt.Sprintf(" (%d more from %s since %s)", src.suppressed, host, src.since.UTC().Format("15:04 MST"))
	}
	if len(l.sources) >= handshakeLogSourcesMax {
		for k, v := range l.sources {
			if now.Sub(v.since) >= handshakeLogWindow {
				delete(l.sources, k)
			}
		}
	}
	if len(l.sources) < handshakeLogSourcesMax || src != nil {
		l.sources[key] = &handshakeSource{since: now}
	}
	l.mu.Unlock()
	log.Print(line)
	return len(p), nil
}
