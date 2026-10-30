package main

import (
	"fmt"
	"log"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

// handshakeLogWindow is how long an address's abandoned handshakes are
// counted rather than logged.
const handshakeLogWindow = time.Hour

// handshakeLogSourcesMax bounds the addresses remembered at once; past it
// the expired windows are forgotten and a new address is logged uncounted.
const handshakeLogSourcesMax = 1024

// abandonedHandshake matches net/http's line for a TLS handshake the client
// gave up on before it finished: the connection closed (EOF) or was reset.
// A LAN client's reachability check that times out writes one of these on
// every run, which says nothing new after the first.
var abandonedHandshake = regexp.MustCompile(`^http: TLS handshake error from ([^ ]+): (EOF|read tcp .*: connection reset by peer)$`)

// handshakeLog is the HTTP servers' error log. It writes every line through
// the standard logger, except that an abandoned handshake is logged at most
// once an hour per client address, the next line counting the ones in
// between.
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

// Write takes one line the server's error logger formatted.
func (l *handshakeLog) Write(p []byte) (int, error) {
	line := strings.TrimRight(string(p), "\n")
	m := abandonedHandshake.FindStringSubmatch(line)
	if m == nil {
		log.Print(line)
		return len(p), nil
	}
	host, _, err := net.SplitHostPort(m[1])
	if err != nil {
		host = m[1]
	}
	l.mu.Lock()
	now := l.now()
	src := l.sources[host]
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
		l.sources[host] = &handshakeSource{since: now}
	}
	l.mu.Unlock()
	log.Print(line)
	return len(p), nil
}
