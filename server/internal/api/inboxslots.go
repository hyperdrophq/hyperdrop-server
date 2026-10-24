package api

import (
	"io"
	"net/http"
	"sync"
	"time"
)

// The anonymous upload is the one write a stranger can open, and the server
// sets no ReadTimeout (a multi-GB body is legitimate), so each upload in
// flight pins a goroutine, a socket, a part's descriptors, a pending row, a
// claim and a pooled 1 MiB copy buffer. These bound how many a server holds:
// across every inbox, into one inbox, and from one address. A sender past a
// bound is refused, never queued, and the upload page sends one file at a
// time.
const (
	inboxUploadsMax      = 64
	inboxUploadsPerShare = 16
	inboxUploadsPerAddr  = 8
)

// inboxIdleTimeout ends an anonymous upload whose body has sent nothing for
// that long; a body that keeps moving, however slowly, is never cut. A
// variable so a test can shorten it.
var inboxIdleTimeout = time.Minute

// inboxSlots counts the anonymous uploads in flight. Its maps hold an entry
// only while an upload holds it, so a key a stranger chooses (an address)
// never outlives the request, and the server-wide bound, checked with the
// others, bounds both maps.
type inboxSlots struct {
	mu      sync.Mutex
	total   int
	byShare map[string]int
	byAddr  map[string]int
}

func newInboxSlots() *inboxSlots {
	return &inboxSlots{byShare: map[string]int{}, byAddr: map[string]int{}}
}

// take holds a slot for one upload into shareID from addr, or answers false
// when any bound is reached. The release gives the slot back; it is safe to
// call more than once.
func (s *inboxSlots) take(shareID, addr string) (release func(), ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.total >= inboxUploadsMax || s.byShare[shareID] >= inboxUploadsPerShare || s.byAddr[addr] >= inboxUploadsPerAddr {
		return nil, false
	}
	s.total++
	s.byShare[shareID]++
	s.byAddr[addr]++
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.total--
			if s.byShare[shareID]--; s.byShare[shareID] == 0 {
				delete(s.byShare, shareID)
			}
			if s.byAddr[addr]--; s.byAddr[addr] == 0 {
				delete(s.byAddr, addr)
			}
		})
	}, true
}

// idleBody pushes the connection's read deadline inboxIdleTimeout ahead of
// every read of the body, so the deadline only ever fires on a body that has
// stopped. Nothing lifts it afterwards: the server sets a kept-alive
// connection's deadline afresh for its next request, and a body abandoned
// midway must not hold the connection while the server drains it after the
// handler. A connection that cannot take a deadline (a test recorder) is
// read without one.
type idleBody struct {
	r  io.Reader
	rc *http.ResponseController
}

func (b idleBody) Read(p []byte) (int, error) {
	_ = b.rc.SetReadDeadline(time.Now().Add(inboxIdleTimeout))
	return b.r.Read(p)
}
