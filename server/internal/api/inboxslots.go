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
// that long. A variable so a test can shorten it.
var inboxIdleTimeout = time.Minute

// inboxPacingLimits is the pace an anonymous body must keep to keep its
// slot, over the idle cut: the time the server spends waiting inside Read
// for the body may reach grace plus one second for every floor bytes
// received, so the sender averages at least the floor while the server
// waits on it. The floor is calm while the pool has room and busy once more
// than half the server's slots are taken (inboxSlots.floor): the slots are
// the one resource a stranger can hold, and a floor that rises with the
// pool's occupancy makes holding it cost bandwidth in proportion, where a
// fixed floor lets a few addresses trickling a kilobyte a second each hold
// every slot for as long as their declared lengths last. A slow sender on a
// crowded server yields; on a calm one it is read to the end.
type inboxPacingLimits struct {
	grace      time.Duration
	calm, busy int64 // bytes per second
}

// inboxPacing is the production pace: two minutes of grace, then the zip
// line's floor of 16 KiB/s on a calm server and 512 KiB/s past half the
// pool. A variable so a test can tighten it.
var inboxPacing = inboxPacingLimits{grace: 2 * time.Minute, calm: 16 << 10, busy: 512 << 10}

// An anonymous upload that fails after its row is declared (a body cut
// short, a stalled sender, a commit refused) costs the server two write
// transactions through the single writer and wakes the owner's devices
// twice, for nothing stored. One address gets inboxFailBurst such failures
// at once and inboxFailPerHour an hour (a token bucket, keyed like the
// slots); past that its uploads answer 429 until a token is back. An honest
// sender's uploads do not fail by the dozen.
const (
	inboxFailBurst   = 30
	inboxFailPerHour = 30
)

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

// floor is the pace the pool asks of every anonymous body right now.
func (s *inboxSlots) floor() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.total > inboxUploadsMax/2 {
		return inboxPacing.busy
	}
	return inboxPacing.calm
}

// pacedUpload reads an anonymous upload's body under the idle cut and the
// pool's pace (inboxPacing). Before every read it sets the connection's read
// deadline to the shorter of inboxIdleTimeout and what the body has left of
// its waiting budget, so the deadline only ever fires on a body that has
// stopped or fallen below the floor; the Read then answers the deadline
// error, which the route refuses as a stalled body. Nothing lifts the
// deadline afterwards: the server sets a kept-alive connection's deadline
// afresh for its next request, and a body abandoned midway must not hold the
// connection while the server drains it after the handler. A connection that
// cannot take a deadline (a test recorder) is read without one. The floor is
// asked for at each read, so a body that began on a calm server is held to
// the busy pace once the pool fills, and let go of it when the pool empties.
type pacedUpload struct {
	r     io.Reader
	rc    *http.ResponseController
	floor func() int64

	waited   time.Duration
	received int64
}

func (b *pacedUpload) Read(p []byte) (int, error) {
	limit := min(inboxIdleTimeout, b.budget())
	if limit <= 0 {
		return 0, ErrBodyStalled
	}
	start := time.Now()
	_ = b.rc.SetReadDeadline(start.Add(limit))
	n, err := b.r.Read(p)
	b.waited += time.Since(start)
	b.received += int64(n)
	return n, err
}

// budget is how much longer the body may keep the server waiting before it
// falls below the floor: the grace, plus a second per floor bytes received,
// minus the time already spent waiting.
func (b *pacedUpload) budget() time.Duration {
	earned := inboxPacing.grace
	if floor := b.floor(); floor > 0 {
		// Whole seconds first: received times a second overflows past 8.59 GiB.
		earned += time.Duration(b.received/floor)*time.Second +
			time.Duration(b.received%floor)*time.Second/time.Duration(floor)
	}
	return earned - b.waited
}
