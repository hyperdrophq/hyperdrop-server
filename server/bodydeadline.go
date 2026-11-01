package main

import (
	"io"
	"net/http"
	"sync"
	"time"

	"hyperdrop/server/internal/api"
)

// A request body is read under two limits, because the server has no
// ReadTimeout (an upload legitimately runs for hours) and a client that
// sends complete headers and then trickles its body would otherwise hold a
// connection, its goroutine and its buffers for as long as it likes:
//
//   - idle: one Read may wait this long for the client's next bytes;
//   - floor: the time spent waiting inside Read, summed over the body, may
//     reach grace plus one second for every floor bytes received, so a client
//     has to average at least floor bytes a second while it is the one being
//     waited on.
//
// Only time spent INSIDE Read counts. A handler that pauses between reads
// (writing to a slow disk, relaying a live share to a slow viewer) spends
// none of the client's budget, and a client held back by its own stream's
// flow control is not being waited on either. On HTTP/2 the connection's
// window is shared, though, and the server returns it only as handlers
// read: streams whose handlers paused (live relays to paused visitors) hold
// up to h2StreamWindow each, and a stream on the same connection starved by
// them waits inside Read and runs down its budget like a stalled client.
//
// Nothing sets a connection deadline while a body is healthy: a Read that
// overruns is aborted by setting the read deadline into the past through
// http.ResponseController, which on HTTP/1.1 fails the connection's pending
// read (over a PROXY-wrapped listener too, whose connection passes the
// deadline down) and on HTTP/2 closes that one stream's body. A deadline left
// armed would fail the HTTP/1.1 server's background read once the body is
// done, cancelling the request's context, and on HTTP/2 a stream timer fires
// whether or not anyone is reading.
type bodyDeadline struct {
	idle  time.Duration
	grace time.Duration
	floor int64 // bytes per second
}

// The production limits: a minute of silence, and about 8 kbit/s averaged
// after the first two minutes of waiting.
var serverBodyDeadline = bodyDeadline{idle: time.Minute, grace: 2 * time.Minute, floor: 1024}

// errBodyStalled is what a Read answers once its body ran out of time, the
// error the routes answer 408 body-incomplete.
var errBodyStalled = api.ErrBodyStalled

// wrap puts every request body next reads under the limits.
func (d bodyDeadline) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body == nil || r.Body == http.NoBody {
			next.ServeHTTP(w, r)
			return
		}
		b := &deadlineBody{ReadCloser: r.Body, limits: d, rc: http.NewResponseController(w)}
		r.Body = b
		defer b.finish()
		next.ServeHTTP(w, r)
	})
}

type deadlineBody struct {
	io.ReadCloser
	limits bodyDeadline
	rc     *http.ResponseController

	mu       sync.Mutex
	timer    *time.Timer
	deadline time.Time // when the Read in progress overruns; zero between reads
	waited   time.Duration
	received int64
	expired  bool
	done     bool
}

func (b *deadlineBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	if b.expired {
		b.mu.Unlock()
		return 0, errBodyStalled
	}
	limit := min(b.limits.idle, b.budget())
	if limit <= 0 {
		b.expired = true
		b.mu.Unlock()
		return 0, errBodyStalled
	}
	start := time.Now()
	b.deadline = start.Add(limit)
	if b.timer == nil {
		b.timer = time.AfterFunc(limit, b.expire)
	} else {
		b.timer.Reset(limit)
	}
	b.mu.Unlock()

	n, err := b.ReadCloser.Read(p)

	b.mu.Lock()
	b.timer.Stop()
	b.deadline = time.Time{}
	b.waited += time.Since(start)
	b.received += int64(n)
	// An aborted Read answers whatever the connection made of the deadline
	// (a timeout on HTTP/1.1, a closed stream on HTTP/2); the body's own
	// error names the cause instead.
	if b.expired && err != io.EOF {
		err = errBodyStalled
	}
	b.mu.Unlock()
	return n, err
}

// budget is how much longer the client may keep the server waiting in Read
// before it falls below the floor.
func (b *deadlineBody) budget() time.Duration {
	earned := b.limits.grace
	if b.limits.floor > 0 {
		earned += time.Duration(b.received) * time.Second / time.Duration(b.limits.floor)
	}
	return earned - b.waited
}

// expire aborts the Read in progress when it has overrun. A timer from an
// earlier Read that fires late finds no Read, or one whose deadline is still
// ahead, and does nothing.
func (b *deadlineBody) expire() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.done || b.deadline.IsZero() || time.Now().Before(b.deadline) {
		return
	}
	b.expired = true
	b.rc.SetReadDeadline(time.Now().Add(-time.Second))
}

// finish runs when the handler returns, after which the ResponseController
// must not be used.
func (b *deadlineBody) finish() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.done = true
	if b.timer != nil {
		b.timer.Stop()
	}
}
