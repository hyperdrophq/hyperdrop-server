package liveshare

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrNoShare   = errors.New("no such live share")
	ErrJobFailed = errors.New("live share transfer failed")
	// ErrBusy is NewJob on a share whose line is full, or one that waited
	// Config.QueueWait in it for a place.
	ErrBusy = errors.New("live share has too many transfers in flight")
	// ErrAddressBusy is NewJob that waited Config.AddressWait for a place of
	// its address. It wraps ErrBusy.
	ErrAddressBusy = fmt.Errorf("%w from this address", ErrBusy)
)

// FailedError is what Job.Body returns when the SHARER reported a failure
// (POST .../jobs/{job}/error, or the share dying underneath the job via
// sweep or Delete) rather than nobody ever answering. Code is exactly what
// was reported: "live-share-ended" for the built-in teardown case, or
// whatever code the sharer's own client names ("source-changed",
// "source-gone", and so on). The API layer reads Code to answer the
// visitor with something more specific than "offline" (see liveshareserve.go's
// writeLiveShareJobError); a plain claim-wait timeout is NOT a FailedError; see
// Body below.
//
// It wraps ErrJobFailed, so an errors.Is(err, ErrJobFailed) check matches it
// too.
type FailedError struct {
	Code string
}

func (e *FailedError) Error() string { return fmt.Sprintf("%s: %s", ErrJobFailed, e.Code) }
func (e *FailedError) Unwrap() error { return ErrJobFailed }

type Offer struct {
	Job   string `json:"job"`
	Kind  string `json:"kind"`
	Path  string `json:"path"`
	Start int64  `json:"start"`
	End   int64  `json:"end"`
}

type Job struct {
	offer Offer

	pr *io.PipeReader
	pw *io.PipeWriter

	mu       sync.Mutex
	claimed  bool
	failCode string
	ready    chan struct{} // closed on Claim or Fail
	dropped  bool
	set      *jobSet
	addr     string // the visitor's address key, counted in set.byAddr and set.held
	// streaming says the sharer claimed the job while it held its place, and
	// gone that the place was given back; both are guarded by set.mu.
	streaming, gone bool
	// sent counts the bytes the visitor's side has read from the sharer, waited
	// the nanoseconds its reads have spent waiting for the sharer, and reading
	// when the read in progress began on the set's clock, 0 between reads. A
	// body's Read keeps the three without taking a lock.
	sent, waited, reading atomic.Int64
	// The job's current idle measurement (idle.go), guarded by set.mu: since
	// when, and sent and the sharer's wait then.
	idleAt     time.Time
	idleSent   int64
	idleWaited int64
	// idled says the job was ended for holding its place idle, and onIdle is
	// what its visitor's request runs then; both are guarded by mu.
	idled  bool
	onIdle func()
}

// jobSet is one share's jobs. The lock order is Registry.mu, then jobSet.mu,
// then Job.mu, and never the reverse: Poll and failAll walk a set holding its
// mu and lock each job in turn, so nothing holding a Job.mu may take its
// set's.
type jobSet struct {
	mu     sync.Mutex
	jobs   map[string]*Job // offered jobs: unclaimed, not failed
	active int             // jobs holding a place, claimed ones included
	// byAddr counts, by visitor address, the jobs holding a place and the
	// visitors in line; an address with none has no entry.
	byAddr map[string]int
	// held counts, by visitor address, the places held: byAddr without the
	// visitors still in line. grantLocked reads it to pick whose turn it is.
	held map[string]int
	// streams holds the jobs that hold a place and are claimed by the sharer,
	// the ones an idle check reads.
	streams map[*Job]struct{}
	// freed holds, for an address NewJob is waiting on, the channel the
	// address's next release closes (and deletes), waking every waiter.
	freed map[string]chan struct{}
	// line holds the *placeWaiter visitors waiting for a place, oldest
	// first. A place given back goes to one of them (grantLocked), so a
	// newcomer takes a free place only when nobody is in line.
	line  *list.List
	ended chan struct{} // closed when the share goes away
	wake  chan struct{} // buffered 1; NewJob signals, Poll drains
	g     gauge         // how many places the share holds, and what it measures
	// born is where the set's clock starts, and idleWindow how long a transfer
	// is measured before it can be ended as idle (idle.go).
	born       time.Time
	idleWindow time.Duration
}

// placeWaiter is one visitor in a share's line. granted is set, under the
// set's mu, when a place is handed to it; ready closes then.
type placeWaiter struct {
	addr    string
	granted bool
	ready   chan struct{}
	at      *list.Element
}

func newJobSet(window, idleWindow time.Duration, ceiling int) *jobSet {
	js := &jobSet{jobs: map[string]*Job{}, byAddr: map[string]int{}, held: map[string]int{},
		streams: map[*Job]struct{}{},
		freed:   map[string]chan struct{}{}, line: list.New(), ended: make(chan struct{}),
		wake: make(chan struct{}, 1), born: time.Now(), idleWindow: idleWindow}
	js.g.limit = MinJobsPerShare
	js.g.ceiling = max(ceiling, MinJobsPerShare)
	js.g.window = window
	return js
}

func (js *jobSet) signal() {
	select {
	case js.wake <- struct{}{}:
	default:
	}
}

// failAll ends every job when the share goes away, so parked visitors get an
// error instead of hanging until their claimWait, and wakes every visitor
// waiting for a place.
func (js *jobSet) failAll(code string) {
	js.mu.Lock()
	defer js.mu.Unlock()
	select {
	case <-js.ended:
	default:
		close(js.ended)
	}
	if js.g.timer != nil {
		js.g.timer.Stop()
		js.g.timer = nil
	}
	for id, j := range js.jobs {
		j.fail(code)
		delete(js.jobs, id)
	}
}

func (j *Job) fail(code string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.claimed || j.failCode != "" {
		return
	}
	j.failCode = code
	close(j.ready)
	j.pw.CloseWithError(fmt.Errorf("%w: %s", ErrJobFailed, code))
}

// NewJob offers the sharer a transfer for a visitor whose address key is
// addr. While the address holds all the places, in line or holding a job,
// one address may have (addrLimitLocked), it waits for one of them to end or
// the share's limit to grow, and gives up with ErrAddressBusy after
// Config.AddressWait. A share holding as many jobs as its limit allows, or
// with anyone in line, puts the visitor at the back of its line, which gives
// each free place to the visitor whose address holds the fewest, the oldest
// of them first (grantLocked); a full line (lineLimitLocked) is ErrBusy at
// once, and a wait in line ends with ErrBusy after Config.QueueWait, or, for
// a request that first waited for its address, when what is left of
// Config.AddressWait runs out. Either wait holds no job and offers the sharer
// nothing. It gives up with ctx's error when ctx ends, and with ErrNoShare
// when the share goes away meanwhile.
func (g *Registry) NewJob(ctx context.Context, shareID, addr, kind, path string, start, end int64) (*Job, error) {
	g.mu.Lock()
	s, ok := g.shares[shareID]
	g.mu.Unlock()
	if !ok {
		return nil, ErrNoShare
	}
	js := s.jobs
	var bound *time.Timer
	defer func() {
		if bound != nil {
			bound.Stop()
		}
	}()
	js.mu.Lock()
	for js.byAddr[addr] >= js.addrLimitLocked() {
		freed := js.freed[addr]
		if freed == nil {
			freed = make(chan struct{})
			js.freed[addr] = freed
		}
		js.mu.Unlock()
		if bound == nil {
			bound = time.NewTimer(g.cfg.AddressWait)
		}
		select {
		case <-freed:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-bound.C:
			return nil, ErrAddressBusy
		case <-js.ended:
			return nil, ErrNoShare
		}
		js.mu.Lock()
	}
	if isEnded(js) {
		js.mu.Unlock()
		return nil, ErrNoShare
	}
	if js.active >= js.g.limit || js.line.Len() > 0 {
		if js.line.Len() >= js.lineLimitLocked() {
			js.mu.Unlock()
			return nil, ErrBusy
		}
		if js.line.Len() == 0 {
			js.markStreamsLocked(time.Now())
		}
		w := &placeWaiter{addr: addr, ready: make(chan struct{})}
		w.at = js.line.PushBack(w)
		js.byAddr[addr]++
		js.armLocked()
		js.mu.Unlock()
		if bound == nil {
			bound = time.NewTimer(g.cfg.QueueWait)
		}
		var gaveUp error
		select {
		case <-w.ready:
		case <-ctx.Done():
			gaveUp = ctx.Err()
		case <-bound.C:
			gaveUp = ErrBusy
		case <-js.ended:
			gaveUp = ErrNoShare
		}
		js.mu.Lock()
		if !w.granted {
			js.line.Remove(w.at)
		}
		if gaveUp == nil && isEnded(js) {
			gaveUp = ErrNoShare
		}
		if gaveUp != nil {
			if w.granted {
				js.active--
				js.unholdLocked(addr)
				js.grantLocked()
			}
			js.forgetAddrLocked(addr)
			js.mu.Unlock()
			return nil, gaveUp
		}
	} else {
		js.active++
		js.held[addr]++
		js.byAddr[addr]++
	}
	pr, pw := io.Pipe()
	j := &Job{
		offer: Offer{Job: "j_" + g.cfg.NewSlug(), Kind: kind, Path: path, Start: start, End: end},
		pr:    pr, pw: pw,
		ready: make(chan struct{}), set: js, addr: addr,
	}
	js.jobs[j.offer.Job] = j
	js.mu.Unlock()
	js.signal()
	return j, nil
}

func isEnded(js *jobSet) bool {
	select {
	case <-js.ended:
		return true
	default:
		return false
	}
}

// grantLocked hands free places to the line, each counted in active and in
// its address's held as it is handed. A place goes to the visitor whose
// address holds the fewest places, and among those to the one that has waited
// longest: an address that holds places cannot refill them ahead of an
// address that holds none. The caller holds js.mu.
func (js *jobSet) grantLocked() {
	for js.active < js.g.limit && js.line.Len() > 0 {
		next := js.line.Front()
		fewest := js.held[next.Value.(*placeWaiter).addr]
		for e := next.Next(); e != nil && fewest > 0; e = e.Next() {
			if n := js.held[e.Value.(*placeWaiter).addr]; n < fewest {
				next, fewest = e, n
			}
		}
		w := js.line.Remove(next).(*placeWaiter)
		w.granted = true
		js.active++
		js.held[w.addr]++
		close(w.ready)
	}
}

// releaseLocked gives back the place j holds, to the line, once: a job that
// has given its place back is left alone. The caller holds js.mu.
func (js *jobSet) releaseLocked(j *Job) {
	if j.gone {
		return
	}
	j.gone = true
	if j.streaming {
		js.streamedLocked(-1)
		delete(js.streams, j)
	}
	js.active--
	js.unholdLocked(j.addr)
	js.grantLocked()
	js.forgetAddrLocked(j.addr)
}

// unholdLocked takes one held place off addr's count. The caller holds js.mu.
func (js *jobSet) unholdLocked(addr string) {
	if js.held[addr]--; js.held[addr] == 0 {
		delete(js.held, addr)
	}
}

// forgetAddrLocked gives one of addr's places back and wakes whoever waits
// for one. The caller holds js.mu.
func (js *jobSet) forgetAddrLocked(addr string) {
	if js.byAddr[addr]--; js.byAddr[addr] == 0 {
		delete(js.byAddr, addr)
	}
	if freed, ok := js.freed[addr]; ok {
		close(freed)
		delete(js.freed, addr)
	}
}

// release gives the job's place back. It takes the set's lock, so it never
// runs under j.mu.
func (j *Job) release() {
	j.set.mu.Lock()
	j.set.releaseLocked(j)
	j.set.mu.Unlock()
}

// jobBody is a claimed job's body as its visitor reads it: the end of the
// stream or its close gives the job's place back.
type jobBody struct{ j *Job }

func (b jobBody) Read(p []byte) (int, error) {
	began := b.j.set.clock()
	b.j.reading.Store(began)
	n, err := b.j.pr.Read(p)
	b.j.waited.Add(b.j.set.clock() - began)
	b.j.reading.Store(0)
	b.j.sent.Add(int64(n))
	b.j.set.g.sent.Add(int64(n))
	if err != nil {
		b.j.release()
	}
	return n, err
}

func (b jobBody) Close() error {
	b.j.release()
	return b.j.pr.Close()
}

func (j *Job) Body(ctx context.Context, claimWait time.Duration) (io.ReadCloser, error) {
	t := time.NewTimer(claimWait)
	defer t.Stop()
	select {
	case <-j.ready:
	case <-ctx.Done():
		j.Cancel()
		return nil, ctx.Err()
	case <-t.C:
		j.Cancel()
		return nil, fmt.Errorf("%w: the sharer did not start sending in time", ErrJobFailed)
	}
	j.mu.Lock()
	code := j.failCode
	j.mu.Unlock()
	if code != "" {
		j.release()
		return nil, &FailedError{Code: code}
	}
	return jobBody{j}, nil
}

func (j *Job) Cancel() {
	j.set.mu.Lock()
	delete(j.set.jobs, j.offer.Job)
	j.set.mu.Unlock()
	j.mu.Lock()
	j.dropped = true
	j.mu.Unlock()
	// Break both ends: a sharer mid-Claim gets a write error, a parked Body
	// returns; both are "the visitor went away", which is not a failure.
	j.pr.CloseWithError(io.ErrClosedPipe)
	j.release()
}

// A share holds at most its adaptive limit of visitor transfers at once
// (adapt.go), waiting for the sharer or streaming from it, so a publicly
// posted link cannot queue unbounded work on the sharer's computer; the
// limit also bounds a poll's answer. A job holds its place from NewJob until
// its visitor's Body fails, its body ends or is closed, Cancel, or the share
// ends it for holding the place idle while others wait (idle.go). One
// address holds a part of them (addrLimitLocked), its places in the share's
// line included: one more from that address waits for one of the address's
// own places (NewJob), so a browser fetching a page's assets at once gets
// every one of them while one address never fills the share. A waiting
// request costs its goroutine and its connection's buffers, so the line is
// bounded too (lineLimitLocked).

func (g *Registry) Poll(ctx context.Context, shareID, owner string, park time.Duration) ([]Offer, error) {
	g.mu.Lock()
	s, ok := g.shares[shareID]
	if !ok || s.rec.Owner != owner {
		g.mu.Unlock()
		return nil, ErrNoShare
	}
	s.lastSeen = g.cfg.Now()
	s.parked++
	js := s.jobs
	g.mu.Unlock()

	defer func() {
		g.mu.Lock()
		if s2, ok := g.shares[shareID]; ok {
			s2.parked--
			s2.lastSeen = g.cfg.Now()
		}
		g.mu.Unlock()
	}()

	deadline := time.NewTimer(park)
	defer deadline.Stop()
	for {
		js.mu.Lock()
		var offers []Offer
		for _, j := range js.jobs {
			j.mu.Lock()
			if !j.claimed && j.failCode == "" {
				offers = append(offers, j.offer)
			}
			j.mu.Unlock()
		}
		js.mu.Unlock()
		if len(offers) > 0 {
			return offers, nil
		}
		select {
		case <-js.wake:
		case <-deadline.C:
			return nil, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-g.drained:
			return nil, nil
		}
	}
}

type Claimed struct{ pw *io.PipeWriter }

func (c *Claimed) Write(p []byte) (int, error)    { return c.pw.Write(p) }
func (c *Claimed) Close() error                   { return c.pw.Close() }
func (c *Claimed) CloseWithError(err error) error { return c.pw.CloseWithError(err) }

func (g *Registry) findJob(owner, jobID string) *Job {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, s := range g.shares {
		if s.rec.Owner != owner {
			continue
		}
		s.jobs.mu.Lock()
		j, ok := s.jobs.jobs[jobID]
		s.jobs.mu.Unlock()
		if ok {
			return j
		}
	}
	return nil
}

func (g *Registry) Claim(owner, jobID string) (*Claimed, bool) {
	j := g.findJob(owner, jobID)
	if j == nil {
		return nil, false
	}
	j.mu.Lock()
	if j.claimed || j.failCode != "" || j.dropped {
		j.mu.Unlock()
		return nil, false
	}
	j.claimed = true
	close(j.ready)
	j.mu.Unlock()
	// Claimed jobs leave the set so re-offers never include them, after j.mu
	// is released (the lock order on jobSet). Poll already skips a claimed
	// job by its j.claimed, so the moment between changes nothing. A job
	// still holding its place starts counting as streaming.
	j.set.mu.Lock()
	delete(j.set.jobs, j.offer.Job)
	if !j.gone {
		j.streaming = true
		j.set.streamedLocked(1)
		j.set.streams[j] = struct{}{}
		j.markIdleLocked(time.Now())
	}
	j.set.mu.Unlock()
	return &Claimed{pw: j.pw}, true
}

func (g *Registry) Fail(owner, jobID, code string) bool {
	j := g.findJob(owner, jobID)
	if j == nil {
		return false
	}
	j.set.mu.Lock()
	delete(j.set.jobs, j.offer.Job)
	j.set.mu.Unlock()
	j.fail(code)
	return true
}

// Drain releases every parked Poll and makes every later Poll answer
// immediately, so a graceful shutdown never waits out a long-poll.
func (g *Registry) Drain() {
	g.mu.Lock()
	defer g.mu.Unlock()
	select {
	case <-g.drained:
	default:
		close(g.drained)
	}
}
