package liveshare

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

var (
	ErrNoShare   = errors.New("no such live share")
	ErrJobFailed = errors.New("live share transfer failed")
	// ErrBusy is NewJob on a share already holding MaxJobsPerShare jobs, or
	// one that waited Config.AddressWait for a place of its address.
	ErrBusy = errors.New("live share has too many transfers in flight")
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
	owner string

	pr *io.PipeReader
	pw *io.PipeWriter

	mu       sync.Mutex
	claimed  bool
	failCode string
	ready    chan struct{} // closed on Claim or Fail
	dropped  bool
	set      *jobSet
	addr     string    // the visitor's address key, counted in set.byAddr
	released sync.Once // gives the job's places in set.active and set.byAddr back
}

// jobSet is one share's jobs. The lock order is Registry.mu, then jobSet.mu,
// then Job.mu, and never the reverse: Poll and failAll walk a set holding its
// mu and lock each job in turn, so nothing holding a Job.mu may take its
// set's.
type jobSet struct {
	mu     sync.Mutex
	jobs   map[string]*Job // offered jobs: unclaimed, not failed
	active int             // jobs holding a place, claimed ones included
	byAddr map[string]int  // active by visitor address; an address with none has no entry
	// freed holds, for an address NewJob is waiting on, the channel the
	// address's next release closes (and deletes), waking every waiter.
	freed map[string]chan struct{}
	wake  chan struct{} // buffered 1; NewJob signals, Poll drains
}

func newJobSet() *jobSet {
	return &jobSet{jobs: map[string]*Job{}, byAddr: map[string]int{},
		freed: map[string]chan struct{}{}, wake: make(chan struct{}, 1)}
}

func (js *jobSet) signal() {
	select {
	case js.wake <- struct{}{}:
	default:
	}
}

// failAll ends every job when the share goes away, so parked visitors get an
// error instead of hanging until their claimWait.
func (js *jobSet) failAll(code string) {
	js.mu.Lock()
	defer js.mu.Unlock()
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
// addr. While the address holds MaxJobsPerAddress of the share's jobs it
// waits for one of them to end, holding no place and offering nothing, and
// gives up with ctx's error when ctx ends or with ErrBusy after
// Config.AddressWait. With a place of its address, a share already holding
// MaxJobsPerShare jobs is ErrBusy at once.
func (g *Registry) NewJob(ctx context.Context, shareID, addr, kind, path string, start, end int64) (*Job, error) {
	g.mu.Lock()
	s, ok := g.shares[shareID]
	g.mu.Unlock()
	if !ok {
		return nil, ErrNoShare
	}
	js := s.jobs
	var bound *time.Timer
	js.mu.Lock()
	for js.byAddr[addr] >= MaxJobsPerAddress {
		freed := js.freed[addr]
		if freed == nil {
			freed = make(chan struct{})
			js.freed[addr] = freed
		}
		js.mu.Unlock()
		if bound == nil {
			bound = time.NewTimer(g.cfg.AddressWait)
			defer bound.Stop()
		}
		select {
		case <-freed:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-bound.C:
			return nil, ErrBusy
		}
		// The share may have ended while the request waited.
		g.mu.Lock()
		cur := g.shares[shareID]
		g.mu.Unlock()
		if cur != s {
			return nil, ErrNoShare
		}
		js.mu.Lock()
	}
	if js.active >= MaxJobsPerShare {
		js.mu.Unlock()
		return nil, ErrBusy
	}
	pr, pw := io.Pipe()
	j := &Job{
		offer: Offer{Job: "j_" + g.cfg.NewSlug(), Kind: kind, Path: path, Start: start, End: end},
		owner: s.rec.Owner, pr: pr, pw: pw,
		ready: make(chan struct{}), set: js, addr: addr,
	}
	js.active++
	js.byAddr[addr]++
	js.jobs[j.offer.Job] = j
	js.mu.Unlock()
	js.signal()
	return j, nil
}

// release gives the job's place back, once. It takes the set's lock, so
// it never runs under j.mu.
func (j *Job) release() {
	j.released.Do(func() {
		j.set.mu.Lock()
		j.set.active--
		if j.set.byAddr[j.addr]--; j.set.byAddr[j.addr] == 0 {
			delete(j.set.byAddr, j.addr)
		}
		if freed, ok := j.set.freed[j.addr]; ok {
			close(freed)
			delete(j.set.freed, j.addr)
		}
		j.set.mu.Unlock()
	})
}

// jobBody is a claimed job's body as its visitor reads it: the end of the
// stream or its close gives the job's place back.
type jobBody struct{ j *Job }

func (b jobBody) Read(p []byte) (int, error) {
	n, err := b.j.pr.Read(p)
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

// MaxJobsPerShare bounds the visitor transfers one share holds at once,
// waiting for the sharer or streaming from it, so a publicly posted link
// cannot queue unbounded work on the sharer's computer; it also bounds a
// poll's answer. A job holds its place from NewJob until its visitor's
// Body fails, its body ends or is closed, or Cancel.
const MaxJobsPerShare = 8

// MaxJobsPerAddress bounds the jobs one visitor address holds of a share at
// once, within MaxJobsPerShare. One more from that address waits for one of
// the address's own places (NewJob), so a browser fetching a page's assets
// at once gets every one of them while one address never fills the share.
const MaxJobsPerAddress = 2

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
	// job by its j.claimed, so the moment between changes nothing.
	j.set.mu.Lock()
	delete(j.set.jobs, j.offer.Job)
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
