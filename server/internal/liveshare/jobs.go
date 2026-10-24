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
}

// jobSet is one share's jobs. The lock order is Registry.mu, then jobSet.mu,
// then Job.mu, and never the reverse: Poll and failAll walk a set holding its
// mu and lock each job in turn, so nothing holding a Job.mu may take its
// set's.
type jobSet struct {
	mu   sync.Mutex
	jobs map[string]*Job
	wake chan struct{} // buffered 1; NewJob signals, Poll drains
}

func newJobSet() *jobSet {
	return &jobSet{jobs: map[string]*Job{}, wake: make(chan struct{}, 1)}
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

func (g *Registry) NewJob(shareID, kind, path string, start, end int64) (*Job, error) {
	g.mu.Lock()
	s, ok := g.shares[shareID]
	g.mu.Unlock()
	if !ok {
		return nil, ErrNoShare
	}
	pr, pw := io.Pipe()
	j := &Job{
		offer: Offer{Job: "j_" + g.cfg.NewSlug(), Kind: kind, Path: path, Start: start, End: end},
		owner: s.rec.Owner, pr: pr, pw: pw,
		ready: make(chan struct{}), set: s.jobs,
	}
	s.jobs.mu.Lock()
	s.jobs.jobs[j.offer.Job] = j
	s.jobs.mu.Unlock()
	s.jobs.signal()
	return j, nil
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
		return nil, &FailedError{Code: code}
	}
	return j.pr, nil
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
}

// MaxOffersPerPoll bounds one poll's answer. A publicly posted link can park
// any number of visitor jobs at once; the sharer's client polls again the
// moment it has taken an answer, and a poll with offers waiting returns at
// once, so the rest go out on the next one.
const MaxOffersPerPoll = 256

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
			if len(offers) >= MaxOffersPerPoll {
				break
			}
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
