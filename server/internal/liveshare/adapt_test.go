package liveshare

import (
	"context"
	"errors"
	"io"
	"strconv"
	"sync"
	"testing"
	"time"
)

// adaptShare is a share holding all its MinJobsPerShare places, every one
// claimed by the sharer, with waiting visitors in line. Its gauge measures in
// windows of five seconds the test steps by hand.
type adaptShare struct {
	t      *testing.T
	g      *Registry
	id     string
	js     *jobSet
	at     time.Time
	jobs   []*Job
	cancel context.CancelFunc
	queued []chan newJobResult
}

func newAdaptShare(t *testing.T, maxJobs, waiting int) *adaptShare {
	t.Helper()
	n := 0
	g := NewRegistry(Config{
		NewID:       func() string { return "aaaaaaaaaa" },
		NewSlug:     func() string { n++; return strconv.Itoa(n) },
		ProbeWindow: time.Hour, // the test moves the windows itself
		MaxJobs:     maxJobs,
	})
	rec, err := g.Create(Record{Owner: "amy"})
	if err != nil {
		t.Fatal(err)
	}
	a := &adaptShare{t: t, g: g, id: rec.ID, jobs: fillShare(t, g, rec.ID)}
	g.mu.Lock()
	a.js = g.shares[rec.ID].jobs
	g.mu.Unlock()
	a.claim()
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	for i := range waiting {
		a.queued = append(a.queued, queue(ctx, g, rec.ID, "203.0.113."+strconv.Itoa(i+1)))
		waitInLine(t, g, rec.ID, i+1)
	}
	a.at = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	a.js.mu.Lock()
	a.js.g.window = 5 * time.Second
	a.js.restartWindowLocked(a.at)
	a.js.mu.Unlock()
	t.Cleanup(a.close)
	return a
}

// claim has the sharer claim every job it is offered.
func (a *adaptShare) claim() {
	a.t.Helper()
	offers, err := a.g.Poll(context.Background(), a.id, "amy", 10*time.Millisecond)
	if err != nil {
		a.t.Fatal(err)
	}
	for _, o := range offers {
		if _, ok := a.g.Claim("amy", o.Job); !ok {
			a.t.Fatalf("claim of %s refused", o.Job)
		}
	}
}

// step ends a window of d in which the share relayed bytes a second.
func (a *adaptShare) step(d time.Duration, perSecond int64) {
	a.at = a.at.Add(d)
	a.js.g.sent.Add(perSecond * int64(d/time.Second))
	a.js.mu.Lock()
	a.js.adaptLocked(a.at)
	a.js.mu.Unlock()
}

// admitted takes the next visitor let in from the line.
func (a *adaptShare) admitted() {
	a.t.Helper()
	r := receive(a.t, a.queued[0])
	a.queued = a.queued[1:]
	if r.err != nil {
		a.t.Fatalf("a visitor let in from the line: %v", r.err)
	}
	a.jobs = append(a.jobs, r.j)
}

func (a *adaptShare) limit() (int, adaptState) {
	a.js.mu.Lock()
	defer a.js.mu.Unlock()
	return a.js.g.limit, a.js.g.state
}

func (a *adaptShare) wantLimit(want int, state adaptState) {
	a.t.Helper()
	if got, st := a.limit(); got != want || st != state {
		a.t.Fatalf("limit %d in state %d, want %d in state %d", got, st, want, state)
	}
}

func (a *adaptShare) close() {
	a.cancel()
	for _, c := range a.queued {
		<-c
	}
	for _, j := range a.jobs {
		j.Cancel()
	}
}

const mb = 1 << 20

// A share whose places all stream while visitors wait tries one more; the
// try's place goes to the oldest in line, and once it streams too, a speed
// that grew with it keeps it.
func TestAShareWithRoomKeepsTheTriedPlace(t *testing.T) {
	a := newAdaptShare(t, 0, 3)
	a.step(5*time.Second, 8*mb)
	a.wantLimit(MinJobsPerShare+1, adaptFilling)
	a.admitted()
	a.claim()
	a.step(5*time.Second, 8*mb)
	a.wantLimit(MinJobsPerShare+1, adaptTrying)
	a.step(5*time.Second, 9*mb)
	a.wantLimit(MinJobsPerShare+1, adaptIdle)
	// And it goes on trying while visitors still wait.
	a.step(5*time.Second, 9*mb)
	a.wantLimit(MinJobsPerShare+2, adaptFilling)
}

// A try that adds no speed gives its place back, and the share waits before
// the next try, twice as long after each failure.
func TestAFullUplinkGivesTheTriedPlaceBack(t *testing.T) {
	a := newAdaptShare(t, 0, 3)
	a.step(5*time.Second, 8*mb)
	a.admitted()
	a.claim()
	a.step(5*time.Second, 8*mb)
	a.step(5*time.Second, 8*mb)
	a.wantLimit(MinJobsPerShare, adaptIdle)
	a.step(5*time.Second, 8*mb)
	a.wantLimit(MinJobsPerShare, adaptIdle)

	// The visitor let in for the try holds a ninth place until its transfer
	// ends: no one else is let in meanwhile.
	a.jobs[0].Cancel()
	a.jobs = a.jobs[1:]
	stillWaiting(t, a.queued[0])
	a.step(adaptHoldMin, 8*mb)
	a.wantLimit(MinJobsPerShare+1, adaptFilling)
	a.admitted()
	a.claim()
	a.step(5*time.Second, 8*mb)
	a.step(5*time.Second, 8*mb)
	a.wantLimit(MinJobsPerShare, adaptIdle)
	a.js.mu.Lock()
	hold := a.js.g.hold
	a.js.mu.Unlock()
	if hold != 2*adaptHoldMin {
		t.Fatalf("hold after a second failure = %v, want %v", hold, 2*adaptHoldMin)
	}
}

// A try whose place the sharer does not claim in time measured nothing: the
// place is given back.
func TestATryThatCannotFillGivesItsPlaceBack(t *testing.T) {
	a := newAdaptShare(t, 0, 3)
	a.step(5*time.Second, 8*mb)
	a.admitted() // let in, never claimed
	a.step(5*time.Second, 8*mb)
	a.wantLimit(MinJobsPerShare+1, adaptFilling)
	a.step(5*time.Second, 8*mb)
	a.step(time.Second, 8*mb)
	a.wantLimit(MinJobsPerShare, adaptIdle)
}

// Nothing is tried while nobody waits, while a place is not streaming, or
// past the limit the server's memory pays for.
func TestASharerTriesOnlyWhenItCanMeasure(t *testing.T) {
	idle := newAdaptShare(t, 0, 0)
	idle.step(5*time.Second, 8*mb)
	idle.wantLimit(MinJobsPerShare, adaptIdle)

	capped := newAdaptShare(t, MinJobsPerShare, 3)
	capped.step(5*time.Second, 8*mb)
	capped.wantLimit(MinJobsPerShare, adaptIdle)

	unsteady := newAdaptShare(t, 0, 3)
	unsteady.jobs[0].Cancel()
	unsteady.jobs = unsteady.jobs[1:]
	unsteady.admitted() // the freed place went to the line, not yet claimed
	unsteady.step(5*time.Second, 8*mb)
	unsteady.wantLimit(MinJobsPerShare, adaptIdle)
}

// One address may hold a quarter of the share's limit, at least two, and the
// line holds twice the limit, at least sixteen.
func TestAddressesAndTheLineFollowTheLimit(t *testing.T) {
	js := newJobSet(time.Second, 1000)
	for _, c := range []struct{ limit, addr, line int }{
		{8, 2, 16}, {12, 3, 24}, {40, 10, 80},
	} {
		js.g.limit = c.limit
		if got := js.addrLimitLocked(); got != c.addr {
			t.Fatalf("limit %d: an address holds %d, want %d", c.limit, got, c.addr)
		}
		if got := js.lineLimitLocked(); got != c.line {
			t.Fatalf("limit %d: the line holds %d, want %d", c.limit, got, c.line)
		}
	}
}

// A raise that gives every address more lets in a request that waited for
// a place of its address.
func TestARaiseWakesAnAddressThatWaits(t *testing.T) {
	a := newAdaptShare(t, 0, 0)
	a.js.mu.Lock()
	a.js.g.limit = 12 // as a share that has learned it
	a.js.mu.Unlock()
	for range 2 {
		j, err := a.g.NewJob(context.Background(), a.id, "198.51.100.1", "file", "a.txt", 0, -1)
		if err != nil {
			t.Fatal(err)
		}
		a.jobs = append(a.jobs, j)
	}
	// 198.51.100.1 holds 3 of the 12-place share's 10: its next waits.
	third := queue(context.Background(), a.g, a.id, "198.51.100.1")
	stillWaiting(t, third)
	a.js.mu.Lock()
	a.js.g.limit = 16
	a.js.wakeAddressesLocked()
	a.js.mu.Unlock()
	r := receive(t, third)
	if r.err != nil {
		t.Fatalf("the address's waiting request: %v", r.err)
	}
	a.jobs = append(a.jobs, r.j)
}

// End to end, with the windows on a real clock: a sharer whose transfers are
// each held back by its visitor, not by its uplink, is given more places; a
// sharer whose uplink is full keeps the places it starts with.
func TestALiveShareFindsWhatItsUplinkCarries(t *testing.T) {
	if testing.Short() {
		t.Skip("measures for seconds")
	}
	run := func(uplink *sync.Mutex) int {
		n := 0
		var mu sync.Mutex
		g := NewRegistry(Config{
			NewID:       func() string { return "aaaaaaaaaa" },
			NewSlug:     func() string { mu.Lock(); defer mu.Unlock(); n++; return strconv.Itoa(n) },
			ProbeWindow: 200 * time.Millisecond,
		})
		rec, _ := g.Create(Record{Owner: "amy"})
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		var wg sync.WaitGroup
		// The sharer: every claimed job sends 4 KiB every 2 ms, on its own or
		// through one uplink that sends one chunk at a time.
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				offers, err := g.Poll(ctx, rec.ID, "amy", 50*time.Millisecond)
				if err != nil {
					return
				}
				for _, o := range offers {
					c, ok := g.Claim("amy", o.Job)
					if !ok {
						continue
					}
					wg.Add(1)
					go func() {
						defer wg.Done()
						defer c.Close()
						chunk := make([]byte, 4<<10)
						for ctx.Err() == nil {
							if uplink != nil {
								uplink.Lock()
							}
							_, err := c.Write(chunk)
							time.Sleep(2 * time.Millisecond)
							if uplink != nil {
								uplink.Unlock()
							}
							if err != nil {
								return
							}
						}
					}()
				}
			}
		}()
		for i := range 40 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				addr := "198.51.100." + strconv.Itoa(i+1)
				for ctx.Err() == nil {
					j, err := g.NewJob(ctx, rec.ID, addr, "file", "a.txt", 0, -1)
					if errors.Is(err, ErrBusy) {
						time.Sleep(10 * time.Millisecond)
						continue
					}
					if err != nil {
						return
					}
					body, err := j.Body(ctx, time.Second)
					if err != nil {
						continue
					}
					io.Copy(io.Discard, body)
					body.Close()
				}
			}()
		}
		<-ctx.Done()
		g.mu.Lock()
		js := g.shares[rec.ID].jobs
		g.mu.Unlock()
		js.mu.Lock()
		limit := js.g.limit
		js.mu.Unlock()
		g.Delete(rec.ID, "amy")
		wg.Wait()
		return limit
	}
	if got := run(nil); got <= MinJobsPerShare {
		t.Fatalf("a sharer with room kept its limit at %d", got)
	}
	if got := run(&sync.Mutex{}); got != MinJobsPerShare {
		t.Fatalf("a sharer whose uplink is full grew its limit to %d", got)
	}
}
