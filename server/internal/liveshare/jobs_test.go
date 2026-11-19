package liveshare

import (
	"context"
	"errors"
	"io"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// testAddr is the visitor address key a test's single jobs come from.
const testAddr = "203.0.113.1"

func TestJobRoundTrip(t *testing.T) {
	now := time.Now()
	g := testRegistry(&now)
	rec, _ := g.Create(Record{Owner: "amy", Files: []File{{Path: "a.txt", Size: 5}}})

	job, err := g.NewJob(context.Background(), rec.ID, testAddr, "file", "a.txt", 0, -1)
	if err != nil {
		t.Fatal(err)
	}
	// The sharer's side: poll sees the job, claims it, writes the body.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		offers, err := g.Poll(context.Background(), rec.ID, "amy", time.Second)
		if err != nil || len(offers) != 1 {
			t.Errorf("poll: %v %v", offers, err)
			return
		}
		c, ok := g.Claim("amy", offers[0].Job)
		if !ok {
			t.Error("claim refused")
			return
		}
		io.Copy(c, strings.NewReader("hello"))
		c.Close()
	}()
	body, err := job.Body(context.Background(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(body)
	if string(got) != "hello" {
		t.Fatalf("visitor got %q", got)
	}
	wg.Wait()
}

func TestClaimIsExactlyOnceAndOwnerChecked(t *testing.T) {
	now := time.Now()
	g := testRegistry(&now)
	rec, _ := g.Create(Record{Owner: "amy"})
	job, _ := g.NewJob(context.Background(), rec.ID, testAddr, "zip", "", 0, -1)
	defer job.Cancel()
	offers, _ := g.Poll(context.Background(), rec.ID, "amy", 10*time.Millisecond)
	if len(offers) != 1 {
		t.Fatalf("offers: %v", offers)
	}
	if _, ok := g.Claim("bob", offers[0].Job); ok {
		t.Fatal("bob claimed amy's job")
	}
	if _, ok := g.Claim("amy", offers[0].Job); !ok {
		t.Fatal("amy's claim refused")
	}
	if _, ok := g.Claim("amy", offers[0].Job); ok {
		t.Fatal("second claim succeeded")
	}
}

func TestFailSurfacesToTheVisitor(t *testing.T) {
	now := time.Now()
	g := testRegistry(&now)
	rec, _ := g.Create(Record{Owner: "amy"})
	job, _ := g.NewJob(context.Background(), rec.ID, testAddr, "file", "a.txt", 0, -1)
	offers, _ := g.Poll(context.Background(), rec.ID, "amy", 10*time.Millisecond)
	if !g.Fail("amy", offers[0].Job, "source-changed") {
		t.Fatal("fail refused")
	}
	_, err := job.Body(context.Background(), time.Second)
	if !errors.Is(err, ErrJobFailed) || !strings.Contains(err.Error(), "source-changed") {
		t.Fatalf("visitor error: %v", err)
	}
}

// TestFailSurfacesAsATypedError pins the shape the API layer reads to give
// the visitor something more specific than "offline": a sharer-reported
// failure (as opposed to a claim-wait timeout, which stays a plain
// ErrJobFailed) must be extractable as a *FailedError with the exact code
// the sharer reported.
func TestFailSurfacesAsATypedError(t *testing.T) {
	now := time.Now()
	g := testRegistry(&now)
	rec, _ := g.Create(Record{Owner: "amy"})
	job, _ := g.NewJob(context.Background(), rec.ID, testAddr, "file", "a.txt", 0, -1)
	offers, _ := g.Poll(context.Background(), rec.ID, "amy", 10*time.Millisecond)
	if !g.Fail("amy", offers[0].Job, "source-gone") {
		t.Fatal("fail refused")
	}
	_, err := job.Body(context.Background(), time.Second)
	var fe *FailedError
	if !errors.As(err, &fe) {
		t.Fatalf("err = %v, want a *FailedError", err)
	}
	if fe.Code != "source-gone" {
		t.Fatalf("Code = %q, want source-gone", fe.Code)
	}
}

// TestClaimWaitTimeoutIsNotAFailedError: nobody ever answers the job, so
// Body times out. That must stay a PLAIN ErrJobFailed, not a *FailedError,
// since the API layer treats the two differently (a typed failure gets its
// own status code; a timeout is the ordinary "offline" 503).
func TestClaimWaitTimeoutIsNotAFailedError(t *testing.T) {
	now := time.Now()
	g := testRegistry(&now)
	rec, _ := g.Create(Record{Owner: "amy"})
	job, _ := g.NewJob(context.Background(), rec.ID, testAddr, "file", "a.txt", 0, -1)
	_, err := job.Body(context.Background(), 10*time.Millisecond)
	var fe *FailedError
	if errors.As(err, &fe) {
		t.Fatalf("a claim-wait timeout produced a *FailedError: %+v", fe)
	}
	if !errors.Is(err, ErrJobFailed) {
		t.Fatalf("err = %v, want it to wrap ErrJobFailed", err)
	}
}

func TestPollParksUntilAJobArrives(t *testing.T) {
	now := time.Now()
	g := testRegistry(&now)
	rec, _ := g.Create(Record{Owner: "amy"})
	started := time.Now()
	go func() {
		time.Sleep(50 * time.Millisecond)
		j, _ := g.NewJob(context.Background(), rec.ID, testAddr, "file", "a.txt", 0, -1)
		_ = j
	}()
	offers, err := g.Poll(context.Background(), rec.ID, "amy", 5*time.Second)
	if err != nil || len(offers) != 1 {
		t.Fatalf("poll: %v %v", offers, err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("poll waited for the full park despite a job arriving")
	}
}

func TestPollWhileParkedMeansOnline(t *testing.T) {
	// Unlike every other test here, this one mutates the fake clock WHILE a
	// goroutine is concurrently parked inside Poll, which itself calls
	// cfg.Now() (Poll's entry-time lastSeen bump). testRegistry's `now` is a
	// bare *time.Time with no synchronization of its own, and a sleep-based
	// handoff gives the race detector no happens-before edge between "let
	// the poll park" and the clock write below, so it flags a race on every
	// run even though the timing is safe in practice. Every other test in
	// this file only reads the clock concurrently (fine) or mutates it with
	// no concurrent reader (fine); this is the sole case with a concurrent
	// writer, so it alone gets its own mutex-guarded clock instead of
	// testRegistry's, with identical semantics otherwise.
	var mu sync.Mutex
	now := time.Now()
	nAt := 0
	g := NewRegistry(Config{
		NewID:   func() string { nAt++; return "id-parked-" + string(rune('a'+nAt)) + "aaaaaaaa" },
		NewSlug: func() string { nAt++; return "slug-parked-" + string(rune('a'+nAt)) },
		Now: func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			return now
		},
	})
	rec, _ := g.Create(Record{Owner: "amy"})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { g.Poll(ctx, rec.ID, "amy", time.Hour); close(done) }()
	time.Sleep(20 * time.Millisecond) // let the poll park
	mu.Lock()
	now = now.Add(time.Minute) // well past OfflineAfter
	mu.Unlock()
	if !g.Online(rec.ID) {
		t.Fatal("share offline while a poll is parked")
	}
	cancel()
	<-done
}

func TestUnclaimedJobsAreReofferedOnTheNextPoll(t *testing.T) {
	now := time.Now()
	g := testRegistry(&now)
	rec, _ := g.Create(Record{Owner: "amy"})
	job, _ := g.NewJob(context.Background(), rec.ID, testAddr, "file", "a.txt", 0, -1)
	defer job.Cancel()
	first, _ := g.Poll(context.Background(), rec.ID, "amy", 10*time.Millisecond)
	second, _ := g.Poll(context.Background(), rec.ID, "amy", 10*time.Millisecond)
	if len(first) != 1 || len(second) != 1 || first[0].Job != second[0].Job {
		t.Fatalf("re-offer: %v then %v", first, second)
	}
}

func TestPollOnUnknownShareIsErrNoShare(t *testing.T) {
	now := time.Now()
	g := testRegistry(&now)
	if _, err := g.Poll(context.Background(), "nope", "amy", time.Millisecond); !errors.Is(err, ErrNoShare) {
		t.Fatalf("err: %v", err)
	}
}

func TestVisitorCancelDropsTheJob(t *testing.T) {
	now := time.Now()
	g := testRegistry(&now)
	rec, _ := g.Create(Record{Owner: "amy"})
	job, _ := g.NewJob(context.Background(), rec.ID, testAddr, "file", "a.txt", 0, -1)
	job.Cancel()
	offers, _ := g.Poll(context.Background(), rec.ID, "amy", 10*time.Millisecond)
	if len(offers) != 0 {
		t.Fatalf("cancelled job still offered: %v", offers)
	}
}

// TestConcurrentPollAndClaimDoNotDeadlock is a regression guard for a
// lock-order inversion: Poll and failAll walk a jobSet holding js.mu and
// lock each job's j.mu in turn (js.mu then j.mu), so a Claim that ever
// nests the same two locks in the opposite order (j.mu then js.mu) is a
// classic AB-BA deadlock the instant a poll and a claim of the same job
// land at once, which is the ordinary case this whole rendezvous exists
// for: the sharer's poll loop racing the server's claim of its own
// incoming upload. This alone cannot prove the absence of a deadlock, only
// its presence under enough concurrent pressure, so it hammers many rounds
// of overlapping NewJob/Poll/Claim on one share and fails fast on a hang
// instead of waiting out the default test timeout.
func TestConcurrentPollAndClaimDoNotDeadlock(t *testing.T) {
	now := time.Now()
	g := testRegistry(&now)
	rec, _ := g.Create(Record{Owner: "amy"})

	const rounds = 300
	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		for i := 0; i < rounds; i++ {
			addr := strconv.Itoa(i)
			job, err := g.NewJob(context.Background(), rec.ID, addr, "file", "a.txt", 0, -1)
			for errors.Is(err, ErrBusy) {
				runtime.Gosched()
				job, err = g.NewJob(context.Background(), rec.ID, addr, "file", "a.txt", 0, -1)
			}
			if err != nil {
				t.Errorf("NewJob: %v", err)
				return
			}
			wg.Add(2)
			go func() {
				defer wg.Done()
				offers, err := g.Poll(context.Background(), rec.ID, "amy", time.Second)
				if err != nil {
					t.Errorf("poll: %v", err)
					return
				}
				for _, o := range offers {
					if c, ok := g.Claim("amy", o.Job); ok {
						c.Close()
					}
				}
			}()
			go func() {
				defer wg.Done()
				body, err := job.Body(context.Background(), time.Second)
				if err == nil {
					io.Copy(io.Discard, body)
				}
			}()
		}
		wg.Wait()
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("Poll and Claim deadlocked under concurrent load")
	}
}

// Shutdown must not wait out a parked poll: Drain releases it, and a poll
// arriving after the drain answers immediately instead of holding the
// listener open.
func TestDrainReleasesAParkedPoll(t *testing.T) {
	now := time.Now()
	g := testRegistry(&now)
	rec, _ := g.Create(Record{Owner: "amy"})
	start := time.Now()
	done := make(chan error, 1)
	go func() {
		_, err := g.Poll(context.Background(), rec.ID, rec.Owner, 10*time.Second)
		done <- err
	}()
	time.Sleep(50 * time.Millisecond) // let the poll park
	g.Drain()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a drained poll is an empty answer, not an error: %v", err)
		}
		if time.Since(start) > 2*time.Second {
			t.Fatal("the poll held past the drain")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the drain did not release the parked poll")
	}

	start = time.Now()
	if _, err := g.Poll(context.Background(), rec.ID, rec.Owner, 10*time.Second); err != nil {
		t.Fatalf("post-drain poll: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("a post-drain poll parked")
	}
}

// A share holds at most MinJobsPerShare jobs: one more waits in line and is
// ErrBusy past Config.QueueWait, never offered, and every way a job ends (its
// visitor leaving, its body read to the end, the sharer failing it) gives its
// place back.
func TestNewJobRefusesBeyondTheCapUntilAJobEnds(t *testing.T) {
	n := 0
	g := NewRegistry(Config{
		NewID:     func() string { return "aaaaaaaaaa" },
		NewSlug:   func() string { n++; return strconv.Itoa(n) },
		QueueWait: 20 * time.Millisecond,
	})
	rec, err := g.Create(Record{Owner: "alice", Files: []File{{Path: "a.txt"}}})
	if err != nil {
		t.Fatal(err)
	}
	// Every job from an address of its own, so only the share's cap counts.
	addrs := 0
	next := func() string { addrs++; return strconv.Itoa(addrs) }
	jobs := make([]*Job, MinJobsPerShare)
	for i := range jobs {
		if jobs[i], err = g.NewJob(context.Background(), rec.ID, next(), "file", "a.txt", 0, -1); err != nil {
			t.Fatal(err)
		}
	}
	full := func(want bool) {
		t.Helper()
		j, err := g.NewJob(context.Background(), rec.ID, next(), "file", "a.txt", 0, -1)
		if got := errors.Is(err, ErrBusy); got != want {
			t.Fatalf("NewJob busy = %v (%v), want %v", got, err, want)
		}
		if j != nil {
			jobs = append(jobs, j)
		}
	}
	full(true)
	if offers, _ := g.Poll(context.Background(), rec.ID, "alice", time.Second); len(offers) != MinJobsPerShare {
		t.Fatalf("offers = %d, want %d", len(offers), MinJobsPerShare)
	}

	jobs[0].Cancel()
	full(false)
	full(true)

	c, ok := g.Claim("alice", jobs[1].offer.Job)
	if !ok {
		t.Fatal("claim refused")
	}
	go func() { io.WriteString(c, "hi"); c.Close() }()
	body, err := jobs[1].Body(context.Background(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(body)
	full(false)
	full(true)

	g.Fail("alice", jobs[2].offer.Job, "source-gone")
	if _, err := jobs[2].Body(context.Background(), time.Second); err == nil {
		t.Fatal("a failed job answered a body")
	}
	full(false)
	full(true)
}

// A share's jobs from one address past MinJobsPerAddress wait for one of
// that address's own places, offering nothing meanwhile, while another
// address goes ahead at once; one of the address's jobs ending lets the
// waiter in.
func TestAnAddressBeyondItsCapWaitsForItsOwnPlace(t *testing.T) {
	now := time.Now()
	g := testRegistry(&now)
	rec, _ := g.Create(Record{Owner: "amy"})
	var held []*Job
	for range MinJobsPerAddress {
		j, err := g.NewJob(context.Background(), rec.ID, "198.51.100.7", "file", "a.txt", 0, -1)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, j)
	}
	type result struct {
		j   *Job
		err error
	}
	waited := make(chan result, 1)
	go func() {
		j, err := g.NewJob(context.Background(), rec.ID, "198.51.100.7", "file", "a.txt", 0, -1)
		waited <- result{j, err}
	}()
	select {
	case r := <-waited:
		t.Fatalf("one more from the same address did not wait: %v", r.err)
	case <-time.After(100 * time.Millisecond):
	}
	other, err := g.NewJob(context.Background(), rec.ID, "203.0.113.9", "file", "a.txt", 0, -1)
	if err != nil {
		t.Fatalf("another address behind the first's queue: %v", err)
	}
	if offers, _ := g.Poll(context.Background(), rec.ID, "amy", 10*time.Millisecond); len(offers) != MinJobsPerAddress+1 {
		t.Fatalf("offers = %d, want %d: a waiting request offers nothing", len(offers), MinJobsPerAddress+1)
	}
	held[0].Cancel()
	var r result
	select {
	case r = <-waited:
	case <-time.After(5 * time.Second):
		t.Fatal("the waiting request was not let in when one of its address's jobs ended")
	}
	if r.err != nil {
		t.Fatalf("the waiting request: %v", r.err)
	}
	for _, j := range append(held[1:], r.j, other) {
		j.Cancel()
	}
	assertNoPlaces(t, g, rec.ID)
}

// assertNoPlaces fails unless the share's jobs hold no place and no address
// is counted or waited on.
func assertNoPlaces(t *testing.T, g *Registry, id string) {
	t.Helper()
	g.mu.Lock()
	js := g.shares[id].jobs
	g.mu.Unlock()
	js.mu.Lock()
	defer js.mu.Unlock()
	if js.active != 0 || len(js.byAddr) != 0 || len(js.held) != 0 || len(js.streams) != 0 || js.g.streaming != 0 || len(js.freed) != 0 || js.line.Len() != 0 {
		t.Fatalf("active %d, by address %v, held %v, streaming %d and %d, waited on %d, in line %d",
			js.active, js.byAddr, js.held, len(js.streams), js.g.streaming, len(js.freed), js.line.Len())
	}
}

// A request that leaves while it waits takes nothing and leaves nothing:
// once the address's jobs end every count is back to zero.
func TestAWaitingRequestThatLeavesHoldsNothing(t *testing.T) {
	now := time.Now()
	g := testRegistry(&now)
	rec, _ := g.Create(Record{Owner: "amy"})
	var held []*Job
	for range MinJobsPerAddress {
		j, err := g.NewJob(context.Background(), rec.ID, "198.51.100.7", "file", "a.txt", 0, -1)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, j)
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	if _, err := g.NewJob(ctx, rec.ID, "198.51.100.7", "file", "a.txt", 0, -1); !errors.Is(err, context.Canceled) {
		t.Fatalf("a waiting request that left: %v, want context.Canceled", err)
	}
	for _, j := range held {
		j.Cancel()
	}
	assertNoPlaces(t, g, rec.ID)
}

// A request that has waited Config.AddressWait without a place of its
// address is ErrBusy, and has offered nothing.
func TestAWaitPastItsBoundIsBusy(t *testing.T) {
	n := 0
	g := NewRegistry(Config{
		NewID:       func() string { return "aaaaaaaaaa" },
		NewSlug:     func() string { n++; return strconv.Itoa(n) },
		AddressWait: 50 * time.Millisecond,
	})
	rec, _ := g.Create(Record{Owner: "amy"})
	for range MinJobsPerAddress {
		if _, err := g.NewJob(context.Background(), rec.ID, "198.51.100.7", "file", "a.txt", 0, -1); err != nil {
			t.Fatal(err)
		}
	}
	started := time.Now()
	if _, err := g.NewJob(context.Background(), rec.ID, "198.51.100.7", "file", "a.txt", 0, -1); !errors.Is(err, ErrAddressBusy) || !errors.Is(err, ErrBusy) {
		t.Fatalf("a wait past its bound: %v, want ErrAddressBusy, which is ErrBusy", err)
	}
	if waited := time.Since(started); waited < 50*time.Millisecond || waited > 5*time.Second {
		t.Fatalf("waited %v, want about the 50 ms bound", waited)
	}
	if offers, _ := g.Poll(context.Background(), rec.ID, "amy", 10*time.Millisecond); len(offers) != MinJobsPerAddress {
		t.Fatalf("offers = %d, want %d", len(offers), MinJobsPerAddress)
	}
}

// fillShare gives a share all MinJobsPerShare places, each from an address
// of its own, and answers the jobs holding them.
func fillShare(t *testing.T, g *Registry, id string) []*Job {
	t.Helper()
	jobs := make([]*Job, MinJobsPerShare)
	for i := range jobs {
		j, err := g.NewJob(context.Background(), id, "198.51.100."+strconv.Itoa(i+1), "file", "a.txt", 0, -1)
		if err != nil {
			t.Fatal(err)
		}
		jobs[i] = j
	}
	return jobs
}

// waitInLine waits until the share's line holds n visitors.
func waitInLine(t *testing.T, g *Registry, id string, n int) {
	t.Helper()
	g.mu.Lock()
	js := g.shares[id].jobs
	g.mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for {
		js.mu.Lock()
		got := js.line.Len()
		js.mu.Unlock()
		if got == n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("in line %d, want %d", got, n)
		}
		time.Sleep(time.Millisecond)
	}
}

type newJobResult struct {
	j   *Job
	err error
}

// queue starts a NewJob from addr that is expected to wait in line, and
// answers where its result arrives.
func queue(ctx context.Context, g *Registry, id, addr string) chan newJobResult {
	out := make(chan newJobResult, 1)
	go func() {
		j, err := g.NewJob(ctx, id, addr, "file", "a.txt", 0, -1)
		out <- newJobResult{j, err}
	}()
	return out
}

func receive(t *testing.T, c chan newJobResult) newJobResult {
	t.Helper()
	select {
	case r := <-c:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("a visitor in line was never answered")
		return newJobResult{}
	}
}

func stillWaiting(t *testing.T, c chan newJobResult) {
	t.Helper()
	select {
	case r := <-c:
		t.Fatalf("a visitor in line was answered early: %v", r.err)
	case <-time.After(50 * time.Millisecond):
	}
}

// A visitor past the share's cap waits in line, offering the sharer nothing,
// and among addresses that hold no place, places go out oldest first: a
// visitor arriving while others wait goes to the back even when a place frees
// as it arrives.
func TestAFullShareGivesPlacesOutOldestFirst(t *testing.T) {
	now := time.Now()
	g := testRegistry(&now)
	rec, _ := g.Create(Record{Owner: "amy"})
	held := fillShare(t, g, rec.ID)
	first := queue(context.Background(), g, rec.ID, "203.0.113.1")
	waitInLine(t, g, rec.ID, 1)
	second := queue(context.Background(), g, rec.ID, "203.0.113.2")
	waitInLine(t, g, rec.ID, 2)
	if offers, _ := g.Poll(context.Background(), rec.ID, "amy", 10*time.Millisecond); len(offers) != MinJobsPerShare {
		t.Fatalf("offers = %d, want %d: a visitor in line offers nothing", len(offers), MinJobsPerShare)
	}

	held[0].Cancel()
	r := receive(t, first)
	if r.err != nil {
		t.Fatalf("the oldest in line: %v", r.err)
	}
	held[0] = r.j
	stillWaiting(t, second)

	third := queue(context.Background(), g, rec.ID, "203.0.113.3")
	waitInLine(t, g, rec.ID, 2)
	held[1].Cancel()
	r = receive(t, second)
	if r.err != nil {
		t.Fatalf("the second in line: %v", r.err)
	}
	held[1] = r.j
	stillWaiting(t, third)
	held[2].Cancel()
	r = receive(t, third)
	if r.err != nil {
		t.Fatalf("the third in line: %v", r.err)
	}
	held[2] = r.j
	for _, j := range held {
		j.Cancel()
	}
	assertNoPlaces(t, g, rec.ID)
}

// A line MinQueuedPerShare long turns the next visitor away at once.
func TestAFullLineIsBusyAtOnce(t *testing.T) {
	now := time.Now()
	g := testRegistry(&now)
	rec, _ := g.Create(Record{Owner: "amy"})
	held := fillShare(t, g, rec.ID)
	ctx, cancel := context.WithCancel(context.Background())
	var waiting []chan newJobResult
	for i := range MinQueuedPerShare {
		waiting = append(waiting, queue(ctx, g, rec.ID, "203.0.113."+strconv.Itoa(i+1)))
		waitInLine(t, g, rec.ID, i+1)
	}
	started := time.Now()
	_, err := g.NewJob(context.Background(), rec.ID, "192.0.2.1", "file", "a.txt", 0, -1)
	if !errors.Is(err, ErrBusy) || errors.Is(err, ErrAddressBusy) {
		t.Fatalf("one past a full line: %v, want ErrBusy of the share", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("one past a full line waited")
	}
	cancel()
	for _, c := range waiting {
		if r := receive(t, c); !errors.Is(r.err, context.Canceled) {
			t.Fatalf("a visitor that left the line: %v, want context.Canceled", r.err)
		}
	}
	for _, j := range held {
		j.Cancel()
	}
	assertNoPlaces(t, g, rec.ID)
}

// A wait in line past Config.QueueWait is ErrBusy of the share, and leaves
// nothing behind.
func TestAWaitInLinePastItsBoundIsBusy(t *testing.T) {
	n := 0
	g := NewRegistry(Config{
		NewID:     func() string { return "aaaaaaaaaa" },
		NewSlug:   func() string { n++; return strconv.Itoa(n) },
		QueueWait: 50 * time.Millisecond,
	})
	rec, _ := g.Create(Record{Owner: "amy"})
	held := fillShare(t, g, rec.ID)
	started := time.Now()
	_, err := g.NewJob(context.Background(), rec.ID, "203.0.113.1", "file", "a.txt", 0, -1)
	if !errors.Is(err, ErrBusy) || errors.Is(err, ErrAddressBusy) {
		t.Fatalf("a wait in line past its bound: %v, want ErrBusy of the share", err)
	}
	if waited := time.Since(started); waited < 50*time.Millisecond || waited > 5*time.Second {
		t.Fatalf("waited %v, want about the 50 ms bound", waited)
	}
	for _, j := range held {
		j.Cancel()
	}
	assertNoPlaces(t, g, rec.ID)
}

// A visitor in line holds one of its address's places: one more request from
// an address whose transfer and places in line are all it may have waits for
// its address, and is ErrAddressBusy past Config.AddressWait.
func TestAPlaceInLineCountsForItsAddress(t *testing.T) {
	n := 0
	g := NewRegistry(Config{
		NewID:       func() string { return "aaaaaaaaaa" },
		NewSlug:     func() string { n++; return strconv.Itoa(n) },
		AddressWait: 50 * time.Millisecond,
	})
	rec, _ := g.Create(Record{Owner: "amy"})
	held := fillShare(t, g, rec.ID) // 198.51.100.1 holds one place
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var inLine []chan newJobResult
	for i := range MinJobsPerAddress - 1 {
		inLine = append(inLine, queue(ctx, g, rec.ID, "198.51.100.1"))
		waitInLine(t, g, rec.ID, i+1)
	}
	if _, err := g.NewJob(context.Background(), rec.ID, "198.51.100.1", "file", "a.txt", 0, -1); !errors.Is(err, ErrAddressBusy) {
		t.Fatalf("one more from an address with all its places: %v, want ErrAddressBusy", err)
	}
	waitInLine(t, g, rec.ID, MinJobsPerAddress-1)
	cancel()
	for _, c := range inLine {
		receive(t, c)
	}
	for _, j := range held {
		j.Cancel()
	}
	assertNoPlaces(t, g, rec.ID)
}

// A place handed to a visitor whose request has already ended goes on to the
// next in line: it is never lost and never counted twice.
func TestAPlaceHandedToAVisitorThatLeftGoesToTheNext(t *testing.T) {
	now := time.Now()
	g := testRegistry(&now)
	rec, _ := g.Create(Record{Owner: "amy"})
	held := fillShare(t, g, rec.ID)
	g.mu.Lock()
	js := g.shares[rec.ID].jobs
	g.mu.Unlock()
	ctx, leave := context.WithCancel(context.Background())
	leaving := queue(ctx, g, rec.ID, "203.0.113.1")
	waitInLine(t, g, rec.ID, 1)
	next := queue(context.Background(), g, rec.ID, "203.0.113.2")
	waitInLine(t, g, rec.ID, 2)
	// The leaving visitor sees its request end while the set is locked, so
	// the place is handed to it before it can step out of line.
	js.mu.Lock()
	leave()
	time.Sleep(100 * time.Millisecond)
	js.releaseLocked(held[0])
	js.mu.Unlock()
	if r := receive(t, leaving); !errors.Is(r.err, context.Canceled) {
		t.Fatalf("a visitor that left before taking its place: %v, want context.Canceled", r.err)
	}
	r := receive(t, next)
	if r.err != nil {
		t.Fatalf("the next in line: %v", r.err)
	}
	held[0].Cancel()
	held[0] = r.j
	for _, j := range held {
		j.Cancel()
	}
	assertNoPlaces(t, g, rec.ID)
}

// A share that goes away answers everyone in its line ErrNoShare at once.
func TestAShareThatEndsEmptiesItsLine(t *testing.T) {
	now := time.Now()
	g := testRegistry(&now)
	rec, _ := g.Create(Record{Owner: "amy"})
	fillShare(t, g, rec.ID)
	inLine := queue(context.Background(), g, rec.ID, "203.0.113.1")
	waitInLine(t, g, rec.ID, 1)
	// 198.51.100.1 holds a place: its next requests fill its places in line,
	// and one more waits for its address.
	waiting := []chan newJobResult{inLine}
	for i := range MinJobsPerAddress - 1 {
		waiting = append(waiting, queue(context.Background(), g, rec.ID, "198.51.100.1"))
		waitInLine(t, g, rec.ID, i+2)
	}
	waiting = append(waiting, queue(context.Background(), g, rec.ID, "198.51.100.1"))
	if !g.Delete(rec.ID, "amy") {
		t.Fatal("delete refused")
	}
	for _, c := range waiting {
		if r := receive(t, c); !errors.Is(r.err, ErrNoShare) {
			t.Fatalf("a visitor waiting on a share that ended: %v, want ErrNoShare", r.err)
		}
	}
}
