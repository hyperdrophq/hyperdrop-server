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

// A share holds at most MaxJobsPerShare jobs: one more is ErrBusy and is
// never offered, and every way a job ends (its visitor leaving, its body
// read to the end, the sharer failing it) gives its place back.
func TestNewJobRefusesBeyondTheCapUntilAJobEnds(t *testing.T) {
	n := 0
	g := NewRegistry(Config{
		NewID:   func() string { return "aaaaaaaaaa" },
		NewSlug: func() string { n++; return strconv.Itoa(n) },
	})
	rec, err := g.Create(Record{Owner: "alice", Files: []File{{Path: "a.txt"}}})
	if err != nil {
		t.Fatal(err)
	}
	// Every job from an address of its own, so only the share's cap counts.
	addrs := 0
	next := func() string { addrs++; return strconv.Itoa(addrs) }
	jobs := make([]*Job, MaxJobsPerShare)
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
	if offers, _ := g.Poll(context.Background(), rec.ID, "alice", time.Second); len(offers) != MaxJobsPerShare {
		t.Fatalf("offers = %d, want %d", len(offers), MaxJobsPerShare)
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

// A share's jobs from one address past MaxJobsPerAddress wait for one of
// that address's own places, offering nothing meanwhile, while another
// address goes ahead at once; one of the address's jobs ending lets the
// waiter in.
func TestAnAddressBeyondItsCapWaitsForItsOwnPlace(t *testing.T) {
	now := time.Now()
	g := testRegistry(&now)
	rec, _ := g.Create(Record{Owner: "amy"})
	var held []*Job
	for range MaxJobsPerAddress {
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
	if offers, _ := g.Poll(context.Background(), rec.ID, "amy", 10*time.Millisecond); len(offers) != MaxJobsPerAddress+1 {
		t.Fatalf("offers = %d, want %d: a waiting request offers nothing", len(offers), MaxJobsPerAddress+1)
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
	for _, j := range []*Job{r.j, held[1], other} {
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
	if js.active != 0 || len(js.byAddr) != 0 || len(js.freed) != 0 {
		t.Fatalf("active %d, by address %v, waited on %d", js.active, js.byAddr, len(js.freed))
	}
}

// A request that leaves while it waits takes nothing and leaves nothing:
// once the address's jobs end every count is back to zero.
func TestAWaitingRequestThatLeavesHoldsNothing(t *testing.T) {
	now := time.Now()
	g := testRegistry(&now)
	rec, _ := g.Create(Record{Owner: "amy"})
	var held []*Job
	for range MaxJobsPerAddress {
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
	for range MaxJobsPerAddress {
		if _, err := g.NewJob(context.Background(), rec.ID, "198.51.100.7", "file", "a.txt", 0, -1); err != nil {
			t.Fatal(err)
		}
	}
	started := time.Now()
	if _, err := g.NewJob(context.Background(), rec.ID, "198.51.100.7", "file", "a.txt", 0, -1); !errors.Is(err, ErrBusy) {
		t.Fatalf("a wait past its bound: %v, want ErrBusy", err)
	}
	if waited := time.Since(started); waited < 50*time.Millisecond || waited > 5*time.Second {
		t.Fatalf("waited %v, want about the 50 ms bound", waited)
	}
	if offers, _ := g.Poll(context.Background(), rec.ID, "amy", 10*time.Millisecond); len(offers) != MaxJobsPerAddress {
		t.Fatalf("offers = %d, want %d", len(offers), MaxJobsPerAddress)
	}
}
