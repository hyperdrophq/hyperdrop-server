package liveshare

import (
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// idleShare is a share on a real clock that measures in windows of 10 ms and
// ends an idle transfer after 200 ms, holding all its MinJobsPerShare places
// and unable to grow past them, so a visitor in line gets a place only when
// one is given back.
type idleShare struct {
	t    *testing.T
	g    *Registry
	id   string
	js   *jobSet
	jobs []*Job
	// sharers are the sharer's sides of the claimed jobs, in the order of jobs.
	sharers []*Claimed
	ctx     context.Context
	wg      sync.WaitGroup
}

const idleTestWindow = 200 * time.Millisecond

func newIdleShare(t *testing.T) *idleShare {
	t.Helper()
	g, id, js := shareAt(t, Config{ProbeWindow: 10 * time.Millisecond, IdleWindow: idleTestWindow, MaxJobs: MinJobsPerShare}, MinJobsPerShare)
	ctx, cancel := context.WithCancel(context.Background())
	s := &idleShare{t: t, g: g, id: id, js: js, jobs: fillShare(t, g, id), ctx: ctx}
	t.Cleanup(func() {
		cancel()
		g.Delete(id, "amy")
		for _, j := range s.jobs {
			j.Cancel()
		}
		s.wg.Wait()
	})
	return s
}

// claimAll has the sharer claim every job that holds a place.
func (s *idleShare) claimAll() {
	s.t.Helper()
	for _, j := range s.jobs {
		c, ok := s.g.Claim("amy", j.offer.Job)
		if !ok {
			s.t.Fatalf("claim of %s refused", j.offer.Job)
		}
		s.sharers = append(s.sharers, c)
	}
}

// feed has every sharer side send chunks of size as fast as its visitor takes
// them, after pause each.
func (s *idleShare) feed(size int, pause time.Duration) {
	for _, c := range s.sharers {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			chunk := make([]byte, size)
			for s.ctx.Err() == nil {
				if _, err := c.Write(chunk); err != nil {
					return
				}
				time.Sleep(pause)
			}
		}()
	}
}

// read has every job's visitor read chunks of size, pausing between them.
func (s *idleShare) read(size int, pause time.Duration) {
	for _, j := range s.jobs {
		body, err := j.Body(s.ctx, time.Second)
		if err != nil {
			s.t.Fatal(err)
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			p := make([]byte, size)
			for s.ctx.Err() == nil {
				if _, err := body.Read(p); err != nil {
					return
				}
				time.Sleep(pause)
			}
		}()
	}
}

func (s *idleShare) idled() (n int) {
	for _, j := range s.jobs {
		if j.Idled() {
			n++
		}
	}
	return n
}

// noneEnded waits several idle windows and fails when a transfer was ended as
// idle or the visitor in line was answered.
func (s *idleShare) noneEnded(waiter chan newJobResult) {
	s.t.Helper()
	time.Sleep(4 * idleTestWindow)
	if n := s.idled(); n != 0 {
		s.t.Fatalf("%d transfers were ended as idle", n)
	}
	if waiter != nil {
		select {
		case r := <-waiter:
			s.t.Fatalf("the visitor in line was answered: %v", r.err)
		default:
		}
	}
}

// A transfer whose visitor takes nothing keeps its place while nobody waits.
// Once a visitor waits in line, one such transfer is ended for it and no
// more: its place goes to the waiter, the sharer's next write and the
// visitor's next read fail, the visitor's request is told, and every count is
// given back once.
func TestAnIdleTransferIsEndedOnlyForAVisitorInLine(t *testing.T) {
	before := runtime.NumGoroutine()
	s := newIdleShare(t)
	s.claimAll()
	s.feed(1<<10, 0) // every sharer has bytes its visitor never takes
	bodies := make([]io.ReadCloser, len(s.jobs))
	var told atomic.Int32
	for i, j := range s.jobs {
		body, err := j.Body(s.ctx, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		bodies[i] = body
		defer j.OnIdle(func() { told.Add(1) })()
	}
	s.noneEnded(nil)

	waiter := queue(s.ctx, s.g, s.id, "203.0.113.1")
	r := receive(t, waiter)
	if r.err != nil {
		t.Fatalf("the visitor in line: %v", r.err)
	}
	defer r.j.Cancel()
	time.Sleep(2 * idleTestWindow)
	if n := s.idled(); n != 1 || told.Load() != 1 {
		t.Fatalf("%d transfers ended as idle and %d requests told, want one of each", n, told.Load())
	}
	for i, j := range s.jobs {
		if !j.Idled() {
			continue
		}
		if _, err := bodies[i].Read(make([]byte, 1)); err == nil {
			t.Fatal("the ended transfer's visitor read on")
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, err := s.sharers[i].Write([]byte{1}); err != nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("the ended transfer's sharer wrote on")
			}
		}
		bodies[i].Close()
	}
	s.js.mu.Lock()
	active, streaming, streams := s.js.active, s.js.g.streaming, len(s.js.streams)
	s.js.mu.Unlock()
	if active != MinJobsPerShare || streaming != MinJobsPerShare-1 || streams != MinJobsPerShare-1 {
		t.Fatalf("active %d, streaming %d and %d, want %d, %d and %d", active, streaming, streams,
			MinJobsPerShare, MinJobsPerShare-1, MinJobsPerShare-1)
	}

	// The share ends: nothing is left measuring, holding or running.
	r.j.Cancel()
	for _, j := range s.jobs {
		j.Cancel()
	}
	assertNoPlaces(t, s.g, s.id)
	s.g.Delete(s.id, "amy")
	s.js.mu.Lock()
	timer := s.js.g.timer
	s.js.mu.Unlock()
	if timer != nil {
		t.Fatal("a share that ended still measures")
	}
	s.wg.Wait()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before {
		if time.Now().After(deadline) {
			t.Fatalf("%d goroutines, %d before the share", runtime.NumGoroutine(), before)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The share stops measuring once the line is empty: a line that empties
// leaves no timer behind on a share that goes on.
func TestMeasuringStopsWhenTheLineEmpties(t *testing.T) {
	s := newIdleShare(t)
	ctx, leave := context.WithCancel(s.ctx)
	waiter := queue(ctx, s.g, s.id, "203.0.113.1")
	waitInLine(t, s.g, s.id, 1)
	leave()
	receive(t, waiter)
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.js.mu.Lock()
		timer := s.js.g.timer
		s.js.mu.Unlock()
		if timer == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the share still measures with nobody in line")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A job the sharer has not claimed is never ended as idle: that wait is the
// sharer's.
func TestAnUnclaimedJobIsNeverIdle(t *testing.T) {
	s := newIdleShare(t)
	s.noneEnded(queue(s.ctx, s.g, s.id, "203.0.113.1"))
}

// A transfer whose sharer sends nothing, or a trickle, is never ended as
// idle: its visitor takes all there is.
func TestASlowSharerCostsItsVisitorNothing(t *testing.T) {
	silent := newIdleShare(t)
	silent.claimAll()
	silent.read(32<<10, 0)
	silent.noneEnded(queue(silent.ctx, silent.g, silent.id, "203.0.113.1"))

	trickle := newIdleShare(t)
	trickle.claimAll()
	trickle.feed(1, idleTestWindow/4) // far under IdleBytesPerSecond
	trickle.read(32<<10, 0)
	trickle.noneEnded(queue(trickle.ctx, trickle.g, trickle.id, "203.0.113.1"))
}

// A visitor on a slow connection that takes more than IdleBytesPerSecond
// keeps its place while others wait.
func TestASlowVisitorAboveTheRateKeepsItsPlace(t *testing.T) {
	s := newIdleShare(t)
	s.claimAll()
	s.feed(1<<10, 0)
	// 512 bytes every 20 ms: the visitor, not the sharer, sets the pace, at
	// some 25 times IdleBytesPerSecond.
	s.read(512, 20*time.Millisecond)
	s.noneEnded(queue(s.ctx, s.g, s.id, "203.0.113.1"))
}

// Transfers that end by themselves, are left, and are ended as idle, all at
// once and with a line that never empties, give every place back exactly
// once.
func TestIdleEndsRaceEveryOtherEnd(t *testing.T) {
	g, id, _ := shareAt(t, Config{ProbeWindow: time.Millisecond, IdleWindow: 10 * time.Millisecond,
		QueueWait: 50 * time.Millisecond, MaxJobs: MinJobsPerShare}, MinJobsPerShare)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var wg sync.WaitGroup
	var ended atomic.Int32
	wg.Add(1)
	go func() { // the sharer: a short body for every job
		defer wg.Done()
		for ctx.Err() == nil {
			offers, err := g.Poll(ctx, id, "amy", 20*time.Millisecond)
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
					for range 4 {
						if _, err := c.Write(make([]byte, 64)); err != nil {
							return
						}
					}
					c.Close()
				}()
			}
		}
	}()
	for v := range 3 * MinJobsPerShare {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addr := "198.51.100." + strconv.Itoa(v+1)
			for ctx.Err() == nil {
				j, err := g.NewJob(ctx, id, addr, "file", "a.txt", 0, -1)
				if errors.Is(err, ErrBusy) {
					continue
				}
				if err != nil {
					return
				}
				body, err := j.Body(ctx, 100*time.Millisecond)
				if err != nil {
					continue
				}
				switch rand.IntN(3) {
				case 0: // reads to the end
					io.Copy(io.Discard, body)
				case 1: // reads some, stalls until it is ended or gives up
					body.Read(make([]byte, 64))
					time.Sleep(time.Duration(rand.IntN(30)) * time.Millisecond)
				case 2: // leaves at once
				}
				body.Close()
				if j.Idled() {
					ended.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	assertNoPlaces(t, g, id)
	if ended.Load() == 0 {
		t.Fatal("no transfer was ended as idle: the race was not run")
	}
}
