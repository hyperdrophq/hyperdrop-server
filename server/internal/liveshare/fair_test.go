package liveshare

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"
)

// shareAt is a registry with one share whose limit is set to limit, as a
// share that has learned it, and the share's jobs.
func shareAt(t *testing.T, cfg Config, limit int) (*Registry, string, *jobSet) {
	t.Helper()
	n := 0
	cfg.NewID = func() string { return "aaaaaaaaaa" }
	cfg.NewSlug = func() string { n++; return strconv.Itoa(n) }
	g := NewRegistry(cfg)
	rec, err := g.Create(Record{Owner: "amy"})
	if err != nil {
		t.Fatal(err)
	}
	g.mu.Lock()
	js := g.shares[rec.ID].jobs
	g.mu.Unlock()
	js.mu.Lock()
	js.g.limit = limit
	js.mu.Unlock()
	return g, rec.ID, js
}

// At the starting limit and at a grown one, nine addresses holding all the
// places an address may have leave room for a tenth, and none of them gets
// one place more.
func TestTenAddressesAreNeededToHoldAShare(t *testing.T) {
	for _, limit := range []int{MinJobsPerShare, 39, 40, 100, 256} {
		g, id, js := shareAt(t, Config{AddressWait: 20 * time.Millisecond, MaxJobs: 256}, limit)
		js.mu.Lock()
		each := js.addrLimitLocked()
		js.mu.Unlock()
		if each*9 >= limit {
			t.Fatalf("limit %d: nine addresses of %d places hold the share", limit, each)
		}
		var jobs []*Job
		for a := range 9 {
			addr := "198.51.100." + strconv.Itoa(a+1)
			for range each {
				j, err := g.NewJob(context.Background(), id, addr, "file", "a.txt", 0, -1)
				if err != nil {
					t.Fatalf("limit %d: a place of %s: %v", limit, addr, err)
				}
				jobs = append(jobs, j)
			}
		}
		if _, err := g.NewJob(context.Background(), id, "198.51.100.1", "file", "a.txt", 0, -1); !errors.Is(err, ErrAddressBusy) {
			t.Fatalf("limit %d: one place more for an address with all of its own: %v, want ErrAddressBusy", limit, err)
		}
		j, err := g.NewJob(context.Background(), id, "203.0.113.1", "file", "a.txt", 0, -1)
		if err != nil {
			t.Fatalf("limit %d: a tenth address beside nine that hold all they may: %v", limit, err)
		}
		for _, j := range append(jobs, j) {
			j.Cancel()
		}
		assertNoPlaces(t, g, id)
	}
}

// A freed place goes to the visitor in line whose address holds the fewest
// places, and among those to the one that has waited longest: an address
// holding places waits behind every address that holds fewer, however early
// it joined the line.
func TestAFreedPlaceGoesToTheAddressHoldingTheFewest(t *testing.T) {
	const limit = 40 // an address may have four places
	g, id, _ := shareAt(t, Config{}, limit)
	const many, one = "192.0.2.1", "192.0.2.2"
	var held []*Job
	take := func(addr string) {
		t.Helper()
		j, err := g.NewJob(context.Background(), id, addr, "file", "a.txt", 0, -1)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, j)
	}
	take(many)
	take(many)
	take(one)
	for i := len(held); i < limit; i++ {
		take("198.51.100." + strconv.Itoa(i))
	}
	free := func() {
		held[len(held)-1].Cancel()
		held = held[:len(held)-1]
	}
	// The line, oldest first: the address holding two, the address holding
	// one, then two addresses holding none.
	inLine := map[string]chan newJobResult{}
	for i, addr := range []string{many, one, "203.0.113.1", "203.0.113.2"} {
		inLine[addr] = queue(context.Background(), g, id, addr)
		waitInLine(t, g, id, i+1)
	}
	for _, addr := range []string{"203.0.113.1", "203.0.113.2", one, many} {
		for other, c := range inLine {
			if other != addr {
				stillWaiting(t, c)
			}
		}
		free()
		r := receive(t, inLine[addr])
		if r.err != nil {
			t.Fatalf("%s in line: %v", addr, r.err)
		}
		delete(inLine, addr)
		defer r.j.Cancel()
	}
}
