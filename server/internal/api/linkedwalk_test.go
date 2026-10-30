package api

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"hyperdrop/server/internal/linked"
)

// Readers of one share under one key share one walk: concurrent readers
// of a cold entry wait for the walk in flight rather than starting their
// own, and later readers within the TTL reuse it. A new key walks again.
func TestLinkedWalksComposeOncePerKey(t *testing.T) {
	var c linkedWalks
	var walks atomic.Int32
	release := make(chan struct{})
	compose := func() (linked.Listing, bool) {
		walks.Add(1)
		<-release
		return linked.Listing{Entries: []linked.Entry{{Rel: "a.jpg"}}}, true
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if w := c.get("abcdefghjk", "k1", compose); len(w.listing.Entries) != 1 || !w.readable {
				t.Errorf("walk = %+v", w)
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	c.get("abcdefghjk", "k1", compose)
	if n := walks.Load(); n != 1 {
		t.Fatalf("20 concurrent readers and one more walked %d times, want 1", n)
	}
	c.get("abcdefghjk", "k2", compose)
	if n := walks.Load(); n != 2 {
		t.Fatalf("a new key walked %d times in all, want 2", n)
	}
}

// An entry past its TTL is walked again, and the cache stays bounded.
func TestLinkedWalksExpireAndStayBounded(t *testing.T) {
	c := linkedWalks{ttl: time.Millisecond}
	var walks atomic.Int32
	compose := func() (linked.Listing, bool) { walks.Add(1); return linked.Listing{}, true }
	c.get("abcdefghjk", "k", compose)
	time.Sleep(5 * time.Millisecond)
	c.get("abcdefghjk", "k", compose)
	if n := walks.Load(); n != 2 {
		t.Fatalf("walked %d times across an expiry, want 2", n)
	}
	for i := range linkedWalkMax * 2 {
		c.get(strings.Repeat("x", 9)+string(rune('a'+i%26))+strings.Repeat("y", i/26), "k", compose)
	}
	c.mu.Lock()
	n := len(c.byShare)
	c.mu.Unlock()
	if n > linkedWalkMax {
		t.Fatalf("cache holds %d shares, want at most %d", n, linkedWalkMax)
	}
}

// The slugs a walk was handed are kept for its next reader.
func TestLinkedWalkKeepsTheSlugsItWasHanded(t *testing.T) {
	w := &linkedWalk{done: make(chan struct{})}
	fills := 0
	fill := func(rels []string) (map[string]string, error) {
		fills++
		out := map[string]string{}
		for _, r := range rels {
			out[r] = "slug-" + r
		}
		return out, nil
	}
	if _, err := w.slugs([]string{"a"}, fill); err != nil {
		t.Fatal(err)
	}
	got, err := w.slugs([]string{"a"}, fill)
	if err != nil || got["a"] != "slug-a" || fills != 1 {
		t.Fatalf("slugs = %v %v after %d fills, want slug-a after 1", got, err, fills)
	}
}

// From the outside: a public read within the TTL answers the walk an
// earlier public read took, while the owner's read walks the folder as it
// is; every edit to the share answers on the very next public read, the
// hide and the revoke included, because the edit moves the cache's key.
func TestPublicLinkedReadsReuseTheWalkAndEveryEditMovesIt(t *testing.T) {
	vol := seedLinkedVolume(t)
	roots, err := linked.NewRoots(nil, []string{vol}, nil)
	if err != nil {
		t.Fatal(err)
	}
	b := testBackendWithRoots(t, roots)
	hd := newHandler(b, "2.0.0", testDomain(t), nil, Deployment{})
	hd.walks.ttl = time.Hour
	h := hd.routes()
	bob := grantedUser(t, h, "bob", "photo/2024")
	var made revokedView
	unmarshal(t, doReq(t, h, "POST", "/api/shares", bob, `{"source":"photo/2024","name":"trip"}`), &made)
	slugA := slugOf(t, made, "a.jpg")
	if rec := doReq(t, h, "GET", "/share/"+made.ID, "", ""); !strings.Contains(rec.Body.String(), "b.jpg") {
		t.Fatalf("first public listing: %d", rec.Code)
	}

	if err := os.WriteFile(filepath.Join(vol, "photo", "2024", "c.jpg"), []byte("C"), 0o644); err != nil {
		t.Fatal(err)
	}
	if rec := doReq(t, h, "GET", "/share/"+made.ID, "", ""); strings.Contains(rec.Body.String(), "c.jpg") {
		t.Fatal("a public read inside the TTL walked the folder again")
	}
	var owner revokedView
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+made.ID, bob, ""), &owner)
	slugOf(t, owner, "c.jpg") // the owner's read is fresh

	if rec := doReq(t, h, "PATCH", "/api/shares/"+made.ID, bob, `{"linked":{"photo/2024":{"hide":["a.jpg"]}}}`); rec.Code != 200 {
		t.Fatalf("hide: %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "GET", "/download/"+made.ID+"/"+slugA, "", ""); rec.Code != 404 {
		t.Fatalf("hidden entry right after the hide: %d, want 404", rec.Code)
	}
	if rec := doReq(t, h, "GET", "/share/"+made.ID, "", ""); !strings.Contains(rec.Body.String(), "c.jpg") {
		t.Fatal("the edit did not move the cache's key: the new file is still missing")
	}
	if rec := doReq(t, h, "PATCH", "/api/shares/"+made.ID, bob, `{"linked":{"photo/2024":{"show":["a.jpg"]}}}`); rec.Code != 200 {
		t.Fatalf("show: %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "GET", "/download/"+made.ID+"/"+slugA, "", ""); rec.Code != 200 {
		t.Fatalf("shown entry: %d, want 200", rec.Code)
	}
	if rec := doReq(t, h, "PATCH", "/api/users/bob", testToken, `{"sourceRoots":[],"confirmRevoke":true}`); rec.Code != 200 {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body)
	}
	rec := doReq(t, h, "GET", "/download/"+made.ID+"/"+slugA, "", "")
	if rec.Body.String() == "AAAA" || !strings.Contains(rec.Body.String(), "not available on this server") {
		t.Fatalf("revoked entry right after the revoke: %d %q", rec.Code, rec.Body.String())
	}
}

// A walk slower than the TTL is still joined while it runs: the TTL counts
// from its end, so a slow volume never has two walks of one share at once.
func TestASlowWalkIsJoinedPastTheTTL(t *testing.T) {
	c := linkedWalks{ttl: 10 * time.Millisecond}
	var walks atomic.Int32
	release := make(chan struct{})
	compose := func() (linked.Listing, bool) {
		walks.Add(1)
		<-release
		return linked.Listing{}, true
	}
	first := make(chan *linkedWalk)
	go func() { first <- c.get("abcdefghjk", "k", compose) }()
	for walks.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(30 * time.Millisecond)
	second := make(chan *linkedWalk)
	go func() { second <- c.get("abcdefghjk", "k", compose) }()
	time.Sleep(10 * time.Millisecond)
	close(release)
	if a, b := <-first, <-second; a != b || walks.Load() != 1 {
		t.Fatalf("walked %d times, shared %v: want one walk for both readers", walks.Load(), a == b)
	}
}

// A finished walk leaves the cache once its TTL runs out, with no reader
// to notice, and the entries it held leave the budget with it.
func TestAnExpiredWalkLeavesTheCacheUnread(t *testing.T) {
	c := linkedWalks{ttl: 10 * time.Millisecond}
	c.get("abcdefghjk", "k", func() (linked.Listing, bool) {
		return linked.Listing{Entries: make([]linked.Entry, 100)}, true
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		c.mu.Lock()
		n, entries := len(c.byShare), c.entries
		c.mu.Unlock()
		if n == 0 && entries == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("after its TTL the cache holds %d walks and %d entries", n, entries)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The walks cached at once hold at most linkedWalkEntries entries between
// them, the oldest dropped first, whatever the share count allows.
func TestTheWalkCacheHoldsABoundedNumberOfEntries(t *testing.T) {
	c := linkedWalks{ttl: time.Hour}
	full := func() (linked.Listing, bool) {
		return linked.Listing{Entries: make([]linked.Entry, linked.MaxWalk)}, true
	}
	for i := range 10 {
		c.get(strings.Repeat("x", 9)+string(rune('a'+i)), "k", full)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries > linkedWalkEntries || len(c.byShare)*linked.MaxWalk != c.entries {
		t.Fatalf("cache holds %d walks and %d entries, want at most %d entries", len(c.byShare), c.entries, linkedWalkEntries)
	}
	if _, ok := c.byShare["xxxxxxxxxj"]; !ok {
		t.Fatal("the newest walk was dropped rather than the oldest")
	}
	if _, ok := c.byShare["xxxxxxxxxa"]; ok {
		t.Fatal("the oldest walk outlived the budget")
	}
}

// A compose that never returns (it panicked) is never served: its waiters
// compose afresh instead of blocking for good on it or reading its
// half-made walk.
func TestAWalkThatPanicsReleasesItsWaiters(t *testing.T) {
	var c linkedWalks
	release := make(chan struct{})
	started := make(chan struct{})
	go func() {
		defer func() { recover() }()
		c.get("abcdefghjk", "k", func() (linked.Listing, bool) {
			close(started)
			<-release
			panic("compose")
		})
	}()
	<-started
	got := make(chan *linkedWalk, 1)
	go func() {
		got <- c.get("abcdefghjk", "k", func() (linked.Listing, bool) {
			return linked.Listing{Entries: []linked.Entry{{Rel: "a.jpg"}}}, true
		})
	}()
	time.Sleep(20 * time.Millisecond)
	close(release)
	select {
	case w := <-got:
		if w.failed || !w.readable || len(w.listing.Entries) != 1 {
			t.Fatalf("the waiter got %+v", w)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a waiter on a walk that panicked never returned")
	}
}
