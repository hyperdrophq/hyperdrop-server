package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// When two of the zip line's caps are reached at once the place is refused, the refused
// request counts against neither, and the line admits again only once both have room.
func TestZipLineRefusesWhenTwoCapsAreFullAndCountsNothing(t *testing.T) {
	var size atomic.Int64
	l := newZipLine(func() int { return int(size.Load()) })
	enter := func(addr, share string) func() {
		t.Helper()
		leave, ok := l.enter(addr, share)
		if !ok {
			t.Fatalf("%s for %s refused with room", addr, share)
		}
		return leave
	}
	refused := func(addr, share string) {
		t.Helper()
		if _, ok := l.enter(addr, share); ok {
			t.Fatalf("%s for %s admitted past a cap", addr, share)
		}
	}

	t.Run("total and address", func(t *testing.T) {
		size.Store(zipLinePerAddress)
		var held []func()
		for i := range zipLinePerAddress {
			held = append(held, enter("203.0.113.5", fmt.Sprintf("share-%d", i)))
		}
		refused("203.0.113.5", "fresh")
		size.Store(1000)
		refused("203.0.113.5", "fresh")
		held[0]()
		enter("203.0.113.5", "fresh")()
		for _, leave := range held {
			leave()
		}
	})

	t.Run("total and share", func(t *testing.T) {
		size.Store(2 * zipLineShareParts)
		var other, flooded []func()
		for i := range 2 {
			flooded = append(flooded, enter(fmt.Sprintf("198.51.100.%d", i), "flooded"))
		}
		for i := range 2*zipLineShareParts - 2 {
			other = append(other, enter(fmt.Sprintf("203.0.113.%d", i), fmt.Sprintf("other-%d", i)))
		}
		refused("192.0.2.1", "flooded")
		other[0]()
		refused("192.0.2.1", "flooded")
		enter("192.0.2.1", "another")()
		flooded[0]()
		enter("192.0.2.1", "flooded")()
		for _, leave := range append(other, flooded...) {
			leave()
		}
	})

	t.Run("address and share", func(t *testing.T) {
		size.Store(zipLinePerAddress * zipLineShareParts)
		var held []func()
		for range zipLinePerAddress {
			held = append(held, enter("203.0.113.5", "flooded"))
		}
		refused("203.0.113.5", "flooded")
		refused("203.0.113.5", "another")
		refused("198.51.100.7", "flooded")
		held[0]()
		enter("203.0.113.5", "flooded")()
		for _, leave := range held {
			leave()
		}
	})

	// Every place given back: the whole line is free again, one address and one share
	// up to their caps.
	size.Store(zipLinePerAddress * zipLineShareParts)
	var all []func()
	for range zipLinePerAddress {
		all = append(all, enter("203.0.113.5", "flooded"))
	}
	for i := range zipLinePerAddress*zipLineShareParts - zipLinePerAddress {
		all = append(all, enter(fmt.Sprintf("10.0.%d.1", i), fmt.Sprintf("s-%d", i)))
	}
	refused("192.0.2.9", "s-new")
	for _, leave := range all {
		leave()
		leave()
	}
	for range zipLinePerAddress {
		all = append(all, enter("203.0.113.5", "flooded"))
	}
	for _, leave := range all {
		leave()
	}
}

// Whichever of the line's caps refuses a zip, the answer is the same busy page that
// retries: an address's places in line are not its running streams, so it is not the
// page about the address's own downloads.
func TestZipLineRefusalIsTheBusyPageWhicheverCapRefuses(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int
		fill func(share string) [][2]string
	}{
		{"total", 2, func(string) [][2]string {
			return [][2]string{{"198.51.100.1", "other-1"}, {"198.51.100.2", "other-2"}}
		}},
		{"share", 2 * zipLineShareParts, func(share string) [][2]string {
			return [][2]string{{"198.51.100.1", share}, {"198.51.100.2", share}}
		}},
		{"address", 1000, func(string) [][2]string {
			var places [][2]string
			for i := range zipLinePerAddress {
				places = append(places, [2]string{"203.0.113.5", fmt.Sprintf("other-%d", i)})
			}
			return places
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saved := zipWaiting
			zipWaiting = newZipLine(func() int { return tc.size })
			t.Cleanup(func() { zipWaiting = saved })
			h := newTestAPI(t)
			id, _ := shareWithFiles(t, h, "pair", map[string]string{"a.txt": "alpha"})
			for _, place := range tc.fill(id) {
				leave, ok := zipWaiting.enter(place[0], place[1])
				if !ok {
					t.Fatalf("filling the line: %v refused", place)
				}
				t.Cleanup(leave)
			}
			r := httptest.NewRequest(http.MethodGet, "/zip/"+id, nil)
			r.RemoteAddr = "203.0.113.5:1000"
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("code %d", w.Code)
			}
			for header, want := range map[string]string{
				"Retry-After":   busyRetryAfter,
				"Connection":    "close",
				"Cache-Control": "no-store",
				"Content-Type":  "text/html; charset=utf-8",
			} {
				if got := w.Header().Get(header); got != want {
					t.Errorf("%s %q, want %q", header, got, want)
				}
			}
			if w.Body.String() != string(zipBusyPage) {
				t.Errorf("the answer is not the busy page:\n%s", w.Body)
			}
		})
	}
}

// When two of the inbox slots' bounds are reached at once the upload is refused, the
// refused upload counts against neither, and a slot is given again only once both have
// room.
func TestInboxSlotsRefuseWhenTwoBoundsAreFullAndCountNothing(t *testing.T) {
	s := newInboxSlots()
	take := func(share, addr string) func() {
		t.Helper()
		release, ok := s.take(share, addr)
		if !ok {
			t.Fatalf("%s into %s refused with room", addr, share)
		}
		return release
	}
	refused := func(share, addr string) {
		t.Helper()
		if _, ok := s.take(share, addr); ok {
			t.Fatalf("%s into %s admitted past a bound", addr, share)
		}
	}
	fillOthers := func(n int) []func() {
		var held []func()
		for i := range n {
			held = append(held, take(fmt.Sprintf("other-%d", i), fmt.Sprintf("10.1.%d.1", i)))
		}
		return held
	}
	releaseAll := func(held []func()) {
		for _, release := range held {
			release()
		}
	}

	t.Run("total and share", func(t *testing.T) {
		var inbox []func()
		for i := range inboxUploadsPerShare {
			inbox = append(inbox, take("inbox", fmt.Sprintf("198.51.100.%d", i)))
		}
		others := fillOthers(inboxUploadsMax - inboxUploadsPerShare)
		refused("inbox", "192.0.2.1")
		others[0]()
		refused("inbox", "192.0.2.1")
		take("another", "192.0.2.1")()
		inbox[0]()
		take("inbox", "192.0.2.1")()
		releaseAll(append(inbox, others...))
	})

	t.Run("total and address", func(t *testing.T) {
		var addr []func()
		for i := range inboxUploadsPerAddr {
			addr = append(addr, take(fmt.Sprintf("share-%d", i), "203.0.113.5"))
		}
		others := fillOthers(inboxUploadsMax - inboxUploadsPerAddr)
		refused("fresh", "203.0.113.5")
		others[0]()
		refused("fresh", "203.0.113.5")
		take("fresh", "192.0.2.1")()
		addr[0]()
		take("fresh", "203.0.113.5")()
		releaseAll(append(addr, others...))
	})

	t.Run("share and address", func(t *testing.T) {
		var held []func()
		for range inboxUploadsPerAddr {
			held = append(held, take("inbox", "203.0.113.5"))
		}
		for i := range inboxUploadsPerShare - inboxUploadsPerAddr {
			held = append(held, take("inbox", fmt.Sprintf("198.51.100.%d", i)))
		}
		refused("inbox", "203.0.113.5")
		refused("another", "203.0.113.5")
		refused("inbox", "192.0.2.1")
		held[0]()
		take("inbox", "203.0.113.5")()
		releaseAll(held)
	})

	// Every slot given back: the whole server-wide bound is free again.
	held := fillOthers(inboxUploadsMax)
	refused("fresh", "192.0.2.9")
	for _, release := range held {
		release()
		release()
	}
	releaseAll(fillOthers(inboxUploadsMax))
	if got := s.floor(); got != inboxPacing.calm {
		t.Errorf("the floor of an empty pool is %d, want the calm %d", got, inboxPacing.calm)
	}
}

// Whichever of the slots' bounds refuses an anonymous upload, the answer is the same
// 429 with the same code, message and Retry-After.
func TestInboxSlotRefusalIsTheSameWhicheverBoundRefuses(t *testing.T) {
	const addr = "203.0.113.5"
	var first string
	for _, tc := range []struct {
		name string
		fill func(id string) [][2]string
	}{
		{"total", func(string) [][2]string {
			var slots [][2]string
			for i := range inboxUploadsMax {
				slots = append(slots, [2]string{fmt.Sprintf("other-%d", i), fmt.Sprintf("10.2.%d.1", i)})
			}
			return slots
		}},
		{"share", func(id string) [][2]string {
			var slots [][2]string
			for i := range inboxUploadsPerShare {
				slots = append(slots, [2]string{id, fmt.Sprintf("10.3.%d.1", i)})
			}
			return slots
		}},
		{"address", func(string) [][2]string {
			var slots [][2]string
			for i := range inboxUploadsPerAddr {
				slots = append(slots, [2]string{fmt.Sprintf("other-%d", i), addrKey(addr)})
			}
			return slots
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, hd := newTestAPIParts(t)
			h := hd.routes()
			id := createInbox(t, h, `{"name":"inbox","receive":true}`)
			for _, slot := range tc.fill(id) {
				release, ok := hd.inboxSlots.take(slot[0], slot[1])
				if !ok {
					t.Fatalf("filling the slots: %v refused", slot)
				}
				t.Cleanup(release)
			}
			req := httptest.NewRequest("PUT", "/receive/"+id+"/files/a.txt", strings.NewReader("x"))
			req.RemoteAddr = addr + ":1234"
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusTooManyRequests {
				t.Fatalf("code %d %s", rec.Code, rec.Body)
			}
			if got := rec.Header().Get("Retry-After"); got != "10" {
				t.Errorf("Retry-After %q", got)
			}
			if got := errCode(t, rec.Body.String()); got != "rate-limited" {
				t.Errorf("code %q", got)
			}
			if !strings.Contains(rec.Body.String(), "too many uploads to this inbox at once, try again in a moment") {
				t.Errorf("message %s", rec.Body)
			}
			if first == "" {
				first = rec.Body.String()
			} else if rec.Body.String() != first {
				t.Errorf("body %s, the total bound's was %s", rec.Body, first)
			}
		})
	}
}

// The download count answers an owner for their own shares only, totals every id asked
// (an id asked twice counts twice), and a release gives back exactly its own read.
func TestDownloadsActiveForTotalsTheOwnersReads(t *testing.T) {
	d := newDownloads()
	a1, a2, b := d.begin("share-a", "alice"), d.begin("share-a", "alice"), d.begin("share-b", "bob")
	for _, tc := range []struct {
		owner string
		ids   []string
		want  int
	}{
		{"alice", []string{"share-a"}, 2},
		{"alice", []string{"share-a", "share-b", "share-c"}, 2},
		{"alice", []string{"share-a", "share-a"}, 4},
		{"bob", []string{"share-a", "share-b"}, 1},
		{"carol", []string{"share-a", "share-b"}, 0},
	} {
		if got := d.activeFor(tc.owner, tc.ids); got != tc.want {
			t.Errorf("activeFor(%s, %v) = %d, want %d", tc.owner, tc.ids, got, tc.want)
		}
	}
	a1()
	a1()
	if got := d.activeFor("alice", []string{"share-a"}); got != 1 {
		t.Errorf("after one release = %d, want 1", got)
	}
	a2()
	b()
	if got := d.activeFor("alice", []string{"share-a"}) + d.activeFor("bob", []string{"share-b"}); got != 0 {
		t.Errorf("after every release = %d, want 0", got)
	}
}
