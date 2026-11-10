package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// spacedShare is a share with a password whose lane an attacker is holding: the
// free guesses are gone and the next is 30 seconds away.
func spacedShare(t *testing.T) (http.Handler, *handler, string) {
	t.Helper()
	hh := newHandler(testBackend(t), "2.0.0", testDomain(t), nil, Deployment{})
	h := hh.routes()
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"p","password":"s3cret"}`)
	var created struct{ ID string }
	unmarshal(t, rec, &created)
	for _, lane := range []string{shareLaneKey(created.ID), shareCrossLaneKey(created.ID)} {
		for range laneFree + 1 {
			att, _, ok := hh.limits.pw.admit(time.Now(), lane)
			if !ok {
				t.Fatal("the lane refused while being filled")
			}
			att.failed(created.ID)
		}
		if _, _, ok := hh.limits.pw.admit(time.Now(), lane); ok {
			t.Fatal("the lane is not spacing guesses")
		}
	}
	return h, hh, created.ID
}

func unlockFrom(t *testing.T, h http.Handler, id, addr, password string, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/unlock/"+id, strings.NewReader("password="+password))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = addr
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func unlocked(rec *httptest.ResponseRecorder) bool {
	return rec.Code < 400 && strings.Contains(rec.Header().Get("Set-Cookie"), "hd_")
}

// Someone guessing wrong once every 30 seconds keeps the share's own count full,
// and a visitor who has guessed nothing still gets in with the right password.
func TestAVisitorWithTheRightPasswordGetsInDuringAnAttack(t *testing.T) {
	h, _, id := spacedShare(t)
	if rec := unlockFrom(t, h, id, "198.51.100.1:1000", "s3cret"); !unlocked(rec) {
		t.Fatalf("= %d %s", rec.Code, rec.Body)
	}
}

// An address has one such guess per share: a wrong one leaves it waiting with
// everybody else, and it does not move the wait anyone else sees.
func TestOneAddressHasOneGuessPastTheWait(t *testing.T) {
	h, _, id := spacedShare(t)
	const addr = "198.51.100.2:1000"
	if rec := unlockFrom(t, h, id, addr, "wrong"); rec.Code == http.StatusTooManyRequests {
		t.Fatalf("the address's one guess was refused: %d", rec.Code)
	}
	if rec := unlockFrom(t, h, id, addr, "s3cret"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("a second guess = %d, want 429", rec.Code)
	}
	if rec := unlockFrom(t, h, id, "198.51.100.3:1000", "s3cret"); !unlocked(rec) {
		t.Fatalf("another address = %d", rec.Code)
	}
}

// One machine commonly holds a whole IPv6 /64 and can rent a /48, so every
// address inside a /48 shares the one guess.
func TestAnIPv6SlashFortyEightHasOneGuess(t *testing.T) {
	h, _, id := spacedShare(t)
	unlockFrom(t, h, id, "[2001:db8:1:1::1]:1000", "wrong")
	if rec := unlockFrom(t, h, id, "[2001:db8:1:2::1]:1000", "s3cret"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("another /64 of the same /48 = %d, want 429", rec.Code)
	}
	if rec := unlockFrom(t, h, id, "[2001:db8:2:1::1]:1000", "s3cret"); !unlocked(rec) {
		t.Fatalf("another /48 = %d", rec.Code)
	}
}

// One share's guess is no help at another's.
func TestAnAddressHasItsGuessPerShare(t *testing.T) {
	h, hh, id := spacedShare(t)
	const addr = "198.51.100.4:1000"
	unlockFrom(t, h, id, addr, "wrong")
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"q","password":"other"}`)
	var other struct{ ID string }
	unmarshal(t, rec, &other)
	for range laneFree + 1 {
		att, _, ok := hh.limits.pw.admit(time.Now(), shareLaneKey(other.ID))
		if !ok {
			t.Fatal("the lane refused while being filled")
		}
		att.failed(other.ID)
	}
	if rec := unlockFrom(t, h, other.ID, addr, "other"); !unlocked(rec) {
		t.Fatalf("the other share = %d", rec.Code)
	}
}

// A cross-site guess is counted under no address, so it has none to spend: a
// page cannot use up its visitors' guesses by making their browsers submit.
func TestACrossSiteGuessHasNoGuessPastTheWait(t *testing.T) {
	h, _, id := spacedShare(t)
	const addr = "198.51.100.5:1000"
	rec := unlockFrom(t, h, id, addr, "s3cret", "Sec-Fetch-Site", "cross-site", "Sec-Fetch-Dest", "document")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("= %d, want 429", rec.Code)
	}
	if rec := unlockFrom(t, h, id, addr, "s3cret"); !unlocked(rec) {
		t.Fatalf("the visitor's own guess afterwards = %d", rec.Code)
	}
}

// Parallel requests cannot spend one guess several times.
func TestAWaiverIsTakenOnce(t *testing.T) {
	l := newPWLimiter()
	now := time.Now()
	var taken atomic.Int32
	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.takeWaiver(now, "k") {
				taken.Add(1)
			}
		}()
	}
	wg.Wait()
	if taken.Load() != 1 {
		t.Fatalf("taken %d times", taken.Load())
	}
	l.returnWaiver("k")
	if !l.takeWaiver(now, "k") {
		t.Fatal("a returned guess cannot be taken again")
	}
	if l.takeWaiver(now.Add(pwFailWindow-time.Second), "k") {
		t.Fatal("taken again inside the window")
	}
	if !l.takeWaiver(now.Add(pwFailWindow), "k") {
		t.Fatal("not available after the window")
	}
}

// The table is bounded: past its size the guess goes back to the shared wait,
// which is the safe answer for an attacker holding that many addresses.
func TestAFullWaiverTableGrantsNothingNew(t *testing.T) {
	l := newPWLimiter()
	now := time.Now()
	l.waivers = make(map[string]time.Time, laneWaiverMaxKeys)
	for i := range laneWaiverMaxKeys {
		l.waivers[string(rune(i+0x10000))] = now
	}
	if l.takeWaiver(now, "new") {
		t.Fatal("granted past the bound")
	}
	if !l.takeWaiver(now.Add(pwFailWindow), "new") {
		t.Fatal("expired entries were not forgotten")
	}
}
