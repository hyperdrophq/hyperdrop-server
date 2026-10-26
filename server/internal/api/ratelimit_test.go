package api

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// guess admits one attempt under keys and settles it as a wrong guess at
// target, failing the test when the attempt is refused.
func guess(t *testing.T, l *pwLimiter, now time.Time, target string, keys ...string) {
	t.Helper()
	att, _, ok := l.admit(now, keys...)
	if !ok {
		t.Fatalf("attempt at %v refused", now)
	}
	att.failed(target)
}

func blocked(l *pwLimiter, now time.Time, keys ...string) bool {
	att, _, ok := l.admit(now, keys...)
	if ok {
		att.abandon()
	}
	return !ok
}

func TestPWLimiterBlocksAfterLimit(t *testing.T) {
	l := newPWLimiter()
	t0 := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	ip := "203.0.113.9"

	for i := 0; i < pwFailLimit-1; i++ {
		guess(t, l, t0.Add(time.Duration(i)*time.Second), "admin", ip)
	}
	if blocked(l, t0.Add(time.Minute), ip) {
		t.Fatalf("blocked after %d failures, limit is %d", pwFailLimit-1, pwFailLimit)
	}

	att, _, _ := l.admit(t0.Add(time.Minute), ip)
	until, isBlocked := att.failed("admin")
	if !isBlocked {
		t.Fatalf("not blocked after %d failures", pwFailLimit)
	}
	if want := t0.Add(time.Minute).Add(pwBlockFor); !until.Equal(want) {
		t.Fatalf("blockedUntil = %v, want %v", until, want)
	}
	if _, refusedUntil, ok := l.admit(t0.Add(2*time.Minute), ip); ok || !refusedUntil.Equal(until) {
		t.Fatalf("admit while blocked = %v until %v, want refused until %v", ok, refusedUntil, until)
	}
}

func TestPWLimiterWindowExpiry(t *testing.T) {
	l := newPWLimiter()
	t0 := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	ip := "203.0.113.9"

	// pwFailLimit-1 old failures fall out of the 1 h window before the next
	// one lands, so a slow trickle never blocks.
	for i := 0; i < pwFailLimit-1; i++ {
		guess(t, l, t0, "admin", ip)
	}
	guess(t, l, t0.Add(pwFailWindow+time.Second), "admin", ip)
	if blocked(l, t0.Add(pwFailWindow+2*time.Second), ip) {
		t.Fatal("stale failures outside the window still count")
	}
}

func TestPWLimiterBlockExpires(t *testing.T) {
	l := newPWLimiter()
	t0 := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	ip := "203.0.113.9"

	for i := 0; i < pwFailLimit; i++ {
		guess(t, l, t0, "admin", ip)
	}
	if !blocked(l, t0.Add(pwBlockFor).Add(-time.Second), ip) {
		t.Fatal("block lifted early")
	}
	if blocked(l, t0.Add(pwBlockFor).Add(time.Second), ip) {
		t.Fatal("block outlived its duration")
	}
	// The expired block also cleared the failure history: one more wrong
	// guess is 1/10, not 11/10.
	guess(t, l, t0.Add(pwBlockFor).Add(2*time.Second), "admin", ip)
	if blocked(l, t0.Add(pwBlockFor).Add(3*time.Second), ip) {
		t.Fatal("failures from before the block still count after it expired")
	}
}

func TestPWLimiterSuccessForgetsTheGuessesAtItsTarget(t *testing.T) {
	l := newPWLimiter()
	t0 := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	ip := "203.0.113.9"

	for i := 0; i < pwFailLimit-1; i++ {
		guess(t, l, t0, "guest", ip)
	}
	att, _, _ := l.admit(t0, ip)
	att.succeeded("guest")
	guess(t, l, t0.Add(time.Second), "guest", ip)
	if blocked(l, t0.Add(2*time.Second), ip) {
		t.Fatal("success did not forget the guesses at its own target")
	}
}

// Proving one target says nothing about another: a guest's own sign-in, or
// a share password the caller holds, must not reset the guesses it made at
// the admin's password or at another share.
func TestPWLimiterSuccessKeepsTheGuessesAtOtherTargets(t *testing.T) {
	l := newPWLimiter()
	t0 := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	ip := "203.0.113.9"

	for round := 0; round < 5; round++ {
		now := t0.Add(time.Duration(round) * time.Minute)
		for i := 0; i < pwFailLimit-1; i++ {
			att, _, ok := l.admit(now, ip)
			if !ok {
				return // the lockout held
			}
			att.failed("admin")
		}
		att, _, ok := l.admit(now, ip)
		if !ok {
			return
		}
		att.succeeded("guest")
	}
	t.Fatal("successes at one target kept resetting the guesses at another")
}

func TestPWLimiterIPsAreIndependent(t *testing.T) {
	l := newPWLimiter()
	t0 := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)

	for i := 0; i < pwFailLimit; i++ {
		guess(t, l, t0, "admin", "203.0.113.9")
	}
	if blocked(l, t0.Add(time.Second), "198.51.100.4") {
		t.Fatal("one IP's failures blocked another IP")
	}
}

// Attempts in flight hold guesses: a burst sent at once is admitted only up
// to the key's remaining budget, so nothing past it is ever checked.
func TestPWLimiterABurstIsAdmittedOnlyUpToTheBudget(t *testing.T) {
	l := newPWLimiter()
	t0 := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	ip := "203.0.113.9"

	guess(t, l, t0, "admin", ip)
	guess(t, l, t0, "admin", ip)
	var held []*pwAttempt
	for range 100 {
		if att, _, ok := l.admit(t0, ip); ok {
			held = append(held, att)
		}
	}
	if len(held) != pwFailLimit-2 {
		t.Fatalf("admitted %d of a burst with %d guesses left", len(held), pwFailLimit-2)
	}
	// An attempt that settles without an outcome gives its guess back.
	held[0].abandon()
	if att, _, ok := l.admit(t0, ip); !ok {
		t.Fatal("an abandoned attempt kept its guess")
	} else {
		att.abandon()
	}
	for _, att := range held[1:] {
		att.failed("admin")
	}
	guess(t, l, t0, "admin", ip)
	if !blocked(l, t0, ip) {
		t.Fatal("the burst's failures did not block")
	}
}

// Every key of an attempt must admit it: a blocked account key refuses the
// attempt, and the address key keeps no guess for it.
func TestPWLimiterAdmitsUnderEveryKeyOrNone(t *testing.T) {
	l := newPWLimiter()
	t0 := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	for i := 0; i < pwFailLimit; i++ {
		guess(t, l, t0, "admin", fmt.Sprintf("198.51.100.%d", i), "account:admin")
	}
	if !blocked(l, t0, "203.0.113.9", "account:admin") {
		t.Fatal("a blocked account key admitted the attempt")
	}
	l.mu.Lock()
	_, kept := l.byKey["203.0.113.9"]
	l.mu.Unlock()
	if kept {
		t.Fatal("a refused attempt left its address key holding a guess")
	}
}

func TestPWLimiterPrunesStaleEntries(t *testing.T) {
	l := newPWLimiter()
	t0 := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)

	guess(t, l, t0, "admin", "203.0.113.9")
	// Far in the future, the entry is dead weight; any traffic prunes it.
	guess(t, l, t0.Add(48*time.Hour), "admin", "198.51.100.4")
	l.mu.Lock()
	_, staleAlive := l.byKey["203.0.113.9"]
	l.mu.Unlock()
	if staleAlive {
		t.Fatal("stale IP entry survived pruning")
	}
}

// The map is bounded: past pwMaxKeys a new key takes the place of an entry
// carrying the least, and a blocked entry is evicted only when the sample
// holds nothing else.
func TestPWLimiterMapIsBounded(t *testing.T) {
	l := newPWLimiter()
	t0 := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	for i := 0; i < pwFailLimit; i++ {
		guess(t, l, t0, "admin", "victim")
	}
	for i := 0; i < pwMaxKeys+1000; i++ {
		att, _, ok := l.admit(t0, fmt.Sprintf("k%d", i))
		if ok {
			att.failed("admin")
		}
	}
	l.mu.Lock()
	n := len(l.byKey)
	l.mu.Unlock()
	if n > pwMaxKeys {
		t.Fatalf("the map holds %d keys, bound %d", n, pwMaxKeys)
	}
	if !blocked(l, t0, "victim") {
		t.Fatal("a blocked entry was evicted")
	}
}

// fillBlocked adds n blocked address entries the cheapest way a stranger
// can: ten malformed device-link secrets from each of n /64s.
func fillBlocked(t *testing.T, l *pwLimiter, now time.Time, n int) {
	t.Helper()
	for i := range n {
		k := fmt.Sprintf("2001:db8:%x:%x::/64", i>>8, i&0xff)
		for range pwFailLimit {
			guess(t, l, now, deviceLinkTarget, k)
		}
	}
}

// A map full of blocked addresses refuses no other address: a new one takes
// the place of a blocked entry, is counted like any other, and the map stays
// bounded.
func TestAFullLimiterOfBlockedAddressesAdmitsANewOne(t *testing.T) {
	l := newPWLimiter()
	t0 := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	fillBlocked(t, l, t0, pwMaxKeys)
	later := t0.Add(10 * time.Minute)
	for i := range 100 {
		if blocked(l, later, fmt.Sprintf("198.51.100.%d", i)) {
			t.Fatalf("new address %d refused by a full map", i)
		}
	}
	const ip = "203.0.113.9"
	for range pwFailLimit {
		guess(t, l, later, "admin", ip)
	}
	if !blocked(l, later, ip) {
		t.Fatal("a new address admitted into a full map was not counted")
	}
	l.mu.Lock()
	n := len(l.byKey)
	l.mu.Unlock()
	if n > pwMaxKeys {
		t.Fatalf("the map holds %d keys, bound %d", n, pwMaxKeys)
	}
}

// An account's keys are never refused for capacity: the owner who signs in
// with the right password, or steps up, from an address already counted,
// gets past a map full of a stranger's blocked addresses.
func TestAnAccountKeyIsNeverRefusedForCapacity(t *testing.T) {
	l := newPWLimiter()
	t0 := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	const ip = "203.0.113.9"
	guess(t, l, t0, "admin", ip)
	fillBlocked(t, l, t0, pwMaxKeys-1)
	later := t0.Add(10 * time.Minute)
	att, _, ok := l.admit(later, ip)
	if !ok {
		t.Fatal("a counted address refused by a full map")
	}
	if _, ok := att.extend(totpLoginKey("admin")); !ok {
		t.Fatal("the sign-in's account key refused by a full map")
	}
	att.succeeded("admin")
	if blocked(l, later, "198.51.100.4", stepUpAccountKey("admin")) {
		t.Fatal("a step-up's account key refused by a full map")
	}
}

// When every sampled entry has an attempt in flight there is nothing to
// evict, and the new address is admitted untracked rather than refused.
func TestAFullLimiterOfAttemptsInFlightAdmitsUntracked(t *testing.T) {
	l := newPWLimiter()
	t0 := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	for i := range pwMaxKeys {
		if _, _, ok := l.admit(t0, fmt.Sprintf("k%d", i)); !ok {
			t.Fatal("fill refused")
		}
	}
	for range pwFailLimit + 1 {
		guess(t, l, t0, "admin", "203.0.113.9")
	}
	l.mu.Lock()
	n := len(l.byKey)
	l.mu.Unlock()
	if n > pwMaxKeys {
		t.Fatalf("the map holds %d keys, bound %d", n, pwMaxKeys)
	}
}

// With every sampled entry blocked, the one evicted is the one whose block
// ends soonest.
func TestAFullLimiterEvictsTheBlockEndingSoonest(t *testing.T) {
	l := newPWLimiter()
	t0 := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	for i := range pwEvictProbe {
		for range pwFailLimit {
			guess(t, l, t0.Add(time.Duration(i)*time.Minute), "admin", fmt.Sprintf("k%d", i))
		}
	}
	l.mu.Lock()
	ok := l.evictOne(t0.Add(time.Hour))
	_, kept := l.byKey["k0"]
	n := len(l.byKey)
	l.mu.Unlock()
	if !ok || kept || n != pwEvictProbe-1 {
		t.Fatalf("evicted %v, k0 kept %v, %d left; want k0 evicted", ok, kept, n)
	}
}

func TestAddrKeyGroupsAnIPv6HostByItsSlash64(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.9":           "203.0.113.9",
		"::ffff:203.0.113.9":    "203.0.113.9",
		"2001:db8:1:2:3:4:5:6":  "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::1":  "2001:db8:1:2::/64",
		"fe80::1%eth0":          "fe80::/64",
		"not an address":        "not an address",
		"2001:db8:1:3::1":       "2001:db8:1:3::/64",
		"2001:0db8:0001:0002::": "2001:db8:1:2::/64",
	} {
		if got := addrKey(in); got != want {
			t.Errorf("addrKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// failures holds the targets the limiter keeps under key.
func failures(l *pwLimiter, key string) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	if a := l.byKey[key]; a != nil {
		for _, f := range a.failures {
			out = append(out, f.target)
		}
	}
	return out
}

// A failure keeps a bounded copy of its target, whatever a caller hands it.
func TestPWLimiterKeepsABoundedTarget(t *testing.T) {
	l := newPWLimiter()
	t0 := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	guess(t, l, t0, strings.Repeat("x", 60<<10), "203.0.113.9")
	got := failures(l, "203.0.113.9")
	if len(got) != 1 || len(got[0]) > pwTargetMax {
		t.Fatalf("kept targets of %d bytes, bound %d", len(got[0]), pwTargetMax)
	}
}

// A wrong sign-in at a name no account can have counts under the address
// and keeps none of the name: a 64 KiB body per guess must not become 64
// KiB the limiter holds for the block's 12 hours.
func TestAWrongSignInAtAMalformedNameKeepsNoneOfIt(t *testing.T) {
	h, hd := newTestAPIParts(t)
	const addr = "203.0.113.50"
	for _, name := range []string{strings.Repeat("a", 60<<10), "Not A Name"} {
		rec := doReqFrom(t, h, "POST", "/api/auth/login", "", loginBody(name, "wrong", ""), addr+":1000")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%.20s: %d %s, want 401", name, rec.Code, rec.Body)
		}
	}
	if rec := doReqFrom(t, h, "POST", "/api/auth/login", "", loginBody("nobody", "wrong", ""), addr+":1000"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("valid name: %d %s, want 401", rec.Code, rec.Body)
	}
	got := failures(hd.limits.login, addr)
	if want := []string{unnamedTarget, unnamedTarget, "nobody"}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("kept targets %.40q, want %q", got, want)
	}
}
