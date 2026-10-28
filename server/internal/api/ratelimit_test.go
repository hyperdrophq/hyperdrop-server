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
	if blocked(l, later, "198.51.100.4", stepUpTokenKey("0123456789abcdef")) {
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

// laneOf is a copy of the lane entry under key, and whether it exists.
func laneOf(l *pwLimiter, key string) (laneState, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.lanes[key]
	if e == nil {
		return laneState{}, false
	}
	return *e, true
}

func TestALaneAdmitsTenFreeThenOnePerThirtySeconds(t *testing.T) {
	l := newPWLimiter()
	t0 := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	const lane = "signin:alice"
	for range laneFree {
		guess(t, l, t0, "alice", lane)
	}
	guess(t, l, t0, "alice", lane)
	if _, until, ok := l.admit(t0, lane); ok || !until.Equal(t0.Add(laneSpacing)) {
		t.Fatalf("12th at t0: admitted %v until %v, want refused until %v", ok, until, t0.Add(laneSpacing))
	}
	if _, until, ok := l.admit(t0.Add(laneSpacing-time.Second), lane); ok || !until.Equal(t0.Add(laneSpacing)) {
		t.Fatalf("12th just before the spacing: admitted %v until %v", ok, until)
	}
	guess(t, l, t0.Add(laneSpacing), "alice", lane)
}

func TestALaneResetsAfterAQuietHour(t *testing.T) {
	l := newPWLimiter()
	t0 := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	const lane = "signin:alice"
	for range laneFree + 1 {
		guess(t, l, t0, "alice", lane)
	}
	if !blocked(l, t0, lane) {
		t.Fatal("the lane is not throttled")
	}
	quiet := t0.Add(laneQuiet)
	// The sweep would drop the quiet lane before the admission reads it, so
	// it is held off: the admission itself frees the lane.
	l.mu.Lock()
	l.lastPrune = quiet
	l.mu.Unlock()
	for i := range laneFree {
		att, _, ok := l.admit(quiet, lane)
		if !ok {
			t.Fatalf("guess %d after a quiet hour refused", i+1)
		}
		att.failed("alice")
	}
	if e, ok := laneOf(l, lane); !ok || e.fails != laneFree || !e.nextAt.IsZero() {
		t.Fatalf("the lane after a quiet hour and %d wrong guesses = %+v (kept %v), want %d failures and no spacing", laneFree, e, ok, laneFree)
	}
}

// An abandoned guess past the free ones gives its slot back: the lane's
// spacing returns to what it was before the guess, directly and through
// extend.
func TestAnAbandonedSpacedGuessGivesBackItsSlot(t *testing.T) {
	l := newPWLimiter()
	t0 := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	const lane, ip = "signin:alice", "203.0.113.9"
	for range laneFree + 1 {
		guess(t, l, t0, "alice", lane)
	}
	t1 := t0.Add(laneSpacing)
	att, _, ok := l.admit(t1, lane)
	if !ok {
		t.Fatal("the spaced guess refused")
	}
	if e, _ := laneOf(l, lane); !e.nextAt.Equal(t1.Add(laneSpacing)) {
		t.Fatalf("the spaced guess holds the next until %v, want %v", e.nextAt, t1.Add(laneSpacing))
	}
	att.abandon()
	if e, _ := laneOf(l, lane); !e.nextAt.Equal(t0.Add(laneSpacing)) || e.fails != laneFree+1 || e.inFlight != 0 {
		t.Fatalf("after the abandon the lane = %+v, want the spacing until %v back", e, t0.Add(laneSpacing))
	}
	guess(t, l, t1, "alice", lane)

	t2 := t1.Add(laneSpacing)
	att, _, ok = l.admit(t2, ip)
	if !ok {
		t.Fatal("the address refused")
	}
	if _, ok := att.extend(lane); !ok {
		t.Fatal("the spaced guess, extended, refused")
	}
	att.abandon()
	if e, _ := laneOf(l, lane); !e.nextAt.Equal(t1.Add(laneSpacing)) || e.inFlight != 0 {
		t.Fatalf("after the extended attempt's abandon the lane = %+v, want the spacing until %v back", e, t1.Add(laneSpacing))
	}
}

// An abandoned guess gives back only the spacing it set: once the lane's
// spacing has moved since (another guess freed it after a quiet hour, or a
// password set forgot it), the abandon leaves it as it is.
func TestAnAbandonedGuessLeavesASpacingThatMoved(t *testing.T) {
	t0 := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	const alice, bob = "signin:alice", "signin:bob"
	l := newPWLimiter()
	for range laneFree + 1 {
		guess(t, l, t0, "alice", alice)
	}
	held, _, ok := l.admit(t0.Add(laneQuiet-time.Minute), alice)
	if !ok {
		t.Fatal("alice's spaced guess refused")
	}
	guess(t, l, t0.Add(laneQuiet), "alice", alice)
	held.abandon()
	if e, _ := laneOf(l, alice); !e.nextAt.IsZero() || e.fails != 1 || e.inFlight != 0 {
		t.Fatalf("alice's lane freed by a later guess, after the abandon = %+v, want 1 failure and no spacing", e)
	}

	l = newPWLimiter()
	for range laneFree + 1 {
		guess(t, l, t0, "bob", bob)
	}
	held, _, ok = l.admit(t0.Add(laneSpacing), bob)
	if !ok {
		t.Fatal("bob's spaced guess refused")
	}
	if e, _ := laneOf(l, bob); !e.nextAt.Equal(t0.Add(2 * laneSpacing)) {
		t.Fatalf("bob's spaced guess holds the next until %v, want %v", e.nextAt, t0.Add(2*laneSpacing))
	}
	l.forgetLane(bob)
	held.abandon()
	if e, ok := laneOf(l, bob); ok {
		t.Fatalf("bob's forgotten lane after the abandon = %+v, want it dropped", e)
	}
}

func TestALaneNeverReportsABlock(t *testing.T) {
	l := newPWLimiter()
	t0 := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	const lane = "signin:alice"
	for i := range 3 * laneFree {
		now := t0.Add(time.Duration(i) * laneSpacing)
		att, _, ok := l.admit(now, lane)
		if !ok {
			t.Fatalf("guess %d refused", i+1)
		}
		if until, isBlocked := att.failed("alice"); isBlocked || !until.IsZero() {
			t.Fatalf("guess %d: failed reported a block until %v", i+1, until)
		}
	}
	if l.blocked(lane, t0) {
		t.Fatal("blocked reports a lane")
	}
}

// The owner's success leaves a stranger lane's and a share lane's count as
// it is, so it hands the strangers no fresh free guesses; a kept browser's
// own lane starts over.
func TestAStrangerLaneKeepsItsCountOnSuccessAndAKnownLaneResets(t *testing.T) {
	t0 := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	for _, lane := range []string{"signin:alice", shareLaneKey("abc123")} {
		l := newPWLimiter()
		for range laneFree {
			guess(t, l, t0, "alice", lane)
		}
		att, _, ok := l.admit(t0, lane)
		if !ok {
			t.Fatalf("%s: the owner's attempt refused", lane)
		}
		att.succeeded("alice")
		if e, _ := laneOf(l, lane); e.fails != laneFree {
			t.Fatalf("%s: %d failures after a success, want %d", lane, e.fails, laneFree)
		}
		if !blocked(l, t0.Add(time.Second), lane) {
			t.Fatalf("%s: a success handed out fresh guesses", lane)
		}
	}

	l := newPWLimiter()
	lane := knownLaneKey("k")
	for range laneFree {
		guess(t, l, t0, "alice", lane)
	}
	att, _, ok := l.admit(t0, lane)
	if !ok {
		t.Fatal("known lane: the owner's attempt refused")
	}
	att.succeeded("alice")
	if _, ok := laneOf(l, lane); ok {
		t.Fatal("known lane: kept after a success")
	}
	for i := range laneFree {
		if _, _, ok := l.admit(t0.Add(time.Second), lane); !ok {
			t.Fatalf("known lane: admit %d after a success refused", i+1)
		}
	}
}

func TestTheFreeGuessesCountThoseInFlight(t *testing.T) {
	l := newPWLimiter()
	t0 := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	const lane = "signin:alice"
	for i := range laneFree {
		if _, _, ok := l.admit(t0, lane); !ok {
			t.Fatalf("admit %d refused", i+1)
		}
	}
	if _, until, ok := l.admit(t0, lane); ok || !until.Equal(t0.Add(pwBusyRetry)) {
		t.Fatalf("11th with ten in flight: admitted %v until %v, want refused until %v", ok, until, t0.Add(pwBusyRetry))
	}
	if e, _ := laneOf(l, lane); !e.nextAt.IsZero() {
		t.Fatalf("a refusal set nextAt %v", e.nextAt)
	}
}

func TestARefusalByAnotherKeyLeavesTheLaneUntouched(t *testing.T) {
	l := newPWLimiter()
	t0 := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	const lane, ip = "signin:alice", "203.0.113.9"
	for range pwFailLimit {
		guess(t, l, t0, "alice", ip)
	}
	for range laneFree {
		guess(t, l, t0, "alice", lane)
	}
	before, _ := laneOf(l, lane)
	if _, _, ok := l.admit(t0.Add(time.Minute), lane, ip); ok {
		t.Fatal("a blocked address admitted the attempt")
	}
	after, _ := laneOf(l, lane)
	if after != before || !after.nextAt.IsZero() {
		t.Fatalf("the refusal changed the lane from %+v to %+v", before, after)
	}

	// A lane past its quiet hour, held by an attempt in flight so the sweep
	// keeps it, is not freed by an admission another key refuses.
	held, _, ok := l.admit(t0, lane)
	if !ok {
		t.Fatal("the held attempt refused")
	}
	before, _ = laneOf(l, lane)
	quiet := t0.Add(laneQuiet + time.Minute)
	if _, _, ok := l.admit(quiet, lane, ip); ok {
		t.Fatal("a blocked address admitted the attempt after a quiet hour")
	}
	if after, _ := laneOf(l, lane); after != before {
		t.Fatalf("after a quiet hour the refusal changed the lane from %+v to %+v", before, after)
	}
	held.abandon()
}

// One account guessed at from a thousand addresses, one guess a second for
// an hour, gets its ten free guesses and then one every laneSpacing, and no
// address is ever blocked; the owner's kept browser, on a lane of its own,
// is admitted every time.
func TestDistributedGuessesStayUnderTheLaneRate(t *testing.T) {
	l := newPWLimiter()
	t0 := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	const lane, owner = "signin:alice", "192.0.2.77"
	addrs := make([]string, 1000)
	for i := range addrs {
		addrs[i] = fmt.Sprintf("2001:db8:%x:%x::/64", i>>8, i&0xff)
	}
	admitted := 0
	for s := range 3600 {
		now := t0.Add(time.Duration(s) * time.Second)
		if s%60 == 0 {
			att, until, ok := l.admit(now, owner, knownLaneKey("k"))
			if !ok {
				t.Fatalf("s=%d: the kept browser refused until %v", s, until)
			}
			att.succeeded("alice")
		}
		att, until, ok := l.admit(now, addrs[s%len(addrs)], lane)
		if !ok {
			if wait := until.Sub(now); wait <= 0 || wait > laneSpacing {
				t.Fatalf("s=%d: refused for %v, want (0, %v]", s, wait, laneSpacing)
			}
			continue
		}
		admitted++
		if until, isBlocked := att.failed("alice"); isBlocked {
			t.Fatalf("s=%d: a guess blocked a key until %v", s, until)
		}
	}
	if admitted > 130 {
		t.Fatalf("admitted %d guesses in an hour, want at most 130", admitted)
	}
	if admitted < 120 {
		t.Fatalf("admitted %d guesses in an hour, want the lane's 130 less rounding", admitted)
	}
	end := t0.Add(3600 * time.Second)
	for _, a := range addrs {
		if l.blocked(a, end) {
			t.Fatalf("address %s blocked", a)
		}
	}
}

// A flood of throwaway names fills the lanes and evicts throwaway names,
// never the throttled account's lane, and the map stays bounded.
func TestAFloodOfNamesDoesNotEvictAThrottledLane(t *testing.T) {
	l := newPWLimiter()
	t0 := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	const lane = "signin:alice"
	for range laneFree + 1 {
		guess(t, l, t0, "alice", lane)
	}
	for i := 0; len(l.lanes) < laneMaxKeys; i++ {
		guess(t, l, t0, "x", fmt.Sprintf("signin:fill%d", i))
	}
	for i := range 5000 {
		guess(t, l, t0, "x", fmt.Sprintf("signin:flood%d", i))
	}
	if _, ok := laneOf(l, lane); !ok {
		t.Fatal("the flood evicted the throttled lane")
	}
	if _, until, ok := l.admit(t0.Add(time.Second), lane); ok || !until.Equal(t0.Add(laneSpacing)) {
		t.Fatalf("the throttled lane admitted %v until %v, want refused until %v", ok, until, t0.Add(laneSpacing))
	}
	if n := len(l.lanes); n > laneMaxKeys {
		t.Fatalf("the lanes hold %d keys, bound %d", n, laneMaxKeys)
	}
}

func TestEvictLaneTakesNoEntryInFlight(t *testing.T) {
	l := newPWLimiter()
	t0 := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	for i := range pwEvictProbe {
		if _, _, ok := l.admit(t0, fmt.Sprintf("signin:n%d", i)); !ok {
			t.Fatal("admit refused")
		}
	}
	l.mu.Lock()
	ok := l.evictLane(t0)
	n := len(l.lanes)
	l.mu.Unlock()
	if ok || n != pwEvictProbe {
		t.Fatalf("evicted %v, %d left; want nothing evicted", ok, n)
	}
}

// With every sampled lane throttled, the one evicted is the one whose quiet
// hour ends soonest.
func TestEvictLaneTakesTheQuietHourEndingSoonest(t *testing.T) {
	l := newPWLimiter()
	t0 := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	for i := range pwEvictProbe {
		for range laneFree {
			guess(t, l, t0.Add(time.Duration(i)*time.Minute), "x", fmt.Sprintf("signin:n%d", i))
		}
	}
	l.mu.Lock()
	ok := l.evictLane(t0.Add(10 * time.Minute))
	_, kept := l.lanes["signin:n0"]
	n := len(l.lanes)
	l.mu.Unlock()
	if !ok || kept || n != pwEvictProbe-1 {
		t.Fatalf("evicted %v, n0 kept %v, %d left; want n0 evicted", ok, kept, n)
	}
}

// With every lane in flight a new lane is admitted untracked.
func TestAFullSetOfLanesInFlightAdmitsUntracked(t *testing.T) {
	l := newPWLimiter()
	t0 := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	for i := range laneMaxKeys {
		if _, _, ok := l.admit(t0, fmt.Sprintf("share:s%d", i)); !ok {
			t.Fatal("fill refused")
		}
	}
	for range laneFree + 2 {
		guess(t, l, t0, "x", "signin:alice")
	}
	if _, ok := laneOf(l, "signin:alice"); ok {
		t.Fatal("a lane was tracked past the bound")
	}
	if n := len(l.lanes); n > laneMaxKeys {
		t.Fatalf("the lanes hold %d keys, bound %d", n, laneMaxKeys)
	}
}

func TestForgetLaneFreesTheLane(t *testing.T) {
	l := newPWLimiter()
	t0 := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	const lane = "signin:alice"
	for range laneFree + 1 {
		guess(t, l, t0, "alice", lane)
	}
	l.forgetLane(lane)
	if _, ok := laneOf(l, lane); ok {
		t.Fatal("a forgotten lane with nothing in flight was kept")
	}
	held, _, ok := l.admit(t0, lane)
	if !ok {
		t.Fatal("a forgotten lane refused")
	}
	for range laneFree - 1 {
		guess(t, l, t0, "alice", lane)
	}
	if _, until, ok := l.admit(t0, lane); ok || !until.Equal(t0.Add(pwBusyRetry)) {
		t.Fatalf("the lane's last free guess, held, admitted %v until %v", ok, until)
	}
	l.forgetLane(lane)
	e, ok := laneOf(l, lane)
	if !ok || e.inFlight != 1 || e.fails != 0 || !e.nextAt.IsZero() {
		t.Fatalf("forgotten lane with one in flight = %+v (kept %v)", e, ok)
	}
	for i := range laneFree - 1 {
		if _, _, ok := l.admit(t0, lane); !ok {
			t.Fatalf("admit %d after forgetLane refused", i+1)
		}
	}
	held.failed("alice")
	if e, _ := laneOf(l, lane); e.fails != 1 {
		t.Fatalf("the held attempt's failure counted %d", e.fails)
	}
}

func TestStaleLanesArePruned(t *testing.T) {
	l := newPWLimiter()
	t0 := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	for range laneFree + 1 {
		guess(t, l, t0, "alice", "signin:alice")
	}
	guess(t, l, t0, "x", shareLaneKey("abc123"))
	att, _, _ := l.admit(t0.Add(laneQuiet+pwPruneEvery), "203.0.113.9")
	att.abandon()
	if n := len(l.lanes); n != 0 {
		t.Fatalf("%d lanes left after a quiet hour", n)
	}
}

func TestLaneKeys(t *testing.T) {
	for key, want := range map[string]bool{
		"signin:alice":         true,
		knownLaneKey("abc"):    true,
		shareLaneKey("abc123"): true,
		"203.0.113.9":          false,
		"totp:alice":           false,
		"account:alice":        false,
		"web:alice":            false,
		"stepup:alice":         false,
	} {
		if got := isLaneKey(key); got != want {
			t.Errorf("isLaneKey(%q) = %v, want %v", key, got, want)
		}
		if isLaneKey(key) && isAccountKey(key) {
			t.Errorf("%q is a lane and an account key", key)
		}
	}
	if knownLaneKey("abc") != "known:abc" || shareLaneKey("abc123") != "share:abc123" {
		t.Fatalf("lane keys %q %q", knownLaneKey("abc"), shareLaneKey("abc123"))
	}
}

// blockKey makes pwFailLimit wrong guesses under key at now and answers the
// block they start.
func blockKey(t *testing.T, l *pwLimiter, now time.Time, key string) time.Time {
	t.Helper()
	var until time.Time
	var isBlocked bool
	for range pwFailLimit {
		att, _, ok := l.admit(now, key)
		if !ok {
			t.Fatalf("a guess at %v refused", now)
		}
		until, isBlocked = att.failed("abc123")
	}
	if !isBlocked {
		t.Fatalf("not blocked after %d failures at %v", pwFailLimit, now)
	}
	return until
}

// An address's block at one share starts at an hour and doubles each time
// it repeats, up to twelve hours.
func TestAShareAddressBlockStartsAtAnHourAndDoublesWhileItRepeats(t *testing.T) {
	l := newPWLimiter()
	key := shareAddrKey("203.0.113.9", "abc123")
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	for i, want := range []time.Duration{
		time.Hour, 2 * time.Hour, 4 * time.Hour, 8 * time.Hour, 12 * time.Hour, 12 * time.Hour,
	} {
		until := blockKey(t, l, now, key)
		if got := until.Sub(now); got != want {
			t.Fatalf("block %d lasts %v, want %v", i+1, got, want)
		}
		if !blocked(l, until.Add(-time.Second), key) {
			t.Fatalf("block %d lifted early", i+1)
		}
		now = until
	}
	if pwShareBlockFor != time.Hour || pwShareBlockMax != 12*time.Hour {
		t.Fatalf("share block %v up to %v, want an hour up to 12h", pwShareBlockFor, pwShareBlockMax)
	}
}

// A block's length is remembered for as long as the block lasted after it
// ends, through the sweep of stale entries, and forgotten after that.
func TestAShareAddressBlockForgetsItsLengthAfterAsLongAQuiet(t *testing.T) {
	l := newPWLimiter()
	key := shareAddrKey("203.0.113.9", "abc123")
	t0 := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	end := blockKey(t, l, t0, key)

	// Another address's guess sweeps the map while the length is remembered.
	guess(t, l, end.Add(30*time.Minute), "abc123", shareAddrKey("198.51.100.1", "abc123"))
	at := end.Add(59 * time.Minute)
	until := blockKey(t, l, at, key)
	if got := until.Sub(at); got != 2*time.Hour {
		t.Fatalf("a block inside the remembered hour lasts %v, want 2h", got)
	}

	// Two quiet hours after a two-hour block, swept again, the next block is
	// an hour again.
	later := until.Add(2 * time.Hour)
	guess(t, l, later.Add(-time.Second), "abc123", shareAddrKey("198.51.100.2", "abc123"))
	if got := blockKey(t, l, later, key).Sub(later); got != time.Hour {
		t.Fatalf("a block after a quiet as long as the last lasts %v, want 1h", got)
	}
}

// An attempt that settles with no outcome right after a block (a client
// gone while queueing for a compare) leaves the block's length remembered.
func TestAnAbandonedGuessAfterABlockKeepsItsLength(t *testing.T) {
	l := newPWLimiter()
	key := shareAddrKey("203.0.113.9", "abc123")
	t0 := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	end := blockKey(t, l, t0, key)

	att, _, ok := l.admit(end, key)
	if !ok {
		t.Fatal("the first guess after the block refused")
	}
	att.abandon()
	at := end.Add(time.Minute)
	if got := blockKey(t, l, at, key).Sub(at); got != 2*time.Hour {
		t.Fatalf("the block after an abandoned guess lasts %v, want 2h", got)
	}
}

// The sign-in limiter's address keeps its fixed twelve hours, however often
// it repeats.
func TestASignInAddressBlockDoesNotEscalate(t *testing.T) {
	l := newPWLimiter()
	const ip = "203.0.113.9"
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	for i := range 3 {
		until := blockKey(t, l, now, ip)
		if got := until.Sub(now); got != pwBlockFor {
			t.Fatalf("sign-in block %d lasts %v, want %v", i+1, got, pwBlockFor)
		}
		now = until
	}
}

func TestShareAddrKeys(t *testing.T) {
	key := shareAddrKey("203.0.113.9", "abc123")
	if isLaneKey(key) || isAccountKey(key) {
		t.Fatalf("%q is a lane or an account key", key)
	}
	if key == shareAddrKey("203.0.113.9", "abc124") || key == shareAddrKey("203.0.113.8", "abc123") {
		t.Fatal("two addresses or two shares share a key")
	}
}
