package api

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Brute-force lockout for the password routes: a key (an address, or an
// account for the guesses only a password holder can make) that guesses
// wrong pwFailLimit times within pwFailWindow is refused further
// verification for pwBlockFor. In-memory by design: a restart clears it,
// which is fine for this threat model (bcrypt + the compare cap already make
// guessing slow; this adds the hard stop).
const (
	pwFailLimit  = 10
	pwFailWindow = time.Hour
	pwBlockFor   = 12 * time.Hour
)

// An address's guesses at a share's password count per address AND share
// (shareAddrKey), so guessing at one share never blocks the address at
// another. Its block lasts pwShareBlockFor, and a block that starts while
// the previous one is remembered lasts twice that one, up to
// pwShareBlockMax. A block is remembered after it ends for as long as it
// lasted (pwAttempts.remembers). The share's lane bounds the guesses at it
// from every address together, so the address block can stay short: it
// mostly falls on the people behind one address with the guesser.
const (
	pwShareBlockFor = time.Hour
	pwShareBlockMax = 12 * time.Hour
)

// shareAddrPrefix starts the key of an address's guesses at one share.
const shareAddrPrefix = "pwaddr:"

// shareAddrKey is the key of the guesses addr (an addrKey) makes at the
// password of the share id. A share id never contains "|".
func shareAddrKey(addr, id string) string { return shareAddrPrefix + addr + "|" + id }

// escalates reports whether key's block grows while it repeats.
func escalates(key string) bool { return strings.HasPrefix(key, shareAddrPrefix) }

// stepUpAccountFailLimit is the wrong step-ups an account takes from all
// of its tokens together within pwFailWindow before every step-up of the
// account waits for stepUpAccountWait (stepUpAccountKey). Each token keeps
// its own lower limit and longer block (stepUpTokenKey); this one bounds
// the total, since an account's tokens are not bounded in number (a token
// can approve a browser sign-in, which mints another), and its wait is
// short because one stolen token's guesses also make the owner's other
// devices wait.
const (
	stepUpAccountFailLimit = 20
	stepUpAccountWait      = pwFailWindow
)

// keyLimit is key's limit and first block: the step-up's account
// counter's, an address's at one share, or every other key's.
func keyLimit(key string) (limit int, block time.Duration) {
	switch {
	case strings.HasPrefix(key, stepUpAccountPrefix):
		return stepUpAccountFailLimit, stepUpAccountWait
	case escalates(key):
		return pwFailLimit, pwShareBlockFor
	}
	return pwFailLimit, pwBlockFor
}

// pwMaxKeys bounds the limiter's address keys. Past it a new address takes
// the place of a sampled entry: the one carrying the fewest live failures,
// or, when every sampled entry is blocked, the one whose block ends soonest,
// never one with an attempt in flight. When every sampled entry has one in
// flight, the new address is admitted untracked. A key is never refused for
// capacity: a stranger who fills the map with blocked addresses, which a
// malformed device-link secret does at no cost, must not lock every other
// address out; each new address takes the place of the block ending soonest
// instead, and the map holds no more entries than the bound. pwPruneEvery is
// how often stale entries are swept, whatever the map's size. An address's
// key at one share (shareAddrKey) is an address key, and one that only
// remembers its last block's length carries no live failure, so it is among
// the first to go.
//
// An account's keys (totp:, token:, account:, stepup:) are not counted
// against the bound and are never evicted: each is made only for an account
// the caller proved the password of, or a token the caller holds and its
// account. A key outlives its token or account until it goes stale, when the
// sweep drops it: no attempt in flight, no failure inside pwFailWindow and
// no block (pwBlockFor at most). So the map holds the keys guessed at within
// the last pwFailWindow and those still blocked.
const (
	pwMaxKeys    = 1 << 16
	pwEvictProbe = 8
	pwPruneEvery = time.Minute
)

// pwBusyRetry is the Retry-After of a key whose remaining guesses are all
// held by attempts still being checked: one of them settles within a
// compare's time.
const pwBusyRetry = 5 * time.Second

// A lane slows the guesses at one account or share from every address
// together, and never blocks: it admits laneFree wrong guesses, then one
// every laneSpacing, until laneQuiet passes with no failure, which frees it
// again. Whoever spreads guesses over many addresses therefore gets at most
// laneFree plus one per laneSpacing. Each refusal's Retry-After is
// laneSpacing at most, but while someone keeps guessing, the owner signing
// in on the same lane with a password alone (a new browser, an app) may wait
// as long as that lasts. A kept browser, phone sign-in and a linked device
// read no stranger lane, and an administrator's password reset frees it, so
// none of those waits. An attempt that checks no wrong guess gives its slot
// back (pwAttempt.abandon), so a password-only leg that a second factor
// answers with totp-required costs the account's sign-in no second slot.
// The lanes live in a map of their own, bounded by laneMaxKeys (evictLane),
// apart from the address and account keys:
//   - signin:<name>, the stranger lane of an account name;
//   - known:<id>, the lane of one kept browser (knownLaneKey);
//   - share:<id>, the lane of a share's password (shareLaneKey);
//   - sharex:<id>, the lane of the password guesses another website
//     makes a browser send at a share (shareCrossLaneKey).
const (
	laneFree    = 10
	laneSpacing = 30 * time.Second
	laneQuiet   = pwFailWindow
	laneMaxKeys = 1 << 16
)

const (
	signInLanePrefix = "signin:"
	knownLanePrefix  = "known:"
	shareLanePrefix  = "share:"
	shareCrossPrefix = "sharex:"
)

// isLaneKey reports whether key names a lane rather than an address or an
// account.
func isLaneKey(key string) bool {
	return strings.HasPrefix(key, signInLanePrefix) || strings.HasPrefix(key, knownLanePrefix) ||
		strings.HasPrefix(key, shareLanePrefix) || strings.HasPrefix(key, shareCrossPrefix)
}

// knownLaneKey is the lane of the kept browser whose known-browser cookie
// carries id.
func knownLaneKey(id string) string { return knownLanePrefix + id }

// shareLaneKey is the lane of the password of the share id.
func shareLaneKey(id string) string { return shareLanePrefix + id }

// shareCrossLaneKey is the lane of the cross-site guesses at the share id,
// apart from shareLaneKey so another website cannot pause the share page.
func shareCrossLaneKey(id string) string { return shareCrossPrefix + id }

// laneState is one lane: the failures since it was last free, the attempts
// admitted and not yet settled, the latest failure, and the earliest a
// guess past the free ones is admitted again.
type laneState struct {
	fails, inFlight  int
	lastFail, nextAt time.Time
}

// quiet reports whether the lane's failures are all older than laneQuiet,
// which frees it at now.
func (e *laneState) quiet(now time.Time) bool {
	return e.fails > 0 && now.Sub(e.lastFail) >= laneQuiet
}

// failsAt is the lane's failures that still count at now.
func (e *laneState) failsAt(now time.Time) int {
	if e.quiet(now) {
		return 0
	}
	return e.fails
}

// refusal reports whether the lane refuses a guess at now, and until when,
// changing nothing.
func (e *laneState) refusal(now time.Time) (time.Time, bool) {
	if e.failsAt(now)+e.inFlight < laneFree {
		return time.Time{}, false
	}
	if !e.quiet(now) && now.Before(e.nextAt) {
		return e.nextAt, true
	}
	if e.inFlight > 0 {
		return now.Add(pwBusyRetry), true
	}
	return time.Time{}, false
}

// reserve holds one guess of a lane that does not refuse it at now: a lane
// past its quiet hour starts free, and a guess past the free ones holds the
// next for laneSpacing. For such a guess it answers the spacing it set and
// the one it replaced, so an abandoned attempt can give its slot back
// (pwAttempt.abandon).
func (e *laneState) reserve(now time.Time) (prev, set time.Time, spaced bool) {
	if e.quiet(now) {
		e.fails, e.nextAt = 0, time.Time{}
	}
	if e.fails+e.inFlight >= laneFree {
		prev, set, spaced = e.nextAt, now.Add(laneSpacing), true
		e.nextAt = set
	}
	e.inFlight++
	return prev, set, spaced
}

// laneSpaced is the spacing an attempt's guess set on the lane key, set,
// and the spacing it replaced, prev.
type laneSpaced struct {
	key       string
	prev, set time.Time
}

// stale reports whether the lane carries no information at now.
func (e *laneState) stale(now time.Time) bool {
	return e.inFlight == 0 && !now.Before(e.nextAt) && e.failsAt(now) == 0
}

// pwTargetMax bounds the target a failure records: the longest account
// name and share id fit with room to spare.
const pwTargetMax = 64

// pwFailure is one wrong guess and what it was aimed at: an account's name,
// a share's id, or the kind of secret ("invite", "device-link"). failed
// keeps at most pwTargetMax bytes of a target, its own copy, so a caller's
// request body is never what the limiter holds on to.
type pwFailure struct {
	at     time.Time
	target string
}

type pwAttempts struct {
	failures     []pwFailure // wrong guesses inside the sliding window
	inFlight     int         // admitted attempts not yet settled
	blockedUntil time.Time   // zero when not blocked
	// The latest block of a key that escalates, and when it ends or ended;
	// zero for any other key.
	lastBlock time.Duration
	lastEnd   time.Time
}

// remembers reports whether the entry's latest block still sets the length
// of the next one at now: until as long after its end as it lasted.
func (a *pwAttempts) remembers(now time.Time) bool {
	return a.lastBlock > 0 && now.Before(a.lastEnd.Add(a.lastBlock))
}

// blockFor is how long a block of key starting at now lasts: twice the
// remembered one, up to pwShareBlockMax, for a key that escalates, and
// keyLimit's block otherwise.
func (a *pwAttempts) blockFor(key string, now time.Time) time.Duration {
	_, block := keyLimit(key)
	if escalates(key) && a.remembers(now) {
		block = min(2*a.lastBlock, pwShareBlockMax)
	}
	return block
}

type pwLimiter struct {
	mu        sync.Mutex
	byKey     map[string]*pwAttempts // address keys, bounded by pwMaxKeys
	accounts  map[string]*pwAttempts // account and token keys, swept once stale
	lanes     map[string]*laneState  // lane keys, bounded by laneMaxKeys
	lastPrune time.Time
}

func newPWLimiter() *pwLimiter {
	return &pwLimiter{
		byKey:    make(map[string]*pwAttempts),
		accounts: make(map[string]*pwAttempts),
		lanes:    make(map[string]*laneState),
	}
}

// isAccountKey reports whether key names an account or one of its tokens
// (totpLoginKey, admitStepUp) rather than an address.
func isAccountKey(key string) bool {
	return strings.HasPrefix(key, "totp:") || strings.HasPrefix(key, "token:") ||
		strings.HasPrefix(key, "account:") || strings.HasPrefix(key, stepUpAccountPrefix)
}

// entries is the map key lives in. Runs under l.mu.
func (l *pwLimiter) entries(key string) map[string]*pwAttempts {
	if isAccountKey(key) {
		return l.accounts
	}
	return l.byKey
}

// live counts the failures inside the window at now.
func (a *pwAttempts) live(now time.Time) int {
	n := 0
	for _, f := range a.failures {
		if now.Sub(f.at) < pwFailWindow {
			n++
		}
	}
	return n
}

// stale reports whether the entry carries no information at `now`.
func (a *pwAttempts) stale(now time.Time) bool {
	return a.inFlight == 0 && !now.Before(a.blockedUntil) && a.live(now) == 0 && !a.remembers(now)
}

// pwAttempt is one admitted guess. Exactly one of failed, succeeded or
// abandon settles it; until then it holds one of each tracked key's
// guesses, so a burst sent at once can never have more guesses checked than
// the key has left. keys holds the tracked keys only: an address or a lane
// admitted untracked counts nothing. spaced holds the spacing each lane's
// guess past the free ones set, for abandon to give back.
type pwAttempt struct {
	l      *pwLimiter
	keys   []string
	spaced []laneSpaced
	now    time.Time
	done   bool
}

// admit reserves one guess under every key, or none: a key that is blocked,
// or whose remaining guesses are all held by attempts in flight, or a lane
// spacing its guesses (laneState.refusal), refuses the attempt and reports
// when to retry. The check pass changes no lane, so a lane is left as it
// was when another key refuses. Capacity never refuses (pwMaxKeys,
// laneMaxKeys).
func (l *pwLimiter) admit(now time.Time, keys ...string) (*pwAttempt, time.Time, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.lastPrune) >= pwPruneEvery {
		for _, m := range []map[string]*pwAttempts{l.byKey, l.accounts} {
			for k, a := range m {
				if a.stale(now) {
					delete(m, k)
				}
			}
		}
		for k, e := range l.lanes {
			if e.stale(now) {
				delete(l.lanes, k)
			}
		}
		l.lastPrune = now
	}
	for _, k := range keys {
		if isLaneKey(k) {
			if e := l.lanes[k]; e != nil {
				if until, refused := e.refusal(now); refused {
					return nil, until, false
				}
			}
			continue
		}
		a, ok := l.entries(k)[k]
		if !ok {
			continue
		}
		if now.Before(a.blockedUntil) {
			return nil, a.blockedUntil, false
		}
		if !a.blockedUntil.IsZero() {
			// The served block is over: start fresh, remembering its length.
			*a = pwAttempts{inFlight: a.inFlight, lastBlock: a.lastBlock, lastEnd: a.lastEnd}
		}
		if limit, _ := keyLimit(k); a.live(now)+a.inFlight >= limit {
			return nil, now.Add(pwBusyRetry), false
		}
	}
	att := &pwAttempt{l: l, keys: make([]string, 0, len(keys)), now: now}
	for _, k := range keys {
		if isLaneKey(k) {
			e := l.lanes[k]
			if e == nil {
				if len(l.lanes) >= laneMaxKeys && !l.evictLane(now) {
					continue
				}
				e = &laneState{}
				l.lanes[k] = e
			}
			if prev, set, spaced := e.reserve(now); spaced {
				att.spaced = append(att.spaced, laneSpaced{key: k, prev: prev, set: set})
			}
			att.keys = append(att.keys, k)
			continue
		}
		m := l.entries(k)
		a := m[k]
		if a == nil {
			if !isAccountKey(k) && len(m) >= pwMaxKeys && !l.evictOne(now) {
				continue
			}
			a = &pwAttempts{}
			m[k] = a
		}
		a.inFlight++
		att.keys = append(att.keys, k)
	}
	return att, time.Time{}, true
}

// evictOne drops one sampled address entry, never one with an attempt in
// flight: the one with the fewest live failures among those not blocked,
// or, when every candidate is blocked, the one whose block ends soonest. It
// reports false when every sampled entry has an attempt in flight. Runs
// under l.mu.
func (l *pwLimiter) evictOne(now time.Time) bool {
	open, least := "", pwFailLimit+1
	blocked, soonest := "", time.Time{}
	seen := 0
	for k, a := range l.byKey {
		if seen++; seen > pwEvictProbe {
			break
		}
		switch {
		case a.inFlight > 0:
		case now.Before(a.blockedUntil):
			if blocked == "" || a.blockedUntil.Before(soonest) {
				blocked, soonest = k, a.blockedUntil
			}
		default:
			if n := a.live(now); n < least {
				open, least = k, n
			}
		}
	}
	victim := open
	if victim == "" {
		victim = blocked
	}
	if victim == "" {
		return false
	}
	delete(l.byKey, victim)
	return true
}

// evictLane drops one sampled lane, never one with an attempt in flight:
// the one with the fewest failures among those still free, or, when every
// candidate is spacing its guesses, the one whose quiet hour ends soonest.
// A flood of new names therefore takes the place of other new names, never
// of a lane it is being throttled on. It reports false when every sampled
// lane has an attempt in flight. Runs under l.mu.
func (l *pwLimiter) evictLane(now time.Time) bool {
	open, least := "", laneFree
	throttled, soonest := "", time.Time{}
	seen := 0
	for k, e := range l.lanes {
		if seen++; seen > pwEvictProbe {
			break
		}
		if e.inFlight > 0 {
			continue
		}
		if n := e.failsAt(now); n < laneFree {
			if n < least {
				open, least = k, n
			}
			continue
		}
		if ends := e.lastFail.Add(laneQuiet); throttled == "" || ends.Before(soonest) {
			throttled, soonest = k, ends
		}
	}
	victim := open
	if victim == "" {
		victim = throttled
	}
	if victim == "" {
		return false
	}
	delete(l.lanes, victim)
	return true
}

// forgetLane frees the lane key: its failures and its spacing are
// forgotten, and an entry with no attempt in flight is dropped.
func (l *pwLimiter) forgetLane(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.lanes[key]
	if e == nil {
		return
	}
	if e.inFlight == 0 {
		delete(l.lanes, key)
		return
	}
	e.fails, e.nextAt = 0, time.Time{}
}

// blocked reports whether key is blocked at now. A lane is never blocked.
func (l *pwLimiter) blocked(key string, now time.Time) bool {
	if isLaneKey(key) {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.entries(key)[key]
	return a != nil && now.Before(a.blockedUntil)
}

// release returns one in-flight guess of key, dropping an entry left with
// nothing to say. An entry that remembers a block's length is left for the
// sweep, which drops it once the memory lapses (pwAttempts.stale). Runs
// under l.mu.
func (l *pwLimiter) release(key string) {
	if isLaneKey(key) {
		e := l.lanes[key]
		if e == nil {
			return
		}
		if e.inFlight > 0 {
			e.inFlight--
		}
		if e.inFlight == 0 && e.fails == 0 && e.nextAt.IsZero() {
			delete(l.lanes, key)
		}
		return
	}
	m := l.entries(key)
	a := m[key]
	if a == nil {
		return
	}
	if a.inFlight > 0 {
		a.inFlight--
	}
	if a.inFlight == 0 && a.blockedUntil.IsZero() && len(a.failures) == 0 && a.lastBlock == 0 {
		delete(m, key)
	}
}

// extend adds key to an admitted attempt, refusing as admit does. A refusal
// leaves the attempt as it was, still to be settled.
func (a *pwAttempt) extend(key string) (time.Time, bool) {
	more, until, ok := a.l.admit(a.now, key)
	if !ok {
		return until, false
	}
	more.done = true
	a.keys = append(a.keys, more.keys...)
	a.spaced = append(a.spaced, more.spaced...)
	return time.Time{}, true
}

// failed settles the attempt as a wrong guess at target, counted under every
// key, and reports whether any key is now locked out and until when. A lane
// counts the failure and is never locked out, so it is never reported.
func (a *pwAttempt) failed(target string) (time.Time, bool) {
	l := a.l
	l.mu.Lock()
	defer l.mu.Unlock()
	if a.done {
		return time.Time{}, false
	}
	a.done = true
	target = strings.Clone(target[:min(len(target), pwTargetMax)])
	var until time.Time
	for _, k := range a.keys {
		if isLaneKey(k) {
			if e := l.lanes[k]; e != nil {
				if e.inFlight > 0 {
					e.inFlight--
				}
				e.fails++
				if a.now.After(e.lastFail) {
					e.lastFail = a.now
				}
			}
			continue
		}
		e := l.entries(k)[k]
		if e == nil {
			continue
		}
		e.inFlight--
		kept := e.failures[:0]
		for _, f := range e.failures {
			if a.now.Sub(f.at) < pwFailWindow {
				kept = append(kept, f)
			}
		}
		e.failures = append(kept, pwFailure{at: a.now, target: target})
		if limit, _ := keyLimit(k); len(e.failures) >= limit && e.blockedUntil.IsZero() {
			block := e.blockFor(k, a.now)
			e.blockedUntil = a.now.Add(block)
			if escalates(k) {
				e.lastBlock, e.lastEnd = block, e.blockedUntil
			}
		}
		if a.now.Before(e.blockedUntil) && e.blockedUntil.After(until) {
			until = e.blockedUntil
		}
	}
	return until, !until.IsZero()
}

// succeeded settles the attempt as a proof of target and forgets the wrong
// guesses aimed at that target under every key, and nothing else: whoever
// signs in to their own account, or opens a share whose password they hold,
// learns nothing about another account or share, so the guesses made at
// those still count. A block stands until it is served. A kept browser's
// lane (known:) is freed; a stranger lane (signin:) and a share's lane
// (share:) keep their failures and spacing, since those are strangers'
// guesses, and the owner's success must not hand them fresh free ones.
func (a *pwAttempt) succeeded(target string) {
	l := a.l
	l.mu.Lock()
	defer l.mu.Unlock()
	if a.done {
		return
	}
	a.done = true
	for _, k := range a.keys {
		if isLaneKey(k) {
			if e := l.lanes[k]; e != nil && strings.HasPrefix(k, knownLanePrefix) {
				e.fails, e.nextAt = 0, time.Time{}
			}
		} else if e := l.entries(k)[k]; e != nil {
			kept := e.failures[:0]
			for _, f := range e.failures {
				if f.target != target {
					kept = append(kept, f)
				}
			}
			e.failures = kept
		}
		l.release(k)
	}
}

// abandon settles the attempt without an outcome: nothing was guessed (a
// missing code, a pending poll), the check could not run (a database fault,
// a full compare queue), or the client left before it ran. No wrong guess
// was checked, so a lane's guess past the free ones gives its slot back: a
// lane whose spacing is still the one this attempt set returns to the
// spacing it had before. A spacing that has moved since (freed by a quiet
// hour or a password set) is left as it is.
func (a *pwAttempt) abandon() {
	l := a.l
	l.mu.Lock()
	defer l.mu.Unlock()
	if a.done {
		return
	}
	a.done = true
	for _, s := range a.spaced {
		if e := l.lanes[s.key]; e != nil && e.nextAt.Equal(s.set) {
			e.nextAt = s.prev
		}
	}
	for _, k := range a.keys {
		l.release(k)
	}
}

// clientIP is the per-connection peer address: the TCP peer, or, on HTTPS,
// the source of the PROXY header a proxy listed in HYPERDROP_TRUSTED_PROXIES
// is required to send (the listener rewrites RemoteAddr below net/http,
// server/proxyproto.go; any other peer's header refuses the connection, and
// nothing is trusted unlisted, loopback included). Docker's DNAT preserves
// source addresses.
func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// addrKey is the lockout's key for a client address: an IPv4 address as
// itself (an IPv4-mapped IPv6 one included), and an IPv6 address by its /64,
// the smallest prefix a host is routed, since a host holding one has 2^64
// addresses to spread its guesses over.
func addrKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap().WithZone("")
	if a.Is4() {
		return a.String()
	}
	return netip.PrefixFrom(a, 64).Masked().String()
}
