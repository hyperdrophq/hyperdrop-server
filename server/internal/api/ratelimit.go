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

// webAccountFailLimit is the wrong web sign-ins an account takes from every
// address together within pwFailWindow before its web sign-in waits for
// webAccountWait (webSignInKey). It is higher than an address's limit, and
// its wait shorter than an address's block, because whoever spreads guesses
// over addresses can make the owner wait as well; the installed apps' login
// never reads it.
const (
	webAccountFailLimit = 20
	webAccountWait      = pwFailWindow
)

// keyLimit is key's limit and block: the web sign-in's account counter's,
// or every other key's.
func keyLimit(key string) (limit int, block time.Duration) {
	if isWebSignInKey(key) {
		return webAccountFailLimit, webAccountWait
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
// how often stale entries are swept, whatever the map's size.
//
// An account's keys (totp:, account:, web:) are not counted against the
// bound and are never evicted: they are made only for an account the caller
// proved the password of, holds a token for, or that exists (webSignInKey),
// so there are at most as many as there are accounts.
const (
	pwMaxKeys    = 1 << 16
	pwEvictProbe = 8
	pwPruneEvery = time.Minute
)

// pwBusyRetry is the Retry-After of a key whose remaining guesses are all
// held by attempts still being checked: one of them settles within a
// compare's time.
const pwBusyRetry = 5 * time.Second

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
}

type pwLimiter struct {
	mu        sync.Mutex
	byKey     map[string]*pwAttempts // address keys, bounded by pwMaxKeys
	accounts  map[string]*pwAttempts // account keys, one per account at most
	lastPrune time.Time
}

func newPWLimiter() *pwLimiter {
	return &pwLimiter{byKey: make(map[string]*pwAttempts), accounts: make(map[string]*pwAttempts)}
}

// isAccountKey reports whether key names an account (totpLoginKey,
// stepUpAccountKey, webSignInKey) rather than an address.
func isAccountKey(key string) bool {
	return strings.HasPrefix(key, "totp:") || strings.HasPrefix(key, "account:") || strings.HasPrefix(key, webAccountPrefix)
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
	return a.inFlight == 0 && !now.Before(a.blockedUntil) && a.live(now) == 0
}

// pwAttempt is one admitted guess. Exactly one of failed, succeeded or
// abandon settles it; until then it holds one of each tracked key's
// guesses, so a burst sent at once can never have more guesses checked than
// the key has left. keys holds the tracked keys only: an address admitted
// untracked counts nothing.
type pwAttempt struct {
	l    *pwLimiter
	keys []string
	now  time.Time
	done bool
}

// admit reserves one guess under every key, or none: a key that is blocked,
// or whose remaining guesses are all held by attempts in flight, refuses the
// attempt and reports when to retry. Capacity never refuses (pwMaxKeys).
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
		l.lastPrune = now
	}
	for _, k := range keys {
		a, ok := l.entries(k)[k]
		if !ok {
			continue
		}
		if now.Before(a.blockedUntil) {
			return nil, a.blockedUntil, false
		}
		if !a.blockedUntil.IsZero() {
			*a = pwAttempts{inFlight: a.inFlight} // the served block is over; start fresh
		}
		if limit, _ := keyLimit(k); a.live(now)+a.inFlight >= limit {
			return nil, now.Add(pwBusyRetry), false
		}
	}
	tracked := make([]string, 0, len(keys))
	for _, k := range keys {
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
		tracked = append(tracked, k)
	}
	return &pwAttempt{l: l, keys: tracked, now: now}, time.Time{}, true
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

// blocked reports whether key is blocked at now.
func (l *pwLimiter) blocked(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.entries(key)[key]
	return a != nil && now.Before(a.blockedUntil)
}

// release returns one in-flight guess of key, dropping an entry left with
// nothing to say. Runs under l.mu.
func (l *pwLimiter) release(key string) {
	m := l.entries(key)
	a := m[key]
	if a == nil {
		return
	}
	if a.inFlight > 0 {
		a.inFlight--
	}
	if a.inFlight == 0 && a.blockedUntil.IsZero() && len(a.failures) == 0 {
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
	return time.Time{}, true
}

// failed settles the attempt as a wrong guess at target, counted under every
// key, and reports whether any key is now locked out and until when.
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
		if limit, block := keyLimit(k); len(e.failures) >= limit && e.blockedUntil.IsZero() {
			e.blockedUntil = a.now.Add(block)
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
// those still count. A block stands until it is served.
func (a *pwAttempt) succeeded(target string) {
	l := a.l
	l.mu.Lock()
	defer l.mu.Unlock()
	if a.done {
		return
	}
	a.done = true
	for _, k := range a.keys {
		if e := l.entries(k)[k]; e != nil {
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
// missing code, a pending poll), the check could not run (a database fault),
// or the client left before it ran.
func (a *pwAttempt) abandon() {
	l := a.l
	l.mu.Lock()
	defer l.mu.Unlock()
	if a.done {
		return
	}
	a.done = true
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
