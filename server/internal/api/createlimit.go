package api

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"hyperdrop/server/internal/metadb"
)

// Per-account throttle on share CREATION. Uploads are deliberately not
// throttled: they're bounded by the owner's quota, and a folder share is one
// PUT per file, so a rate limit there would break a legitimate 500-file
// upload. Creating shares is the cheap operation that no quota bounds: an
// empty share costs a directory and a meta write, and empty shares are only
// swept after an hour, which a loop easily outruns.
//
// Token bucket per username: burst absorbs normal use (share a batch of files
// in a minute and nothing notices), the refill rate is what a script hits.
// In-memory like the password lockout: a restart forgiving the counters is
// fine for this threat model.
const (
	createBurst      = 30
	createPerHour    = 300
	createPruneAbove = 1024
	// tokenMaxKeys bounds a limiter's buckets. Past it a key with no bucket
	// is admitted untracked (it fails open: the limiter protects the server's
	// time, and a flood of addresses must not take anyone's uploads with it),
	// after a prune has made no room.
	tokenMaxKeys = 1 << 16
)

type createBucket struct {
	tokens float64
	last   time.Time
}

type createLimiter struct {
	mu        sync.Mutex
	byUser    map[string]*createBucket
	lastPrune time.Time
	// burst/perHour are fields (not the consts directly) so tests can drive
	// the limiter without sleeping for real refills.
	burst   float64
	perHour float64
	maxKeys int
}

func newCreateLimiter() *createLimiter {
	return newTokenLimiter(createBurst, createPerHour)
}

// newTokenLimiter is a token bucket per key with the given burst and refill:
// the create limiter's shape, keyed by whatever the caller spends for.
func newTokenLimiter(burst, perHour float64) *createLimiter {
	return &createLimiter{byUser: make(map[string]*createBucket), burst: burst, perHour: perHour, maxKeys: tokenMaxKeys}
}

// exhausted reports whether key's bucket has no token left at now, and how
// long until one is back, spending nothing.
func (l *createLimiter) exhausted(key string, now time.Time) (retryAfter time.Duration, out bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.byUser[key]
	if b == nil {
		return 0, false
	}
	perSecond := l.perHour / 3600
	tokens := min(b.tokens+now.Sub(b.last).Seconds()*perSecond, l.burst)
	if tokens >= 1 {
		return 0, false
	}
	wait := time.Duration((1 - tokens) / perSecond * float64(time.Second))
	return max(wait, time.Second), true
}

// allow spends one token for user. ok=false means the caller is over its rate;
// retryAfter is how long until one token is back (always ≥ 1s so a client's
// Retry-After is never "0").
func (l *createLimiter) allow(user string, now time.Time) (retryAfter time.Duration, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(now)

	b := l.byUser[user]
	if b == nil {
		if len(l.byUser) >= l.maxKeys {
			l.lastPrune = time.Time{}
			l.pruneLocked(now)
			if len(l.byUser) >= l.maxKeys {
				return 0, true
			}
		}
		b = &createBucket{tokens: l.burst, last: now}
		l.byUser[user] = b
	}
	perSecond := l.perHour / 3600
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = min(b.tokens+elapsed*perSecond, l.burst)
		b.last = now
	}
	if b.tokens < 1 {
		wait := time.Duration((1 - b.tokens) / perSecond * float64(time.Second))
		if wait < time.Second {
			wait = time.Second
		}
		return wait, false
	}
	b.tokens--
	return 0, true
}

// pruneLocked shares buckets that have refilled completely: they carry no
// information a fresh bucket wouldn't.
func (l *createLimiter) pruneLocked(now time.Time) {
	if len(l.byUser) <= createPruneAbove && now.Sub(l.lastPrune) < time.Hour {
		return
	}
	l.lastPrune = now
	full := l.burst / (l.perHour / 3600) // seconds to refill from empty
	for user, b := range l.byUser {
		if b.tokens >= l.burst || now.Sub(b.last).Seconds() > full {
			delete(l.byUser, user)
		}
	}
}

// allowCreate spends one of u's creation tokens, or answers 429 rate-limited
// with a Retry-After and reports false. An admin is exempt: they own the box.
func (h *handler) allowCreate(w http.ResponseWriter, u metadb.User) bool {
	if u.IsAdmin() || h.limits.create == nil {
		return true
	}
	retry, ok := h.limits.create.allow(u.Username, time.Now())
	if !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(retry.Round(time.Second)/time.Second)))
		writeErrorCode(w, http.StatusTooManyRequests, "rate-limited",
			"too many shares created just now, wait a moment and try again")
	}
	return ok
}
