package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"hyperdrop/server/internal/metadb"
)

// Who has read a share, counted once per browser. The hd_visitor cookie is
// one token per browser for the whole server; a request without one in the
// minted shape counts once per peer address and User-Agent. What reaches
// the rows is HMAC(volume secret, token), never the token, and no gate reads
// the cookie: like the inbox's hdv_ cookie it groups requests and grants
// nothing.

// visitorCookie is minted on page responses (the share page, the site root
// redirect, the inbox page, the password form) and read on every counted
// route. Path=/ and Domain=<registrable domain> so it rides the hop to
// files.<domain>; host-only when there is no split.
const visitorCookie = "hd_visitor"

// visitorCookieTTL is a year: long enough that the same person opening the
// same link next month is not a second visitor.
const visitorCookieTTL = 365 * 24 * time.Hour

// visitFlushInterval is how often pending visits become rows. A popular share
// costs one write and one coalesced journal row per interval rather than
// one per hit.
const visitFlushInterval = 15 * time.Second

// visitTracker holds the (share, token) pairs seen since the last flush and
// writes them in one transaction. It has no view of the rows, so a token
// already stored is written again as an INSERT OR IGNORE; the pending set
// is what dedupes a burst within one interval.
type visitTracker struct {
	db      *metadb.DB
	mu      sync.Mutex
	pending map[metadb.Visit]struct{}
	stop    chan struct{}
	done    chan struct{}
	// started is set by run's first line. close reads it to decide whether
	// done is a channel anything will ever close: a tracker New built for a
	// test never has run called on it, and done would otherwise sit unclosed
	// forever.
	started atomic.Bool
}

func newVisitTracker(db *metadb.DB) *visitTracker {
	return &visitTracker{db: db, pending: map[metadb.Visit]struct{}{},
		stop: make(chan struct{}), done: make(chan struct{})}
}

// note records one visit for the next flush.
func (t *visitTracker) note(shareID string, token [32]byte) {
	t.mu.Lock()
	t.pending[metadb.Visit{ShareID: shareID, Token: token}] = struct{}{}
	t.mu.Unlock()
}

// flush writes every pending visit and empties the set. A failed write
// puts the batch back so the next flush retries it.
func (t *visitTracker) flush() error {
	t.mu.Lock()
	batch := make([]metadb.Visit, 0, len(t.pending))
	for v := range t.pending {
		batch = append(batch, v)
	}
	t.pending = map[metadb.Visit]struct{}{}
	t.mu.Unlock()
	if len(batch) == 0 {
		return nil
	}
	if err := t.db.RecordVisits(batch); err != nil {
		t.mu.Lock()
		for _, v := range batch {
			t.pending[v] = struct{}{}
		}
		t.mu.Unlock()
		return err
	}
	return nil
}

// run flushes every interval until close is called; the Server starts it
// and Drain stops it. A handler built by New for a test never runs it and
// flushes on demand.
func (t *visitTracker) run(interval time.Duration) {
	t.started.Store(true)
	defer close(t.done)
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			_ = t.flush()
		case <-t.stop:
			return
		}
	}
}

// close stops run and writes what is pending, so a shutdown loses no visit
// that was already answered. A tracker run was never called on (the test
// constructor New) has no goroutine to wait for, so close skips the wait
// rather than blocking on a done channel nothing will ever close.
func (t *visitTracker) close() {
	select {
	case <-t.stop:
	default:
		close(t.stop)
	}
	if t.started.Load() {
		<-t.done
	}
	_ = t.flush()
}

// visitorHash keys a token with the volume secret, so a row identifies a
// visitor to this server alone and reveals nothing if the database leaks.
func (h *handler) visitorHash(parts ...string) [32]byte {
	mac := hmac.New(sha256.New, h.fs.Secret())
	for i, p := range parts {
		if i > 0 {
			mac.Write([]byte{'|'})
		}
		mac.Write([]byte(p))
	}
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// visitorToken is who this request counts as: its hd_visitor cookie when
// one arrives in the minted shape, otherwise its peer address and
// User-Agent, which is what makes curl and a cookieless bot one visitor each.
// Every cookie of the name is tried, for the reason validAccess gives: a
// browser sends a same-named cookie from a sibling server too.
func (h *handler) visitorToken(r *http.Request) [32]byte {
	if tok, ok := h.cookieToken(r); ok {
		return tok
	}
	return h.visitorHash("ipua", clientIP(r), r.UserAgent())
}

// cookieToken is the request's hd_visitor cookie as a visitor token, when one
// arrives in the minted shape.
func (h *handler) cookieToken(r *http.Request) ([32]byte, bool) {
	for _, c := range r.CookiesNamed(visitorCookie) {
		if validVisitor(c.Value) {
			return h.visitorHash("cookie", c.Value), true
		}
	}
	return [32]byte{}, false
}

// mintVisitor is visitorToken for a PAGE response: a request carrying no
// minted cookie is handed one, and counts as the token it was handed, so the
// payload request the page leads to is the same visitor. A request already
// carrying one keeps it.
func (h *handler) mintVisitor(w http.ResponseWriter, r *http.Request) [32]byte {
	if tok, ok := h.cookieToken(r); ok {
		return tok
	}
	v := h.setGroupingCookie(w, r, visitorCookie, "/", h.origins().CookieDomain(), visitorCookieTTL)
	if v == "" {
		return h.visitorHash("ipua", clientIP(r), r.UserAgent())
	}
	return h.visitorHash("cookie", v)
}

// setGroupingCookie mints a grouping token (16 random bytes, base64url: the
// 22-character shape validVisitor accepts) and hands it to the browser as an
// HttpOnly, SameSite=Lax cookie, Secure whenever cookieSecure says the
// browser reached it over HTTPS. An empty domain makes it host-only. When
// the random source fails it sets nothing and returns "".
func (h *handler) setGroupingCookie(w http.ResponseWriter, r *http.Request, name, cookiePath, domain string, ttl time.Duration) string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	v := base64.RawURLEncoding.EncodeToString(buf)
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: v, Path: cookiePath, Domain: domain,
		MaxAge: int(ttl / time.Second), HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Secure: h.cookieSecure(r),
	})
	return v
}

// recordVisit counts one successful public read of v under token. A live
// share keeps its set in the registry; a stored share's visit waits for the
// next flush. The caller decides what a read is: after the unfurler card,
// after the waiting page, never for the owner's own bearer fetch.
func (h *handler) recordVisit(v shareView, token [32]byte) {
	if v.LiveShare {
		h.liveShareReg.Visit(v.ID, token)
		return
	}
	h.visits.note(v.ID, token)
}
