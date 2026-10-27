package api

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"sync"
	"time"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/shareid"
)

const (
	// ticketFor is how long a download ticket lives unspent.
	ticketFor = 2 * time.Minute
	// ticketsPerUser and ticketsTotal bound the live tickets of one account
	// and of the whole server; issue refuses past either.
	ticketsPerUser = 64
	ticketsTotal   = 4096
	// ticketSweepEvery bounds how often issue walks the book for expired
	// tickets, so a burst of issues walks it once.
	ticketSweepEvery = time.Second
)

// errTooManyTickets is issue's refusal past ticketsPerUser or ticketsTotal.
var errTooManyTickets = errors.New("too many download tickets outstanding")

// ticketBook keeps the download tickets the web client asks for, in memory
// only. The web session cookie never reaches the files origin, so a ticket
// carries the owner's right to read ONE file there: 32 random bytes, bound
// to the user, the token that asked for it (a web session or a device
// token), the share and the file's slug, single use, valid for ticketFor. A
// restart forgets every ticket.
type ticketBook struct {
	mu      sync.Mutex
	m       map[string]ticket
	perUser map[string]int // live tickets per account, the cap's count
	swept   time.Time      // the last sweep
}

type ticket struct {
	user, tokenID, shareID, slug string
	until                        time.Time
}

// issue mints a ticket at now for user, asked for by the token tokenID, to
// read slug of shareID, answering errTooManyTickets when user already holds
// ticketsPerUser live tickets or the server ticketsTotal.
func (b *ticketBook) issue(user, tokenID, shareID, slug string, now time.Time) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		panic("download ticket: " + err.Error())
	}
	t := base64.RawURLEncoding.EncodeToString(raw)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.m == nil {
		b.m, b.perUser = map[string]ticket{}, map[string]int{}
	}
	if !now.Before(b.swept.Add(ticketSweepEvery)) {
		b.sweep(now)
	}
	if len(b.m) >= ticketsTotal || b.perUser[user] >= ticketsPerUser {
		return "", errTooManyTickets
	}
	b.m[t] = ticket{user, tokenID, shareID, slug, now.Add(ticketFor)}
	b.perUser[user]++
	return t, nil
}

// spend consumes t and answers the ticket, when it is live and names this
// share and slug. A ticket is gone after any spend, whether or not it
// matched.
func (b *ticketBook) spend(t, shareID, slug string, now time.Time) (ticket, bool) {
	return b.take(t, shareID, slug, now, true)
}

// peek is spend that leaves a matching ticket in place, for a HEAD that
// must not use up the GET which follows it.
func (b *ticketBook) peek(t, shareID, slug string, now time.Time) (ticket, bool) {
	return b.take(t, shareID, slug, now, false)
}

// take is spend and peek: a ticket that is expired or names another share
// or slug is deleted either way, a matching one only when consume is set.
func (b *ticketBook) take(t, shareID, slug string, now time.Time, consume bool) (ticket, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	k, ok := b.m[t]
	if !ok {
		return ticket{}, false
	}
	stale := !now.Before(k.until) || k.shareID != shareID || k.slug != slug
	if consume || stale {
		b.drop(t, k)
	}
	if stale {
		return ticket{}, false
	}
	return k, true
}

// drop deletes ticket t, k; b.mu is held.
func (b *ticketBook) drop(t string, k ticket) {
	delete(b.m, t)
	if b.perUser[k.user]--; b.perUser[k.user] <= 0 {
		delete(b.perUser, k.user)
	}
}

// sweep drops every ticket that has run out; b.mu is held.
func (b *ticketBook) sweep(now time.Time) {
	b.swept = now
	for t, k := range b.m {
		if !now.Before(k.until) {
			b.drop(t, k)
		}
	}
}

// hasTicket reports whether the request carries a download ticket, live or
// not.
func hasTicket(r *http.Request) bool { return r.URL.Query().Get("t") != "" }

// ticketOwns reports whether the request presents a live download ticket
// issued to the share's owner for the file it names, whose issuing token is
// still live (metadb.TokenLive) and, for a web session, while the web
// client's switch is on: a sign-out, a revoke, a password change or the
// switch leaves every ticket that session or device asked for unspendable.
// The request path carries the slug on /download.
func (h *handler) ticketOwns(r *http.Request, v shareView) bool {
	t := r.URL.Query().Get("t")
	if t == "" {
		return false
	}
	take := h.tickets.spend
	if r.Method == http.MethodHead {
		take = h.tickets.peek
	}
	now := time.Now()
	k, ok := take(t, v.ID, r.PathValue("path"), now)
	if !ok || k.user != v.Owner {
		return false
	}
	kind, live, err := h.db.TokenLive(k.user, k.tokenID, now)
	if err != nil {
		log.Printf("download ticket: reading token %s: %v", k.tokenID, err)
		return false
	}
	return live && (kind != metadb.TokenKindWeb || h.webOn())
}

// downloadTicket answers POST /api/shares/{id}/download-ticket: a URL on
// the files origin that downloads one file of the caller's own share once.
func (h *handler) downloadTicket(w http.ResponseWriter, r *http.Request) {
	v, u, ok := h.ownedShareMeta(w, r)
	if !ok {
		return
	}
	caller := h.callerToken(r)
	if caller.ID == "" {
		writeNoCallerToken(w)
		return
	}
	var body struct {
		Slug string `json:"slug"`
	}
	if !decodeJSONBody(w, r, 64<<10, &body) {
		return
	}
	notFound := func() {
		writeErrorCode(w, http.StatusNotFound, "not-found", "no such file in this share")
	}
	if !shareid.ValidSlug(body.Slug) {
		notFound()
		return
	}
	files, err := h.lookupFor(v)
	if err != nil {
		writeRefusal(w, err)
		return
	}
	f, ok := files.bySlug(body.Slug)
	if !ok {
		notFound()
		return
	}
	if f.Pending {
		writeErrorCode(w, http.StatusConflict, "file-pending", "the file is still uploading")
		return
	}
	base := h.payloadBase()
	if base == "" {
		base = h.canonicalBase(r)
	}
	t, err := h.tickets.issue(u.Username, caller.ID, v.ID, body.Slug, time.Now())
	if err != nil {
		w.Header().Set("Retry-After", "5")
		writeErrorCode(w, http.StatusTooManyRequests, "too-many-tickets",
			"too many downloads asked for at once, try again in a moment")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"url": base + "/download/" + v.ID + "/" + body.Slug + "?t=" + t,
	})
}
