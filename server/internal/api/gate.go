package api

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"hyperdrop/server/internal/metadb"
)

// bcryptSem caps concurrent bcrypt compares. Each costs ~100 ms of pure CPU
// and the routes are unauthenticated, so without a cap a burst of parallel
// password attempts pegs a 1-vCPU box.
var bcryptSem = make(chan struct{}, 2)

// shareBcryptSem adds per-owner fairness to the share-password compares: one
// account's protected shares can hold at most one of the two slots, so a guest
// (or a stranger hammering that guest's links) can't stall everyone else's
// password checks. Login compares keep the plain global cap: their key would
// have to come from request input, and they already have the per-IP lockout.
var shareBcryptSem = newFairSem(cap(bcryptSem), 1)

// passwordMatchesForOwner runs a share-password compare under the owner-fair
// cap. aborted = ctx ended while queueing for a slot (the client gave up), and
// is reported separately from a wrong password so a disconnect never counts
// against the guess budget of whoever's IP it was.
func passwordMatchesForOwner(ctx context.Context, owner, hash, password string) (matched, aborted bool) {
	if !shareBcryptSem.acquire(ctx, owner) {
		return false, true
	}
	defer shareBcryptSem.release(owner)
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil, false
}

// passwordSubmit verifies a submitted password, sets the access cookie, and
// redirects to `next` (default the listing). Wrong password re-renders the
// form with a 401 and an error message.
func (h *handler) passwordSubmit(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	// Any kind: this is how a password-protected INBOX's form
	// submits too, so the kind rule cannot apply here. Every question the
	// form asks is a column of the row, so the row is all it reads.
	sh, ok := h.visibleShareAnyVia(r, h.viewMeta)
	if !ok || sh.PasswordHash == "" {
		http.NotFound(w, r)
		return
	}
	// The form is tiny; anything bigger is abuse, not a password.
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "bad form")
		return
	}
	fallback := "/share/" + id
	if sh.Inbox {
		fallback = "/receive/" + id
	}
	next := unlockNext(r.FormValue("next"), id, fallback)
	unlocked, done := h.unlockShare(w, r, sh, r.FormValue("password"))
	if done {
		return
	}
	if !unlocked {
		h.renderPasswordForm(w, r, sh, next, "Incorrect password. Try again.", http.StatusUnauthorized)
		return
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// unlockNext is where a correct password sends the visitor: `next` when it
// names one of this share's own public routes, otherwise fallback. The form
// fills `next` with the address that asked for the password, query
// included, so the query is kept (a folder's ?dir= is the difference
// between that folder's zip and the whole share's) except `pw`, which the
// cookie this redirect follows has already spent.
//
// Nothing the browser could read as another host survives: a scheme, a host,
// a protocol-relative "//", a backslash (browsers read "\" as "/"), a dot
// segment, and any control character, encoded or not (browsers strip a tab
// or a newline out of a URL, so "/\t/evil.com" becomes "//evil.com"). The
// answer is re-serialized from the parsed path and query, so what reaches
// the Location header is percent-encoded ASCII.
func unlockNext(raw, id, fallback string) string {
	bad := func(s string) bool {
		return strings.ContainsFunc(s, func(c rune) bool { return c < 0x20 || c == 0x7f || c == '\\' })
	}
	if bad(raw) {
		return fallback
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" ||
		bad(u.Path) || strings.Contains(u.Path+"/", "/../") || strings.Contains(u.Path+"/", "/./") ||
		!shareRoute(u.Path, id) {
		return fallback
	}
	return withoutPassword(u)
}

// shareRoute reports whether p is an address of share id on one of the public
// routes that can ask for its password.
func shareRoute(p, id string) bool {
	switch p {
	case "/share/" + id, "/zip/" + id, "/receive/" + id, "/site/" + id:
		return true
	}
	for _, route := range []string{"/view/", "/download/", "/site/", "/thumb/"} {
		if strings.HasPrefix(p, route+id+"/") {
			return true
		}
	}
	return false
}

// withoutPassword is u's path and query, re-serialized, with `pw` taken out
// of the query.
func withoutPassword(u *url.URL) string {
	out := url.URL{Path: u.Path, RawPath: u.RawPath}
	q := u.Query()
	q.Del("pw")
	out.RawQuery = q.Encode()
	return out.String()
}

// unlockShare checks one guess at v's password on the share-password
// lockout and, when it is right, sets the access cookie. done reports that
// the response is written (the caller's address is locked out) or that the
// client left while queueing for a compare slot, which counts nothing. A
// right password forgets only the guesses made at this share: knowing one
// share's password says nothing about another's.
func (h *handler) unlockShare(w http.ResponseWriter, r *http.Request, v shareView, password string) (unlocked, done bool) {
	now := time.Now()
	att, until, ok := h.limits.pw.admit(now, addrKey(clientIP(r)))
	if !ok {
		h.renderLockedOut(w, until, now)
		return false, true
	}
	defer att.abandon()
	matched, aborted := passwordMatchesForOwner(r.Context(), v.Owner, v.PasswordHash, password)
	if aborted {
		return false, true
	}
	if !matched {
		if until, blocked := att.failed(v.ID); blocked {
			h.renderLockedOut(w, until, now)
			return false, true
		}
		return false, false
	}
	att.succeeded(v.ID)
	h.setAccessCookie(w, r, v.ID, v.PasswordGen)
	return true, false
}

// rateLimits are the server's throttles, in one place.
//
// pw and login are SEPARATE instances on purpose: sharing one would let an
// attacker guessing a share password lock the owner out of signing in.
type rateLimits struct {
	// pw throttles share-password guessing.
	pw *pwLimiter
	// login throttles account logins.
	login *pwLimiter
	// create throttles share creation per account (non-admins; an admin owns
	// the box).
	create *createLimiter
}

// visibleShareVia answers the question every public route asks first: does
// this share exist for the outside world at all? Missing, expired, or owned
// by a suspended, expired or deleted account are all the same answer, and
// the caller renders it (404 page, JSON 404), which is the only part that
// differs.
//
// An inbox is refused here: its only public surface is /receive/{id} and the
// upload PUT, which resolve through visibleInbox. Refusing in one place
// is what makes a new consumer inherit the containment.
//
// An id the database does not hold falls back to the relay registry
// (server/internal/liveshare): a live share has no row and no expiry of its
// own, so it skips straight to the owner-active check. This is the ONE
// fallback point, so a live share answers every public route with no second
// implementation.
//
// read is the caller's choice of read (h.publicView, or a windowed one for a
// route that needs no file list).
func (h *handler) visibleShareVia(r *http.Request, read func(string) (shareView, error)) (shareView, bool) {
	v, ok := h.visibleShareAnyVia(r, read)
	if !ok || v.Inbox {
		return shareView{}, false
	}
	return v, true
}

// visibleShareAny is visibleShareVia without the kind rule: exists, not expired,
// owner active. The /receive handlers and /unlock build on it.
func (h *handler) visibleShareAny(r *http.Request) (shareView, bool) {
	return h.visibleShareAnyVia(r, h.publicView)
}

func (h *handler) visibleShareAnyVia(r *http.Request, read func(string) (shareView, error)) (shareView, bool) {
	v, err := read(r.PathValue("id"))
	if err != nil {
		rec, ok := h.liveShareReg.Get(r.PathValue("id"))
		if !ok {
			return shareView{}, false
		}
		v = liveShareView(rec)
	}
	if v.Expired() {
		return shareView{}, false
	}
	// A suspended, expired, or deleted owner takes their public links with
	// them; re-enabling restores everything.
	u, err := h.db.User(v.Owner)
	if err != nil || !u.Active(time.Now()) {
		return shareView{}, false
	}
	v.ownerNoEmbed = u.NoEmbed
	return v, true
}

// visibleInbox resolves an inbox for the /receive routes: anything that is
// not an inbox answers 404, so a share id pasted into a /receive URL reveals
// nothing.
func (h *handler) visibleInbox(r *http.Request) (shareView, bool) {
	v, ok := h.visibleShareAny(r)
	if !ok || !v.Inbox {
		return shareView{}, false
	}
	return v, true
}

// loadPublicShare fetches the share for a public route and enforces access:
// 404 if missing or expired; for a password-protected share, access requires
// a valid access cookie or a correct ?pw= query. Otherwise it renders the
// HTML password form (browser path) so the file bytes are never served.
func (h *handler) loadPublicShare(w http.ResponseWriter, r *http.Request) (shareView, bool) {
	return h.loadPublicShareVia(w, r, h.publicView)
}

// loadPublicShareVia is loadPublicShare over a caller-chosen read; see
// visibleShareVia for why a route would want the windowed one.
func (h *handler) loadPublicShareVia(w http.ResponseWriter, r *http.Request,
	read func(string) (shareView, error)) (shareView, bool) {
	v, ok := h.visibleShareVia(r, read)
	if !ok {
		http.NotFound(w, r)
		return shareView{}, false
	}
	v, ok = h.enforceAccess(w, r, v)
	if !ok {
		return shareView{}, false
	}
	if v.SourceMissing {
		h.renderUnavailable(w, v)
		return shareView{}, false
	}
	privateIfProtected(w, v)
	return v, true
}

// privateIfProtected marks a response a password stands in front of as one
// no shared cache may keep: a proxy or CDN between the server and its
// visitors would otherwise answer the next request for the same URL itself,
// cookie or not. A route that sets its own Cache-Control afterwards (no-store
// on a page that changes under it, a thumbnail's lifetime) keeps it private
// itself.
func privateIfProtected(w http.ResponseWriter, v shareView) {
	if v.PasswordHash != "" {
		w.Header().Set("Cache-Control", "private")
	}
}

// enforceAccess is loadPublicShare's second half, split out for callers
// that already hold the share: serveFile loads it to check the owner-bearer
// bypass before it knows whether the password gate applies.
func (h *handler) enforceAccess(w http.ResponseWriter, r *http.Request, v shareView) (shareView, bool) {
	if v.PasswordHash == "" {
		return v, true
	}
	if h.validAccess(r, v.ID, v.PasswordGen) {
		return v, true
	}
	// ?pw= burns the same per-address guess budget as the form; otherwise
	// the lockout is trivially sidestepped by brute-forcing the query
	// parameter.
	if pw := r.URL.Query().Get("pw"); pw != "" {
		unlocked, done := h.unlockShare(w, r, v, pw)
		if done {
			return shareView{}, false
		}
		if unlocked {
			// A browser opening the link in a tab is sent to the same address
			// without the password, on the cookie just set: left in place, it
			// stays in the history and the address bar, and an uploaded page
			// served at that address reads it from location.href (the sandbox
			// still runs scripts). Only a top-level navigation is: a frame's
			// navigation stores no SameSite=Lax cookie set from another site,
			// so the redirect would land on the password form. A frame, and
			// any client that sends no Fetch Metadata, keeps the bytes in
			// place.
			if r.Method == http.MethodGet && r.Header.Get("Sec-Fetch-Mode") == "navigate" &&
				r.Header.Get("Sec-Fetch-Dest") == "document" {
				http.Redirect(w, r, withoutPassword(r.URL), http.StatusSeeOther)
				return shareView{}, false
			}
			return v, true
		}
	}
	// Browser: show the password form, pre-filling the current path as `next`.
	h.renderPasswordForm(w, r, v, r.URL.RequestURI(), "", http.StatusOK)
	return shareView{}, false
}

// ownedShare loads a share for an authenticated share route and enforces
// ownership: every role, an admin included, only ever sees their own shares,
// anything else is a plain 404 indistinguishable from a share that does not
// exist. ok=false means the response has been written.
func (h *handler) ownedShare(w http.ResponseWriter, r *http.Request) (shareView, metadb.User, bool) {
	return h.ownedShareVia(w, r, h.view)
}

// ownedShareMeta is ownedShare over the windowed read, for routes that never
// walk the file list (upload, batch, thumbs).
func (h *handler) ownedShareMeta(w http.ResponseWriter, r *http.Request) (shareView, metadb.User, bool) {
	return h.ownedShareVia(w, r, h.viewCapped)
}

func (h *handler) ownedShareVia(w http.ResponseWriter, r *http.Request,
	read func(string) (shareView, error)) (shareView, metadb.User, bool) {
	u := reqUser(r)
	v, err := read(r.PathValue("id"))
	if err == nil && v.Owner != u.Username {
		err = metadb.ErrNotFound
	}
	if err != nil {
		writeRefusal(w, err)
		return shareView{}, u, false
	}
	return v, u, true
}
