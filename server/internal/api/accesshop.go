package api

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// The hd_<id> access cookie is host-only: each origin that reads it holds its
// own copy, and no other host under the domain ever receives one. An admin's
// domain can be a bare apex whose www, blog or CNAMEd SaaS hosts belong to
// somebody else, so a cookie scoped to the domain would hand them a 12-hour
// key to every share the visitor unlocked.
//
// A password is always checked on the APP origin (/unlock, or ?pw= on a page),
// and the file origin cannot read a cookie set there. So an app-origin unlock
// sends the browser through GET /access/{id} on files.<domain> with a hop
// token: a short-lived HMAC over the share id and its password generation,
// signed under its own scope (accessHopScope). That route sets the file
// origin's own host-only cookie and forwards to where the visitor was going.
//
// The hop is browser-only (no client calls it), resolves its share through
// visibleShareVia, so an inbox answers 404 there, and forwards only to one of
// the share's own public routes (unlockNext) on this server's two origins.

// accessHopTTL is how long a hop token verifies: the one redirect it rides.
const accessHopTTL = time.Minute

// accessHopPrefix is the route's path prefix, which isAccessPath pins to the
// file origin.
const accessHopPrefix = "/access/"

// unlockedRedirect answers a correct password with a 303 to next. On the app
// origin of a split server, for a share whose files the file origin serves,
// the 303 goes through that origin's access hop first, so the visitor holds
// a cookie on both. An inbox's page and upload live on the app origin alone,
// so it takes no hop; neither does a server with one origin.
func (h *handler) unlockedRedirect(w http.ResponseWriter, r *http.Request, v shareView, next string) {
	o := h.origins()
	if !o.Split() || v.Inbox || hostOnly(r.Host) != o.App {
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	q := url.Values{
		"token": {h.signAccessHop(v.ID, v.PasswordGen, time.Now().Add(accessHopTTL))},
		"next":  {next},
	}
	http.Redirect(w, r, "https://"+o.File+accessHopPrefix+url.PathEscape(v.ID)+"?"+q.Encode(), http.StatusSeeOther)
}

// accessHop is GET /access/{id} on the file origin. A token that verifies for
// this share sets the access cookie here; any other token sets nothing. Either
// way the answer is a 303 onward, so a stale or refused hop lands on the
// password form of the address the visitor asked for.
func (h *handler) accessHop(w http.ResponseWriter, r *http.Request) {
	v, ok := h.visibleShareVia(r, h.viewMeta)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if v.Linked() {
		// Only a composed linked share says whether its source can be
		// read; a revoked one answers the unavailable page every other
		// route of it answers.
		full, err := h.lookupFor(v)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if full.v.SourceMissing {
			h.renderUnavailable(w, r, full.v)
			return
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	q := r.URL.Query()
	if v.PasswordHash != "" && h.accessHopValid(q.Get("token"), v.ID, v.PasswordGen) {
		h.setAccessCookie(w, r, v.ID, v.PasswordGen)
	}
	next := unlockNext(q.Get("next"), v.ID, "/share/"+v.ID)
	http.Redirect(w, r, h.onward(r, next), http.StatusSeeOther)
}

// onward is next on the origin that serves it: relative when that is the
// origin the request arrived on, absolute on the configured app origin
// otherwise. next is already one of the share's own public routes.
func (h *handler) onward(r *http.Request, next string) string {
	path, _, _ := strings.Cut(next, "?")
	if want, misrouted := h.origins().Misrouted(path, r.Host); misrouted {
		return "https://" + want + next
	}
	return next
}

// clearPixel is a 1x1 transparent GIF, so the web client's <img> that asks
// for the clear loads without an error event.
var clearPixel, _ = base64.StdEncoding.DecodeString("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")

// The access clear is the half of a web sign-out the app origin cannot do:
// the access cookie is host-only, so the file origin's copies never reach
// DELETE /api/web/session. On a split server that sign-out answers
// accessClearURL, the clear's address with a token in it, and sets the
// hd_clear cookie holding the token's nonce; the web client loads the
// address as a picture and the file origin clears its access cookies.
//
// The clear clears only for that PAIR. The token is an HMAC under its own
// scope (accessClearScope) over the nonce and a one-minute expiry, and the
// nonce is 16 random bytes minted per sign-out that only the signing-out
// browser holds, in a cookie scoped to the clear's path. A request without
// the pair gets the same picture and no Set-Cookie at all.
//
// A cross-site page cannot trigger the clear: it can get a token (any
// caller can sign out and be answered one) but cannot put the nonce cookie
// in the visitor's browser. A host under the same registrable domain that
// can set cookies there can: another *.hyperdrop.link server, since that
// zone is not a public suffix, can mint a pair through this server's
// sign-out, set hd_clear with Domain=hyperdrop.link, and load the clear. The
// cost is only that the visitor enters the share's password again; the
// clear opens nothing. The clear is handed out for every sign-out, ended
// session or not, because an idle sign-out on a public computer often
// finds its session already gone and must still clear the file origin.

// accessClearScope prefixes the message a clear token is signed over, so it
// never verifies as an access cookie, a site grant or a hop token, and none
// of those verifies as a clear token.
const accessClearScope = "access-clear|"

// accessClearCookie carries a sign-out's nonce to the file origin's clear.
// Its name is not in the access cookie's shape, so no clear of hd_<id>
// touches it.
const accessClearCookie = "hd_clear"

// accessClearTTL is how long a clear token verifies and its cookie lives:
// the one picture request that follows the sign-out.
const accessClearTTL = time.Minute

// accessClearPath is the clear's route, and its cookie's Path.
const accessClearPath = accessHopPrefix + "clear"

// signAccessClear returns a clear token for nonce: "<expUnix>.<hexMAC>".
func (h *handler) signAccessClear(nonce string, exp time.Time) string {
	return h.signScoped(accessClearScope, nonce, 0, exp)
}

// accessClearURL is the address a web sign-out hands the browser to clear
// the file origin's access cookies, and sets the hd_clear cookie its token
// is bound to: Domain=<the configured domain>, so files.<domain> receives
// it, Path=/access/clear, one minute, HttpOnly, SameSite=Lax, Secure. It is
// "" without a split, where the sign-out's own answer clears every access
// cookie, and when the random source fails, which costs the clear and not
// the sign-out. It follows the server's own split (h.origins()), not the
// domain /api/health advertises, which a free name still being registered
// leaves empty while the hop already sets cookies on its file origin.
func (h *handler) accessClearURL(w http.ResponseWriter, r *http.Request) string {
	o := h.origins()
	if !o.Split() {
		return ""
	}
	nonce := h.setGroupingCookie(w, r, accessClearCookie, accessClearPath, o.App, accessClearTTL)
	if nonce == "" {
		return ""
	}
	token := h.signAccessClear(nonce, time.Now().Add(accessClearTTL))
	return "https://" + o.File + accessClearPath + "?" + url.Values{"t": {token}}.Encode()
}

// accessClearPaired reports whether the request carries a sign-out's pair:
// a token in t that verifies for the nonce in one of its hd_clear cookies.
// Every cookie of the name is tried, for the reason validAccess gives.
func (h *handler) accessClearPaired(r *http.Request) bool {
	token := r.URL.Query().Get("t")
	if token == "" {
		return false
	}
	for _, c := range r.CookiesNamed(accessClearCookie) {
		if validVisitor(c.Value) && h.scopedValueValid(accessClearScope, token, c.Value, 0) {
			return true
		}
	}
	return false
}

// accessClear is GET /access/clear on the file origin. With a sign-out's
// pair it clears every hd_<id> the request carries here (clearAccessCookies)
// and the hd_clear cookie itself; without one it clears nothing. Either way
// it answers the same 1x1 GIF, reads no body and sets nothing else.
func (h *handler) accessClear(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if h.accessClearPaired(r) {
		h.clearAccessCookies(w, r)
		http.SetCookie(w, &http.Cookie{
			Name: accessClearCookie, Path: accessClearPath, Domain: h.origins().App,
			MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: h.cookieSecure(r),
		})
	}
	w.Header().Set("Content-Type", "image/gif")
	w.Header().Set("Content-Length", strconv.Itoa(len(clearPixel)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(clearPixel)
}

// isAccessPath reports whether a path is the access hop or its clear, which
// belong on the file origin: the cookies they set and clear are that
// origin's own.
func isAccessPath(path string) bool {
	return strings.HasPrefix(path, accessHopPrefix)
}
