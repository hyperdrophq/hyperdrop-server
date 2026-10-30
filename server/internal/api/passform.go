package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"hyperdrop/server/internal/shareid"
)

// A visitor who enters a share's password holds one of two kinds of access
// cookie: an unticked one lives accessTTL, and one the visitor asked to keep
// ("This is my computer") lives accessKeepTTL, the longest a browser keeps a
// cookie. The kind is not stored anywhere: each is signed under its own scope
// (accessScope), so a cookie verifies as the kind it was issued as and no
// other. Every visit the cookie admits re-issues it with a fresh expiry of its
// own kind, at most once per accessRenewEvery (renewDue).
const (
	accessTTL     = 24 * time.Hour
	accessKeepTTL = 400 * 24 * time.Hour
	// accessRenewEvery is how much of a cookie's lifetime a visit lets pass
	// before it re-issues the cookie, so most answers carry no Set-Cookie.
	accessRenewEvery = time.Hour
)

// accessLifetime is how long a cookie of the kind lives from its issue.
func accessLifetime(keep bool) time.Duration {
	if keep {
		return accessKeepTTL
	}
	return accessTTL
}

// accessProof is what a verified access cookie says: its kind and expiry.
type accessProof struct {
	keep bool
	exp  time.Time
}

// renewDue reports whether a visit at now re-issues the cookie: once more
// than accessRenewEvery of its lifetime has passed.
func (p accessProof) renewDue(now time.Time) bool {
	return p.exp.Sub(now) < accessLifetime(p.keep)-accessRenewEvery
}

func (h *handler) cookieName(id string) string { return "hd_" + id }

// accessKeepScope prefixes the message a kept hd_<id> cookie is signed over.
// An unticked cookie is signed with no prefix, so its message starts with the
// share id, which is base58 and never contains "-" or "|": neither kind's
// message coincides with the other's or with any other scope's.
const accessKeepScope = "access-keep|"

// accessScope is the scope an hd_<id> cookie of the kind is signed under.
func accessScope(keep bool) string {
	if keep {
		return accessKeepScope
	}
	return ""
}

// signAccess returns "<expUnix>.<hexMAC>" binding the share id to an expiry,
// the cookie's kind and the share's password generation: changing or removing
// the password bumps the generation, so cookies of both kinds issued under the
// old password stop verifying. It is the hd_<id> cookie's value and nothing
// else's: a site grant is signed over its own message (signGrant).
func (h *handler) signAccess(id string, gen int, exp time.Time, keep bool) string {
	return h.signScoped(accessScope(keep), id, gen, exp)
}

// grantScope prefixes the message a /site grant (site.go) is signed over.
// The cookie's message starts with a share id, which never contains "|", so
// the two messages never coincide: a grant does not verify as an access
// cookie, and a cookie value does not verify as a grant.
const grantScope = "site-grant|"

// signGrant returns a /site grant: the cookie's shape, share id, password
// generation and expiry, signed over the grant's own message.
func (h *handler) signGrant(id string, gen int, exp time.Time) string {
	return h.signScoped(grantScope, id, gen, exp)
}

// accessHopScope and accessHopKeepScope prefix the message an access hop
// token (accesshop.go) is signed over, one per cookie kind, so the file
// origin's copy is of the kind the app origin's unlock was. Neither verifies
// as an access cookie or a site grant, and neither of those verifies as a
// hop token.
const (
	accessHopScope     = "access-hop|"
	accessHopKeepScope = "access-hop-keep|"
)

// signAccessHop returns an access hop token: the cookie's shape, share id,
// password generation and expiry, signed over the hop's own message for the
// kind of cookie the hop sets.
func (h *handler) signAccessHop(id string, gen int, exp time.Time, keep bool) string {
	scope := accessHopScope
	if keep {
		scope = accessHopKeepScope
	}
	return h.signScoped(scope, id, gen, exp)
}

// accessHopValid reports whether value is a hop token this server issued for
// this share at this password generation, and is unexpired, and the kind of
// cookie it sets.
func (h *handler) accessHopValid(value, id string, gen int) (keep, ok bool) {
	p, ok := h.kindValue(accessHopScope, accessHopKeepScope, value, id, gen)
	return p.keep, ok
}

// signScoped signs scope+"id|exp|gen" and returns "<expUnix>.<hexMAC>".
// "|" is a safe delimiter here because share IDs and file keys are base58
// (crypto/rand) and never contain it.
func (h *handler) signScoped(scope, id string, gen int, exp time.Time) string {
	msg := scope + id + "|" + strconv.FormatInt(exp.Unix(), 10) + "|" + strconv.Itoa(gen)
	mac := hmac.New(sha256.New, h.fs.Secret())
	mac.Write([]byte(msg))
	return strconv.FormatInt(exp.Unix(), 10) + "." + hex.EncodeToString(mac.Sum(nil))
}

// validAccess reports whether the request carries a valid, unexpired access
// cookie of either kind for the share at its current password generation.
// It renews nothing: a route that admits the visitor on it calls
// admitAccess instead.
func (h *handler) validAccess(r *http.Request, id string, gen int) bool {
	_, ok := h.accessProofOf(r, id, gen)
	return ok
}

// accessProofOf answers the first access cookie of the request that verifies
// for the share at its current password generation.
func (h *handler) accessProofOf(r *http.Request, id string, gen int) (accessProof, bool) {
	if !h.cookieHonoured(r) {
		return accessProof{}, false
	}
	// EVERY cookie of this name is tried, not the first. A share's own name
	// sits beside other people's servers under one parent, and a browser
	// sends a cookie set with Domain=<parent> to all of them, so a request
	// can carry a same-named cookie this server never issued. Such a cookie
	// grants nothing, being signed with a secret only this volume holds, but
	// reading only the first match would let it hide the real one and put a
	// visitor back at the password form.
	for _, c := range r.CookiesNamed(h.cookieName(id)) {
		if keep, exp, ok := h.accessValue(c.Value, id, gen); ok {
			return accessProof{keep: keep, exp: exp}, true
		}
	}
	return accessProof{}, false
}

// admitAccess is validAccess for a request the cookie admits. The answer is
// made private (admitted), and when the cookie is due it is re-issued on the
// origin answering, of the same kind with a fresh expiry.
func (h *handler) admitAccess(w http.ResponseWriter, r *http.Request, id string, gen int) bool {
	_, ok := h.admitAccessProof(w, r, id, gen)
	return ok
}

// admitAccessProof is admitAccess answering the proof that admitted the
// request, for a caller that needs its kind.
func (h *handler) admitAccessProof(w http.ResponseWriter, r *http.Request, id string, gen int) (accessProof, bool) {
	p, ok := h.accessProofOf(r, id, gen)
	if ok && h.admitted(w, r, h.cookieName(id), p) {
		h.setAccessCookie(w, r, id, gen, p.keep)
	}
	return p, ok
}

// admitted is what every admission by a cookie does to the answer, and
// reports whether the cookie is to be re-issued on it.
//
// The answer is marked private unless a Cache-Control is already set, so a
// renewal never rides an answer a shared cache keeps, whatever the route
// goes on to answer (a redirect, a 404).
//
// The cookie is re-issued when it is due (renewDue), the request may renew
// it (renewingRequest), and the answer carries no Set-Cookie of that name yet:
// a request that passes two gates (a /site page under a live grant passes
// siteGate and serveFile) renews once.
func (h *handler) admitted(w http.ResponseWriter, r *http.Request, name string, p accessProof) bool {
	if w.Header().Get("Cache-Control") == "" {
		w.Header().Set("Cache-Control", "private")
	}
	return p.renewDue(time.Now()) && h.renewingRequest(r) && !setsCookie(w, name)
}

// renewingRequest reports whether the request may keep an unlock alive. An
// embed from another site never does: a cross-site one (which applyNoEmbed
// refuses for an owner with the no-embed setting), and a same-site one that
// is not this server's own page (another server under the same registrable
// domain). Navigations, this server's own pages' loads and clients that send
// no Fetch Metadata do.
func (h *handler) renewingRequest(r *http.Request) bool {
	if !embedDests[r.Header.Get("Sec-Fetch-Dest")] {
		return true
	}
	switch r.Header.Get("Sec-Fetch-Site") {
	case "cross-site":
		return false
	case "same-site":
		return h.embeddedByOwnPage(r)
	}
	return true
}

// setsCookie reports whether the answer already carries a Set-Cookie for name.
func setsCookie(w http.ResponseWriter, name string) bool {
	for _, line := range w.Header().Values("Set-Cookie") {
		if strings.HasPrefix(line, name+"=") {
			return true
		}
	}
	return false
}

// accessValue reports whether one cookie value is a signature this server
// issued for this share at this password generation, unexpired, and answers
// its kind and expiry.
func (h *handler) accessValue(value, id string, gen int) (keep bool, exp time.Time, ok bool) {
	p, ok := h.kindValue("", accessKeepScope, value, id, gen)
	return p.keep, p.exp, ok
}

// grantValid reports whether a /site grant segment is a grant this server
// issued for this share at this password generation, and is unexpired.
func (h *handler) grantValid(value, id string, gen int) bool {
	return h.scopedValueValid(grantScope, value, id, gen)
}

// kindValue verifies value under the unticked scope, then the kept one, and
// answers the kind it verified as and its expiry.
func (h *handler) kindValue(unticked, kept, value, id string, gen int) (accessProof, bool) {
	if exp, ok := h.scopedValueExp(unticked, value, id, gen); ok {
		return accessProof{exp: exp}, true
	}
	if exp, ok := h.scopedValueExp(kept, value, id, gen); ok {
		return accessProof{keep: true, exp: exp}, true
	}
	return accessProof{}, false
}

func (h *handler) scopedValueValid(scope, value, id string, gen int) bool {
	_, ok := h.scopedValueExp(scope, value, id, gen)
	return ok
}

// scopedValueExp reports whether value is unexpired and signed under scope
// for id and gen, and answers its expiry.
func (h *handler) scopedValueExp(scope, value, id string, gen int) (time.Time, bool) {
	dot := strings.IndexByte(value, '.')
	if dot < 0 {
		return time.Time{}, false
	}
	expUnix, err := strconv.ParseInt(value[:dot], 10, 64)
	if err != nil || time.Now().Unix() > expUnix {
		return time.Time{}, false
	}
	exp := time.Unix(expUnix, 0)
	want := h.signScoped(scope, id, gen, exp)
	if !hmac.Equal([]byte(value), []byte(want)) {
		return time.Time{}, false
	}
	return exp, true
}

// openDests are the Sec-Fetch-Dest values a browser sends when a PERSON is
// opening the file: a plugin or a media element re-requesting what the tab
// already navigated to. They are honoured on the file origin; the ones left
// out (iframe, frame, fencedframe, script, style, font, the worker family,
// manifest, xslt) only ever come from a page pulling the response INTO itself
// somewhere it can read it.
var openDests = map[string]bool{
	"image": true, "video": true, "audio": true, "track": true,
	"embed": true, "object": true,
}

// cookieHonoured reports whether an access cookie may be honoured for this
// request's shape. Uploaded bytes all share one origin, so script in an
// uploaded .html is same-origin with every other share's payload, and the
// viewer's cookie rides along on anything that page fetches. The sandbox in
// serve.go takes that origin away; this is the second lock on the same door.
//
// The headers are a hint, not an authorisation: a client sending none (curl,
// the app itself, an old browser) is not the attacker's script in a browser.
func (h *handler) cookieHonoured(r *http.Request) bool {
	dest := r.Header.Get("Sec-Fetch-Dest")
	if dest == "" || dest == "document" {
		return true
	}
	// The app origin serves our own pages and nothing else (no upload ever
	// lands there), so script asking from it IS ours: the listing and waiting
	// pages poll /share/{id}/status with fetch(). Without the split (a development server with no domain) an
	// uploaded page WOULD be same-origin with these, so the rule stays tight.
	if o := h.origins(); o.Split() && hostOnly(r.Host) == o.App {
		return true
	}
	if dest == "empty" {
		// "Save Link As…" and any <a download> is a navigation that carries an
		// empty destination (measured in Chrome 141: dest=empty,
		// mode=navigate). A fetch()/XHR is never mode=navigate, so the pair
		// separates a download from a script read; `empty` alone refuses
		// both.
		if r.Header.Get("Sec-Fetch-Mode") == "navigate" {
			return true
		}
		// The scripted fetches the FILE origin honours: its own waiting
		// page polling /share/{id}/status, or /f/{fileKey}/status for a file
		// link. That page is OURS (a pending payload link renders it right
		// there), the response is progress metadata, never payload bytes,
		// and an uploaded page cannot forge the shape: the sandbox (serve.go)
		// puts it in an opaque origin, whose fetches arrive Sec-Fetch-Site:
		// cross-site, not same-origin.
		return (isStatusPath(r.URL.Path) || isFileLinkStatusPath(r.URL.Path)) &&
			r.Header.Get("Sec-Fetch-Site") == "same-origin"
	}
	if openDests[dest] {
		return true
	}
	// Everything else asks to pull the response INTO a page. A protected
	// site's own stylesheets and scripts are NOT an exception here: a
	// sandboxed page is an opaque origin, so its subresource requests carry
	// no cookie to honour in the first place (and no Referer to tell them
	// apart by). They prove access with the grant in their address instead,
	// which siteGate checks (site.go).
	return false
}

// setAccessCookie sets hd_<id> of the kind, living that kind's lifetime.
func (h *handler) setAccessCookie(w http.ResponseWriter, r *http.Request, id string, gen int, keep bool) {
	exp := time.Now().Add(accessLifetime(keep))
	c := h.accessCookie(r, id, h.signAccess(id, gen, exp, keep))
	c.Expires = exp
	http.SetCookie(w, c)
}

// fileLinkScope and fileLinkKeepScope prefix the message a file link's
// cookie (hdf_<fileKey>) is signed over, unticked and kept, so it never
// verifies as an access cookie, a site grant or a hop token, none of those
// verifies as it, and neither kind verifies as the other.
const (
	fileLinkScope     = "file-link|"
	fileLinkKeepScope = "file-link-keep|"
)

// fileCookieName is a file link's own cookie. It is named after the link's
// key, never the share: the share's hd_<id> opens no file link, and a file
// link never sets it.
func fileCookieName(key string) string { return "hdf_" + key }

// signFileAccess returns a file link's cookie value, "<expUnix>.<hexMAC>" over
// "file-link|<fileKey>|<exp>|<passwordGen>" (the kept kind under
// fileLinkKeepScope). The share's password generation binds it, so changing
// or removing the share's password signs every file-link visitor out too.
func (h *handler) signFileAccess(key string, gen int, exp time.Time, keep bool) string {
	scope := fileLinkScope
	if keep {
		scope = fileLinkKeepScope
	}
	return h.signScoped(scope, key, gen, exp)
}

// validFileAccess reports whether the request carries an unexpired cookie of
// either kind for this file link at the share's current password generation.
// Every cookie of the name is tried, for the reason validAccess tries every
// hd_<id>. It renews nothing; admitFileAccess does.
func (h *handler) validFileAccess(r *http.Request, key string, gen int) bool {
	_, ok := h.fileAccessProofOf(r, key, gen)
	return ok
}

// fileAccessProofOf answers the first hdf_<fileKey> cookie of the request
// that verifies for the link at the share's current password generation.
func (h *handler) fileAccessProofOf(r *http.Request, key string, gen int) (accessProof, bool) {
	if !h.cookieHonoured(r) {
		return accessProof{}, false
	}
	for _, c := range r.CookiesNamed(fileCookieName(key)) {
		if p, ok := h.kindValue(fileLinkScope, fileLinkKeepScope, c.Value, key, gen); ok {
			return p, true
		}
	}
	return accessProof{}, false
}

// admitFileAccess is validFileAccess for a request the cookie admits, under
// admitAccess's rules (admitted): the answer is private, and a due cookie is
// re-issued, of the same kind with a fresh expiry.
func (h *handler) admitFileAccess(w http.ResponseWriter, r *http.Request, key string, gen int) bool {
	p, ok := h.fileAccessProofOf(r, key, gen)
	if ok && h.admitted(w, r, fileCookieName(key), p) {
		h.setFileAccessCookie(w, r, key, gen, p.keep)
	}
	return ok
}

// setFileAccessCookie sets hdf_<fileKey> of the kind: host-only on the origin
// that answered (the file origin), and scoped to the link's own path, so it
// reaches /f/<fileKey> and its sub-routes and nothing else.
func (h *handler) setFileAccessCookie(w http.ResponseWriter, r *http.Request, key string, gen int, keep bool) {
	exp := time.Now().Add(accessLifetime(keep))
	http.SetCookie(w, &http.Cookie{
		Name: fileCookieName(key), Value: h.signFileAccess(key, gen, exp, keep),
		Path: "/f/" + key, Expires: exp, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: h.cookieSecure(r),
	})
}

// keepRequested reports whether a password form's POST body ticked "This is
// my computer". Only the body is read: a query string never asks to keep.
func keepRequested(r *http.Request) bool {
	return r.PostFormValue("keep") == "1"
}

// accessCookie is the hd_<id> cookie with the attributes every Set-Cookie
// of it carries, its setting and its clearing alike: a browser clears a
// cookie only when the clear names the same name, domain and path.
//
// It names no Domain, so it is host-only on the origin that answered: no
// other host under the server's domain ever receives it. The file origin
// gets its own copy through the access hop (accesshop.go).
func (h *handler) accessCookie(r *http.Request, id, value string) *http.Cookie {
	return &http.Cookie{
		Name: h.cookieName(id), Value: value,
		Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: h.cookieSecure(r),
	}
}

// maxAccessClears bounds the clearing lines one answer carries; a browser
// holds fewer cookies than this for one domain.
const maxAccessClears = 256

// clearAccessCookies answers a clearing Set-Cookie for every share access
// cookie (hd_<share id>) the request carries. The cookie is host-only, so
// this clears the copies of the origin answering: the web sign-out runs it
// on the app origin and GET /access/clear on the file origin, so a browser
// signed out of the web client keeps no protected share unlocked on
// either. Only names in the
// access cookie's shape are cleared: hd_visitor and an inbox's hdv_<id>
// grouping cookie are not keys to anything.
func (h *handler) clearAccessCookies(w http.ResponseWriter, r *http.Request) {
	seen := map[string]bool{}
	for _, c := range r.Cookies() {
		id, ok := strings.CutPrefix(c.Name, "hd_")
		if !ok || !shareid.ValidID(id) || seen[id] {
			continue
		}
		if len(seen) == maxAccessClears {
			return
		}
		seen[id] = true
		clear := h.accessCookie(r, id, "")
		clear.MaxAge = -1
		http.SetCookie(w, clear)
	}
}

// cookieSecure reports whether a cookie set on this response is marked
// Secure: when the request arrived over TLS, and whenever the origin split is
// live. A split server sends every visitor to https:// (originRouter, the
// password form's action, every copied link), so its browsers always speak
// HTTPS, even when TLS ends at a proxy in front of a plain-HTTP listener and
// r.TLS is nil here. Without Secure, one plaintext request to the domain
// would hand a network attacker the hd_<id> cookie, a key to a protected
// share that lives up to 400 days.
func (h *handler) cookieSecure(r *http.Request) bool {
	return r.TLS != nil || h.origins().Split()
}

var passwordFormTmpl = page("pw", "password.html")

// passwordFormAction is where the password form POSTs.
//
// It must be ABSOLUTE whenever this form is rendered on the FILE origin,
// which is the common case: a single-file share's links are /view and
// /download, both served from files.<domain>, and the gate renders the form in
// place there. A relative action would resolve against that origin, where
// /unlock is pinned away and anything that is not a GET is misrouted to 404,
// so even the correct password would answer 404. The POST must reach the app
// origin, which answers 303.
//
// A server with no domain has no split and no absolute host to name, so the
// relative form is both correct and the only option there.
func (h *handler) passwordFormAction(r *http.Request, id string) string {
	rel := "/unlock/" + url.PathEscape(id)
	o := h.origins()
	if o.App == "" || o.File == "" || hostOnly(r.Host) != o.File {
		return rel
	}
	return "https://" + o.App + rel
}

// renderPasswordForm is also what a link unfurler sees for a protected
// share, so it carries the deliberately blank "Password-protected" card:
// the share's name stays behind the password.
func (h *handler) renderPasswordForm(w http.ResponseWriter, r *http.Request, sh shareView, next, errMsg string, code int) {
	// The form is a page response: the browser that answers it carries the
	// cookie onto the page it unlocks.
	h.mintVisitor(w, r)
	h.renderPage(w, unframed, code, false, passwordFormTmpl, map[string]any{
		"ID": sh.ID, "Next": next, "Error": errMsg, "OG": h.protectedCard(r, sh).tags(),
		"Action": h.passwordFormAction(r, sh.ID),
	})
}

// renderFileLinkPassword is a file link's password form. It is built from the
// key, so it names neither the share nor its file. It renders on the file
// origin and posts there, to /f/{fileKey}/unlock, so its action is relative.
// It is also what a link unfurler sees for the link, so it carries
// protectedFileLinkCard's tags. f is the zero fileView when the share no
// longer holds the file.
func (h *handler) renderFileLinkPassword(w http.ResponseWriter, r *http.Request, key string, v shareView, f fileView, next, errMsg string, code int) {
	h.mintVisitor(w, r)
	h.renderPage(w, unframed, code, false, passwordFormTmpl, map[string]any{
		"Next": next, "Error": errMsg, "OG": h.protectedFileLinkCard(r, key, v, f).tags(),
		"Action": "/f/" + key + "/unlock",
	})
}

var lockedOutTmpl = page("locked", "lockedout.html")

// renderLockedOut is the 429 page of a password attempt, right or wrong,
// that the share-password limiter refuses; until is when it admits again.
// forShare words it as the share's wait (its lane is spacing the guesses of
// every address) rather than the caller's address's.
func (h *handler) renderLockedOut(w http.ResponseWriter, until, now time.Time, forShare bool) {
	wait := "12 hours"
	if left := until.Sub(now).Round(time.Hour); left > 0 {
		if hrs := int(left / time.Hour); hrs <= 1 {
			wait = "an hour"
		} else {
			wait = strconv.Itoa(hrs) + " hours"
		}
	} else {
		wait = "a minute"
	}
	paused := "Password entry from your address is paused."
	if forShare {
		paused = "Password entry for this share is paused."
	}
	h.renderPage(w, framable, http.StatusTooManyRequests, false, lockedOutTmpl,
		map[string]string{"Wait": wait, "Paused": paused})
}
