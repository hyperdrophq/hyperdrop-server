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

const accessTTL = 12 * time.Hour

func (h *handler) cookieName(id string) string { return "hd_" + id }

// signAccess returns "<expUnix>.<hexMAC>" binding the share id to an expiry
// and the share's password generation: changing or removing the password
// bumps the generation, so cookies issued under the old password stop
// verifying. It is the hd_<id> cookie's value and nothing else's: a site
// grant is signed over its own message (signGrant).
func (h *handler) signAccess(id string, gen int, exp time.Time) string {
	return h.signScoped("", id, gen, exp)
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

// accessHopScope prefixes the message an access hop token (accesshop.go) is
// signed over, so it never verifies as an access cookie or a site grant, and
// neither of those verifies as a hop token.
const accessHopScope = "access-hop|"

// signAccessHop returns an access hop token: the cookie's shape, share id,
// password generation and expiry, signed over the hop's own message.
func (h *handler) signAccessHop(id string, gen int, exp time.Time) string {
	return h.signScoped(accessHopScope, id, gen, exp)
}

// accessHopValid reports whether value is a hop token this server issued for
// this share at this password generation, and is unexpired.
func (h *handler) accessHopValid(value, id string, gen int) bool {
	return h.scopedValueValid(accessHopScope, value, id, gen)
}

// signScoped signs scope+"id|exp|gen" and returns "<expUnix>.<hexMAC>".
// "|" is a safe delimiter here because share IDs are 10-char base58
// (crypto/rand) and never contain it.
func (h *handler) signScoped(scope, id string, gen int, exp time.Time) string {
	msg := scope + id + "|" + strconv.FormatInt(exp.Unix(), 10) + "|" + strconv.Itoa(gen)
	mac := hmac.New(sha256.New, h.fs.Secret())
	mac.Write([]byte(msg))
	return strconv.FormatInt(exp.Unix(), 10) + "." + hex.EncodeToString(mac.Sum(nil))
}

// validAccess reports whether the request carries a valid, unexpired access
// cookie for the share at its current password generation.
func (h *handler) validAccess(r *http.Request, id string, gen int) bool {
	if !h.cookieHonoured(r) {
		return false
	}
	// EVERY cookie of this name is tried, not the first. A share's own name
	// sits beside other people's servers under one parent, and a browser
	// sends a cookie set with Domain=<parent> to all of them, so a request
	// can carry a same-named cookie this server never issued. Such a cookie
	// grants nothing, being signed with a secret only this volume holds, but
	// reading only the first match would let it hide the real one and put a
	// visitor back at the password form.
	for _, c := range r.CookiesNamed(h.cookieName(id)) {
		if h.accessValueValid(c.Value, id, gen) {
			return true
		}
	}
	return false
}

// accessValueValid reports whether one cookie value is a signature this
// server issued for this share at this password generation, and is unexpired.
func (h *handler) accessValueValid(value, id string, gen int) bool {
	return h.scopedValueValid("", value, id, gen)
}

// grantValid reports whether a /site grant segment is a grant this server
// issued for this share at this password generation, and is unexpired.
func (h *handler) grantValid(value, id string, gen int) bool {
	return h.scopedValueValid(grantScope, value, id, gen)
}

func (h *handler) scopedValueValid(scope, value, id string, gen int) bool {
	dot := strings.IndexByte(value, '.')
	if dot < 0 {
		return false
	}
	expUnix, err := strconv.ParseInt(value[:dot], 10, 64)
	if err != nil || time.Now().Unix() > expUnix {
		return false
	}
	want := h.signScoped(scope, id, gen, time.Unix(expUnix, 0))
	return hmac.Equal([]byte(value), []byte(want))
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
		// The one scripted fetch the FILE origin honours: its own waiting
		// page polling /share/{id}/status. That page is OURS (a pending payload
		// link renders it right there), the response is progress metadata,
		// never payload bytes, and an uploaded page cannot forge the shape:
		// the sandbox (serve.go) puts it in an opaque origin, whose fetches
		// arrive Sec-Fetch-Site: cross-site, not same-origin.
		return isStatusPath(r.URL.Path) &&
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

func (h *handler) setAccessCookie(w http.ResponseWriter, r *http.Request, id string, gen int) {
	exp := time.Now().Add(accessTTL)
	c := h.accessCookie(r, id, h.signAccess(id, gen, exp))
	c.Expires = exp
	http.SetCookie(w, c)
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
// would hand a network attacker the hd_<id> cookie, a 12-hour key to a
// protected share.
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
