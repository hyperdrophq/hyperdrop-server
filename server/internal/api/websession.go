package api

import (
	"net/http"
	"strings"
	"time"

	"hyperdrop/server/internal/metadb"
)

// The web client's sign-in. A browser never holds a device token: it signs
// in to a web session (metadb/websessions.go) carried only in the
// webCookie cookie, host-only on the app origin. h.auth reads the cookie
// only from a request without an Authorization header that
// webCookieAccepted accepts.

// webCookie names the session cookie. The __Host- prefix makes the browser
// refuse it unless it is Secure, Path=/ and carries no Domain, so it never
// reaches files.<domain>.
const webCookie = "__Host-hd_web"

// webElevateFor is how long an elevated web session may make admin changes.
const webElevateFor = 10 * time.Minute

// webSignInLabelPrefix starts a web session's label in the device list.
const webSignInLabelPrefix = "Web browser · "

// newWebCookie is the session cookie carrying value, with the attributes
// every Set-Cookie of it carries: a browser refuses a __Host- cookie without
// Secure, Path=/ and no Domain, a clear included, so a clear that differs
// leaves the cookie in place.
func newWebCookie(value string) *http.Cookie {
	return &http.Cookie{Name: webCookie, Value: value, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode}
}

// setWebCookie sets the session cookie: a browser-session cookie for a
// public session, and one living metadb.WebKeepFor for a kept one.
func setWebCookie(w http.ResponseWriter, raw string, keep bool) {
	c := newWebCookie(raw)
	if keep {
		c.MaxAge = int(metadb.WebKeepFor / time.Second)
	}
	http.SetCookie(w, c)
}

// clearWebCookie tells the browser to drop the session cookie (Max-Age=0).
func clearWebCookie(w http.ResponseWriter) {
	c := newWebCookie("")
	c.MaxAge = -1
	http.SetCookie(w, c)
}

// webCookieAccepted reports whether a request may be judged by its web
// session cookie: it arrived on the app host (any host when there is no
// split, the development setup), it names the web client in
// X-HyperDrop-Client (a custom header, which another site cannot send
// without a CORS preflight this server never answers), its Origin, when
// present, is the app's own, and its Sec-Fetch-Site, when present, is
// same-origin. The web sign-in asks the same of its request.
func (h *handler) webCookieAccepted(r *http.Request) bool {
	if metadb.ParseClientHeader(r.Header.Get("X-HyperDrop-Client")).Platform != "web" {
		return false
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		return false
	}
	origin := r.Header.Get("Origin")
	if o := h.origins(); o.Split() {
		if hostOnly(r.Host) != o.App {
			return false
		}
		return origin == "" || origin == "https://"+o.App || origin == "https://"+strings.ToLower(r.Host)
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return origin == "" || origin == scheme+"://"+strings.ToLower(r.Host)
}

// webAuth is h.auth for a route only a web session calls: a bearer caller
// is refused 400 web-session-only.
func (h *handler) webAuth(next http.HandlerFunc) http.Handler {
	return h.auth(func(w http.ResponseWriter, r *http.Request) {
		if h.callerToken(r).Kind != metadb.TokenKindWeb {
			writeErrorCode(w, http.StatusBadRequest, "web-session-only", "this route is for the web client's session")
			return
		}
		next(w, r)
	})
}

// webSignIn signs a browser in: the login's own path (signIn), so its
// address lockout, the account name's stranger lane it shares with the app
// login (signInLaneKey), bcrypt cap and second-factor counting are the
// login's. A browser whose known-browser cookie holds for the account
// (knownBrowser) counts on the cookie's lane in place of the stranger lane.
// The answer sets the session cookie, and on a kept sign-in a fresh
// known-browser cookie (mintKnownCookie); it never carries the session's
// value or any token. The route refuses while the web client is not served
// (webServed, around it in routes).
func (h *handler) webSignIn(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	client := metadb.ParseClientHeader(r.Header.Get("X-HyperDrop-Client"))
	if h.refuseClientOutsideWindow(w, r, client.Version) {
		return
	}
	if !h.webCookieAccepted(r) {
		writeErrorCode(w, http.StatusForbidden, "web-session-refused", "sign in from the web client on this server's own address")
		return
	}
	now := time.Now()
	att, ok := h.admitLogin(w, r, now)
	if !ok {
		return
	}
	defer att.abandon()
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		// TOTP is the second factor for an account that has one, as at login.
		TOTP string `json:"totp"`
		// Keep is "this is my computer": a session that lives 30 days,
		// sliding, instead of a public one.
		Keep bool `json:"keep"`
	}
	if !decodeJSONBody(w, r, 64<<10, &req) {
		return
	}
	// A guess that blocks the codes guessed with the account's right password
	// (totpLoginKey), and not the caller's address, is answered as the
	// account's wait.
	addr := addrKey(clientIP(r))
	codes := totpLoginKey(loginTarget(req.Username))
	lockedOut := func(w http.ResponseWriter, until, now time.Time) {
		l := h.limits.login
		if !l.blocked(addr, now) && l.blocked(codes, now) {
			writeAccountLockedOut(w, until, now)
			return
		}
		writeLoginLockedOut(w, until, now)
	}
	// A browser holding a known-browser cookie that holds for this account
	// counts on its own lane; every other sign-in, a stranger's, on the
	// account name's.
	lane := signInLaneKey(req.Username)
	if id, ok := h.knownBrowser(r, req.Username, now); ok {
		lane = knownLaneKey(id)
	}
	label := webSignInLabelPrefix + uaSummary(r.UserAgent())
	u, raw, ok := h.signIn(w, r, att, req.Username, req.Password, lane, lockedOut, func(u metadb.User) (string, error) {
		return h.db.MintWebSessionIfPasswordIs(u.Username, label, u.PasswordHash, req.TOTP, req.Keep, now)
	})
	if !ok {
		return
	}
	idle, absolute := metadb.WebSessionLimits(req.Keep)
	setWebCookie(w, raw, req.Keep)
	if req.Keep {
		h.mintKnownCookie(w, u, now)
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": h.toUserOut(u), "session": map[string]any{
		"keep": req.Keep, "expiresAt": now.Add(absolute), "idleSeconds": int(idle / time.Second),
	}})
}

// webSessionInfo answers who is signed in and the calling session's limits.
func (h *handler) webSessionInfo(w http.ResponseWriter, r *http.Request) {
	tok := h.callerToken(r)
	session := map[string]any{"keep": tok.Keep, "expiresAt": tok.ExpiresAt, "idleUntil": tok.IdleUntil}
	if tok.ElevatedUntil.After(time.Now()) {
		session["elevatedUntil"] = tok.ElevatedUntil
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": h.toUserOut(reqUser(r)), "session": session})
}

// webSignOut deletes the session the cookie names and clears the cookie
// and every share access cookie the browser sent (clearAccessCookies). Those
// are the app origin's host-only copies. On a split server it answers 200
// {"accessClear": <url>} (accessClearURL), the file origin's clear the web
// client then loads for the rest, so a public computer keeps no unlocked
// share after a sign-out; on one origin it answers 204. Both answers come
// whatever the cookie names: a session already gone (signed
// out, expired, revoked by the off switch) is already signed out. It runs
// outside h.auth, with no version window, switch or account check, so a
// session can always end; the request must still meet webCookieAccepted's
// conditions (401 otherwise, as h.auth answers), so another site cannot
// sign a browser out, and a bearer caller is refused 400 web-session-only.
func (h *handler) webSignOut(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Header.Get("Authorization") != "" {
		writeErrorCode(w, http.StatusBadRequest, "web-session-only", "this route is for the web client's session")
		return
	}
	if !h.webCookieAccepted(r) {
		writeError(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}
	if c, err := r.Cookie(webCookie); err == nil {
		if err := h.db.EndWebSession(c.Value); err != nil {
			writeRefusal(w, err)
			return
		}
	}
	clearWebCookie(w)
	h.clearAccessCookies(w, r)
	if u := h.accessClearURL(w, r); u != "" {
		writeJSON(w, http.StatusOK, map[string]string{"accessClear": u})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// webElevate is the step-up of a web session: the caller's password and,
// on an account with a second factor, its code, counted on the step-up's
// lockout keys (stepUp). It lets the session make admin changes for
// webElevateFor.
func (h *handler) webElevate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CurrentPassword string `json:"currentPassword"`
		TOTP            string `json:"totp"`
	}
	if !decodeJSONBody(w, r, 64<<10, &req) {
		return
	}
	if req.CurrentPassword == "" {
		writeStepUpRequired(w)
		return
	}
	u := reqUser(r)
	if !h.stepUp(w, r, req.CurrentPassword, req.TOTP, u.TwoFactorEnabled()) {
		return
	}
	until := time.Now().Add(webElevateFor)
	if err := h.db.ElevateWebSession(u.Username, h.callerToken(r).ID, until); err != nil {
		writeRefusal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"elevatedUntil": until})
}

// uaSummary names a browser and its system from a User-Agent, as a device
// row shows it ("Chrome on Windows"); "a browser" when it names neither.
func uaSummary(ua string) string {
	has := func(s ...string) bool {
		for _, x := range s {
			if strings.Contains(ua, x) {
				return true
			}
		}
		return false
	}
	browser := ""
	switch {
	case has("Edg/", "EdgiOS/", "EdgA/"):
		browser = "Edge"
	case has("Firefox/", "FxiOS/"):
		browser = "Firefox"
	case has("Chrome/", "CriOS/"):
		browser = "Chrome"
	case has("Safari/") && has("Version/"):
		browser = "Safari"
	}
	system := ""
	switch {
	case has("iPhone"):
		system = "iPhone"
	case has("iPad"):
		system = "iPad"
	case has("Android"):
		system = "Android"
	case has("CrOS"):
		system = "ChromeOS"
	case has("Windows"):
		system = "Windows"
	case has("Macintosh", "Mac OS X"):
		system = "macOS"
	case has("Linux"):
		system = "Linux"
	}
	switch {
	case browser != "" && system != "":
		return browser + " on " + system
	case browser != "":
		return browser
	case system != "":
		return "a browser on " + system
	}
	return "a browser"
}
