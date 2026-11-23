package api

import (
	"context"
	"errors"
	"hyperdrop/server/internal/metadb"
	"net/http"
	"time"
)

// noSniff stops a browser second-guessing a Content-Type. Without it a
// file uploaded as .txt (or a mislabelled .png) can be sniffed into HTML and
// executed, which routes around every decision made from the declared type.
func noSniff(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// userKey carries the authenticated user through the request context,
// tokenKey the caller's own token row (its device token, or its web
// session), and adminRouteKey marks a request h.admin let through.
type ctxKey int

const (
	userKey ctxKey = iota
	tokenKey
	adminRouteKey
)

// reqUser returns the authenticated user an auth-wrapped handler runs as.
func reqUser(r *http.Request) metadb.User {
	u, _ := r.Context().Value(userKey).(metadb.User)
	return u
}

// auth refuses a client outside this server's version window (409, before
// the token is looked up), resolves the caller to its user (401 unknown,
// 403 inactive, a 500 when the database cannot answer, which a client must
// not read as a revoked token) and stores the user and the caller's own
// token row in the request context. A request with an Authorization header
// is judged by its bearer token alone; one without is judged by its web
// session cookie, when webCookieAccepted accepts the request, and is
// otherwise unknown. A cookie caller is refused 401 web-session-refused,
// before its session is looked up, on a request cookieClassOf does not class
// cookieJSON, and every answer to it carries Cache-Control: no-store. While
// the web client's switch is off every cookie caller is unknown. A
// request the user made moves the session's idle limit; one marked
// X-HyperDrop-Background: 1 (the change-feed watch, a poll) does not. When
// that move slides a kept session (at most once a minute), the answer sets
// the cookie again with a fresh 30-day Max-Age. A caller that owes a second
// factor (twoFactorRestricted) is refused 403 two-factor-setup-required on
// every route but the setup routes (twoFactorSetupRoutes).
func (h *handler) auth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		client := metadb.ParseClientHeader(r.Header.Get("X-HyperDrop-Client"))
		if h.refuseClientOutsideWindow(w, r, client.Version) {
			return
		}
		var u metadb.User
		var tok metadb.Token
		var err error
		cookie, cookieErr := r.Cookie(webCookie)
		switch {
		case r.Header.Get("Authorization") != "":
			raw := bearerToken(r)
			if u, err = h.db.UserByToken(raw, client); err == nil {
				tok = tokenNamed(u, metadb.TokenHash(raw))
			}
		case cookieErr == nil && h.webCookieAccepted(r):
			w.Header().Set("Cache-Control", "no-store")
			if cookieClassOf(r) != cookieJSON {
				writeErrorCode(w, http.StatusUnauthorized, "web-session-refused", "this route does not take the web client's session")
				return
			}
			if !h.webOn() {
				// Turning the switch off revokes every session, and one a
				// sign-in minted after that revoke is refused here.
				err = metadb.ErrBadCredentials
				break
			}
			u, tok, err = h.db.UserByWebSession(cookie.Value, client, time.Now(), r.Header.Get("X-HyperDrop-Background") != "1")
			if err == nil && tok.Slid {
				// A kept session's cookie slides with its row.
				setWebCookie(w, cookie.Value, true)
			}
		default:
			err = metadb.ErrBadCredentials
		}
		switch {
		case errors.Is(err, metadb.ErrBadCredentials):
			writeError(w, http.StatusUnauthorized, "invalid or missing token")
			return
		case err != nil:
			writeRefusal(w, err)
			return
		}
		if h.twoFactorRestricted(u, tok) && !h.twoFactorSetupAllows(r) {
			writeTwoFactorSetupRequired(w)
			return
		}
		ctx := context.WithValue(context.WithValue(r.Context(), userKey, u), tokenKey, tok)
		next(w, r.WithContext(ctx))
	})
}

// tokenNamed is u's token row whose hash is hash, zero when none is.
func tokenNamed(u metadb.User, hash string) metadb.Token {
	for _, tok := range u.Tokens {
		if tok.SHA256 == hash {
			return tok
		}
	}
	return metadb.Token{}
}

// admin guards an /api route for the admin role. A write (any method but
// GET and HEAD) from a web session also needs the session elevated
// (POST /api/web/session/elevate): 403 web-elevation-required otherwise,
// a code of its own so a client tells it from a route's step-up
// (step-up-required). A device token needs no elevation. The request goes
// on marked adminRouteKey, so the route's own step-up asks an elevated
// session the password alone (webElevated), unless the route names the
// caller's own account ({name}): a change to the caller's own account asks
// the code from every caller, as PATCH /api/me/password does. Account
// names compare exactly, as the users table's key does.
func (h *handler) admin(next http.HandlerFunc) http.Handler {
	return h.auth(func(w http.ResponseWriter, r *http.Request) {
		u := reqUser(r)
		if !u.IsAdmin() {
			writeError(w, http.StatusForbidden, "admin only")
			return
		}
		if tok := h.callerToken(r); r.Method != http.MethodGet && r.Method != http.MethodHead &&
			tok.Kind == metadb.TokenKindWeb && !tok.ElevatedUntil.After(time.Now()) {
			writeErrorCode(w, http.StatusForbidden, "web-elevation-required",
				"confirm your password to make admin changes from the web")
			return
		}
		if r.PathValue("name") == u.Username {
			next(w, r)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), adminRouteKey, true)))
	})
}

func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	got := r.Header.Get("Authorization")
	if len(got) > len(prefix) && got[:len(prefix)] == prefix {
		return got[len(prefix):]
	}
	return ""
}
