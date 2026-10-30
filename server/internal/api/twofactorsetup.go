package api

import (
	"log"
	"net/http"
	"strings"

	"hyperdrop/server/internal/ddns"
	"hyperdrop/server/internal/metadb"
)

// An account that owes a second factor (twoFactorRestricted) reaches only
// the routes in twoFactorSetupRoutes: signing in still mints, and the
// account may enrol, look after its own sign-ins, devices and this device's
// push registration, draw the apps' screens and gate, and, during first
// setup, claim the server's first free name. h.auth
// refuses every other authenticated route with 403
// two-factor-setup-required, after the caller resolves and before the
// route runs, so the rule covers every gate built on it (h.read, h.admin,
// h.adminRead, h.webAuth). twofactorsetup_test.go walks api.go and drives
// every authenticated route missing from the map as such an account, so a
// new route is refused until it is listed here.

// setupRule decides whether a restricted account may make request r on a
// listed route.
type setupRule func(h *handler, r *http.Request) bool

// always admits every request on its route.
func always(*handler, *http.Request) bool { return true }

// twoFactorSetupRoutes is keyed by the matched mux pattern
// ("METHOD /pattern", r.Pattern), like cookieRoutes, so a HEAD on a GET
// route reads the GET route's entry. The unauthenticated routes (sign-in,
// the web sign-out, /api/health) never reach the check and are not listed.
var twoFactorSetupRoutes = map[string]setupRule{
	"GET /api/me":                   always,
	"GET /api/me/totp":              always,
	"POST /api/me/totp":             always,
	"POST /api/me/totp/confirm":     always,
	"POST /api/me/totp/recovery":    always,
	"DELETE /api/auth/token":        always,
	"PATCH /api/me/password":        always,
	"GET /api/me/tokens":            always,
	"DELETE /api/me/tokens/{id}":    always,
	"GET /api/me/push":              always,
	"PUT /api/me/push":              always,
	"DELETE /api/me/push":           always,
	"PUT /api/me/activity":          always,
	"GET /api/web/session":          always,
	"POST /api/web/session/elevate": always,
	"GET /api/usage":                always,
	"GET /api/server/settings":      always,
	"GET /api/local-addresses":      always,
	"GET /api/ddns":                 always,
	"GET /api/ddns/available":       always,
	"PUT /api/ddns":                 choosesAFreeName,
	"DELETE /api/ddns":              cancelsAPendingName,
}

// choosesAFreeName admits a restricted account's free-name choice while
// the server holds a confirmed free name, which putDDNS answers through
// heldNameConfirmation (the held name's retry is a confirmation that
// changes nothing, any other request is refused), and otherwise only during
// first setup (firstFreeNameSetup).
func choosesAFreeName(h *handler, _ *http.Request) bool {
	if h.ddns == nil {
		return false
	}
	if st := h.ddns.Store().Snapshot(); st.Name != "" && !st.Pending {
		return true
	}
	return h.firstFreeNameSetup()
}

// firstFreeNameSetup reports whether the server is in first setup, where an
// admin owing a second factor may choose the server's first free name, its
// retry after the owner approves it, and that retry once the background
// updater has confirmed the claim, with the password alone. First setup is
// a server on which no admin able to sign in has a confirmed second factor
// (metadb.ActiveAdminHasSecondFactor) and which serves no domain but, at
// most, a free name (HYPERDROP_DDNS_NAME adopts the name its install asked
// for at boot whether or not the claim went through). Once an admin has a
// second factor, choosing a free name needs an account with one, also when
// the served free name was released and the store holds none; so does
// moving a server that serves a domain of its own onto a free name. A store
// that cannot be read ends nothing open: it answers false.
func (h *handler) firstFreeNameSetup() bool {
	if h.ddns == nil {
		return false
	}
	d := h.dom.Current()
	if d != "" && !strings.HasSuffix(d, "."+ddns.Zone) {
		return false
	}
	enrolled, err := h.db.ActiveAdminHasSecondFactor()
	if err != nil {
		log.Printf("two-factor: reading whether an admin has a second factor: %v; the first free-name choice stays closed until it can be read", err)
		return false
	}
	return !enrolled
}

// heldNameConfirmation answers a restricted account's PUT /api/ddns outside
// first setup, and while the server holds a confirmed free name, and
// reports whether it did. With a confirmed name held, the held name itself
// without replace is answered 200 with the name's state, as GET /api/ddns
// would answer it, and changes nothing; any other request is refused
// two-factor-setup-required, as is every request outside first setup while
// no confirmed name is held. During first setup with no confirmed name held
// (none, or a claim still pending), and for an unrestricted account,
// nothing is answered here.
func (h *handler) heldNameConfirmation(w http.ResponseWriter, r *http.Request, name string, replace bool) bool {
	if !h.twoFactorRestricted(reqUser(r), h.callerToken(r)) {
		return false
	}
	st := h.ddns.Store().Snapshot()
	if st.Name == "" || st.Pending {
		if h.firstFreeNameSetup() {
			return false
		}
		writeTwoFactorSetupRequired(w)
		return true
	}
	if name != st.Name || replace {
		writeTwoFactorSetupRequired(w)
		return true
	}
	writeJSON(w, http.StatusOK, h.ddnsOut())
	return true
}

// cancelsAPendingName admits the cancel of a pending free name, which
// serves nothing, during first setup, where the person changing the name
// cancels the one they chose first; outside first setup a pending name
// belongs to an account with a second factor, and cancelling it, like
// releasing a held name, needs one.
func cancelsAPendingName(h *handler, r *http.Request) bool {
	return r.URL.Query().Get("pendingName") != "" && h.firstFreeNameSetup()
}

// twoFactorRestricted reports whether u, calling with tok, owes a second
// factor before it may use the server: an account with no confirmed one
// that is an admin, or whose tok was signed in at or after the second
// "require two-factor for every account" was turned on
// (requireTwoFactorSince). tok.CreatedAt is the sign-in time, which a
// password change's replacement token keeps, so a device signed in before
// the switch stays unrestricted. A zero tok (no row of the account's) has
// no sign-in time and counts as signed in after the switch.
func (h *handler) twoFactorRestricted(u metadb.User, tok metadb.Token) bool {
	if u.TwoFactorEnabled() {
		return false
	}
	if u.Role == metadb.RoleAdmin {
		return true
	}
	since, on := h.requireTwoFactorSince()
	return on && (tok.ID == "" || !tok.CreatedAt.Before(since))
}

// twoFactorSetupAllows reports whether a restricted account may make r.
func (h *handler) twoFactorSetupAllows(r *http.Request) bool {
	rule, ok := twoFactorSetupRoutes[r.Pattern]
	return ok && rule(h, r)
}

// writeTwoFactorSetupRequired answers a restricted account's request on a
// route outside the setup routes.
func writeTwoFactorSetupRequired(w http.ResponseWriter) {
	writeErrorCode(w, http.StatusForbidden, "two-factor-setup-required", "Set up two-factor for this account first.")
}
