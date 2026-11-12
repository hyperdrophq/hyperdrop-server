package api

import (
	"fmt"
	"net/http"

	"hyperdrop/core/compatwindow"
)

// versionHelp is the page a refusal links, the one the clients' own refusals
// link.
const versionHelp = "https://gethyperdrop.com/docs/updates/#version-mismatch"

// windowExempt are the routes a client outside the window still reaches:
// the ones that repair the mismatch. Updating the server needs the update
// route and, before it, a confirmed second factor (enrolment), and the app
// reads the account's role from /api/me to word the mismatch for an admin
// or a user. The clients leave the same commands outside their own gate.
var windowExempt = map[string]bool{
	"POST /api/server/update":   true,
	"GET /api/me":               true,
	"GET /api/me/totp":          true,
	"POST /api/me/totp":         true,
	"POST /api/me/totp/confirm": true,
}

// A client checks compatibility before it sends a credential; this check stops
// what that cannot: a long-running client (sync, an MCP session) that a server
// update left outside the window.
//
// refuseClientOutsideWindow answers 409 and reports true when the client
// version a request names (X-HyperDrop-Client) is outside this server's
// window (core/compatwindow.Compatible, the rule the clients apply to a
// server): client-outdated for a client too old for this server,
// server-outdated for one too new. A request that names no client, or one
// that does not parse, is let through: there is nothing to judge, and so is a
// windowExempt route.
func (h *handler) refuseClientOutsideWindow(w http.ResponseWriter, r *http.Request, client string) bool {
	if windowExempt[r.Pattern] {
		return false
	}
	switch compatwindow.Compatible(client, h.version) {
	case compatwindow.ClientOutdated:
		writeErrorCode(w, http.StatusConflict, "client-outdated", fmt.Sprintf(
			"this server runs v%s, which HyperDrop v%s does not work with: update HyperDrop (app/CLI): %s", h.version, client, versionHelp))
	case compatwindow.ServerOutdated:
		writeErrorCode(w, http.StatusConflict, "server-outdated", fmt.Sprintf(
			"this server runs v%s, older than HyperDrop v%s works with: an admin updates it. Help: %s", h.version, client, versionHelp))
	default:
		return false
	}
	return true
}
