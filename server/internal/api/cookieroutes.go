package api

// What a web session cookie may call. The cookie is the web client's
// credential on the app origin, so an /api route that answers uploaded
// bytes there would serve them first-party to whatever page holds the
// session, and a route that mints or answers a bearer token would hand a
// browser the long-lived credential it is never meant to hold. h.auth
// therefore judges a cookie caller by the route's class, read from the
// matched mux pattern, before it looks the session up: only cookieJSON
// takes the session, and the other two answer 401 web-session-refused.
//
// cookieroutes_test.go walks api.go and fails on an /api route with no
// entry and on an entry naming no route. A route with no entry reads as
// cookieNever, the zero class, so a missing entry refuses rather than
// serves.
type cookieClass int

const (
	// cookieNever: the route mints or answers a bearer token, or exists
	// for installed apps alone (device links, push, console activity, the
	// relay of a Live Share, the LAN shortcut, the binary and web bundle
	// uploads).
	cookieNever cookieClass = iota
	// cookieBytes: the route answers file bytes or other non-JSON content
	// on the app origin.
	cookieBytes
	// cookieJSON: the route answers JSON the web client may call.
	cookieJSON
)

// cookieRoutes classifies every /api route api.go registers, keyed by its
// mux pattern. The unauthenticated routes never read the cookie; they are
// classified so the walk is complete.
var cookieRoutes = map[string]cookieClass{
	"GET /api/health":                  cookieJSON,
	"POST /api/auth/login":             cookieNever,
	"POST /api/auth/invite":            cookieNever,
	"POST /api/auth/device-link/claim": cookieNever,
	"POST /api/auth/device-link/poll":  cookieNever,
	"DELETE /api/auth/token":           cookieNever,

	"POST /api/web/session":         cookieJSON,
	"GET /api/web/session":          cookieJSON,
	"DELETE /api/web/session":       cookieJSON,
	"POST /api/web/session/elevate": cookieJSON,

	"POST /api/web/phone-sign-in":            cookieJSON,
	"POST /api/web/phone-sign-in/poll":       cookieJSON,
	"POST /api/me/web-sign-ins/claim":        cookieNever,
	"POST /api/me/web-sign-ins/{id}/approve": cookieNever,
	"POST /api/me/web-sign-ins/{id}/deny":    cookieNever,

	"GET /api/me":                cookieJSON,
	"GET /api/local-addresses":   cookieNever,
	"GET /api/me/tokens":         cookieJSON,
	"DELETE /api/me/tokens/{id}": cookieJSON,

	"POST /api/me/device-links":              cookieNever,
	"GET /api/me/device-links/{id}":          cookieNever,
	"POST /api/me/device-links/{id}/renew":   cookieNever,
	"POST /api/me/device-links/{id}/approve": cookieNever,
	"POST /api/me/device-links/{id}/deny":    cookieNever,

	"PATCH /api/me/password": cookieJSON,
	"GET /api/me/push":       cookieNever,
	"PUT /api/me/push":       cookieNever,
	"DELETE /api/me/push":    cookieNever,
	"PUT /api/me/activity":   cookieNever,

	"GET /api/me/totp":              cookieJSON,
	"POST /api/me/totp":             cookieJSON,
	"POST /api/me/totp/confirm":     cookieJSON,
	"DELETE /api/me/totp":           cookieJSON,
	"POST /api/me/totp/recovery":    cookieJSON,
	"DELETE /api/users/{name}/totp": cookieJSON,

	"POST /api/server/update":        cookieNever,
	"POST /api/server/update/latest": cookieJSON,
	"GET /api/server/settings":       cookieJSON,
	"PATCH /api/server/settings":     cookieJSON,
	"PUT /api/server/web":            cookieNever,

	"POST /api/shares":        cookieJSON,
	"GET /api/shares":         cookieJSON,
	"GET /api/shares/watch":   cookieJSON,
	"GET /api/shares/changes": cookieJSON,
	"POST /api/shares/delete": cookieJSON,
	"POST /api/shares/edit":   cookieJSON,
	"GET /api/shares/{id}":    cookieJSON,
	"GET /api/sources":        cookieJSON,
	"GET /api/sources/browse": cookieJSON,
	"GET /api/sources/file":   cookieBytes,

	"PUT /api/shares/{id}/files/{path...}":      cookieJSON,
	"DELETE /api/shares/{id}/files/{path...}":   cookieJSON,
	"POST /api/shares/{id}/move":                cookieJSON,
	"POST /api/shares/{id}/folders":             cookieJSON,
	"DELETE /api/shares/{id}/folders/{path...}": cookieJSON,
	"POST /api/shares/{id}/batch":               cookieJSON,
	"PUT /api/shares/{id}/poster":               cookieJSON,
	"DELETE /api/shares/{id}/poster":            cookieJSON,
	"POST /api/shares/{id}/thumbs":              cookieJSON,
	"PUT /api/shares/{id}/thumbs/{slug}":        cookieJSON,
	"PUT /api/shares/{id}/gallery":              cookieJSON,
	"GET /api/downloads":                        cookieJSON,
	"GET /api/shares/{id}/poster":               cookieBytes,
	"GET /api/shares/{id}/thumbs/{slug}":        cookieBytes,
	"GET /api/shares/{id}/text":                 cookieJSON,
	"GET /api/shares/{id}/uploads/{path...}":    cookieJSON,
	"PUT /api/shares/{id}/preparing/{path...}":  cookieJSON,
	"PATCH /api/shares/{id}":                    cookieJSON,
	"POST /api/shares/{id}/download-ticket":     cookieJSON,
	"DELETE /api/shares/{id}":                   cookieJSON,

	"POST /api/live-share":                  cookieNever,
	"GET /api/live-share/{id}/jobs":         cookieNever,
	"POST /api/live-share/jobs/{job}":       cookieNever,
	"POST /api/live-share/jobs/{job}/error": cookieNever,
	"PATCH /api/live-share/{id}":            cookieNever,
	"DELETE /api/live-share/{id}":           cookieNever,

	"GET /api/users":           cookieJSON,
	"POST /api/users":          cookieJSON,
	"GET /api/users/{name}":    cookieJSON,
	"PATCH /api/users/{name}":  cookieJSON,
	"DELETE /api/users/{name}": cookieJSON,
	"GET /api/usage":           cookieJSON,
	"GET /api/admin/log":       cookieBytes,
	"POST /api/speedtest":      cookieJSON,

	"GET /api/domain":              cookieJSON,
	"PUT /api/domain":              cookieJSON,
	"GET /api/ddns":                cookieJSON,
	"GET /api/connectivity":        cookieJSON,
	"PUT /api/connectivity":        cookieJSON,
	"POST /api/connectivity/check": cookieJSON,
	"GET /api/ddns/available":      cookieJSON,
	"PUT /api/ddns":                cookieJSON,
	"DELETE /api/ddns":             cookieJSON,
}
