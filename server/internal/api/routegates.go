package api

import "net/http"

// The named gate combinations the route table is built from: a signed-in
// GET whose JSON body is worth compressing, and a route that exists only
// where the address updater runs.

// read is a signed-in GET whose JSON body is worth compressing.
func (h *handler) read(next http.HandlerFunc) http.Handler {
	return h.auth(compressText(next))
}

// adminRead is an admin-only GET whose JSON body is worth compressing.
func (h *handler) adminRead(next http.HandlerFunc) http.Handler {
	return h.admin(compressText(next))
}

// ddnsOnly is the gate for a route that exists only on a server running
// the address updater: 503 ddns-unavailable anywhere else, so the handler
// behind it always has one.
func (h *handler) ddnsOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.ddns == nil {
			writeErrorCode(w, http.StatusServiceUnavailable, "ddns-unavailable",
				"connectivity monitoring is unavailable")
			return
		}
		next(w, r)
	}
}
