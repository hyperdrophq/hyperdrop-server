package api

import "net/http"

// stepUpIfSent verifies the caller's own password and code when the request
// carries either, for a route that must keep accepting the body of a client
// that sends no step-up. It returns true when nothing was sent or what was
// sent verifies, and otherwise writes the refusal itself and returns false.
// A code without a password is 403 step-up-required, like the routes that
// always ask.
func (h *handler) stepUpIfSent(w http.ResponseWriter, r *http.Request, password, code string) bool {
	if password == "" && code == "" {
		return true
	}
	return h.requireCurrentPasswordAndCode(w, r, password, code)
}
