package api

import "net/http"

func (h *handler) namesEnrollmentChallenge(w http.ResponseWriter, r *http.Request) {
	if h.ddns == nil {
		http.NotFound(w, r)
		return
	}
	h.ddns.ServeEnrollmentChallenge(w, r)
}
