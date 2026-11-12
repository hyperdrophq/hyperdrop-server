package api

import (
	"net/http"
	"path/filepath"
	"strconv"

	"hyperdrop/server/internal/logfile"
)

// adminLog answers the tail of the server's own log file as plain text;
// `skip` leaves out the newest lines a reader already holds, which is how
// it pages back.
// Read-only and admin-gated with the bearer alone, no step-up: the log holds
// no secret by construction (responselog.go), and it is what an operator
// pastes to support when the app cannot say what is wrong.
func (h *handler) adminLog(w http.ResponseWriter, r *http.Request) {
	tail := logfile.DefaultTail
	if v := r.URL.Query().Get("tail"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeErrorCode(w, http.StatusBadRequest, "bad-request", "tail must be a positive number")
			return
		}
		tail = min(n, logfile.MaxTail)
	}
	skip := 0
	if v := r.URL.Query().Get("skip"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeErrorCode(w, http.StatusBadRequest, "bad-request", "skip must be a number")
			return
		}
		skip = n
	}
	out, err := logfile.TailBefore(filepath.Join(h.dep.DataDir, "logs"), tail, skip)
	if err != nil {
		writeRefusal(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(out)
}
