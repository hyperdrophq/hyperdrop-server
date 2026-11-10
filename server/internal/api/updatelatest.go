package api

import (
	"errors"
	"log"
	"net/http"

	"hyperdrop/server/internal/selfupdate"
)

// updateLatest is POST /api/server/update/latest: the server fetches its
// newest release itself and stages it through the self-updater's
// download, checksum and signature checks, the way the web client updates a
// server (a browser has no binary to upload). The step-up is
// updateServer's, with the credentials in the JSON body since there is no
// binary in it: a second factor is required on the account, and the
// caller's password and code are checked (a web session elevated now
// skips only the code).
//
// 202 {"version"} when a release was staged (the swap, restart and health
// check happen after this response), 200 {"updated":false,"reason":"already
// current"} when the server runs the newest, 501 update-unsupported when
// this box cannot install a release itself.
func (h *handler) updateLatest(w http.ResponseWriter, r *http.Request) {
	if why := h.updates.Unsupported(); why != "" {
		writeErrorCode(w, http.StatusNotImplemented, "update-unsupported", why)
		return
	}
	var req struct {
		CurrentPassword string `json:"currentPassword"`
		TOTP            string `json:"totp"`
	}
	if !decodeJSONBody(w, r, 4<<10, &req) {
		return
	}
	if !reqUser(r).TwoFactorEnabled() {
		writeErrorCode(w, http.StatusForbidden, "totp-setup-required",
			"set up two-factor authentication before updating the server over the network")
		return
	}
	if !h.requireCurrentPasswordAndCode(w, r, req.CurrentPassword, req.TOTP) {
		return
	}
	version, err := h.updates.InstallLatest(r.Context())
	switch {
	case errors.Is(err, selfupdate.ErrUnsupported):
		writeErrorCode(w, http.StatusNotImplemented, "update-unsupported", err.Error())
	case errors.Is(err, selfupdate.ErrPending):
		writeErrorCode(w, http.StatusConflict, "update-in-progress", err.Error())
	case err != nil:
		log.Printf("server update: %v", err)
		writeErrorCode(w, http.StatusBadGateway, "update-failed", "the newest release could not be fetched or verified; the server log has the cause")
	case version == "":
		h.nudgeWebFetch()
		writeJSON(w, http.StatusOK, map[string]any{"updated": false, "reason": "already current"})
	default:
		writeJSON(w, http.StatusAccepted, map[string]any{"version": version})
	}
}
