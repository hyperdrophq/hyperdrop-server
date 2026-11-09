package api

import (
	"errors"
	"net/http"
	"time"

	"hyperdrop/server/internal/metadb"
)

// spendInvite exchanges a one-time invite for a device token: what the
// app does when a hdjoin2 link is opened, so an invited person is signed
// in without typing the password the invite also carries. The invite is
// spent by the exchange (metadb.SpendInvite); a second device with the
// same link signs in with the password. Shares the login lockout, so a
// guessed invite costs what a guessed password does, and an invite is
// refused for an account with a second factor rather than bypassing it.
func (h *handler) spendInvite(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	att, ok := h.admitLogin(w, r, now)
	if !ok {
		return
	}
	defer att.abandon()
	var req struct {
		Token string `json:"token"`
		// Label names the device in the token list (optional).
		Label string `json:"label"`
	}
	if !decodeJSONBody(w, r, 64<<10, &req) {
		return
	}
	if req.Token == "" {
		writeError(w, http.StatusBadRequest, "token is required")
		return
	}
	u, token, err := h.db.SpendInvite(req.Token, req.Label, now)
	switch {
	case errors.Is(err, metadb.ErrInviteInvalid):
		if !lockedOutBy(w, att, inviteTarget, writeLoginLockedOut) {
			writeErrorCode(w, http.StatusNotFound, "invite-invalid", err.Error())
		}
		return
	case errors.Is(err, metadb.ErrInviteNeedsSecondFactor):
		writeErrorCode(w, http.StatusForbidden, "invite-needs-code", err.Error())
		return
	case err != nil:
		writeRefusal(w, err)
		return
	}
	att.succeeded(inviteTarget)
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "user": h.toUserOut(u)})
}

// inviteTarget is what a guessed invite is aimed at on the login lockout:
// an invite names no account until it is found.
const inviteTarget = "invite"

// mintInviteInto adds the account's one-time invite to a create or reset
// answer. A mint that fails is a server error, not a missing field: the
// admin would send an invite with no link and nothing to say why.
func (h *handler) mintInviteInto(out map[string]any, name string) error {
	invite, err := h.db.MintInvite(name)
	if err != nil {
		return err
	}
	out["inviteToken"] = invite
	return nil
}
