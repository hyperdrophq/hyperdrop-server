package api

import (
	"context"
	"errors"
	"net/http"

	"hyperdrop/server/internal/ddns"
)

func (h *handler) ddnsOut() map[string]any {
	out := map[string]any{"configured": false, "name": "", "fqdn": ""}
	if h.ddns == nil {
		return out
	}
	st := h.ddns.Store().Snapshot()
	if !ddnsPublished(st) {
		out["name"] = st.Name
		if st.Pending && st.Enrollment != nil {
			out["enrollment"] = map[string]any{"approvalURL": st.Enrollment.ApprovalURL, "expiresAt": st.Enrollment.ExpiresAt}
		}
		// A refused claim leaves nothing in the ddns state to attach a reason to,
		// so this is the only channel it has: on the Synology path the user
		// reads this from Package Center, never from the app.
		if reason := h.ddns.LastClaimError(); reason != "" {
			out["lastClaimError"] = reason
		}
		return out
	}
	out["configured"] = true
	out["name"] = st.Name
	out["fqdn"] = ddns.FQDN(st.Name)
	out["lastUpdate"] = st.LastUpdate
	out["lastIP"] = st.LastIP
	out["lastError"] = st.LastError

	return out
}

func (h *handler) getDDNS(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.ddnsOut())
}

// putDDNS starts account approval, then adopts the domain after publication.
func (h *handler) putDDNS(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string `json:"name"`
		Replace bool   `json:"replace,omitempty"`
	}
	if !decodeJSONBody(w, r, 1<<16, &req) {
		return
	}
	if !ddns.ValidName(req.Name) {
		writeError(w, http.StatusBadRequest,
			"name: use 5 to 32 characters of lowercase letters, digits and hyphens, no doubled hyphens")
		return
	}
	if h.ddns == nil {
		writeError(w, http.StatusServiceUnavailable, "this server has no ddns updater")
		return
	}
	// Detached from the request context for the same reason PUT /api/domain
	// is: a client disconnect must not half-apply the sequence.
	ctx := context.WithoutCancel(r.Context())
	choose := h.ddns.Choose
	if req.Replace {
		choose = h.ddns.Replace
	}
	// Periodic address monitoring runs once this request is done, whether
	// the claim succeeded or not: a failed claim or publication is retried.
	defer h.ddns.Start(context.Background())
	var err error
	// A claim waiting for account approval is the app's choice too.
	h.addressChange(func() bool {
		err = choose(ctx, req.Name, h.fs.ServerID())
		var serviceErr *ddns.ServiceError
		return err == nil || errors.As(err, &serviceErr) && serviceErr.Code == "account-required"
	})
	if err != nil {
		var serviceErr *ddns.ServiceError
		if errors.As(err, &serviceErr) {
			if serviceErr.Code == "account-required" {
				writeJSON(w, http.StatusAccepted, h.ddnsOut())
				return
			}
			status := http.StatusServiceUnavailable
			if errors.Is(err, ddns.ErrClaimRateLimited) {
				status = http.StatusTooManyRequests
			}
			writeJSON(w, status, serviceErr)
			return
		}
		if errors.Is(err, ddns.ErrNamePermanent) {
			writeErrorCode(w, http.StatusConflict, "name-permanent", err.Error())
			return
		}
		writeError(w, claimErrorStatus(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, h.ddnsOut())
}

// claimErrorStatus maps a refusal from Updater.Choose to the status code that
// carries its reason: 409 for a name somebody else holds, 422 for a shape
// or policy refusal, 429 for the per-address rate limit. Anything else
// (a network failure, an unreadable answer) is 502: the service itself did
// not refuse, it could not be reached or understood.
func claimErrorStatus(err error) int {
	switch {
	case errors.Is(err, ddns.ErrNameTaken):
		return http.StatusConflict
	case errors.Is(err, ddns.ErrNameRefused):
		return http.StatusUnprocessableEntity
	case errors.Is(err, ddns.ErrClaimRateLimited):
		return http.StatusTooManyRequests
	default:
		return http.StatusBadGateway
	}
}

// deleteDDNS disconnects DNS before forgetting its machine credential. It does not change the server's current domain; the product-level
// domain switch has already installed a replacement before calling this.
func (h *handler) deleteDDNS(w http.ResponseWriter, r *http.Request) {
	if h.ddns != nil {
		release := func() error { return h.ddns.Release(context.WithoutCancel(r.Context())) }
		if name := r.URL.Query().Get("pendingName"); name != "" {
			release = func() error { return h.ddns.CancelCandidate(context.WithoutCancel(r.Context()), name) }
		}
		var err error
		h.addressChange(func() bool { err = release(); return err == nil })
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		h.ddns.Start(context.Background())
	}
	writeJSON(w, http.StatusOK, map[string]any{"configured": false})
}
