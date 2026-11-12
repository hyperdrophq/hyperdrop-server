package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"hyperdrop/server/internal/ddns"
)

func (h *handler) getConnectivity(w http.ResponseWriter, r *http.Request) {
	s := h.ddns.Store().Snapshot()
	writeJSON(w, http.StatusOK, map[string]any{"serverID": h.fs.ServerID(), "status": h.ddns.Connectivity(), "hasCustomConfig": s.Custom != nil, "certStatus": h.dom.CertStatus()})
}

func (h *handler) putConnectivity(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Config   ddns.HTTPConfig `json:"config"`
		Password string          `json:"currentPassword"`
		TOTP     string          `json:"totp"`
	}
	if !decodeJSONBody(w, r, 128<<10, &in) {
		return
	}
	if !h.requireCurrentPasswordAndCode(w, r, in.Password, in.TOTP) {
		return
	}
	if err := h.ddns.ConfigureHTTP(in.Config); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.ddns.Start(context.Background())
	h.getConnectivity(w, r)
}

func (h *handler) checkConnectivity(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	// Outcomes, including failed requests, are carried by the status and
	// activity response. Never turn a provider body into an API error. A
	// manual check respects a provider or registry retry deadline, like a
	// scheduled tick. On a server with neither a free name nor a DDNS
	// recipe it is the only check of the address and both hostnames the
	// server makes (ddns.Updater.CheckNow).
	// A manual check is what a user presses after fixing the router, so the
	// NAT and port verdicts are re-probed first, synchronously.
	if h.dom != nil && h.dom.ReprobeNAT != nil {
		h.dom.ReprobeNAT()
	}
	_ = h.ddns.CheckNow(ctx)
	h.getConnectivity(w, r)
}

func (h *handler) availableDDNS(w http.ResponseWriter, r *http.Request) {
	data, err := h.ddns.Available(r.Context(), r.URL.Query().Get("name"))
	if err != nil {
		writeError(w, http.StatusBadGateway, "free-name availability could not be checked")
		return
	}
	var answer map[string]any
	if json.Unmarshal(data, &answer) != nil {
		writeError(w, http.StatusBadGateway, "invalid availability response")
		return
	}
	writeJSON(w, http.StatusOK, answer)
}
