package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"hyperdrop/server/internal/ddns"
	"hyperdrop/server/internal/domain"
)

func (h *handler) domainOut() map[string]any {
	out := map[string]any{"domain": h.dom.Current(), "ip": h.dom.IP}
	// Diagnostics, both omitted when empty: per-subject certificate
	// lifecycle from CertMagic's events, and the NAT verdict of the boot
	// probe. Admin-only by the route, so the CA's raw error text is fine.
	if cs := h.dom.CertStatus(); len(cs) != 0 {
		out["certStatus"] = cs
	}
	if v := h.dom.NAT(); v != "" {
		out["nat"] = v
	}
	// What the router's 443 and 80 forwards reach, seen from outside.
	if p, ok := h.dom.Ports(); ok {
		out["ports"] = p
	}
	return out
}

// addressChange runs change, one of the app's address changes, through the
// deployment's hook when it has one.
func (h *handler) addressChange(change func() bool) {
	if h.dep.AddressChange == nil {
		change()
		return
	}
	h.dep.AddressChange(change)
}

func (h *handler) getDomain(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.domainOut())
}

// putDomain configures the server's custom domain at runtime: validate,
// require the domain to already resolve to this server (protects the ACME
// rate limit), persist, and start certificate management.
func (h *handler) putDomain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
		// Adopt skips the "does it already point here" pre-check. Needed when
		// the server sits behind NAT: the record resolves to the router's WAN
		// IP while this box knows only its LAN address, so the check compares
		// two things that are correctly different. ACME then proves it: the
		// certificate issues, or it does not.
		Adopt bool `json:"adopt,omitempty"`
		// The caller's step-up (stepUpCreds), which every PUT requires.
		stepUpCreds
	}
	if !decodeJSONBody(w, r, 1<<16, &req) {
		return
	}
	// Detached from the request context: a client disconnect mid-Set must
	// not half-apply the pipeline or masquerade as a DNS failure.
	set := h.dom.Set
	if req.Adopt {
		set = func(_ context.Context, d string) error { return h.dom.Adopt(d) }
	}
	apply := func() error { return set(context.WithoutCancel(r.Context()), req.Domain) }
	var applyErr error
	if h.ddns != nil && strings.HasSuffix(strings.ToLower(strings.TrimSuffix(req.Domain, ".")), "."+ddns.Zone) {
		writeError(w, 400, "connect managed domains through account approval")
		return
	}
	// Adopting moves every link and the certificate onto a name nothing has
	// shown resolves to this server, so it takes the caller's own password
	// (and code), the step-up PUT /api/connectivity takes: a bearer token
	// alone must not be able to point the server at a name its holder
	// controls. Checked before anything is applied.
	if req.Adopt && !h.requireCurrentPasswordAndCode(w, r, req.CurrentPassword, req.TOTP) {
		return
	}
	// Without Adopt the step-up is checked only after the domain is known to
	// be valid and to point here, so a code is not spent on a request that
	// would be refused anyway.
	if !req.Adopt {
		if err := h.dom.CheckPointsHere(r.Context(), req.Domain); err != nil {
			writeDomainError(w, err)
			return
		}
		if !h.requireCurrentPasswordAndCode(w, r, req.CurrentPassword, req.TOTP) {
			return
		}
	}
	h.addressChange(func() bool {
		if h.ddns != nil {
			applyErr = h.ddns.ChangeDomain(context.WithoutCancel(r.Context()), apply)
		} else {
			applyErr = apply()
		}
		return applyErr == nil
	})
	if applyErr != nil {
		writeDomainError(w, applyErr)
		return
	}
	writeJSON(w, http.StatusOK, h.domainOut())
}

// writeDomainError maps a domain.Manager refusal to its response.
func writeDomainError(w http.ResponseWriter, err error) {
	var np *domain.ErrNotPointing
	switch {
	case errors.Is(err, domain.ErrBadDomain):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, domain.ErrNoTLS):
		writeError(w, http.StatusConflict, err.Error())
	case errors.As(err, &np):
		writeError(w, http.StatusConflict, err.Error())
	default:
		writeRefusal(w, err)
	}
}
