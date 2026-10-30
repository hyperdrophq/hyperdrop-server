package api

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"hyperdrop/core/webbundle"
	"hyperdrop/server/internal/webapp"
)

// The web client on this server: the administrator's switch, stored as a
// server setting beside automatic updates, and the installed bundle
// (internal/webapp). /app serves the bundle while webState is on, and the
// /api/web routes refuse while it is not.

// webSwitchKey is the switch's setting: "off" is off, absent is on.
const webSwitchKey = "webapp.enabled"

// webBundleMax caps a bundle archive installed over the API, the fetcher's
// own cap.
const webBundleMax = 64 << 20

// webOn reports whether the administrator's switch is on. A setting that
// cannot be read is off: the web client is not served on a guess. The log
// says when reading it starts failing and when it works again, not on every
// read (the health poll reads it).
func (h *handler) webOn() bool {
	v, ok, err := h.db.Setting(webSwitchKey)
	if err != nil {
		if !h.webSwitchUnread.Swap(true) {
			log.Printf("web client: reading the switch: %v; the web client is off until it can be read", err)
		}
		return false
	}
	if h.webSwitchUnread.Swap(false) {
		log.Printf("web client: the switch can be read again")
	}
	return !ok || v != "off"
}

// webState is whether /app serves the installed bundle: off when the
// switch is, missing with no bundle, updating when the installed bundle's
// contract is one this server no longer serves (webbundle.Serves), and on
// otherwise.
func (h *handler) webState() webapp.State {
	if !h.webOn() {
		return webapp.StateOff
	}
	inst, ok := h.dep.Web.Current()
	switch {
	case !ok:
		return webapp.StateMissing
	case !webbundle.Serves(inst.Contract, h.version):
		return webapp.StateUpdating
	}
	return webapp.StateOn
}

// refuseWebUnavailable answers a web client route while the web client is
// not served (403 web-off for the switch, 503 web-unavailable for no
// bundle the server serves) and reports whether it did.
func (h *handler) refuseWebUnavailable(w http.ResponseWriter) bool {
	switch h.webState() {
	case webapp.StateOn:
		return false
	case webapp.StateOff:
		writeErrorCode(w, http.StatusForbidden, "web-off", "the web client is turned off on this server")
	default:
		writeErrorCode(w, http.StatusServiceUnavailable, "web-unavailable", "the web client is not installed on this server")
	}
	return true
}

// webServed is next behind refuseWebUnavailable.
func (h *handler) webServed(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.refuseWebUnavailable(w) {
			return
		}
		next(w, r)
	}
}

// webCSP is the CSP of every /app answer, naming the file origin when the
// origins are split.
func (h *handler) webCSP() string {
	if o := h.origins(); o.Split() {
		return webapp.CSP("https://" + o.File)
	}
	return webapp.CSP("")
}

// setWebSwitch turns the web client on or off. Off is stored first and
// then every phone sign-in request is dropped and every web session
// revoked, so no session outlives the switch; on forgets the setting and
// asks the fetcher for a bundle at once.
func (h *handler) setWebSwitch(on bool) error {
	if !on {
		if err := h.db.SetSetting(webSwitchKey, "off"); err != nil {
			return err
		}
		h.signIns.clear()
		n, err := h.db.RevokeWebSessions()
		if n > 0 {
			log.Printf("web client: turned off, %d web sessions signed out", n)
		}
		return err
	}
	if err := h.db.DeleteSetting(webSwitchKey); err != nil {
		return err
	}
	h.nudgeWebFetch()
	return nil
}

// webAppOut is GET /api/server/settings' webApp: the switch, the bundle
// installed and what the last fetch of the web manifest found.
type webAppOut struct {
	Enabled   bool       `json:"enabled"`
	Installed bool       `json:"installed"`
	Version   string     `json:"version,omitempty"`
	Build     int        `json:"build,omitempty"`
	Latest    string     `json:"latest,omitempty"`
	CheckedAt *time.Time `json:"checkedAt,omitempty"`
	Failed    string     `json:"failed,omitempty"`
}

func (h *handler) webAppSettings() webAppOut {
	out := webAppOut{Enabled: h.webOn()}
	if inst, ok := h.dep.Web.Current(); ok {
		out.Installed, out.Version, out.Build = true, inst.Version, inst.Build
	}
	if h.dep.WebFetcher != nil {
		st := h.dep.WebFetcher.Status()
		out.Latest, out.CheckedAt, out.Failed = st.Latest, wireTime(st.CheckedAt), st.Failed
	}
	if h.dep.WebFailed != "" {
		out.Failed = h.dep.WebFailed
	}
	return out
}

// installWebBundle is PUT /api/server/web?version=&build=&contract=: an
// admin installs a bundle archive (the body, at most webBundleMax) with its
// signature file's base64 in X-HyperDrop-Signature, for a box that cannot
// reach the web manifest. It is verified and installed exactly as a fetched
// bundle is. X-HyperDrop-Password and X-HyperDrop-TOTP, when sent, must
// verify as the caller's own step-up; the bearer alone installs.
func (h *handler) installWebBundle(w http.ResponseWriter, r *http.Request) {
	if h.dep.Web == nil {
		writeErrorCode(w, http.StatusServiceUnavailable, "web-unavailable", "this server has no place to install the web client")
		return
	}
	archive, err := io.ReadAll(http.MaxBytesReader(w, r.Body, webBundleMax))
	var tooBig *http.MaxBytesError
	switch {
	case errors.As(err, &tooBig):
		writeErrorCode(w, http.StatusRequestEntityTooLarge, "body-too-large",
			fmt.Sprintf("the web bundle archive is larger than %d bytes", webBundleMax))
		return
	case err != nil:
		// The body stopped arriving: the request failed, the archive was
		// not refused.
		writeError(w, http.StatusBadRequest, "the web bundle archive stopped arriving")
		return
	}
	q := r.URL.Query()
	version, contract := q.Get("version"), q.Get("contract")
	build, err := strconv.Atoi(q.Get("build"))
	if err != nil {
		writeErrorCode(w, http.StatusBadRequest, "web-bundle-invalid", "build must be a number")
		return
	}
	sig := []byte(r.Header.Get("X-HyperDrop-Signature"))
	// The bundle's signature and window are checked before the step-up, so
	// a bundle that would be refused anyway spends no code.
	if err := h.dep.Web.Check(archive, sig, version, build, contract); err != nil {
		writeWebBundleRefusal(w, err)
		return
	}
	if !h.requireCurrentPasswordAndCode(w, r, r.Header.Get("X-HyperDrop-Password"), r.Header.Get("X-HyperDrop-TOTP")) {
		return
	}
	if err := h.dep.Web.Install(archive, sig, version, build, contract); err != nil {
		writeWebBundleRefusal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": version, "build": build})
}

// writeWebBundleRefusal answers a Check or Install error of a bundle an admin
// sent.
func writeWebBundleRefusal(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, webbundle.ErrMalformed), errors.Is(err, webbundle.ErrUntrusted), errors.Is(err, webapp.ErrBadArchive):
		writeErrorCode(w, http.StatusBadRequest, "web-bundle-invalid", err.Error())
	case errors.Is(err, webapp.ErrOutsideWindow):
		writeErrorCode(w, http.StatusConflict, "web-bundle-outside-window", err.Error())
	default:
		writeRefusal(w, err)
	}
}
