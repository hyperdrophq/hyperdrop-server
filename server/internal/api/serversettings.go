package api

import (
	"io"
	"net/http"
	"time"

	"hyperdrop/core/domainconn"
	"hyperdrop/core/updatenotice"
	"hyperdrop/server/internal/selfupdate"
)

// serverSettingsOut is GET /api/server/settings: whether this server
// updates itself, and what an admin is told about its updates.
type serverSettingsOut struct {
	AutoUpdate      bool                  `json:"autoUpdate"`
	SelfUpdate      string                `json:"selfUpdate"`
	Latest          string                `json:"latest,omitempty"`
	UpdateAvailable bool                  `json:"updateAvailable"`
	CheckedAt       *time.Time            `json:"checkedAt,omitempty"`
	Failed          *selfupdate.Failure   `json:"failed,omitempty"`
	LastAutoUpdate  *selfupdate.Done      `json:"lastAutoUpdate,omitempty"`
	Notices         []updatenotice.Notice `json:"notices,omitempty"`
	// WebApp is the web client's switch and bundle (webswitch.go).
	WebApp webAppOut `json:"webApp"`
	// DesktopSignIn is whether a computer may sign in with a phone
	// (desktopsignin.go).
	DesktopSignIn bool `json:"desktopSignIn"`
	// DomainChanges is the last week's moves of this server's address,
	// oldest first, worded for an administrator.
	DomainChanges []domainconn.ChangeNotice `json:"domainChanges,omitempty"`
}

func wireTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC().Truncate(time.Second)
	return &u
}

func settingsOut(f selfupdate.Facts) serverSettingsOut {
	out := serverSettingsOut{AutoUpdate: f.AutoUpdate, SelfUpdate: f.SelfUpdate, Latest: f.Latest,
		UpdateAvailable: f.UpdateAvailable,
		CheckedAt:       wireTime(f.CheckedAt), Notices: f.Notices}
	if f.Failed != nil {
		c := *f.Failed
		c.At = c.At.UTC().Truncate(time.Second)
		out.Failed = &c
	}
	if f.LastAutoUpdate != nil {
		c := *f.LastAutoUpdate
		c.At = c.At.UTC().Truncate(time.Second)
		out.LastAutoUpdate = &c
	}
	return out
}

// settings is the GET document.
func (h *handler) settings() serverSettingsOut {
	out := settingsOut(h.updates.Facts())
	out.WebApp = h.webAppSettings()
	out.DesktopSignIn = h.desktopSignInOn()
	if changes, err := h.db.DomainChanges(time.Now()); err == nil {
		for _, c := range changes {
			out.DomainChanges = append(out.DomainChanges, domainconn.NoticeOf(c))
		}
	}
	return out
}

func (h *handler) serverSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.settings())
}

// patchServerSettings turns automatic updates, the web client and signing
// computers in by phone on or off; at least one is named. The admin's
// bearer is enough for a request that carries no step-up: the box can only
// ever install a release its own binary verifies, and every admin surface
// shows each switch's state. A currentPassword or totp the request carries
// must verify as the caller's own. Automatic updates are refused where the
// box cannot install on its own (Unsupported), before the step-up is
// checked and before any switch moves; the other two switch on every box.
func (h *handler) patchServerSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		AutoUpdate      *bool  `json:"autoUpdate"`
		WebApp          *bool  `json:"webApp"`
		DesktopSignIn   *bool  `json:"desktopSignIn"`
		CurrentPassword string `json:"currentPassword"`
		TOTP            string `json:"totp"`
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<10))
	if err == nil {
		err = decodeRequest(body, &in)
	}
	if err != nil || (in.AutoUpdate == nil && in.WebApp == nil && in.DesktopSignIn == nil) {
		msg := `expected {"autoUpdate": true or false, "webApp": true or false, "desktopSignIn": true or false}, at least one of them`
		if err != nil {
			if named := badJSONMessage(err); named != "invalid JSON" {
				msg = named
			}
		}
		writeErrorCode(w, http.StatusBadRequest, "invalid", msg)
		return
	}
	if in.AutoUpdate != nil {
		if why := h.updates.Unsupported(); why != "" {
			writeErrorCode(w, http.StatusConflict, "self-update-unavailable", why)
			return
		}
	}
	if !h.stepUpIfSent(w, r, in.CurrentPassword, in.TOTP) {
		return
	}
	if in.AutoUpdate != nil {
		if err := h.updates.SetAuto(*in.AutoUpdate); err != nil {
			writeRefusal(w, err)
			return
		}
		if *in.AutoUpdate {
			h.nudgeWebFetch()
		}
	}
	if in.WebApp != nil {
		if err := h.setWebSwitch(*in.WebApp); err != nil {
			writeRefusal(w, err)
			return
		}
	}
	if in.DesktopSignIn != nil {
		if err := h.setDesktopSwitch(*in.DesktopSignIn); err != nil {
			writeRefusal(w, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, h.settings())
}
