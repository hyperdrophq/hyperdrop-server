package api

import (
	"io"
	"net/http"
	"time"

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

func (h *handler) serverSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, settingsOut(h.updates.Facts()))
}

// patchServerSettings turns automatic updates on or off. The admin's bearer
// is enough: the box can only ever install a release its own binary
// verifies, and every admin surface shows the switch's state.
func (h *handler) patchServerSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		AutoUpdate *bool `json:"autoUpdate"`
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<10))
	if err == nil {
		err = decodeRequest(body, &in)
	}
	if err != nil || in.AutoUpdate == nil {
		msg := `expected {"autoUpdate": true or false}`
		if err != nil {
			if named := badJSONMessage(err); named != "invalid JSON" {
				msg = named
			}
		}
		writeErrorCode(w, http.StatusBadRequest, "invalid", msg)
		return
	}
	if why := h.updates.Unsupported(); why != "" {
		writeErrorCode(w, http.StatusConflict, "self-update-unavailable", why)
		return
	}
	if err := h.updates.SetAuto(*in.AutoUpdate); err != nil {
		writeRefusal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, settingsOut(h.updates.Facts()))
}
