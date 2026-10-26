package api

import (
	"net/http"
)

var unavailableTmpl = page("unavailable", "unavailable.html")

type unavailableData struct {
	ID    string
	Title string
}

// renderUnavailable answers every public route of a linked share whose
// source cannot be read: the share exists, the folder behind it does not,
// which is the owner's to fix and the visitor's to be told about.
func (h *handler) renderUnavailable(w http.ResponseWriter, v shareView) {
	d := unavailableData{ID: v.ID, Title: v.Name}
	if d.Title == "" {
		d.Title = "Files"
	}
	h.renderPage(w, framable, 0, true, unavailableTmpl, d)
}
