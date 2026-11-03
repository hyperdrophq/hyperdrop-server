package api

import (
	"net/http"
)

var unavailableTmpl = page("unavailable", "unavailable.html")

type unavailableData struct {
	ID    string
	Title string
}

// unavailableUnnamed is the unavailable page's title for a visitor a
// password stands in front of.
const unavailableUnnamed = "This share is unavailable"

// renderUnavailable answers every public route of a linked share whose
// source cannot be read: the share exists, the folder behind it does not,
// which is the owner's to fix and the visitor's to be told about. A
// password-protected share is named only to a visitor holding its access
// cookie, as its link card (protectedCard) names it to nobody: the name
// stays behind the password.
func (h *handler) renderUnavailable(w http.ResponseWriter, r *http.Request, v shareView) {
	d := unavailableData{ID: v.ID, Title: v.Name}
	switch {
	case v.PasswordHash != "" && !h.validAccess(r, v.ID, v.PasswordGen):
		d.Title = unavailableUnnamed
	case d.Title == "":
		d.Title = "Files"
	}
	h.renderPage(w, framable, 0, true, unavailableTmpl, d)
}

// fileLinkUnavailableTitle is the unavailable page's title on a file link,
// whether or not the visitor holds its cookie: the share's name is never
// shown there.
const fileLinkUnavailableTitle = "This file is unavailable"

// renderFileLinkUnavailable answers a file link whose share's source cannot
// be read. It carries no share id and no name.
func (h *handler) renderFileLinkUnavailable(w http.ResponseWriter, r *http.Request) {
	h.renderPage(w, framable, 0, true, unavailableTmpl, unavailableData{Title: fileLinkUnavailableTitle})
}
