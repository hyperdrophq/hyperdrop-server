package api

import "net/http"

// linksOffTmpl is the page every public route of a share whose links are
// off answers (gateLinksOff): the share is still there, its owner has
// turned its links off for now.
var linksOffTmpl = page("links-off", "linksoff.html")

// renderLinksOff answers a share whose owner turned its links off. The page
// names nothing (no id, no name, no file, no Open Graph card), so it is the
// same for a share's own routes and its file links, open or protected, and a
// stranger holding a link learns only that the link is off. 503 rather than
// 404 or 410, because the share is coming back; no-store, so no cache keeps
// the page past the moment the links are on again. No visit is recorded and
// no cookie is set: nothing was read.
func (h *handler) renderLinksOff(w http.ResponseWriter) {
	w.Header().Set("Referrer-Policy", "no-referrer")
	h.renderPage(w, framable, http.StatusServiceUnavailable, true, linksOffTmpl, nil)
}
