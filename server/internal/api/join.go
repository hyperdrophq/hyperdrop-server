package api

import (
	"html/template"
	"net/http"
	"net/url"
)

// The server's front page (/) and its join page (/join), one template. An
// invite names the server, and a recipient who clicks that address before
// reading the rest of the message lands on the front page rather than a
// 404: one line saying the server's files are shared through the HyperDrop
// app, and where to read more. /join is the steps: get HyperDrop, then a
// button that opens the app's Join step with this server filled in
// (joincode.ServerLink; the login and password come from the message). An
// invite's own link is /join with the join code in the URL FRAGMENT, which
// the browser never sends: the page's script reads it, shows the sign-in
// and points the same button at the hyperdrop://join link that fills every
// field, so the server serving the page never sees a password.
//
// Self-contained like the 404 page: no second request, no branding beyond
// HyperDrop's own, and nothing about this server but its canonical address.
var joinTmpl = page("join", "join.html")

type joinPageData struct {
	// The join steps (/join) rather than the front page (/).
	Join bool
	// The server's canonical origin (canonicalBase), what the Join step
	// is opened with.
	Server string
	// The hyperdrop://join link carrying that server alone. Typed as a URL
	// because html/template replaces an href of an unknown scheme with a
	// placeholder otherwise.
	ServerLink template.URL
}

func (h *handler) joinPage(w http.ResponseWriter, r *http.Request) {
	tmpl := joinTmpl
	if r.Method == http.MethodHead {
		tmpl = nil
	}
	server := h.canonicalBase(r)
	h.renderPage(w, unframed, 0, true, tmpl, joinPageData{
		Join:       r.URL.Path == "/join",
		Server:     server,
		ServerLink: template.URL(serverJoinLink(server)), // #nosec G203 -- a fixed hyperdrop: prefix and a query-escaped origin
	})
}

// serverJoinLink is core/joincode.ServerLink spelled here, since the server
// links no client package: the app's Join step opened with the server alone.
// TestServerJoinLinkMatchesTheClient in core/joincode pins the two.
func serverJoinLink(server string) string {
	return "hyperdrop://join?server=" + url.QueryEscape(server)
}
