package api

import (
	"net"
	"net/http"
	"strings"
)

// A file somebody uploaded is untrusted content. `/view` serves it INLINE
// with the type its extension implies, so an .html or an .svg is a live web
// page, and on the app's own origin its script would be first-party: able to
// ride the hd_ access cookies of any share the viewer had unlocked, and to
// draw a pixel-perfect copy of the password form under the real domain and
// the real certificate.
//
// No response header fixes that; the browser's trust boundary IS the origin.
// So payload bytes get their own hostname, `files.<domain>`, exactly as every
// comparable file host does (raw.githubusercontent.com, *.googleusercontent.com).
// Script that runs there is on a throwaway origin with no reach into the app.
//
// This is why a custom domain is required: an IP address cannot be split this
// way, and a second PORT would not do it either, since cookies ignore ports.

// fileLabel is the subdomain payloads are served from. The client's copy is
// core/api.fileOriginLabel; a sync test in core/api/fileorigin_test.go pins
// the two together.
const fileLabel = "files."

// ShareHost is the hostname uploaded bytes are served from. Exported because
// the certificate order, the DNS records and the client's link building all
// have to agree on it.
func ShareHost(domain string) string {
	if domain == "" {
		return ""
	}
	return fileLabel + domain
}

// Origins is the pair of hostnames this server answers on.
type Origins struct {
	// App serves listings, the password form and the API.
	App string
	// File serves uploaded bytes: /view, /download, /zip, /site, /thumb.
	File string
}

// OriginsFor derives both hostnames from the configured domain. An empty
// domain is the development escape hatch: one host, no split.
func OriginsFor(domain string) Origins {
	if domain == "" {
		return Origins{}
	}
	return Origins{App: domain, File: ShareHost(domain)}
}

// Split reports whether payloads are served from a separate hostname.
func (o Origins) Split() bool { return o.App != "" && o.File != "" }

// VisitorCookieDomain is the Domain attribute of the hd_visitor grouping
// cookie: the configured domain, which every host under it receives. A page
// on the app origin mints the cookie, and the payload request it leads to on
// files.<domain> must carry the same one, or one visitor counts twice. The
// cookie grants nothing (no gate reads it), so a sibling host learns only a
// random token. No access cookie names a Domain: hd_<id> is host-only on
// each origin (accesshop.go). Empty means host-only, which is right when
// there is no split.
func (o Origins) VisitorCookieDomain() string {
	if !o.Split() {
		return ""
	}
	return o.App
}

// isPayloadPath reports whether a path serves uploaded bytes.
//
// This list is maintained separately from the mux registrations, so a route
// added there and forgotten here still serves: from the APP origin, which is
// the one place uploaded HTML must never run. origincoverage_test.go is what
// forces the two to agree.
func isPayloadPath(path string) bool {
	for _, p := range []string{"/view/", "/download/", "/zip/", "/site/", "/thumb/"} {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// isStatusPath matches exactly GET /share/{id}/status, the one /share
// sub-route the FILE origin must also answer. The waiting page for a pending
// /view|/download|/zip link renders on the file origin and polls this route
// with a relative fetch(). Pinned to the app origin it answers 308, which a
// fetch() cannot follow cross-origin without CORS, leaving the page on
// "waiting for the first bytes…" through the whole upload and past the
// commit.
func isStatusPath(path string) bool {
	rest, ok := strings.CutPrefix(path, "/share/")
	if !ok {
		return false
	}
	id, tail, found := strings.Cut(rest, "/")
	return found && id != "" && tail == "status"
}

// isPagePath reports whether a path serves one of OUR OWN HTML pages: the
// listing and the password form. These are what an uploaded page would want
// to impersonate or read, so they are pinned to the app origin. The status
// poll is carved out: it is progress JSON, not a page, and the file-origin
// waiting page needs it (see isStatusPath).
func isPagePath(path string) bool {
	if isStatusPath(path) {
		return false
	}
	// /receive/ covers the inbox upload page AND its PUT endpoint: the PUT is
	// cookie-gated (the unlock cookie proves the sender passed the password
	// form), so it must live where the cookie policy already pins pages.
	// The page's own JS PUTs same-origin, so the no-redirect-for-non-GET
	// rule in originRouter never bites it.
	// The front page and the invite's /join page are ours too: the join
	// page reads a sign-in out of its fragment, which must never render
	// where an uploaded page could be served as the same origin. /app is
	// the web client, whose session cookie is host-only on the app origin.
	return strings.HasPrefix(path, "/share/") || path == "/share" ||
		strings.HasPrefix(path, "/unlock/") || strings.HasPrefix(path, "/receive/") ||
		path == "/" || path == "/join" || path == "/app" || strings.HasPrefix(path, "/app/")
}

// Misrouted reports whether a request for path arriving with this Host
// belongs on the OTHER origin, and which one. Callers redirect a GET there
// and refuse anything else.
//
// An unrecognised Host is treated as misrouted to the canonical origin for
// that path: someone else's DNS pointed at this IP, or a bare-IP probe, and
// answering it would serve payload bytes from whatever name the client chose.
func (o Origins) Misrouted(path, host string) (string, bool) {
	if !o.Split() {
		return "", false
	}
	// Only the two categories that matter are pinned. Everything else (the
	// whole /api surface, /card.png) answers on any host, deliberately: the API
	// is Bearer-authenticated, and reads the web session cookie only on the
	// app host (webCookieAccepted), so an uploaded page calling it has no more
	// power than curl, while pinning it WOULD break the client dialling the
	// bare IP before DNS resolves (post-install login, the LAN shortcut).
	var want string
	switch {
	case isPayloadPath(path) || isAccessPath(path):
		want = o.File
	case isPagePath(path):
		want = o.App
	default:
		return "", false
	}
	if hostOnly(host) == want {
		return "", false
	}
	return want, true
}

// hostOnly strips a port from a Host header and lowercases what is left, the
// form the configured domain is stored in: a host name is case-insensitive.
// A bare IPv6 literal without a port is left alone.
func hostOnly(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(strings.Trim(host, "[]"))
}

// originRouter enforces the split in front of the mux. Origins are resolved
// per request, not captured: the domain can be set, changed or removed at
// runtime through PUT /api/domain, and a router holding a stale pair would
// keep serving payloads on the app origin after the change.
//
// The 308 below is load-bearing, not a recovery path: the client composes
// every copied link on the APP origin so the pasted URL shows the bare
// domain, and this redirect is the first hop of every view/download/zip
// link anyone holds. Its Location never carries a fragment (RequestURI
// cannot), so a fragment a link was shared with survives the hop.
func originRouter(origins func() Origins, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o := origins()
		want, misrouted := o.Misrouted(r.URL.Path, r.Host)
		if !misrouted {
			next.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			// Only GETs are links someone might hold; anything else arriving
			// on the wrong origin is a mistake or a probe.
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "https://"+want+r.URL.RequestURI(), http.StatusPermanentRedirect)
	})
}
