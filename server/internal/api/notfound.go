package api

import (
	"io"
	"net/http"
	"strings"
)

// brandedNotFoundWriter upgrades a route handler's ordinary 404 into the
// same finished page as the public catch-all, while leaving every successful
// response byte-for-byte alone. It lives INSIDE compressText at registration
// time: a missing /share page may then be compressed normally, instead of a
// wrapper outside the mux accidentally labelling an uncompressed page gzip.
//
// Only human-facing public routes opt into this wrapper. The status poll,
// anonymous upload endpoint, API, thumbnails and preview assets keep their
// machine-readable or asset-shaped failures.
type brandedNotFoundWriter struct {
	h        *handler
	w        http.ResponseWriter
	r        *http.Request
	wrote    bool
	replaced bool
}

func (w *brandedNotFoundWriter) Header() http.Header { return w.w.Header() }

func (w *brandedNotFoundWriter) WriteHeader(code int) {
	if w.wrote {
		return
	}
	w.wrote = true
	// A 404 that already declared a JSON body is meant for a machine:
	// writeErrorCode's error code is the answer, and burying it under the
	// branded page would hand a CLI a web page instead. Only a bare 404
	// becomes the page.
	if code == http.StatusNotFound && !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		w.replaced = true
		w.h.notFoundPage(w.w, w.r)
		return
	}
	w.w.WriteHeader(code)
}

func (w *brandedNotFoundWriter) Write(p []byte) (int, error) {
	if w.replaced {
		// net/http's http.NotFound writes "404 page not found" after setting
		// the status. Consume that stale body after replacing it.
		return len(p), nil
	}
	w.wrote = true
	return w.w.Write(p)
}

// Unwrap lets http.ResponseController reach optional capabilities (notably
// Flush) on the real writer for successful streaming responses.
func (w *brandedNotFoundWriter) Unwrap() http.ResponseWriter { return w.w }

// ReadFrom passes a file body through to the real writer's own ReadFrom, so
// /view, /download and /site keep net/http's sendfile path. A body behind a
// replaced 404 is consumed, as Write consumes it.
func (w *brandedNotFoundWriter) ReadFrom(src io.Reader) (int64, error) {
	if w.replaced {
		return io.Copy(io.Discard, src)
	}
	w.wrote = true
	return readFrom(w.w, src)
}

func (h *handler) brandedNotFound(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		next(&brandedNotFoundWriter{h: h, w: w, r: r}, r)
	}
}

// The public catch-all. It is deliberately self-contained: a missing path
// must not trigger more missing asset requests, and a custom-domain owner
// should get the same finished page as a free HyperDrop domain without any
// server-specific branding or information leaking into it.
var notFoundTmpl = page("not-found", "notfound.html")

func (h *handler) notFoundPage(w http.ResponseWriter, r *http.Request) {
	tmpl := notFoundTmpl
	if r.Method == http.MethodHead {
		tmpl = nil
	}
	h.renderPage(w, framable, http.StatusNotFound, true, tmpl, nil)
}
