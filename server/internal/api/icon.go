package api

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"net/http"
	"time"
)

// The tab mark for the pages this server draws, byte for byte the copy the
// public site publishes (website/favicon.svg, served here at /icon.svg, and
// website/favicon.ico; TestTheIconMatchesTheSiteCopy pins them equal). The
// server is its own Go module, so it cannot embed across the repository and
// carries its own.
//
// iconTouch is website/apple-touch-icon.png, the app icon as an opaque 512 px
// square. Every page of the server's links it as its apple-touch-icon, which
// iOS takes for a home-screen icon and for the lock screen's artwork while the
// page plays sound; a share's page that names none links it too (pageicon.go).
var (
	//go:embed favicon.svg
	iconSVG []byte
	//go:embed favicon.ico
	iconICO []byte
	//go:embed apple-touch-icon.png
	iconTouch []byte
)

// serveIcon answers with a static asset that never varies by share, viewer or
// origin. Every icon route is deliberately unpinned (routeOrigins calls them
// anyHost): our pages render on BOTH hostnames, the listing and the password
// form on the app origin and the waiting page on the file origin, and a tab
// icon pinned to one of them would 308 the other.
func serveIcon(body []byte, contentType string) http.HandlerFunc {
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:8]) + `"`
	return func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Type", contentType)
		h.Set("Cache-Control", "public, max-age=604800")
		h.Set("ETag", etag)
		// An SVG opened as a document is an active page. This one is ours and
		// carries no script, and the policy keeps it inert for anyone who
		// navigates to the file itself rather than loading it as an icon.
		h.Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(body))
	}
}
