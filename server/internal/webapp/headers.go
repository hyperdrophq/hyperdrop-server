package webapp

import (
	"net/http"
	"strings"
)

// CSP is the Content-Security-Policy of every /app answer. fileOrigin is the
// origin uploaded bytes are served from (https://files.<domain>), which the
// page may show as images and media; "" when the server has one origin, and
// its sources are then left out. The page runs only its own script and the
// WebAssembly it compiles, with no inline script or style.
func CSP(fileOrigin string) string {
	files := ""
	if fileOrigin != "" {
		files = " " + fileOrigin
	}
	return strings.Join([]string{
		"default-src 'none'",
		"script-src 'self' 'wasm-unsafe-eval'",
		"style-src 'self'",
		"img-src 'self' blob: data:" + files,
		"media-src 'self' blob:" + files,
		"connect-src 'self'",
		"font-src 'self'",
		"manifest-src 'self'",
		"worker-src 'self' blob:",
		"frame-ancestors 'none'",
		"base-uri 'none'",
		"form-action 'self'",
	}, "; ")
}

// SecurityHeaders sets the browser hardening every /app answer carries: the
// given CSP, no framing, no referrer, its own browsing context group, no type
// sniffing and none of the device features the page does not use.
func SecurityHeaders(h http.Header, csp string) {
	h.Set("Content-Security-Policy", csp)
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
}
