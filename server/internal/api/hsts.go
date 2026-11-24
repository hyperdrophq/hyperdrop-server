package api

import "net/http"

// hstsValue tells a browser to reach this host over https only, for a year.
// It names no includeSubDomains: the admin's domain may serve other sites
// under it that are not HyperDrop's to decide for.
const hstsValue = "max-age=31536000"

// hsts sets Strict-Transport-Security on every response a configured domain
// serves over TLS, so a browser's later visit to a share, the files origin
// or /app never starts on plain http. Port 80 serves only ACME, health and
// a redirect, and a development server without a domain is plain http by
// design: neither gets the header.
func hsts(origins func() Origins, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && origins().App != "" {
			w.Header().Set("Strict-Transport-Security", hstsValue)
		}
		next.ServeHTTP(w, r)
	})
}
