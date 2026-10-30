package api

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Every response a configured domain serves over TLS carries HSTS, the
// files origin's and a redirect's included; plain http and a server with no
// domain never do.
func TestHSTSOnlyOverTLSWithADomain(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	cases := []struct {
		name   string
		domain string
		tls    bool
		host   string
		want   string
	}{
		{"app origin over TLS", "share.example.com", true, "share.example.com", hstsValue},
		{"files origin over TLS", "share.example.com", true, "files.share.example.com", hstsValue},
		{"plain http", "share.example.com", false, "share.example.com", ""},
		{"no domain", "", true, "localhost", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := hsts(func() Origins { return OriginsFor(tc.domain) }, ok)
			r := httptest.NewRequest("GET", "/share/abc", nil)
			r.Host = tc.host
			if tc.tls {
				r.TLS = &tls.ConnectionState{}
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if got := w.Header().Get("Strict-Transport-Security"); got != tc.want {
				t.Fatalf("Strict-Transport-Security = %q, want %q", got, tc.want)
			}
		})
	}
	if hstsValue != "max-age=31536000" {
		t.Fatalf("hstsValue = %q: includeSubDomains or preload would bind every name under the admin's domain", hstsValue)
	}
}
