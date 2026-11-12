package api

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUnknownBrowserPathGetsTheBranded404(t *testing.T) {
	h := withDomain(t, "share.example.com")

	for _, tc := range []struct {
		name string
		host string
	}{
		{"custom domain", "share.example.com"},
		{"free HyperDrop domain", "alice.hyperdrop.link"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := req(t, h, http.MethodGet, tc.host, "/missing")
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404", rec.Code)
			}
			if got := rec.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
				t.Errorf("Content-Type = %q", got)
			}
			if got := rec.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q", got)
			}
			if got := rec.Header().Get("X-Robots-Tag"); got != "noindex" {
				t.Errorf("X-Robots-Tag = %q", got)
			}
			body := rec.Body.String()
			for _, want := range []string{"This link isn’t here", "Powered by", "HyperDrop", "prefers-color-scheme: dark"} {
				if !strings.Contains(body, want) {
					t.Errorf("body is missing %q", want)
				}
			}
			if strings.Contains(body, "404 page not found") {
				t.Error("net/http's plain-text fallback leaked through")
			}
		})
	}
}

func TestNotFoundHeadHasNoBody(t *testing.T) {
	h := withDomain(t, "share.example.com")
	rec := req(t, h, http.MethodHead, "share.example.com", "/missing")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("HEAD wrote %d body bytes", rec.Body.Len())
	}
}

func assertBrandedNotFound(t *testing.T, recBody string, code int, contentType string) {
	t.Helper()
	if code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", code)
	}
	if contentType != "text/html; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want branded HTML", contentType)
	}
	if !strings.Contains(recBody, "This link isn’t here") ||
		strings.Contains(recBody, "404 page not found") {
		t.Fatalf("body is not the branded page: %s", recBody)
	}
}

func TestMissingPublicShareRoutesGetTheBranded404(t *testing.T) {
	h := withDomain(t, "share.example.com")
	for _, tc := range []struct {
		name, method, host, path string
	}{
		{"listing", http.MethodGet, "share.example.com", "/share/zzzzzzzzzz"},
		{"view", http.MethodGet, "files.share.example.com", "/view/zzzzzzzzzz/missing"},
		{"download", http.MethodGet, "files.share.example.com", "/download/zzzzzzzzzz/missing"},
		{"zip", http.MethodGet, "files.share.example.com", "/zip/zzzzzzzzzz"},
		{"site", http.MethodGet, "files.share.example.com", "/site/zzzzzzzzzz/missing"},
		{"inbox page", http.MethodGet, "share.example.com", "/receive/zzzzzzzzzz"},
		{"password submit", http.MethodPost, "share.example.com", "/unlock/zzzzzzzzzz"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := req(t, h, tc.method, tc.host, tc.path)
			assertBrandedNotFound(t, rec.Body.String(), rec.Code, rec.Header().Get("Content-Type"))
		})
	}
}

func TestMissingFileInsideExistingShareGetsTheBranded404(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id, _ := shareWithFiles(t, h, "report", map[string]string{"report.txt": "hello"})
	rec := req(t, h, http.MethodGet, "files.share.example.com", "/view/"+id+"/missing-file-slug")
	assertBrandedNotFound(t, rec.Body.String(), rec.Code, rec.Header().Get("Content-Type"))
}

func TestShareStatus404StaysMachineReadable(t *testing.T) {
	h := withDomain(t, "share.example.com")
	rec := req(t, h, http.MethodGet, "share.example.com", "/share/zzzzzzzzzz/status")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") ||
		strings.Contains(rec.Body.String(), "This link isn’t here") {
		t.Fatalf("status poll was changed into a browser page: %s", rec.Body.String())
	}
}

func TestBrandedRoute404UsesNegotiatedCompression(t *testing.T) {
	h := withDomain(t, "share.example.com")
	r := httptest.NewRequest(http.MethodGet, "/share/zzzzzzzzzz", nil)
	r.Host = "share.example.com"
	r.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusNotFound || rec.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("status/encoding = %d/%q", rec.Code, rec.Header().Get("Content-Encoding"))
	}
	zr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "This link isn’t here") {
		t.Fatalf("decompressed body is not branded: %s", body)
	}
}
