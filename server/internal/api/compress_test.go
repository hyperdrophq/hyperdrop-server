package api

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func TestNegotiateEncodingPrefersZstdThenGzip(t *testing.T) {
	cases := map[string]string{
		"":                           "",
		"identity":                   "",
		"gzip":                       "gzip",
		"gzip, deflate, br":          "gzip",
		"gzip, deflate, br, zstd":    "zstd", // Chrome 123+/Firefox 126+
		"zstd":                       "zstd",
		"br":                         "", // no brotli encoder here
		"gzip;q=1.0, identity;q=0.5": "gzip",
		"zstd;q=0, gzip":             "gzip",
		"zstd; q=0.000, gzip;q=0.5":  "gzip",
		"gzip;q=0":                   "",
		"zstd;q=0, gzip;q=0":         "",
		"zstd;q=0.1":                 "zstd",
		"zstd;q=x":                   "zstd",
	}
	for accept, want := range cases {
		if got := negotiateEncoding(accept); got != want {
			t.Errorf("negotiateEncoding(%q) = %q, want %q", accept, got, want)
		}
	}
}

// Folder pages negotiate compression and decode to the same complete HTML
// as an uncompressed response.
func TestListingIsCompressedOnTheWire(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	id, _ := shareWithFiles(t, h, "bundle", map[string]string{
		"a/one.txt": "alpha", "a/two.txt": "beta", "b/three.txt": "gamma",
	})

	plain := doReq(t, h, "GET", "/share/"+id+"?dir=a", "", "")
	if enc := plain.Header().Get("Content-Encoding"); enc != "" {
		t.Fatalf("no Accept-Encoding but got Content-Encoding %q", enc)
	}

	for _, tc := range []struct {
		accept, want string
		decode       func(io.Reader) (io.Reader, error)
	}{
		{"gzip", "gzip", func(r io.Reader) (io.Reader, error) { return gzip.NewReader(r) }},
		{"zstd", "zstd", func(r io.Reader) (io.Reader, error) { d, e := zstd.NewReader(r); return d.IOReadCloser(), e }},
	} {
		req := httptest.NewRequest("GET", "/share/"+id+"?dir=a", nil)
		req.Header.Set("Accept-Encoding", tc.accept)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if got := rec.Header().Get("Content-Encoding"); got != tc.want {
			t.Fatalf("Accept-Encoding %q → Content-Encoding %q, want %q", tc.accept, got, tc.want)
		}
		if !strings.Contains(rec.Header().Get("Vary"), "Accept-Encoding") {
			t.Errorf("%s response must Vary: Accept-Encoding", tc.accept)
		}
		if rec.Header().Get("Content-Length") != "" {
			t.Errorf("%s response kept a Content-Length describing the uncompressed body", tc.accept)
		}
		dec, err := tc.decode(rec.Body)
		if err != nil {
			t.Fatalf("%s: %v", tc.accept, err)
		}
		body, err := io.ReadAll(dec)
		if err != nil {
			t.Fatalf("%s decode: %v", tc.accept, err)
		}
		if string(body) != plain.Body.String() || !strings.Contains(string(body), "one.txt") {
			t.Fatalf("%s body is not the full listing (%d bytes)", tc.accept, len(body))
		}
		if rec.Body.Len() >= len(body) {
			t.Errorf("%s made it bigger: %d → %d", tc.accept, len(body), rec.Body.Len())
		}
	}
}

// File bytes are NOT compressed: /download carries an exact Content-Length and
// supports Range, both of which a content encoding would break.
func TestFileDownloadsAreNotCompressed(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	id, slugs := shareWithFiles(t, h, "one", map[string]string{"a.txt": strings.Repeat("compressible ", 500)})
	req := httptest.NewRequest("GET", "/download/"+id+"/"+slugs["a.txt"], nil)
	req.Header.Set("Accept-Encoding", "gzip, zstd")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("download → %d", rec.Code)
	}
	if enc := rec.Header().Get("Content-Encoding"); enc != "" {
		t.Fatalf("download was encoded as %q: breaks Content-Length and Range", enc)
	}
	if rec.Header().Get("Content-Length") == "" {
		t.Error("download lost its Content-Length")
	}
}
