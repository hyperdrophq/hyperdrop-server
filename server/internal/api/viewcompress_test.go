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

// viewBody is a payload big enough that compressing it is unambiguous.
var viewBody = strings.Repeat("the listing of a thousand files is mostly the same bytes. ", 400)

// serveShared uploads body as rel and returns the handler plus the public
// path prefix for its single file (share id + slug).
func serveShared(t *testing.T, rel, body string) (http.Handler, string, string) {
	t.Helper()
	h := newTestAPI(t)
	id := createShare(t, h, "s")
	out := uploadEcho(t, h, id, rel, body)
	slug, _ := out["slug"].(string)
	if slug == "" {
		t.Fatalf("upload %s returned no slug: %v", rel, out)
	}
	return h, id, slug
}

// getWith issues a public GET carrying the given headers.
func getWith(t *testing.T, h http.Handler, path string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeResponse(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	switch enc := rec.Header().Get("Content-Encoding"); enc {
	case "":
		return rec.Body.String()
	case "zstd":
		zr, err := zstd.NewReader(rec.Body)
		if err != nil {
			t.Fatal(err)
		}
		defer zr.Close()
		data, err := io.ReadAll(zr)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	case "gzip":
		gz, err := gzip.NewReader(rec.Body)
		if err != nil {
			t.Fatal(err)
		}
		defer gz.Close()
		data, err := io.ReadAll(gz)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	default:
		t.Fatalf("unexpected Content-Encoding %q", enc)
		return ""
	}
}

func TestViewNegotiatesCompressionForTextTypes(t *testing.T) {
	h, id, slug := serveShared(t, "notes.txt", viewBody)
	for _, enc := range []string{"zstd", "gzip"} {
		rec := getWith(t, h, "/view/"+id+"/"+slug, map[string]string{"Accept-Encoding": enc})
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", enc, rec.Code)
		}
		if got := rec.Header().Get("Content-Encoding"); got != enc {
			t.Errorf("%s: Content-Encoding = %q, want %q", enc, got, enc)
		}
		if got := decodeResponse(t, rec); got != viewBody {
			t.Errorf("%s: decoded body differs from the original (%d vs %d bytes)",
				enc, len(got), len(viewBody))
		}
		if rec.Body.Len() >= len(viewBody) {
			t.Errorf("%s: wire body %d bytes, not smaller than the %d-byte original",
				enc, rec.Body.Len(), len(viewBody))
		}
		// A compressed body is chunked: the stored length does not describe it.
		if got := rec.Header().Get("Content-Length"); got != "" {
			t.Errorf("%s: Content-Length = %q, want it dropped", enc, got)
		}
		if !strings.Contains(rec.Header().Get("Vary"), "Accept-Encoding") {
			t.Errorf("%s: Vary = %q, want Accept-Encoding", enc, rec.Header().Get("Vary"))
		}
	}
}

// zstd wins when the client offers both: it is the better codec and every
// browser that advertises it is recent.
func TestViewPrefersZstdOverGzip(t *testing.T) {
	h, id, slug := serveShared(t, "notes.txt", viewBody)
	rec := getWith(t, h, "/view/"+id+"/"+slug, map[string]string{"Accept-Encoding": "gzip, deflate, zstd"})
	if got := rec.Header().Get("Content-Encoding"); got != "zstd" {
		t.Fatalf("Content-Encoding = %q, want zstd", got)
	}
}

// Range is the resume path: byte offsets refer to the ORIGINAL bytes, so a
// ranged request always gets identity however much the client would accept.
func TestViewNeverCompressesRangeRequests(t *testing.T) {
	h, id, slug := serveShared(t, "notes.txt", viewBody)
	rec := getWith(t, h, "/view/"+id+"/"+slug, map[string]string{
		"Accept-Encoding": "zstd, gzip", "Range": "bytes=0-99"})
	if rec.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206", rec.Code)
	}
	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q, want identity for a Range request", got)
	}
	if got := rec.Body.String(); got != viewBody[:100] {
		t.Errorf("body = %d bytes, want the first 100 original bytes", len(got))
	}
}

// The compressed representation needs its own entity tag: a cache that holds
// the compressed body must not use its ETag to validate a Range request, which
// is answered with identity bytes.
func TestViewTagsEncodedRepresentationsDistinctly(t *testing.T) {
	h, id, slug := serveShared(t, "notes.txt", viewBody)
	plain := getWith(t, h, "/view/"+id+"/"+slug, nil).Header().Get("ETag")
	zstdTag := getWith(t, h, "/view/"+id+"/"+slug,
		map[string]string{"Accept-Encoding": "zstd"}).Header().Get("ETag")
	gzipTag := getWith(t, h, "/view/"+id+"/"+slug,
		map[string]string{"Accept-Encoding": "gzip"}).Header().Get("ETag")
	if plain == "" || zstdTag == "" || gzipTag == "" {
		t.Fatalf("missing ETag: plain=%q zstd=%q gzip=%q", plain, zstdTag, gzipTag)
	}
	if plain == zstdTag || plain == gzipTag || zstdTag == gzipTag {
		t.Fatalf("ETags must differ per encoding: plain=%s zstd=%s gzip=%s", plain, zstdTag, gzipTag)
	}
}

// Media and archives carry their own compression; re-encoding them costs CPU
// on both ends and the exact Content-Length for nothing.
func TestViewLeavesIncompressibleTypesRaw(t *testing.T) {
	h, id, slug := serveShared(t, "shot.png", viewBody)
	rec := getWith(t, h, "/view/"+id+"/"+slug, map[string]string{"Accept-Encoding": "zstd, gzip"})
	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want identity for image/png", got)
	}
	if rec.Header().Get("Content-Length") == "" {
		t.Error("Content-Length dropped on an uncompressed response")
	}
}

// /download and /zip stay raw BY DESIGN: a download progress bar needs the exact
// length, and a zip is already compressed.
func TestDownloadAndZipStayUncompressed(t *testing.T) {
	h, id, slug := serveShared(t, "notes.txt", viewBody)
	for _, path := range []string{"/download/" + id + "/" + slug, "/zip/" + id} {
		rec := getWith(t, h, path, map[string]string{"Accept-Encoding": "zstd, gzip"})
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", path, rec.Code)
		}
		if got := rec.Header().Get("Content-Encoding"); got != "" {
			t.Errorf("%s: Content-Encoding = %q, want identity", path, got)
		}
	}
}

// A client that advertises nothing gets exactly what it always got.
func TestViewWithoutAcceptEncodingIsByteExact(t *testing.T) {
	h, id, slug := serveShared(t, "notes.txt", viewBody)
	rec := getWith(t, h, "/view/"+id+"/"+slug, nil)
	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want none", got)
	}
	if rec.Body.String() != viewBody {
		t.Fatal("body differs from the original")
	}
	if rec.Header().Get("Content-Length") == "" {
		t.Error("Content-Length missing on an identity response")
	}
}
