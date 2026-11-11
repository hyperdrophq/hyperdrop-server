package api

import (
	"bytes"
	"image/png"
	"net/http"
	"strings"
	"testing"
)

func TestTheIconCarriesNoScript(t *testing.T) {
	if strings.Contains(strings.ToLower(string(iconSVG)), "<script") {
		t.Fatal("the icon carries a script")
	}
}

// The touch icon is what iOS shows as a page's lock-screen artwork while it
// plays sound, and a page of the server's may render on either origin, so it
// answers on both, as an opaque 512 px square, and every page links it with
// the size it is.
func TestTheTouchIconAnswersOnBothOrigins(t *testing.T) {
	h := withDomain(t, "share.example.com")
	for _, host := range []string{"share.example.com", "files.share.example.com"} {
		rec := req(t, h, "GET", host, "/apple-touch-icon.png")
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "image/png" {
			t.Fatalf("%s: %d %q", host, rec.Code, rec.Header().Get("Content-Type"))
		}
		if got := rec.Header().Get("Cache-Control"); got != "public, max-age=604800" || rec.Header().Get("ETag") == "" {
			t.Errorf("%s: Cache-Control %q, ETag %q", host, got, rec.Header().Get("ETag"))
		}
		img, err := png.Decode(bytes.NewReader(rec.Body.Bytes()))
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		if b := img.Bounds(); b.Dx() != 512 || b.Dy() != 512 {
			t.Fatalf("%s: the touch icon is %dx%d, want 512x512", host, b.Dx(), b.Dy())
		}
		for _, p := range [][2]int{{0, 0}, {511, 0}, {0, 511}, {511, 511}} {
			if _, _, _, a := img.At(p[0], p[1]).RGBA(); a != 0xffff {
				t.Fatalf("%s: pixel %v is not opaque", host, p)
			}
		}
	}
	const link = `<link rel="apple-touch-icon" sizes="512x512" href="/apple-touch-icon.png">`
	if !strings.Contains(brandPartials, link) {
		t.Fatalf("the server's pages do not link the touch icon as %s", link)
	}
}
