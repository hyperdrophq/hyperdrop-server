package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every page that says the file came through HyperDrop links the name to the
// site, and a page that carries the brand without the link is a page someone
// forgot: the check walks the templates rather than a list of them.
func TestEveryBrandLineLinksToTheSite(t *testing.T) {
	const site = `href="https://gethyperdrop.com"`
	files, err := filepath.Glob("pages/*.html")
	if err != nil || len(files) == 0 {
		t.Fatalf("pages: %v %v", files, err)
	}
	seen := 0
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		s := string(data)
		if !strings.Contains(s, "Powered by") && !strings.Contains(s, "Shared with") {
			continue
		}
		seen++
		if !strings.Contains(s, site) {
			t.Errorf("%s carries the brand line without linking HyperDrop to the site", f)
		}
	}
	if seen < 5 {
		t.Fatalf("only %d pages carry a brand line; the listing, gallery, waiting, unavailable, inbox and 404 pages all do", seen)
	}
	// Rendered, not only in the template: the 404 page is the one a visitor
	// with a stale link lands on.
	h := newTestAPI(t)
	rec := doReq(t, h, "GET", "/share/nosuchshare", "", "")
	if rec.Code != 404 || !strings.Contains(rec.Body.String(), site) {
		t.Fatalf("404 page: %d, link present: %v", rec.Code, strings.Contains(rec.Body.String(), site))
	}
}
