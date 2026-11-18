package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// sandboxDocument fails closed: a Content-Type Go cannot parse cleanly is
// one a browser may still read as a document (Chrome renders "text/html; x"
// as HTML), so it is sandboxed rather than waved through.
func TestSandboxDocumentFailsClosed(t *testing.T) {
	cases := []struct {
		mime    string
		sandbox bool
	}{
		{"text/html", true},
		{"TEXT/HTML; charset=utf-8", true},
		{"image/svg+xml", true},
		{"application/rss+xml", true},
		{"application/atom+xml", true},
		{"application/xslt+xml", true},
		{"application/mathml+xml", true},
		{"application/vnd.example.page+XML; charset=utf-8", true},
		{"application/x+xml", true},
		{"text/html; x", true},
		{"text/html;;", true},
		{"text/plain,text/html", true},
		{"", true},
		{"text/plain", false},
		{"text/plain; charset=utf-8", false},
		{"image/png", false},
		{"application/pdf", false},
		{"video/mp4", false},
		{"application/json", false},
		{"application/ld+json", false},
	}
	for _, c := range cases {
		w := httptest.NewRecorder()
		sandboxDocument(w, c.mime)
		got := w.Header().Get("Content-Security-Policy") == sandboxCSP
		if got != c.sandbox {
			t.Errorf("sandboxDocument(%q): sandboxed = %v, want %v", c.mime, got, c.sandbox)
		}
	}
}

// A live share's types come from the sharer's client, so the server keeps
// only one that parses cleanly and serves anything else as a download, on
// create and on both PATCH lists.
func TestALiveShareTypeThatDoesNotParseIsADownload(t *testing.T) {
	h := newTestLiveShareHandler(t)
	mux := h.routes()
	sh := createLiveShare(t, mux, testToken, `{"name":"t","files":[`+
		`{"path":"page.html","size":5,"mime":"text/html; x","mtime":"2026-08-06T10:00:00Z"},`+
		`{"path":"a.txt","size":5,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"}]}`)
	for _, body := range []string{
		`{"addFiles":[{"path":"b.html","size":5,"mime":"text/plain,text/html","mtime":"2026-08-06T10:00:00Z"}]}`,
		`{"replaceFiles":[` +
			`{"path":"page.html","size":5,"mime":"text/html; x","mtime":"2026-08-06T10:00:00Z"},` +
			`{"path":"a.txt","size":5,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"},` +
			`{"path":"b.html","size":5,"mime":"text/plain,text/html","mtime":"2026-08-06T10:00:00Z"},` +
			`{"path":"c.html","size":5,"mime":"text/html;;","mtime":"2026-08-06T10:00:00Z"}]}`,
	} {
		if rec := doReq(t, mux, "PATCH", "/api/live-share/"+sh.ID, testToken, body); rec.Code != http.StatusOK {
			t.Fatalf("PATCH: %d %s", rec.Code, rec.Body)
		}
	}
	rec, ok := h.liveShareReg.Get(sh.ID)
	if !ok {
		t.Fatal("live share gone")
	}
	want := map[string]string{
		"page.html": "application/octet-stream",
		"a.txt":     "text/plain",
		"b.html":    "application/octet-stream",
		"c.html":    "application/octet-stream",
	}
	for _, f := range rec.Files {
		if f.Mime != want[f.Path] {
			t.Errorf("%s: mime = %q, want %q", f.Path, f.Mime, want[f.Path])
		}
	}
	if len(rec.Files) != len(want) {
		t.Errorf("files = %d, want %d", len(rec.Files), len(want))
	}
}
