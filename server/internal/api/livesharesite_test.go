package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/liveshare"
	"hyperdrop/server/internal/metadb"
)

const liveShareSiteBody = `{"name":"site","entry":"index.html","files":[` +
	`{"path":"index.html","size":5,"mime":"text/html","mtime":"2026-08-06T10:00:00Z"},` +
	`{"path":"style.css","size":5,"mime":"text/css","mtime":"2026-08-06T10:00:00Z"}]}`

// A live share opens as a web page exactly as a stored one does: the entry
// page is set at creation, /share/{id} lands on it, and /site relays the
// page and its assets off the sharer's Mac through the same sandboxed serve
// path a stored page takes.
func TestALiveShareOpensAsAWebPage(t *testing.T) {
	h := newTestLiveShareHandler(t)
	mux := h.routes()
	sh := createLiveShare(t, mux, testToken, liveShareSiteBody)
	if sh.Entry != "index.html" {
		t.Fatalf("created share entry = %q, want index.html", sh.Entry)
	}
	serveLiveShareBody(t, h, sh.ID, metadb.DefaultAdminName, "hello")

	rec := doReq(t, mux, "GET", "/share/"+sh.ID, "", "")
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/site/"+sh.ID+"/index.html" {
		t.Fatalf("/share = %d %q, want 302 to the entry page: %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	for _, path := range []string{"/site/" + sh.ID + "/index.html", "/site/" + sh.ID + "/"} {
		rec = doLiveShareGet(t, mux, path, nil)
		if rec.Code != http.StatusOK || rec.Body.String() != "hello" {
			t.Fatalf("GET %s = %d %q, want the relayed page", path, rec.Code, rec.Body.String())
		}
		if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "sandbox") {
			t.Fatalf("GET %s served a page without the sandbox policy: %q", path, csp)
		}
	}
}

// The entry must name a file the relay serves: the manifest is complete at
// creation, so there is nothing to wait for and nothing to guess.
func TestAStreamEntryMustNameAFileOfTheShare(t *testing.T) {
	h := newTestLiveShareHandler(t)
	mux := h.routes()
	body := strings.Replace(liveShareSiteBody, `"entry":"index.html"`, `"entry":"missing.html"`, 1)
	rec := doReq(t, mux, "POST", "/api/live-share", testToken, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("entry naming no file = %d, want 400: %s", rec.Code, rec.Body)
	}
	// An entry and a listing are two answers to the one question.
	body = strings.Replace(liveShareSiteBody, `"entry":"index.html"`, `"entry":"index.html","listing":true`, 1)
	rec = doReq(t, mux, "POST", "/api/live-share", testToken, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("entry beside listing = %d, want 400: %s", rec.Code, rec.Body)
	}
}

// A running relay switches to a web page and back through PATCH, the way a
// stored share does through its own edit.
func TestALiveShareSwitchesToAndFromAWebPage(t *testing.T) {
	h := newTestLiveShareHandler(t)
	mux := h.routes()
	body := strings.Replace(liveShareSiteBody, `"entry":"index.html",`, ``, 1)
	sh := createLiveShare(t, mux, testToken, body)
	if sh.Entry != "" {
		t.Fatalf("created without entry, got %q", sh.Entry)
	}
	rec := doReq(t, mux, "GET", "/share/"+sh.ID, "", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "style.css") {
		t.Fatalf("/share before the switch = %d, want the listing: %s", rec.Code, rec.Body)
	}

	rec = doReq(t, mux, "PATCH", "/api/live-share/"+sh.ID, testToken, `{"entry":"index.html"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH entry = %d %s", rec.Code, rec.Body)
	}
	rec = doReq(t, mux, "GET", "/share/"+sh.ID, "", "")
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/site/"+sh.ID+"/index.html" {
		t.Fatalf("/share after the switch = %d %q, want the entry page", rec.Code, rec.Header().Get("Location"))
	}

	rec = doReq(t, mux, "PATCH", "/api/live-share/"+sh.ID, testToken, `{"entry":"nope.html"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PATCH entry naming no file = %d, want 400: %s", rec.Code, rec.Body)
	}
	rec = doReq(t, mux, "PATCH", "/api/live-share/"+sh.ID, testToken, `{"entry":"index.html","media":true}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PATCH entry beside media = %d, want 400: %s", rec.Code, rec.Body)
	}

	rec = doReq(t, mux, "PATCH", "/api/live-share/"+sh.ID, testToken, `{"entry":""}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH entry off = %d %s", rec.Code, rec.Body)
	}
	rec = doReq(t, mux, "GET", "/share/"+sh.ID, "", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "style.css") {
		t.Fatalf("/share after switching back = %d, want the listing: %s", rec.Code, rec.Body)
	}
}

// A page of a stream whose sharer is away answers the same offline page a
// file link does, never a 404 that reads as "no such share".
func TestALiveShareSiteIsOfflineWithTheSharer(t *testing.T) {
	now := time.Now()
	h := newTestHandlerLiveShare(t, liveshare.Config{
		OfflineAfter: 10 * time.Second,
		Now:          func() time.Time { return now },
	})
	mux := h.routes()
	sh := createLiveShare(t, mux, testToken, liveShareSiteBody)
	// Nothing polls this share, so once OfflineAfter passes it reads as
	// offline with no sleep required.
	now = now.Add(15 * time.Second)
	rec := doReq(t, mux, "GET", "/site/"+sh.ID+"/index.html", "", "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("offline stream page = %d, want 503: %s", rec.Code, rec.Body)
	}
}
