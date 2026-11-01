package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hyperdrop/server/internal/domain"
	"hyperdrop/server/internal/linked"
)

// siteShare makes a share holding a small site and returns its ID. Paths are
// uploaded in the order given; the first is the natural entry point.
func siteShare(t *testing.T, h http.Handler, files ...string) string {
	t.Helper()
	id := createShare(t, h, "site")
	for _, p := range files {
		uploadGetSlug(t, h, id, p, "body of "+p)
	}
	return id
}

// fileGet fetches a path on the FILE origin, which is where payload routes
// answer once a domain is configured.
func fileGet(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	return req(t, h, "GET", "files.share.example.com", path)
}

// The bug this whole route exists for. A page served at /view/{id}/{slug}
// resolves href="style.css" to /view/{id}/style.css, which names nothing, so
// every relative reference in a shared page is dead. Addressed by relpath it
// resolves.
func TestARelativeAssetResolvesByPath(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := siteShare(t, h, "index.html", "style.css")

	if rec := fileGet(t, h, "/view/"+id+"/style.css"); rec.Code != 404 {
		t.Fatalf("the old shape still 404s: /view by filename = %d", rec.Code)
	}
	rec := fileGet(t, h, "/site/"+id+"/style.css")
	if rec.Code != 200 {
		t.Fatalf("/site by relpath = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/css") {
		t.Errorf("Content-Type = %q, want text/css", got)
	}
}

// A directory request is its index, at the root and nested. The trailing
// slash is what a relative href inside that page resolves against, so a
// request without one must redirect rather than serve: without the slash
// every asset would be looked up one directory too high.
func TestADirectoryRequestIsItsIndex(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := siteShare(t, h, "index.html", "docs/index.html", "docs/a.css")

	for _, tc := range []struct {
		path string
		want string // the body we expect to be served
	}{
		{"/site/" + id + "/", "body of index.html"},
		{"/site/" + id + "/docs/", "body of docs/index.html"},
	} {
		rec := fileGet(t, h, tc.path)
		if rec.Code != 200 {
			t.Fatalf("GET %s = %d, want 200", tc.path, rec.Code)
		}
		if rec.Body.String() != tc.want {
			t.Errorf("GET %s served %q, want %q", tc.path, rec.Body, tc.want)
		}
	}

	for _, tc := range []struct{ from, to string }{
		{"/site/" + id, "/site/" + id + "/"},
		{"/site/" + id + "/docs", "/site/" + id + "/docs/"},
	} {
		rec := fileGet(t, h, tc.from)
		if rec.Code != 301 {
			t.Fatalf("GET %s = %d, want 301", tc.from, rec.Code)
		}
		if got := rec.Header().Get("Location"); got != tc.to {
			t.Errorf("GET %s -> %q, want %q", tc.from, got, tc.to)
		}
	}
}

// A share with no index has no directory listing to fall back on: /site serves
// files, and the listing page is /share's job on the app origin.
func TestADirectoryWithNoIndexIsNotFound(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := siteShare(t, h, "a.txt", "docs/b.txt")
	for _, p := range []string{"/site/" + id + "/", "/site/" + id + "/docs/", "/site/" + id + "/docs"} {
		if rec := fileGet(t, h, p); rec.Code != 404 {
			t.Errorf("GET %s = %d, want 404", p, rec.Code)
		}
	}
}

// The server stores on Linux and serves back what it was sent, so the index
// lookup is exact. A Swift or Go caller that matched case-insensitively (as a
// Mac filesystem does) would offer a site the server then cannot open.
func TestIndexMatchingIsCaseSensitive(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := siteShare(t, h, "Index.html")
	if rec := fileGet(t, h, "/site/"+id+"/"); rec.Code != 404 {
		t.Errorf("Index.html served as an index: %d", rec.Code)
	}
	if rec := fileGet(t, h, "/site/"+id+"/Index.html"); rec.Code != 200 {
		t.Errorf("Index.html by its own name = %d, want 200", rec.Code)
	}
}

// Matching against the share's stored paths IS the traversal defence: a path
// the share does not hold cannot be served however it is spelled. A slug is
// refused for the same reason: it is not a relpath the share contains.
func TestSiteRefusesAnythingTheShareDoesNotHold(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := createShare(t, h, "site")
	slug := uploadGetSlug(t, h, id, "index.html", "hello")

	for _, p := range []string{
		"/site/" + id + "/" + slug,
		"/site/" + id + "/../../../etc/passwd",
		"/site/" + id + "/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"/site/" + id + "/./index.html",
		"/site/" + id + "//index.html",
		"/site/" + id + "/nope.html",
	} {
		if rec := fileGet(t, h, p); rec.Code == 200 {
			t.Errorf("GET %s served 200, want a refusal", p)
		}
	}
}

// The sandbox is the reason uploads on one origin cannot reach each other.
// /site must carry it exactly as /view does, or the new route is a hole in the old
// route's defence.
func TestSiteCarriesTheSandbox(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := siteShare(t, h, "index.html", "art.svg", "style.css")

	for _, p := range []string{"index.html", "art.svg"} {
		csp := fileGet(t, h, "/site/"+id+"/"+p).Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "sandbox") {
			t.Errorf("%s: no sandbox CSP (got %q)", p, csp)
		}
		if strings.Contains(csp, "allow-same-origin") {
			t.Errorf("%s: sandbox grants allow-same-origin (%q)", p, csp)
		}
	}
}

// The origin split covers /site like every other payload route: an uploaded page
// must never be reachable on the hostname that serves the listing, the
// password form and the note page.
func TestSiteIsPinnedToTheFileOrigin(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := siteShare(t, h, "index.html")

	rec := req(t, h, "GET", "share.example.com", "/site/"+id+"/index.html")
	if rec.Code != http.StatusPermanentRedirect {
		t.Fatalf("/site on the app origin = %d, want 308", rec.Code)
	}
	if got, want := rec.Header().Get("Location"),
		"https://files.share.example.com/site/"+id+"/index.html"; got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
	if rec := req(t, h, "POST", "share.example.com", "/site/"+id+"/index.html"); rec.Code != 404 {
		t.Errorf("non-GET on the wrong origin = %d, want 404", rec.Code)
	}
}

// setEntry PATCHes a share's entry point.
func setEntry(t *testing.T, h http.Handler, id, entry string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"entry": entry})
	return doReq(t, h, "PATCH", "/api/shares/"+id, testToken, string(body))
}

// pageGet fetches a path on the APP origin, where /share answers.
func pageGet(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	return req(t, h, "GET", "share.example.com", path)
}

// The share link opens the page rather than the file list it is built from,
// and ?files=1 is the listing's own address, the only way back, since the
// site page is the user's own HTML and nothing may be injected into it.
func TestAnEntryPointRedirectsTheShareLink(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := siteShare(t, h, "index.html", "style.css")

	if rec := pageGet(t, h, "/share/"+id); rec.Code != 200 {
		t.Fatalf("with no entry, /share = %d, want the listing", rec.Code)
	}
	if rec := setEntry(t, h, id, "index.html"); rec.Code != 200 {
		t.Fatalf("PATCH entry = %d %s", rec.Code, rec.Body)
	}
	rec := pageGet(t, h, "/share/"+id)
	if rec.Code != 302 {
		t.Fatalf("/share with an entry = %d, want 302", rec.Code)
	}
	if got, want := rec.Header().Get("Location"), "https://files.share.example.com/site/"+id+"/index.html"; got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
	if rec := pageGet(t, h, "/share/"+id+"?files=1"); rec.Code != 200 {
		t.Errorf("/share?files=1 = %d, want the listing", rec.Code)
	}
	// And it is reversible.
	if rec := setEntry(t, h, id, ""); rec.Code != 200 {
		t.Fatalf("clearing the entry = %d %s", rec.Code, rec.Body)
	}
	if rec := pageGet(t, h, "/share/"+id); rec.Code != 200 {
		t.Errorf("after clearing, /share = %d, want the listing", rec.Code)
	}
}

// A web page is one unit from the visitor's point of view. Landing on an early
// index.html while CSS, scripts or images are still pending renders a broken
// site, so both the share link and direct site paths wait for the full
// manifest rather than only for the requested file.
func TestWebPageWaitsUntilEveryFileIsUploaded(t *testing.T) {
	h := withDomain(t, "share.example.com")
	rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"name":"site","folder":true,"entry":"index.html","files":[{"path":"index.html","size":5},{"path":"style.css","size":6}]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	var cr struct{ ID string }
	unmarshal(t, rec, &cr)
	uploadGetSlug(t, h, cr.ID, "index.html", "index")

	for _, got := range []*httptest.ResponseRecorder{
		pageGet(t, h, "/share/"+cr.ID),
		fileGet(t, h, "/site/"+cr.ID+"/index.html"),
	} {
		if got.Code != http.StatusOK {
			t.Fatalf("pending web page = %d, want waiting page", got.Code)
		}
		body := got.Body.String()
		if !strings.Contains(body, "the share will open right here") ||
			!strings.Contains(body, `const shareID = "`+cr.ID+`"`) {
			t.Fatalf("pending web page did not show whole-share progress: %s", body)
		}
	}

	uploadGetSlug(t, h, cr.ID, "style.css", "styles")
	if got := pageGet(t, h, "/share/"+cr.ID); got.Code != http.StatusFound {
		t.Fatalf("completed /share = %d, want redirect", got.Code)
	}
	if got := fileGet(t, h, "/site/"+cr.ID+"/index.html"); got.Code != http.StatusOK || got.Body.String() != "index" {
		t.Fatalf("completed site = %d %q", got.Code, got.Body)
	}
}

// The entry is stored without being checked against the file list, because it
// is set at creation when a manifest's files are all still pending. So it is
// resolved here, and a value naming nothing falls back to the listing rather
// than redirecting into a 404.
func TestAnEntryThatNamesNothingFallsBackToTheListing(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := siteShare(t, h, "index.html", "style.css")
	if rec := setEntry(t, h, id, "missing.html"); rec.Code != 200 {
		t.Fatalf("PATCH = %d %s", rec.Code, rec.Body)
	}
	if rec := pageGet(t, h, "/share/"+id); rec.Code != 200 {
		t.Errorf("/share = %d, want the listing", rec.Code)
	}
}

// An entry point has to be a relative path: it becomes a URL under /site/{id}/.
func TestAnInvalidEntryIsRefused(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := siteShare(t, h, "index.html")
	for _, bad := range []string{"../escape.html", "/abs.html", "."} {
		if rec := setEntry(t, h, id, bad); rec.Code != 400 {
			t.Errorf("PATCH entry=%q = %d, want 400", bad, rec.Code)
		}
	}
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"s","entry":"../x.html"}`)
	if rec.Code != 400 {
		t.Errorf("POST with a traversal entry = %d, want 400", rec.Code)
	}
}

// HTML rows are addressed by relpath, because that is the only address a
// relative href inside them can resolve against. Everything else keeps the
// slug, which is the identity a content replacement donates.
func TestTheListingLinksHTMLByPathAndTheRestBySlug(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := createShare(t, h, "site")
	uploadGetSlug(t, h, id, "index.html", "<html>")
	cssSlug := uploadGetSlug(t, h, id, "style.css", "body{}")

	body := pageGet(t, h, "/share/"+id).Body.String()
	if !strings.Contains(body, `href="https://files.share.example.com/site/`+id+`/index.html"`) {
		t.Error("index.html is not linked by relpath")
	}
	if !strings.Contains(body, `href="https://files.share.example.com/view/`+id+`/`+cssSlug+`"`) {
		t.Error("style.css lost its slug View link")
	}
}

// A linked folder keeps the server filesystem's bytes, and a folder copied
// from a Mac often holds its names decomposed. /site finds such a page by
// the spelling the request carries (the listing's own link) and by the
// composed spelling a page's author typed.
func TestSiteOpensALinkedPageWhoseNameIsDecomposed(t *testing.T) {
	vol := t.TempDir()
	nfd := "café"
	for p, body := range map[string]string{
		"web/" + nfd + ".html":       "<p>page",
		"web/" + nfd + "/index.html": "<p>index",
	} {
		os.MkdirAll(filepath.Dir(filepath.Join(vol, p)), 0o755)
		os.WriteFile(filepath.Join(vol, p), []byte(body), 0o644)
	}
	roots, err := linked.NewRoots(nil, []string{vol}, nil)
	if err != nil {
		t.Fatal(err)
	}
	dom, err := domain.Load(filepath.Join(t.TempDir(), "domain"), "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	if err := dom.Adopt("share.example.com"); err != nil {
		t.Fatal(err)
	}
	b := testBackendWithRoots(t, roots)
	h := New(b, "2.0.0", dom, nil)
	id := linkedShare(t, b, "web")
	for _, spelled := range []string{"cafe%CC%81", "caf%C3%A9"} {
		rec := fileGet(t, h, "/site/"+id+"/"+spelled+".html")
		if rec.Code != 200 || rec.Body.String() != "<p>page" {
			t.Errorf("%s.html = %d, want the page", spelled, rec.Code)
		}
		rec = fileGet(t, h, "/site/"+id+"/"+spelled+"/")
		if rec.Code != 200 || rec.Body.String() != "<p>index" {
			t.Errorf("%s/ = %d, want the folder's index", spelled, rec.Code)
		}
		rec = fileGet(t, h, "/site/"+id+"/"+spelled)
		if rec.Code != http.StatusMovedPermanently && rec.Code != http.StatusFound &&
			rec.Code != http.StatusPermanentRedirect && rec.Code != http.StatusTemporaryRedirect {
			t.Errorf("%s = %d, want the trailing-slash redirect", spelled, rec.Code)
		}
	}
}
