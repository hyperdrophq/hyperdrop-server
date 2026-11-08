package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"hyperdrop/server/internal/domain"
	"hyperdrop/server/internal/metadb"
)

// noEmbedFixture uploads a viewable file for a no-embed user and returns its
// /view URL.
func noEmbedFixture(t *testing.T, h http.Handler, um *metadb.DB) string {
	t.Helper()
	alice := seedUser(t, um, "alice")
	yes := true
	if _, err := um.UpdateUser("alice", metadb.Settings{NoEmbed: &yes}); err != nil {
		t.Fatal(err)
	}
	id := createShareAs(t, h, alice, `{"name":"pic"}`)
	rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/pic.png", alice, "pngbytes")
	var up struct {
		Slug string `json:"slug"`
	}
	unmarshal(t, rec, &up)
	return "/view/" + id + "/" + up.Slug
}

func TestNoEmbedHeadersAndRedirect(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	url := noEmbedFixture(t, h, um)

	// Direct open: served, but stamped with CORP so browsers refuse it as a
	// cross-origin subresource.
	rec := doReq(t, h, "GET", url, "", "")
	if rec.Code != 200 {
		t.Fatalf("direct open: %d", rec.Code)
	}
	if got := rec.Header().Get("Cross-Origin-Resource-Policy"); got != "same-origin" {
		t.Fatalf("CORP header: %q", got)
	}

	// Explicit cross-site embed fetch → redirected to the share page.
	req := httptest.NewRequest("GET", url, nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Sec-Fetch-Dest", "image")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Code != 302 {
		t.Fatalf("cross-site embed: %d, want 302", rec2.Code)
	}

	// Cross-site NAVIGATION (clicking a link on another site) still works.
	req = httptest.NewRequest("GET", url, nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Sec-Fetch-Dest", "document")
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req)
	if rec3.Code != 200 {
		t.Fatalf("cross-site navigation: %d, want 200", rec3.Code)
	}
}

func TestEmbedAllowedByDefault(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	alice := seedUser(t, um, "alice")
	id := createShareAs(t, h, alice, `{"name":"pic"}`)
	rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/pic.png", alice, "png")
	var up struct {
		Slug string `json:"slug"`
	}
	unmarshal(t, rec, &up)
	req := httptest.NewRequest("GET", "/view/"+id+"/"+up.Slug, nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Sec-Fetch-Dest", "image")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Code != 200 {
		t.Fatalf("default embed: %d, want 200", rec2.Code)
	}
	if got := rec2.Header().Get("Cross-Origin-Resource-Policy"); got != "" {
		t.Fatalf("unexpected CORP for embed-allowed user: %q", got)
	}
}

func TestSuspendedOwnerPublicLinks404(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	alice := seedUser(t, um, "alice")
	id := createShareAs(t, h, alice, `{"name":"s"}`)
	rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/a.txt", alice, "hello")
	var up struct {
		Slug string `json:"slug"`
	}
	unmarshal(t, rec, &up)

	// /share/{id}/status is in this list because it is the public route most
	// easily left checking existence and expiry but not the OWNER, which
	// keeps a suspended account's file names and upload progress readable
	// while every other link for the same share correctly 404s.
	paths := []string{"/share/" + id, "/share/" + id + "/status",
		"/view/" + id + "/" + up.Slug, "/download/" + id + "/" + up.Slug, "/zip/" + id}
	for _, p := range paths {
		if rec := doReq(t, h, "GET", p, "", ""); rec.Code == 404 {
			t.Fatalf("%s dead before suspension: %d", p, rec.Code)
		}
	}

	yes := true
	um.UpdateUser("alice", metadb.Settings{Disabled: &yes})
	for _, p := range paths {
		if rec := doReq(t, h, "GET", p, "", ""); rec.Code != 404 {
			t.Errorf("%s while suspended: %d, want 404", p, rec.Code)
		}
	}

	no := false
	um.UpdateUser("alice", metadb.Settings{Disabled: &no})
	for _, p := range paths {
		if rec := doReq(t, h, "GET", p, "", ""); rec.Code == 404 {
			t.Errorf("%s after resume: %d, want served again", p, rec.Code)
		}
	}
}

// noEmbedDomainAPI is a handler with the origin split live and a no-embed
// account, alice, holding share id: a site opening at its page, index.html,
// beside a picture.
func noEmbedDomainAPI(t *testing.T) (h http.Handler, id, pic string) {
	t.Helper()
	h, id, pic, _ = noEmbedDomainParts(t)
	return h, id, pic
}

// noEmbedDomainParts is noEmbedDomainAPI with the plain picture share of
// the same owner beside the site: plain is its id, holding pic.png alone.
func noEmbedDomainParts(t *testing.T) (h http.Handler, id, pic, plain string) {
	t.Helper()
	b := testBackend(t)
	dom, err := domain.Load(filepath.Join(t.TempDir(), "domain"), "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	if err := dom.Adopt("share.example.com"); err != nil {
		t.Fatal(err)
	}
	h = New(b, "2.0.0", dom, nil)
	alice := seedUser(t, b.DB, "alice")
	yes := true
	if _, err := b.DB.UpdateUser("alice", metadb.Settings{NoEmbed: &yes}); err != nil {
		t.Fatal(err)
	}
	id = createShareAs(t, h, alice, `{"name":"pics","entry":"index.html"}`)
	rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/pic.png", alice, "pngbytes")
	var up struct {
		Slug string `json:"slug"`
	}
	unmarshal(t, rec, &up)
	doReq(t, h, "PUT", "/api/shares/"+id+"/files/index.html", alice, "<img src=pic.png>")
	plain = createShareAs(t, h, alice, `{"name":"plain"}`)
	doReq(t, h, "PUT", "/api/shares/"+plain+"/files/pic.png", alice, "pngbytes")
	return h, id, up.Slug, plain
}

func embedReq(h http.Handler, path, site, dest, referer string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", path, nil)
	r.Host = "files.share.example.com"
	r.Header.Set("Sec-Fetch-Site", site)
	r.Header.Set("Sec-Fetch-Dest", dest)
	if referer != "" {
		r.Header.Set("Referer", referer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// The gallery renders on the app origin and loads every picture from the
// file origin: same-site, never same-origin. A no-embed owner's own gallery
// must still show its pictures, while a sibling server under the same
// registrable domain, which is same-site too, stays refused.
func TestNoEmbedAdmitsThisServersOwnPagesOnly(t *testing.T) {
	h, id, slug := noEmbedDomainAPI(t)
	view := "/view/" + id + "/" + slug

	rec := embedReq(h, view, "same-site", "image", "https://share.example.com/share/"+id)
	if rec.Code != 200 {
		t.Fatalf("own gallery: %d", rec.Code)
	}
	if got := rec.Header().Get("Cross-Origin-Resource-Policy"); got != "same-site" {
		t.Fatalf("own gallery CORP = %q, want same-site", got)
	}
	for _, ref := range []string{"https://other.example.com/", "http://share.example.com/", ""} {
		rec = embedReq(h, view, "same-site", "image", ref)
		if got := rec.Header().Get("Cross-Origin-Resource-Policy"); got != "same-origin" {
			t.Fatalf("Referer %q: CORP = %q, want same-origin", ref, got)
		}
	}
	if v := rec.Header().Values("Vary"); len(v) == 0 || !strings.Contains(strings.Join(v, ","), "Referer") {
		t.Fatalf("Vary = %q, want it to name Referer", v)
	}
}

// /site of a share that opens as a page is not covered by no-embed: a
// site's own pages run in the sandbox's opaque origin, so their assets
// arrive as cross-site embeds, and refusing those would leave every page of
// a no-embed owner's site without them. Any other share keeps the setting
// on /site, or a file's path would be the way around it.
func TestNoEmbedLeavesASitesOwnAssetsAlone(t *testing.T) {
	h, id, _, plain := noEmbedDomainParts(t)
	rec := embedReq(h, "/site/"+id+"/pic.png", "cross-site", "image", "")
	if rec.Code != 200 {
		t.Fatalf("site asset: %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Cross-Origin-Resource-Policy"); got != "" {
		t.Fatalf("site asset CORP = %q, want none", got)
	}
	rec = embedReq(h, "/site/"+plain+"/pic.png", "cross-site", "image", "")
	if rec.Code != http.StatusFound || rec.Body.String() == "pngbytes" {
		t.Fatalf("plain share's file by path: %d %q, want 302 to the share", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Cross-Origin-Resource-Policy"); got != "same-origin" {
		t.Fatalf("plain share's file by path CORP = %q, want same-origin", got)
	}
}
