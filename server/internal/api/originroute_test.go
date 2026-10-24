package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"hyperdrop/server/internal/domain"
)

// withDomain builds a handler whose domain is already configured, so the
// origin split is live. Adopt rather than Set: Set verifies the domain
// resolves HERE, which no unit test can arrange.
func withDomain(t *testing.T, name string) http.Handler {
	t.Helper()
	dom, err := domain.Load(filepath.Join(t.TempDir(), "domain"), "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	if err := dom.Adopt(name); err != nil {
		t.Fatalf("Adopt(%q): %v", name, err)
	}
	return New(testBackend(t), "2.0.0", dom, nil)
}

// createShareWithPassword makes a password-protected share holding one file
// and returns its ID.
func createShareWithPassword(t *testing.T, h http.Handler, name, password string) string {
	t.Helper()
	rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"name":"`+name+`","password":"`+password+`"}`)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	var cr struct{ ID string }
	unmarshal(t, rec, &cr)
	uploadGetSlug(t, h, cr.ID, "a.txt", "data")
	return cr.ID
}

func req(t *testing.T, h http.Handler, method, host, path string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, nil)
	r.Host = host
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// The whole point of the split: an uploaded .html must not be servable from
// the origin that hosts the listing and the password form.
func TestPayloadOnTheAppOriginRedirectsToTheFileOrigin(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := createShare(t, h, "mine")

	rec := req(t, h, "GET", "share.example.com", "/view/"+id+"/whatever")
	if rec.Code != http.StatusPermanentRedirect {
		t.Fatalf("code = %d, want 308", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "https://files.share.example.com/view/") {
		t.Errorf("Location = %q, want the file origin", loc)
	}
}

func TestListingOnTheFileOriginRedirectsBack(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := createShare(t, h, "mine")

	rec := req(t, h, "GET", "files.share.example.com", "/share/"+id)
	if rec.Code != http.StatusPermanentRedirect {
		t.Fatalf("code = %d, want 308", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "https://share.example.com/share/") {
		t.Errorf("Location = %q, want the app origin", loc)
	}
}

// Only GETs are links somebody might hold. Anything else on the wrong origin
// is a mistake or a probe, and must not be redirected into a replay.
func TestNonGetOnTheWrongOriginIs404(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := createShare(t, h, "mine")
	rec := req(t, h, "POST", "files.share.example.com", "/unlock/"+id)
	if rec.Code != http.StatusNotFound {
		t.Errorf("code = %d, want 404", rec.Code)
	}
}

// Sniffing routes around every decision made from the declared Content-Type.
func TestEveryResponseCarriesNoSniff(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := createShare(t, h, "mine")
	for _, c := range []struct{ host, path string }{
		{"share.example.com", "/share/" + id},
		{"share.example.com", "/api/health"},
		{"files.share.example.com", "/zip/" + id},
	} {
		rec := req(t, h, "GET", c.host, c.path)
		if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s%s: X-Content-Type-Options = %q", c.host, c.path, got)
		}
	}
}

// A share unlocked on the app origin has to stay unlocked when its files
// download from the file origin, so the cookie is scoped to cover both.
func TestAccessCookieIsScopedToCoverBothOrigins(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := createShareWithPassword(t, h, "secret", "pw123")

	r := httptest.NewRequest("GET", "/share/"+id+"?pw=pw123", nil)
	r.Host = "share.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	var found *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if strings.HasPrefix(c.Name, "hd_") {
			found = c
		}
	}
	if found == nil {
		t.Fatalf("no access cookie set (code %d)", rec.Code)
	}
	if found.Domain != "share.example.com" {
		t.Errorf("cookie Domain = %q, want share.example.com so files.* receives it", found.Domain)
	}
}

// Script on the file origin would read a share the viewer had unlocked by
// fetching it with the cookie attached. A person never reaches a share's
// BYTES that way: they navigate, or save the link.
//
// The rule is per-origin: our own pages live on the app origin and do fetch
// their own JSON (the status poll), and no upload is ever served from there,
// so the refusal belongs on the file origin.
func TestAccessCookieIsNotHonouredForAScriptedFetch(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := createShareWithPassword(t, h, "secret", "pw123")

	unlock := httptest.NewRequest("GET", "/share/"+id+"?pw=pw123", nil)
	unlock.Host = "share.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, unlock)
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("no cookie to replay (code %d)", rec.Code)
	}

	// A navigation with the cookie is fine.
	nav := httptest.NewRequest("GET", "/share/"+id, nil)
	nav.Host = "share.example.com"
	nav.Header.Set("Sec-Fetch-Dest", "document")
	for _, c := range cookies {
		nav.AddCookie(c)
	}
	navRec := httptest.NewRecorder()
	h.ServeHTTP(navRec, nav)
	// A single-file share redirects straight to its file, which IS the
	// unlocked answer; the locked answer is the password form.
	if navRec.Code != http.StatusFound {
		t.Fatalf("navigation with a valid cookie = %d, want the unlocked redirect", navRec.Code)
	}
	if loc := navRec.Header().Get("Location"); !strings.Contains(loc, "/view/") {
		t.Fatalf("navigation redirected to %q, want the file", loc)
	}

	// The same cookie on a fetch()/XHR for the BYTES is not honoured: the
	// password form comes back instead of the file.
	viewPrefix := "https://files.share.example.com/view/" + id + "/"
	slug, onFileOrigin := strings.CutPrefix(navRec.Header().Get("Location"), viewPrefix)
	if !onFileOrigin || slug == "" || strings.Contains(slug, "/") {
		t.Fatalf("navigation redirected to %q, want %s<slug>", navRec.Header().Get("Location"), viewPrefix)
	}
	x := httptest.NewRequest("GET", "/view/"+id+"/"+slug, nil)
	x.Host = "files.share.example.com"
	x.Header.Set("Sec-Fetch-Dest", "empty")
	x.Header.Set("Sec-Fetch-Mode", "cors")
	for _, c := range cookies {
		x.AddCookie(c)
	}
	xRec := httptest.NewRecorder()
	h.ServeHTTP(xRec, x)
	if !strings.Contains(xRec.Body.String(), "password") {
		t.Errorf("scripted fetch got %d, want the password form: %.200s", xRec.Code, xRec.Body)
	}
}

// The waiting page for a pending /view|/download|/zip link renders on the FILE origin and
// polls the relative /share/{id}/status with fetch(). Pinned to the app
// origin, that poll answers 308, which a fetch() cannot follow cross-origin
// without CORS, leaving the page on "waiting for the first bytes…" through
// the upload and after it commits. The status sub-route answers on BOTH
// origins.
func TestStatusAnswersOnTheFileOrigin(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := createShare(t, h, "mine")
	rec := req(t, h, "GET", "files.share.example.com", "/share/"+id+"/status")
	if rec.Code != http.StatusOK {
		t.Fatalf("status on the file origin = %d, want 200 (Location %q)",
			rec.Code, rec.Header().Get("Location"))
	}
	// The listing itself stays pinned: only the status sub-route travels.
	if rec := req(t, h, "GET", "files.share.example.com", "/share/"+id); rec.Code != http.StatusPermanentRedirect {
		t.Fatalf("listing on the file origin = %d, want 308", rec.Code)
	}
}

// A PROTECTED share's waiting page needs its poll to carry the access
// cookie. The poll is a fetch (Sec-Fetch-Dest: empty), which the file origin
// otherwise refuses, but this one comes from OUR OWN waiting page on the
// same origin (an uploaded page is sandboxed into an opaque origin, whose
// fetches arrive Sec-Fetch-Site: cross-site), and status is progress
// metadata, never payload bytes.
func TestProtectedStatusPollOnTheFileOriginHonoursTheCookie(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := createShareWithPassword(t, h, "secret", "pw123")

	unlock := httptest.NewRequest("GET", "/share/"+id+"?pw=pw123", nil)
	unlock.Host = "share.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, unlock)
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("no cookie to replay (code %d)", rec.Code)
	}

	poll := func(site string) int {
		r := httptest.NewRequest("GET", "/share/"+id+"/status", nil)
		r.Host = "files.share.example.com"
		r.Header.Set("Sec-Fetch-Dest", "empty")
		r.Header.Set("Sec-Fetch-Mode", "cors")
		r.Header.Set("Sec-Fetch-Site", site)
		for _, c := range cookies {
			r.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}
	if got := poll("same-origin"); got != http.StatusOK {
		t.Errorf("same-origin waiting-page poll = %d, want 200", got)
	}
	if got := poll("cross-site"); got != http.StatusUnauthorized {
		t.Errorf("cross-site poll = %d, want 401: a sandboxed page's fetch must stay refused", got)
	}
}
