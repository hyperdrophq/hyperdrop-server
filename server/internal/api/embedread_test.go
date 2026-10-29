package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// unlockCookies returns the access cookies a viewer holds after entering the
// password for a protected share.
func unlockCookies(t *testing.T, h http.Handler, id, pw string) []*http.Cookie {
	t.Helper()
	r := httptest.NewRequest("GET", "/share/"+id+"?pw="+pw, nil)
	r.Host = "share.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("no access cookie after unlock (code %d)", rec.Code)
	}
	return cookies
}

// createProtectedFile makes a password-protected share holding one file and
// returns its id and the file's slug.
func createProtectedFile(t *testing.T, h http.Handler, pw, name, content string) (string, string) {
	t.Helper()
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"secret","password":"`+pw+`"}`)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	var cr struct{ ID string }
	unmarshal(t, rec, &cr)
	return cr.ID, uploadGetSlug(t, h, cr.ID, name, content)
}

// fileReq builds a GET for a share's file on the FILE origin with the given
// fetch metadata and access cookies.
func fileReq(path, dest, mode string, cookies []*http.Cookie) *http.Request {
	r := httptest.NewRequest("GET", path, nil)
	r.Host = "files.share.example.com"
	if dest != "" {
		r.Header.Set("Sec-Fetch-Dest", dest)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
	}
	if mode != "" {
		r.Header.Set("Sec-Fetch-Mode", mode)
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	return r
}

// Every user's uploads are served from ONE origin, files.<domain>. So an
// uploaded .html is same-origin with every other share's payload, and the
// viewer's access cookie rides along on the subresource loads that page can
// make. An <iframe> (or a <script>) is a document context the embedding page
// reads directly, so those request shapes never get a protected file's bytes.
//
// The other half of the answer is the sandbox below, which takes away the
// same-origin privilege that makes any of these readable at all.
func TestUploadedPageCannotReadAnUnlockedShareAsADocumentSubresource(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id, slug := createProtectedFile(t, h, "pw123", "a.txt", "TOP-SECRET-PAYLOAD")
	cookies := unlockCookies(t, h, id, "pw123")

	for _, dest := range []string{"iframe", "frame", "fencedframe", "script", "style", "worker"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, fileReq("/view/"+id+"/"+slug, dest, "no-cors", cookies))
		if strings.Contains(rec.Body.String(), "TOP-SECRET-PAYLOAD") {
			t.Errorf("Sec-Fetch-Dest=%s: same-origin script was handed the protected bytes (code %d)",
				dest, rec.Code)
		}
	}
}

// A fetch()/XHR is not how a person opens a share, and it is the most direct
// read an uploaded page can attempt.
func TestScriptedFetchOnTheFileOriginIsRefused(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id, slug := createProtectedFile(t, h, "pw123", "a.txt", "TOP-SECRET-PAYLOAD")
	cookies := unlockCookies(t, h, id, "pw123")

	for _, mode := range []string{"cors", "no-cors", "same-origin"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, fileReq("/view/"+id+"/"+slug, "empty", mode, cookies))
		if strings.Contains(rec.Body.String(), "TOP-SECRET-PAYLOAD") {
			t.Errorf("mode=%s: fetch() was handed the protected bytes (code %d)", mode, rec.Code)
		}
	}
}

// An uploaded page runs on the file origin, so its script is same-origin with
// every other share's bytes. The sandbox puts it in an OPAQUE origin instead:
// it can still render and run its own script, but it cannot read a response
// from files.<domain> through any channel: not an iframe's document, not a
// canvas, not a credentialed fetch. allow-same-origin would hand that
// privilege straight back and must never appear.
func TestUploadedDocumentTypesAreSandboxed(t *testing.T) {
	h := withDomain(t, "share.example.com")
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"pages"}`)
	var cr struct{ ID string }
	unmarshal(t, rec, &cr)

	for _, name := range []string{"page.html", "doc.xhtml", "draw.svg", "feed.xml"} {
		slug := uploadGetSlug(t, h, cr.ID, name, "<x>hi</x>")
		for _, route := range []string{"/view/", "/download/"} {
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, fileReq(route+cr.ID+"/"+slug, "document", "navigate", nil))
			csp := rr.Header().Get("Content-Security-Policy")
			if !strings.Contains(csp, "sandbox") {
				t.Errorf("%s%s: no sandbox CSP (got %q)", route, name, csp)
			}
			if strings.Contains(csp, "allow-same-origin") {
				t.Errorf("%s%s: sandbox grants allow-same-origin (%q)", route, name, csp)
			}
		}
	}
}

// Sandboxing a plain download or an image would cost the file its own origin
// for no gain: only content a browser can turn into a document can read
// anything.
func TestOrdinaryFilesAreNotSandboxed(t *testing.T) {
	h := withDomain(t, "share.example.com")
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"files"}`)
	var cr struct{ ID string }
	unmarshal(t, rec, &cr)

	for _, name := range []string{"notes.txt", "photo.png", "clip.mp4", "report.pdf"} {
		slug := uploadGetSlug(t, h, cr.ID, name, "bytes")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, fileReq("/view/"+cr.ID+"/"+slug, "document", "navigate", nil))
		if csp := rr.Header().Get("Content-Security-Policy"); csp != "" {
			t.Errorf("%s: unexpected CSP %q", name, csp)
		}
	}
}

// A navigation is how a person actually opens a share, the control for the
// tests above.
func TestNavigationWithAValidCookieStillGetsTheFile(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id, slug := createProtectedFile(t, h, "pw123", "a.txt", "TOP-SECRET-PAYLOAD")
	cookies := unlockCookies(t, h, id, "pw123")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, fileReq("/view/"+id+"/"+slug, "document", "navigate", cookies))
	if !strings.Contains(rec.Body.String(), "TOP-SECRET-PAYLOAD") {
		t.Fatalf("navigation did not get the file: code %d body %.200s", rec.Code, rec.Body)
	}
}

// "Save Link As…", and any <a download>, is a NAVIGATION that carries an
// empty destination, measured in Chrome 141:
//
//	dest="empty" mode="navigate" site="same-origin"
//
// Reading `empty` alone as "this is a script" therefore refused the cookie for
// an ordinary download of a protected file. A fetch()/XHR is never
// mode=navigate, so the pair separates them.
func TestSavingAProtectedLinkToDiskKeepsTheCookie(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id, slug := createProtectedFile(t, h, "pw123", "a.txt", "TOP-SECRET-PAYLOAD")
	cookies := unlockCookies(t, h, id, "pw123")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, fileReq("/download/"+id+"/"+slug, "empty", "navigate", cookies))
	if !strings.Contains(rec.Body.String(), "TOP-SECRET-PAYLOAD") {
		t.Fatalf("download did not get the file: code %d body %.200s", rec.Code, rec.Body)
	}
}

// A client with no Sec-Fetch headers at all (curl, an old browser, the app
// itself) must keep working: the headers are a hint, not an authorisation.
func TestPlainClientWithNoSecFetchHeadersStillGetsTheFile(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id, slug := createProtectedFile(t, h, "pw123", "a.txt", "TOP-SECRET-PAYLOAD")
	cookies := unlockCookies(t, h, id, "pw123")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, fileReq("/view/"+id+"/"+slug, "", "", cookies))
	if !strings.Contains(rec.Body.String(), "TOP-SECRET-PAYLOAD") {
		t.Fatalf("plain client did not get the file: code %d body %.200s", rec.Code, rec.Body)
	}
}

// The listing and waiting pages poll their own share's status with fetch(),
// which is `dest: empty, mode: cors`. That request is on the APP origin, where
// nothing but our own pages is ever served, so refusing it as "scripted" only
// breaks the poll: it 401s, the page reloads on 401, and a protected share
// with an upload still running reloads itself every 1.5 s.
func TestStatusPollFromOurOwnPageKeepsTheCookie(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id, _ := createProtectedFile(t, h, "pw123", "a.txt", "TOP-SECRET-PAYLOAD")
	cookies := unlockCookies(t, h, id, "pw123")

	r := httptest.NewRequest("GET", "/share/"+id+"/status", nil)
	r.Host = "share.example.com"
	r.Header.Set("Sec-Fetch-Dest", "empty")
	r.Header.Set("Sec-Fetch-Mode", "cors")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	for _, c := range cookies {
		r.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 200 {
		t.Fatalf("status poll = %d, want 200: %s", rec.Code, rec.Body)
	}
}

// …and without the cookie it still refuses, or the password would be
// bypassable by asking for the JSON instead of the page.
func TestStatusPollWithoutACookieIsStillRefused(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id, _ := createProtectedFile(t, h, "pw123", "a.txt", "TOP-SECRET-PAYLOAD")

	r := httptest.NewRequest("GET", "/share/"+id+"/status", nil)
	r.Host = "share.example.com"
	r.Header.Set("Sec-Fetch-Dest", "empty")
	r.Header.Set("Sec-Fetch-Mode", "cors")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 401 {
		t.Fatalf("status poll without a cookie = %d, want 401", rec.Code)
	}
}
