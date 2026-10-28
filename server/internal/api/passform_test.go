package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestBrowserFormFlow(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"secret","password":"hunter2"}`)
	var cr struct{ ID string }
	unmarshal(t, rec, &cr)
	slug := uploadGetSlug(t, h, cr.ID, "a.txt", "data")

	// GET a protected route with no auth → HTML form, 200, no bytes
	form := doReq(t, h, "GET", "/share/"+cr.ID, "", "")
	if form.Code != 200 || !strings.Contains(form.Body.String(), "<form") ||
		!strings.Contains(strings.ToLower(form.Body.String()), "password") {
		t.Fatalf("expected password form, got %d %s", form.Code, form.Body)
	}

	// POST correct password → 303 redirect + Set-Cookie
	body := url.Values{"password": {"hunter2"}, "next": {"/share/" + cr.ID}}.Encode()
	sub := doReqForm(t, h, "POST", "/unlock/"+cr.ID, body)
	if sub.Code != 303 {
		t.Fatalf("submit = %d, want 303", sub.Code)
	}
	cookie := sub.Header().Get("Set-Cookie")
	if !strings.HasPrefix(cookie, "hd_"+cr.ID+"=") {
		t.Fatalf("no access cookie: %q", cookie)
	}

	// Re-request WITH the cookie → 200 + bytes
	authed := doReqWithHeader(t, h, "GET", "/download/"+cr.ID+"/"+slug, "Cookie", strings.SplitN(cookie, ";", 2)[0])
	if authed.Code != 200 || authed.Body.String() != "data" {
		t.Fatalf("with cookie: %d %q", authed.Code, authed.Body)
	}

	// Wrong password → form again, no access cookie (the form still mints a
	// visitor cookie, since it is shown again regardless of the password).
	badBody := url.Values{"password": {"nope"}}.Encode()
	bad := doReqForm(t, h, "POST", "/unlock/"+cr.ID, badBody)
	for _, c := range bad.Result().Cookies() {
		if c.Name == "hd_"+cr.ID {
			t.Fatal("wrong password set an access cookie")
		}
	}
}

// Free names put every user on a sibling of the same parent, and a browser
// sends a cookie set with Domain=<parent> to all of them. A stranger's server
// cannot read this cookie, which is scoped to its own name, and cannot forge
// one, which is signed with this server's own secret. What it CAN do is send
// a same-named cookie of its own, and a reader that looked at only the first
// match would take the decoy and ask a visitor for the password again.
func TestAShadowingCookieDoesNotUnauthenticateAVisitor(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"secret","password":"hunter2"}`)
	var cr struct{ ID string }
	unmarshal(t, rec, &cr)
	slug := uploadGetSlug(t, h, cr.ID, "a.txt", "data")

	body := url.Values{"password": {"hunter2"}, "next": {"/share/" + cr.ID}}.Encode()
	sub := doReqForm(t, h, "POST", "/unlock/"+cr.ID, body)
	real := strings.SplitN(sub.Header().Get("Set-Cookie"), ";", 2)[0]
	if !strings.HasPrefix(real, "hd_"+cr.ID+"=") {
		t.Fatalf("no access cookie: %q", real)
	}
	decoy := "hd_" + cr.ID + "=0.deadbeef"

	// Either order: nothing decides which one a browser sends first.
	for _, header := range []string{decoy + "; " + real, real + "; " + decoy} {
		got := doReqWithHeader(t, h, "GET", "/download/"+cr.ID+"/"+slug, "Cookie", header)
		if got.Code != 200 || got.Body.String() != "data" {
			t.Fatalf("cookies %q: got %d %q, want the real one to be honoured",
				header, got.Code, got.Body)
		}
	}

	// A decoy on its own still proves nothing: it must not serve the bytes.
	// The status alone cannot say so, the password form being a 200 too.
	only := doReqWithHeader(t, h, "GET", "/download/"+cr.ID+"/"+slug, "Cookie", decoy)
	if only.Body.String() == "data" {
		t.Fatal("an unsigned cookie served the file")
	}
}

func TestPasswordSubmitOpenRedirect(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"secret","password":"hunter2"}`)
	var cr struct{ ID string }
	unmarshal(t, rec, &cr)
	slug := uploadGetSlug(t, h, cr.ID, "a.txt", "data")

	// A protocol-relative "next" must NOT be honored: browsers treat
	// "//evil.com" as an absolute, cross-origin redirect (CWE-601).
	body := url.Values{"password": {"hunter2"}, "next": {"//evil.com"}}.Encode()
	sub := doReqForm(t, h, "POST", "/unlock/"+cr.ID, body)
	if sub.Code != 303 {
		t.Fatalf("submit = %d, want 303", sub.Code)
	}
	if loc := sub.Header().Get("Location"); loc != "/share/"+cr.ID {
		t.Fatalf("open redirect not closed: Location = %q, want /share/%s", loc, cr.ID)
	}

	// A backslash-prefixed "next" must also be rejected: browsers normalize
	// "\" to "/", so "/\evil.com" would become "//evil.com" (CWE-601).
	backslashBody := url.Values{"password": {"hunter2"}, "next": {"/\\evil.com"}}.Encode()
	subBackslash := doReqForm(t, h, "POST", "/unlock/"+cr.ID, backslashBody)
	if subBackslash.Code != 303 {
		t.Fatalf("submit = %d, want 303", subBackslash.Code)
	}
	if loc := subBackslash.Header().Get("Location"); loc != "/share/"+cr.ID {
		t.Fatalf("backslash open redirect not closed: Location = %q, want /share/%s", loc, cr.ID)
	}

	// A normal, local "next" (e.g. a direct-download link) is still honored.
	next := "/download/" + cr.ID + "/" + slug
	body2 := url.Values{"password": {"hunter2"}, "next": {next}}.Encode()
	sub2 := doReqForm(t, h, "POST", "/unlock/"+cr.ID, body2)
	if sub2.Code != 303 {
		t.Fatalf("submit = %d, want 303", sub2.Code)
	}
	if loc := sub2.Header().Get("Location"); loc != next {
		t.Fatalf("valid next not honored: Location = %q, want %q", loc, next)
	}
}

// unlockNext keeps a visitor on this share's own addresses and nothing else.
// Each case is the raw form value, so "%09" here is what a form posting
// next=/%2509/evil.com hands over: url.Parse decodes it to a tab in the path,
// and browsers strip a tab out of a Location, which leaves //evil.com.
func TestUnlockNextStaysOnTheSharesOwnRoutes(t *testing.T) {
	const id, fb = "abcdefghij", "/share/abcdefghij"
	for _, tc := range []struct{ raw, want string }{
		{"/share/" + id, "/share/" + id},
		{"/share/" + id + "?dir=photos%2F2024", "/share/" + id + "?dir=photos%2F2024"},
		{"/share/" + id + "?files=1&pw=hunter2", "/share/" + id + "?files=1"},
		{"/zip/" + id + "?dir=photos", "/zip/" + id + "?dir=photos"},
		{"/view/" + id + "/0f8e6d1c-0000-4000-8000-000000000000", "/view/" + id + "/0f8e6d1c-0000-4000-8000-000000000000"},
		{"/download/" + id + "/slug?pw=x", "/download/" + id + "/slug"},
		{"/site/" + id + "/My%20Page.html?q=a+b", "/site/" + id + "/My%20Page.html?q=a+b"},
		{"/site/" + id, "/site/" + id},
		{"/thumb/" + id + "/slug", "/thumb/" + id + "/slug"},
		{"/receive/" + id, "/receive/" + id},

		{"", fb},
		{"//evil.com", fb},
		{"/\\evil.com", fb},
		{"/%5Cevil.com", fb},
		{"/%2F/evil.com", fb},
		{"/%09/evil.com", fb},
		{"/\t/evil.com", fb},
		{"/%0a/evil.com", fb},
		{"/%0d/evil.com", fb},
		{"/%7f/evil.com", fb},
		{"https://evil.com/share/" + id, fb},
		{"//evil.com/share/" + id, fb},
		{"javascript:alert(1)", fb},
		{"/share/" + id + "/../../evil.com", fb},
		{"/view/" + id + "/./x", fb},
		{"/share/" + id + "%09", fb},
		{"/view/" + id + "/%09/evil.com", fb},
		{"/share/otherid000", fb},
		{"/view/otherid000/slug", fb},
		{"/share/" + id + "x", fb},
		{"/api/shares", fb},
		{"/", fb},
	} {
		if got := unlockNext(tc.raw, id, fb); got != tc.want {
			t.Errorf("unlockNext(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

// The redirect after the password keeps the query the form was rendered for:
// a folder's zip asked for behind a password is that folder's zip after it.
func TestUnlockKeepsTheQueryAndDropsThePassword(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"secret","password":"hunter2"}`)
	var cr struct{ ID string }
	unmarshal(t, rec, &cr)
	uploadGetSlug(t, h, cr.ID, "photos/a.txt", "data")

	form := doReq(t, h, "GET", "/zip/"+cr.ID+"?dir=photos", "", "")
	if !strings.Contains(form.Body.String(), `value="/zip/`+cr.ID+`?dir=photos"`) {
		t.Fatalf("the form does not carry the asked-for address:\n%s", form.Body)
	}
	body := url.Values{"password": {"hunter2"}, "next": {"/zip/" + cr.ID + "?dir=photos&pw=wrong"}}.Encode()
	sub := doReqForm(t, h, "POST", "/unlock/"+cr.ID, body)
	if sub.Code != 303 {
		t.Fatalf("submit = %d, want 303", sub.Code)
	}
	if loc := sub.Header().Get("Location"); loc != "/zip/"+cr.ID+"?dir=photos" {
		t.Fatalf("Location = %q, want the folder's zip", loc)
	}
}

// What a password protects must not sit in a shared cache, where the next
// request for the same URL would be answered without the cookie. An open
// share's responses keep their ordinary caching.
func TestProtectedContentIsPrivateToTheBrowser(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"secret","password":"hunter2"}`)
	var cr struct{ ID string }
	unmarshal(t, rec, &cr)
	slug := uploadGetSlug(t, h, cr.ID, "a.txt", "data")
	uploadGetSlug(t, h, cr.ID, "b.txt", "more")
	open := createShare(t, h, "open")
	openSlug := uploadGetSlug(t, h, open, "a.txt", "data")

	for _, p := range []string{
		"/view/" + cr.ID + "/" + slug, "/download/" + cr.ID + "/" + slug,
		"/zip/" + cr.ID, "/share/" + cr.ID,
	} {
		got := doReq(t, h, "GET", p+"?pw=hunter2", "", "")
		if got.Code != 200 {
			t.Fatalf("%s: %d", p, got.Code)
		}
		if cc := got.Header().Get("Cache-Control"); cc != "private" {
			t.Errorf("%s: Cache-Control = %q, want private", p, cc)
		}
	}
	// /site puts a protected share's file under a grant, which a page's
	// asset request then proves access with.
	site := doReq(t, h, "GET", "/site/"+cr.ID+"/a.txt?pw=hunter2", "", "")
	granted := doReqWithHeader(t, h, "GET", site.Header().Get("Location"), "Sec-Fetch-Dest", "image")
	if cc := granted.Header().Get("Cache-Control"); granted.Body.String() != "data" || cc != "private" {
		t.Errorf("granted /site asset: %d, Cache-Control = %q, want private", granted.Code, cc)
	}
	owner := doReq(t, h, "GET", "/download/"+cr.ID+"/"+slug, testToken, "")
	if cc := owner.Header().Get("Cache-Control"); owner.Code != 200 || cc != "private" {
		t.Errorf("owner's fetch: %d, Cache-Control = %q, want private", owner.Code, cc)
	}
	for _, p := range []string{"/view/" + open + "/" + openSlug, "/zip/" + open} {
		if cc := doReq(t, h, "GET", p, "", "").Header().Get("Cache-Control"); cc != "" {
			t.Errorf("open share %s: Cache-Control = %q, want none", p, cc)
		}
	}
}

// A browser that opens a ?pw= link is sent to the same address without the
// password, carrying the cookie, so the password leaves the address bar and
// the history, and a page served at that address cannot read it back. A
// client that is not navigating (curl, the CLI) keeps the bytes in place.
func TestAPasswordInTheAddressIsDroppedForABrowser(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"secret","password":"hunter2"}`)
	var cr struct{ ID string }
	unmarshal(t, rec, &cr)
	slug := uploadGetSlug(t, h, cr.ID, "photos/a.txt", "data")

	for _, p := range []string{"/view/" + cr.ID + "/" + slug, "/zip/" + cr.ID} {
		r := httptest.NewRequest("GET", p+"?dir=photos&pw=hunter2", nil)
		r.Header.Set("Sec-Fetch-Mode", "navigate")
		r.Header.Set("Sec-Fetch-Dest", "document")
		got := httptest.NewRecorder()
		h.ServeHTTP(got, r)
		if got.Code != http.StatusSeeOther {
			t.Fatalf("%s: %d, want 303", p, got.Code)
		}
		if loc := got.Header().Get("Location"); loc != p+"?dir=photos" {
			t.Fatalf("%s: Location = %q, want the address without pw", p, loc)
		}
		if len(got.Result().Cookies()) == 0 {
			t.Fatalf("%s: no access cookie with the redirect", p)
		}
	}
	if got := doReq(t, h, "GET", "/view/"+cr.ID+"/"+slug+"?pw=hunter2", "", ""); got.Body.String() != "data" {
		t.Fatalf("a non-browser ?pw= fetch = %d, want the bytes", got.Code)
	}
}

// A ?pw= link opened in a frame keeps the bytes in place: a cross-site
// frame stores no SameSite=Lax cookie, so a redirect would lead it to the
// password form, and submitting that form inside the frame back to it.
func TestAPasswordInAFramesAddressServesInPlace(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"secret","password":"hunter2"}`)
	var cr struct{ ID string }
	unmarshal(t, rec, &cr)
	slug := uploadGetSlug(t, h, cr.ID, "a.txt", "data")

	for _, dest := range []string{"iframe", "frame"} {
		r := httptest.NewRequest("GET", "/view/"+cr.ID+"/"+slug+"?pw=hunter2", nil)
		r.Header.Set("Sec-Fetch-Mode", "navigate")
		r.Header.Set("Sec-Fetch-Dest", dest)
		r.Header.Set("Sec-Fetch-Site", "cross-site")
		got := httptest.NewRecorder()
		h.ServeHTTP(got, r)
		if got.Code != http.StatusOK || got.Body.String() != "data" {
			t.Fatalf("%s: %d %q, want 200 and the bytes", dest, got.Code, got.Body)
		}
	}
}
