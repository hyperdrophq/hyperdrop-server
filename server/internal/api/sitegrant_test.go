package api

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// grantRe matches a leftover granted /site address. Page links must not
// use that shape: it is not a shareable key.
var grantRe = regexp.MustCompile(`^/site/([A-Za-z0-9]+)/(\d+\.[0-9a-f]{64})/(.*)$`)

// protectedSite makes a site share (an index and a stylesheet beside it)
// and then locks it with a password through PATCH, the order in which a
// person turns a working site into a protected one.
func protectedSite(t *testing.T, h http.Handler, pw string) string {
	t.Helper()
	id := siteShare(t, h, "index.html", "assets/style.css", "docs/index.html")
	if rec := setEntry(t, h, id, "index.html"); rec.Code != 200 {
		t.Fatalf("set entry = %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"password":"`+pw+`"}`); rec.Code != 200 {
		t.Fatalf("set password = %d %s", rec.Code, rec.Body)
	}
	return id
}

// unlockSite unlocks the share link and returns the copyable /site address
// on the file origin it redirects to, plus the access cookies.
func unlockSite(t *testing.T, h http.Handler, id, pw string) (location string, cookies []*http.Cookie) {
	t.Helper()
	r := httptest.NewRequest("GET", "/share/"+id+"?pw="+pw, nil)
	r.Host = "share.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 302 {
		t.Fatalf("/share unlocked = %d, want 302 to the site; body %s", rec.Code, rec.Body)
	}
	loc := rec.Header().Get("Location")
	if grantRe.MatchString(strings.TrimPrefix(loc, "https://files.share.example.com")) || loc != "https://files.share.example.com/site/"+id+"/index.html" {
		t.Fatalf("Location = %q, want copyable https://files.share.example.com/site/%s/index.html", loc, id)
	}
	return loc, rec.Result().Cookies()
}

func accessCookieValue(t *testing.T, cookies []*http.Cookie, id string) string {
	t.Helper()
	name := "hd_" + id
	for _, c := range cookies {
		if c.Name == name && c.Value != "" {
			return c.Value
		}
	}
	t.Fatalf("no %s cookie", name)
	return ""
}

// grantedPage follows the gate's redirect from a copyable /site address to
// the granted one, which is the address a page's own relative references
// resolve against.
func grantedPage(t *testing.T, h http.Handler, plain string, cookies []*http.Cookie) string {
	t.Helper()
	rec := fileGetWith(t, h, plain, map[string]string{
		"Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate",
	}, cookies)
	if rec.Code != 302 {
		t.Fatalf("unlocked %s = %d, want 302 onto a granted address; body %.120s", plain, rec.Code, rec.Body)
	}
	loc := rec.Header().Get("Location")
	if !grantRe.MatchString(loc) {
		t.Fatalf("Location = %q, want a granted address", loc)
	}
	return loc
}

// liveGrant unlocks a protected site and returns the grant segment its
// admitted page was redirected onto.
func liveGrant(t *testing.T, h http.Handler, id, pw string) (grant string, cookies []*http.Cookie) {
	t.Helper()
	loc, cookies := unlockSite(t, h, id, pw)
	return grantRe.FindStringSubmatch(grantedPage(t, h, loc, cookies))[2], cookies
}

// subresource is the header set a browser really sends for a sandboxed
// page's stylesheet: cross-site, with no cookie and no Referer to carry.
var subresource = map[string]string{
	"Sec-Fetch-Dest": "style", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Site": "cross-site",
}

// fileGetWith fetches a path on the FILE origin with extra headers and
// cookies, the way a browser loads a page's subresources.
func fileGetWith(t *testing.T, h http.Handler, path string, headers map[string]string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("GET", path, nil)
	r.Host = "files.share.example.com"
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// What a share's link opens is decided by entry, listing and media alone.
// Adding a password changes who may open it, never what opens: a site is a
// site behind the password form too.
func TestAPasswordDoesNotChangeWhatTheLinkOpens(t *testing.T) {
	t.Run("site", func(t *testing.T) {
		h := withDomain(t, "share.example.com")
		id := protectedSite(t, h, "hunter2")

		var sh struct{ Entry string }
		unmarshal(t, doReq(t, h, "GET", "/api/shares/"+id, testToken, ""), &sh)
		if sh.Entry != "index.html" {
			t.Fatalf("entry after the password = %q, want index.html", sh.Entry)
		}

		loc, cookies := unlockSite(t, h, id, "hunter2")
		granted := grantedPage(t, h, loc, cookies)
		page := fileGetWith(t, h, granted, map[string]string{"Sec-Fetch-Dest": "document"}, cookies)
		if page.Code != 200 || page.Body.String() != "body of index.html" {
			t.Fatalf("unlocked index = %d %q", page.Code, page.Body)
		}
		if got := page.Header().Get("Content-Security-Policy"); got != sandboxCSP {
			t.Errorf("page CSP = %q, want the sandbox", got)
		}
		// The page's own stylesheet, requested the way that sandboxed page
		// really requests it: cross-site, no cookie, no Referer. The grant
		// its href resolved under is the whole proof.
		css := fileGetWith(t, h, strings.TrimSuffix(granted, "index.html")+"assets/style.css",
			subresource, nil)
		if css.Code != 200 || css.Body.String() != "body of assets/style.css" {
			t.Fatalf("site stylesheet = %d %q", css.Code, css.Body)
		}
	})
	t.Run("gallery", func(t *testing.T) {
		h := withDomain(t, "share.example.com")
		id := createShareBody(t, h, `{"name":"Trip","media":true}`)
		uploadGetSlug(t, h, id, "a.jpg", "x")
		if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"password":"hunter2"}`); rec.Code != 200 {
			t.Fatalf("set password = %d %s", rec.Code, rec.Body)
		}
		rec := pageGet(t, h, "/share/"+id+"?pw=hunter2")
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), `id="lb"`) {
			t.Fatalf("protected gallery = %d, want the gallery page", rec.Code)
		}
	})
	t.Run("listing", func(t *testing.T) {
		h := withDomain(t, "share.example.com")
		id := createShareBody(t, h, `{"name":"Docs","listing":true}`)
		uploadGetSlug(t, h, id, "only.pdf", "x")
		if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"password":"hunter2"}`); rec.Code != 200 {
			t.Fatalf("set password = %d %s", rec.Code, rec.Body)
		}
		rec := pageGet(t, h, "/share/"+id+"?pw=hunter2")
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "only.pdf") {
			t.Fatalf("protected listing = %d, want the listing", rec.Code)
		}
	})
}

// An expiry is the same kind of edit: it decides how long the link lives,
// never what it opens.
func TestAnExpiryDoesNotChangeWhatTheLinkOpens(t *testing.T) {
	expire := func(t *testing.T, h http.Handler, id string) {
		t.Helper()
		if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"expiresInSeconds":3600}`); rec.Code != 200 {
			t.Fatalf("set expiry = %d %s", rec.Code, rec.Body)
		}
	}
	t.Run("site", func(t *testing.T) {
		h := withDomain(t, "share.example.com")
		id := siteShare(t, h, "index.html", "assets/style.css")
		setEntry(t, h, id, "index.html")
		expire(t, h, id)
		rec := pageGet(t, h, "/share/"+id)
		if rec.Code != 302 || rec.Header().Get("Location") != "https://files.share.example.com/site/"+id+"/index.html" {
			t.Fatalf("expiring site = %d %q, want 302 to https://files.share.example.com/site/%s/index.html", rec.Code, rec.Header().Get("Location"), id)
		}
	})
	t.Run("gallery", func(t *testing.T) {
		h := withDomain(t, "share.example.com")
		id := createShareBody(t, h, `{"name":"Trip","media":true}`)
		uploadGetSlug(t, h, id, "a.jpg", "x")
		expire(t, h, id)
		rec := pageGet(t, h, "/share/"+id)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), `id="lb"`) {
			t.Fatalf("expiring gallery = %d, want the gallery page", rec.Code)
		}
	})
	t.Run("listing", func(t *testing.T) {
		h := withDomain(t, "share.example.com")
		id := createShareBody(t, h, `{"name":"Docs","listing":true}`)
		uploadGetSlug(t, h, id, "only.pdf", "x")
		expire(t, h, id)
		rec := pageGet(t, h, "/share/"+id)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "only.pdf") {
			t.Fatalf("expiring listing = %d, want the listing", rec.Code)
		}
	})
}

// A /site link copied while the share was open keeps working after a
// password is added: it asks for the password like every other link, and
// once unlocked serves that same copyable address.
func TestAPlainSiteLinkOnAProtectedShareAsksForThePassword(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := protectedSite(t, h, "hunter2")
	plain := "/site/" + id + "/docs/index.html"

	form := fileGet(t, h, plain)
	if form.Code != 200 || !strings.Contains(form.Body.String(), "password-protected") {
		t.Fatalf("plain link without the password = %d, want the password form; body %.200s", form.Code, form.Body)
	}
	if strings.Contains(form.Body.String(), "body of docs/index.html") {
		t.Fatal("the page's bytes leaked past the password form")
	}
	if !strings.Contains(form.Body.String(), `name="next" value="`+plain+`"`) {
		t.Error("the form does not return the visitor to the page they asked for")
	}

	cookies := unlockCookies(t, h, id, "hunter2")
	rec := fileGetWith(t, h, grantedPage(t, h, plain, cookies), nil, cookies)
	if rec.Code != 200 || rec.Body.String() != "body of docs/index.html" {
		t.Fatalf("plain link with the cookie = %d %q, want the page", rec.Code, rec.Body)
	}

	r := httptest.NewRequest("POST", "/unlock/"+id, strings.NewReader("password=hunter2&next="+plain))
	r.Host = "share.example.com"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post := httptest.NewRecorder()
	h.ServeHTTP(post, r)
	hop, q := hopTarget(t, post, id)
	if q.Get("next") != plain {
		t.Fatalf("unlock hop next = %q, want %s", q.Get("next"), plain)
	}
	if landed := browse(t, h, "GET", hopFile, hop, ""); landed.Code != 303 || landed.Header().Get("Location") != plain {
		t.Fatalf("access hop = %d %q, want 303 back to %s", landed.Code, landed.Header().Get("Location"), plain)
	}
}

// A granted address copied from the address bar is not a shareable key.
// Another person opening it as a top-level navigation must enter the
// password, the same as the public View link.
func TestACopiedSitePageURLAsksForThePassword(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := protectedSite(t, h, "hunter2")
	grant, _ := liveGrant(t, h, id, "hunter2")
	copied := "/site/" + id + "/" + grant + "/docs/index.html"
	rec := fileGetWith(t, h, copied, map[string]string{
		"Sec-Fetch-Dest": "document",
		"Sec-Fetch-Mode": "navigate",
		"Sec-Fetch-Site": "none",
	}, nil)
	if rec.Code == 200 && rec.Body.String() == "body of docs/index.html" {
		t.Fatal("copied granted URL served the page without the password")
	}
	if !strings.Contains(rec.Body.String(), "password-protected") {
		t.Fatalf("copied URL = %d, want the password form; body %.200s", rec.Code, rec.Body)
	}
}

// A grant only this server could have signed opens the share; anything
// else is a visitor without the password.
func TestAForgedGrantIsRefused(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := protectedSite(t, h, "hunter2")
	forged := "/site/" + id + "/9999999999." + strings.Repeat("0", 64) + "/index.html"
	rec := fileGet(t, h, forged)
	if rec.Code == 200 && rec.Body.String() == "body of index.html" {
		t.Fatal("a forged grant served the page")
	}
	if !strings.Contains(rec.Body.String(), "password-protected") {
		t.Errorf("forged grant = %d, want the password form", rec.Code)
	}
}

// A grant that does not verify but a cookie that does is a visitor holding
// a stale address: they are reissued a live grant for the same page rather
// than sent to the form.
func TestAnInvalidGrantWithAValidCookieIsReissued(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := protectedSite(t, h, "hunter2")
	cookies := unlockCookies(t, h, id, "hunter2")
	stale := "/site/" + id + "/9999999999." + strings.Repeat("0", 64) + "/docs/index.html"
	rec := fileGetWith(t, h, stale, nil, cookies)
	loc := rec.Header().Get("Location")
	m := grantRe.FindStringSubmatch(loc)
	if rec.Code != 302 || m == nil || m[3] != "docs/index.html" {
		t.Fatalf("stale grant with the cookie = %d %q, want 302 onto a live grant for the same page", rec.Code, loc)
	}
	if page := fileGetWith(t, h, loc, nil, cookies); page.Code != 200 {
		t.Fatalf("reissued page = %d", page.Code)
	}
}

// Changing the password revokes every granted address at once, the way it
// already revokes every cookie.
func TestChangingThePasswordRevokesAGrant(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := protectedSite(t, h, "hunter2")
	grant, _ := liveGrant(t, h, id, "hunter2")
	old := "/site/" + id + "/" + grant + "/assets/style.css"
	if rec := fileGetWith(t, h, old, subresource, nil); rec.Code != 200 {
		t.Fatalf("stylesheet under a live grant = %d, want its bytes", rec.Code)
	}
	if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"password":"changed"}`); rec.Code != 200 {
		t.Fatalf("change password = %d %s", rec.Code, rec.Body)
	}
	rec := fileGetWith(t, h, old, subresource, nil)
	if rec.Body.String() == "body of assets/style.css" {
		t.Fatal("a grant survived a password change")
	}
}

// A grant names one share. Two shares behind the same password do not
// share one.
func TestAGrantIsBoundToItsShare(t *testing.T) {
	h := withDomain(t, "share.example.com")
	a := protectedSite(t, h, "hunter2")
	b := protectedSite(t, h, "hunter2")
	grant, _ := liveGrant(t, h, a, "hunter2")
	rec := fileGetWith(t, h, "/site/"+b+"/"+grant+"/assets/style.css", subresource, nil)
	if rec.Body.String() == "body of assets/style.css" {
		t.Fatal("share A's grant opened share B")
	}
}

// The directory redirect keeps the address it arrived on: a page reached at
// .../docs must land on .../docs/, or its relative references resolve one
// directory too high, and dropping the grant on the way would refuse every
// one of them.
func TestADirectoryRedirectKeepsTheGrant(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := protectedSite(t, h, "hunter2")
	cookies := unlockCookies(t, h, id, "hunter2")
	granted := grantedPage(t, h, "/site/"+id+"/docs", cookies)
	rec := fileGetWith(t, h, granted, nil, cookies)
	if rec.Code != 301 || rec.Header().Get("Location") != granted+"/" {
		t.Fatalf("directory = %d %q, want 301 to %s/", rec.Code, rec.Header().Get("Location"), granted)
	}
	root := grantedPage(t, h, "/site/"+id+"/", cookies)
	if idx := fileGetWith(t, h, root, nil, cookies); idx.Code != 200 || idx.Body.String() != "body of index.html" {
		t.Fatalf("unlocked root = %d %q, want the index", idx.Code, idx.Body)
	}
}

// Once the password is removed the grant means nothing, so an address
// still carrying one is sent to the plain form of the same page instead of
// answering 404 for a file the share plainly holds.
func TestAnOldGrantOnAnOpenShareRedirectsToThePlainPath(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := protectedSite(t, h, "hunter2")
	grant, _ := liveGrant(t, h, id, "hunter2")
	old := "/site/" + id + "/" + grant + "/index.html"
	if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"password":""}`); rec.Code != 200 {
		t.Fatalf("remove password = %d %s", rec.Code, rec.Body)
	}
	rec := fileGet(t, h, old)
	if rec.Code != 301 || rec.Header().Get("Location") != "/site/"+id+"/index.html" {
		t.Fatalf("old grant on an open share = %d %q, want 301 to the plain path", rec.Code, rec.Header().Get("Location"))
	}
}

// A granted response sends no Referer: the address holds a live grant, and
// a link out of the page would otherwise hand it to a third party. (The
// sandbox strips the Referer of a page's own subresources anyway, which is
// why they need the grant at all.)
func TestAGrantedSiteResponseSendsNoReferrer(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := protectedSite(t, h, "hunter2")
	loc, cookies := unlockSite(t, h, id, "hunter2")
	granted := grantedPage(t, h, loc, cookies)
	if got := fileGetWith(t, h, granted, nil, cookies).Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("Referrer-Policy = %q, want no-referrer", got)
	}
}

// The listing of a protected share links its pages by relpath, so a copied
// file-list URL still asks the next visitor for the password.
func TestAProtectedListingLinksPagesByRelpath(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := protectedSite(t, h, "hunter2")
	rec := pageGet(t, h, "/share/"+id+"?files=1&pw=hunter2")
	if rec.Code != 200 {
		t.Fatalf("listing = %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "has a password") {
		t.Error("the listing still says its pages open as files")
	}
	hrefs := regexp.MustCompile(`href="(?:https://files\.share\.example\.com)?(/site/[^"]+)"`).FindAllStringSubmatch(body, -1)
	if len(hrefs) == 0 {
		t.Fatal("no /site links on the listing")
	}
	for _, m := range hrefs {
		if grantRe.MatchString(m[1]) {
			t.Errorf("listing links %s with a grant", m[1])
		}
	}
}

// The grant in the address is the ONLY thing that opens a protected page's
// stylesheet. Neither the access cookie nor a Referer naming a page of this
// share stands in for it: a browser sends neither from a sandboxed page, so
// honouring them would only ever admit something that is not that browser.
func TestOnlyAGrantOpensAProtectedSitesStylesheet(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := protectedSite(t, h, "hunter2")
	cookies := unlockCookies(t, h, id, "hunter2")
	plain := "/site/" + id + "/assets/style.css"

	if bare := fileGetWith(t, h, plain, subresource, nil); bare.Body.String() == "body of assets/style.css" {
		t.Fatal("an ungranted stylesheet served its bytes")
	}
	withCookie := fileGetWith(t, h, plain, subresource, cookies)
	if withCookie.Body.String() == "body of assets/style.css" {
		t.Fatal("the access cookie opened a stylesheet on the file origin")
	}
	withReferer := fileGetWith(t, h, plain, map[string]string{
		"Sec-Fetch-Dest": "style", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Site": "cross-site",
		"Referer": "https://files.share.example.com/site/" + id + "/index.html",
	}, cookies)
	if withReferer.Body.String() == "body of assets/style.css" {
		t.Fatal("a same-share Referer opened a stylesheet on the file origin")
	}
}

// The regression that rendered every protected web page unstyled: a page
// sandboxed into an opaque origin asks for its stylesheet cross-site with
// NO cookie and NO Referer (measured in Chrome under every Referrer-Policy
// the page can set), so any gate that wants one of those refuses the whole
// site's CSS, scripts and pictures while the page itself loads.
func TestASandboxedPagesOwnAssetsLoadWithNothingButTheGrant(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := protectedSite(t, h, "hunter2")
	loc, cookies := unlockSite(t, h, id, "hunter2")
	granted := grantedPage(t, h, loc, cookies)
	// What href="assets/style.css" inside that page resolves to.
	css := fileGetWith(t, h, strings.TrimSuffix(granted, "index.html")+"assets/style.css",
		subresource, nil)
	if css.Code != 200 || css.Body.String() != "body of assets/style.css" {
		t.Fatalf("stylesheet of an unlocked page = %d %q, want its bytes", css.Code, css.Body)
	}
	// A picture is the same request with another destination.
	img := fileGetWith(t, h, strings.TrimSuffix(granted, "index.html")+"assets/style.css",
		map[string]string{
			"Sec-Fetch-Dest": "image", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Site": "cross-site",
		}, nil)
	if img.Code != 200 {
		t.Fatalf("picture of an unlocked page = %d, want its bytes", img.Code)
	}
	// A DOCUMENT is not admitted by the grant, however live it is: that is
	// what keeps a copied address asking for the password.
	doc := fileGetWith(t, h, granted, map[string]string{
		"Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "none",
	}, nil)
	if doc.Body.String() == "body of index.html" {
		t.Fatal("a granted address opened the page with no cookie")
	}
}

// grantScopeSite is protectedSite with the slugs kept: an index, a nested
// page, a stylesheet and a picture.
func grantScopeSite(t *testing.T, h http.Handler) (id string, slugs map[string]string) {
	t.Helper()
	id = createShare(t, h, "site")
	slugs = map[string]string{}
	for _, p := range []string{"index.html", "docs/index.html", "assets/style.css", "img/logo.png"} {
		slugs[p] = uploadGetSlug(t, h, id, p, "body of "+p)
	}
	if rec := setEntry(t, h, id, "index.html"); rec.Code != 200 {
		t.Fatalf("set entry = %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"password":"hunter2"}`); rec.Code != 200 {
		t.Fatalf("set password = %d %s", rec.Code, rec.Body)
	}
	return id, slugs
}

// A grant copied out of an address bar, a history or a log is signed over
// its own message, so presented as the hd_<id> cookie it opens nothing: not
// the zip, not /view or /download, not the share link.
func TestAGrantIsNotAnAccessCookie(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id, slugs := grantScopeSite(t, h)
	grant, _ := liveGrant(t, h, id, "hunter2")
	asCookie := []*http.Cookie{{Name: "hd_" + id, Value: grant}}

	for _, path := range []string{
		"/zip/" + id,
		"/view/" + id + "/" + slugs["index.html"],
		"/view/" + id + "/" + slugs["img/logo.png"],
		"/download/" + id + "/" + slugs["assets/style.css"],
	} {
		rec := fileGetWith(t, h, path, nil, asCookie)
		if strings.Contains(rec.Body.String(), "body of ") || rec.Header().Get("Content-Type") == "application/zip" {
			t.Errorf("%s with the grant as the cookie = %d, served the share's bytes", path, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "password-protected") {
			t.Errorf("%s with the grant as the cookie = %d, want the password form", path, rec.Code)
		}
	}

	r := httptest.NewRequest("GET", "/share/"+id, nil)
	r.Host = "share.example.com"
	r.AddCookie(asCookie[0])
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code == 302 || !strings.Contains(rec.Body.String(), "password-protected") {
		t.Fatalf("/share with the grant as the cookie = %d %q, want the password form", rec.Code, rec.Header().Get("Location"))
	}
}

// The other direction: the access cookie's value placed in the address is
// not a grant, so it opens no asset either.
func TestAnAccessCookieValueIsNotAGrant(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := protectedSite(t, h, "hunter2")
	cookies := unlockCookies(t, h, id, "hunter2")
	path := "/site/" + id + "/" + accessCookieValue(t, cookies, id) + "/assets/style.css"
	if rec := fileGetWith(t, h, path, subresource, nil); rec.Body.String() == "body of assets/style.css" {
		t.Fatal("the cookie's value in the address opened a stylesheet")
	}
}

// A grant alone opens a site's non-page files and never a page, whatever
// Sec-Fetch-Dest the request claims: the header is the client's to write,
// so the file's own type is what decides.
func TestAGrantAloneNeverServesAPage(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id, _ := grantScopeSite(t, h)
	grant, _ := liveGrant(t, h, id, "hunter2")
	base := "/site/" + id + "/" + grant + "/"

	for _, dest := range []string{"", "image", "style", "script", "object", "embed", "video"} {
		for _, page := range []string{"index.html", "docs/index.html", "docs/"} {
			headers := map[string]string{}
			if dest != "" {
				headers = map[string]string{
					"Sec-Fetch-Dest": dest, "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Site": "cross-site",
				}
			}
			rec := fileGetWith(t, h, base+page, headers, nil)
			if strings.Contains(rec.Body.String(), "body of ") {
				t.Errorf("%s under a grant, Sec-Fetch-Dest %q = %d, served the page", page, dest, rec.Code)
			}
		}
	}

	// The site keeps working: its stylesheet and picture load on the grant.
	css := fileGetWith(t, h, base+"assets/style.css", subresource, nil)
	if css.Code != 200 || css.Body.String() != "body of assets/style.css" {
		t.Fatalf("stylesheet under a grant = %d %q, want its bytes", css.Code, css.Body)
	}
	img := fileGetWith(t, h, base+"img/logo.png", map[string]string{
		"Sec-Fetch-Dest": "image", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Site": "cross-site",
	}, nil)
	if img.Code != 200 || img.Body.String() != "body of img/logo.png" {
		t.Fatalf("picture under a grant = %d %q, want its bytes", img.Code, img.Body)
	}
}

// A visitor who holds the cookie as well still gets a page's bytes on a
// subresource request: the cookie gate the page falls back to admits them.
func TestAPageUnderAGrantStillOpensWithTheCookie(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id, _ := grantScopeSite(t, h)
	grant, cookies := liveGrant(t, h, id, "hunter2")
	rec := fileGetWith(t, h, "/site/"+id+"/"+grant+"/docs/index.html", map[string]string{
		"Sec-Fetch-Dest": "object", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Site": "same-origin",
	}, cookies)
	if rec.Code != 200 || rec.Body.String() != "body of docs/index.html" {
		t.Fatalf("page under a grant with the cookie = %d %q, want its bytes", rec.Code, rec.Body)
	}
}
