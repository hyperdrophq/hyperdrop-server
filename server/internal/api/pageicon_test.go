package api

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// iconVer is the version a stored icon's address carries: the start of its
// content hash.
func iconVer(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])[:16]
}

// sitePage makes a share of the given files (path, content pairs) and returns
// its id.
func sitePage(t *testing.T, h http.Handler, files ...string) string {
	t.Helper()
	id := createShare(t, h, "site")
	for i := 0; i < len(files); i += 2 {
		uploadGetSlug(t, h, id, files[i], files[i+1])
	}
	return id
}

const plainPage = "<!doctype html><html><head><title>x</title></head><body>hi</body></html>"

// touchLink is the touch icon link a page is given for an address.
func touchLink(href string) string {
	return `<link rel="apple-touch-icon" sizes="512x512" href="` + href + `">`
}

// serverTouch is the server's own touch icon link, the one a page gets when
// its share holds no apple-touch-icon.png.
var serverTouch = touchLink("/apple-touch-icon.png")

// untouched is a served page with the server's touch icon link taken off its
// start, where a page with no head is given it: what a test about something
// other than icons compares against the stored bytes.
func untouched(body string) string {
	return strings.TrimPrefix(body, serverTouch)
}

// A page that names no icon of its own gets the share's, right after its
// <head>, addressed through the route the page was served on and versioned
// by the icon's bytes, and no touch icon: the share's favicon stands; the
// response's length is the rewritten page's.
func TestAPageWithoutAnIconLinksTheSharesFavicon(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := sitePage(t, h, "index.html", plainPage, "favicon.ico", "ICO1")

	rec := fileGet(t, h, "/site/"+id+"/index.html")
	if rec.Code != 200 {
		t.Fatalf("page = %d", rec.Code)
	}
	link := `<link rel="icon" href="/site/` + id + `/favicon.ico?v=` + iconVer("ICO1") + `">`
	want := strings.Replace(plainPage, "<head>", "<head>"+link, 1)
	if got := rec.Body.String(); got != want {
		t.Fatalf("body =\n%s\nwant\n%s", got, want)
	}
	if got := rec.Header().Get("Content-Length"); got != strconv.Itoa(len(want)) {
		t.Errorf("Content-Length = %q, want %d", got, len(want))
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache", got)
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != sandboxCSP {
		t.Errorf("CSP = %q, want the sandbox", got)
	}
	sum := sha256.Sum256([]byte(plainPage))
	if tag := rec.Header().Get("ETag"); tag == `"`+hex.EncodeToString(sum[:])+`"` || tag == "" {
		t.Errorf("ETag = %q: a rewritten page must not carry the stored file's tag", tag)
	}
	if rec.Header().Get("Last-Modified") != "" {
		t.Errorf("a rewritten page carries Last-Modified %q, which cannot see the icon change", rec.Header().Get("Last-Modified"))
	}

	// A compressed answer carries the same rewritten page.
	gz := fileGetWith(t, h, "/site/"+id+"/index.html", map[string]string{"Accept-Encoding": "gzip"}, nil)
	if gz.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", gz.Header().Get("Content-Encoding"))
	}
	zr, err := gzip.NewReader(gz.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := io.ReadAll(zr); string(got) != want {
		t.Errorf("gzip body = %q, want the rewritten page", got)
	}
	if gz.Header().Get("ETag") == rec.Header().Get("ETag") {
		t.Errorf("the gzip and identity answers share the ETag %q", gz.Header().Get("ETag"))
	}

	// The href resolves: the icon is served by the same route.
	icon := fileGet(t, h, "/site/"+id+"/favicon.ico?v="+iconVer("ICO1"))
	if icon.Code != 200 || icon.Body.String() != "ICO1" {
		t.Fatalf("icon = %d %q", icon.Code, icon.Body)
	}
}

// A share's own apple-touch-icon.png is the touch icon its pages link, the
// nearest one like the tab icon, through the page's route and versioned by
// its bytes; it never stands in for the tab icon.
func TestThePageLinksTheSharesOwnTouchIcon(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := sitePage(t, h,
		"index.html", plainPage,
		"apple-touch-icon.png", "ROOT",
		"docs/apple-touch-icon.png", "DOCS",
		"docs/guide/index.html", plainPage,
		"blog/index.html", plainPage,
	)
	for _, tc := range []struct{ page, icon, content string }{
		{"index.html", "apple-touch-icon.png", "ROOT"},
		{"docs/guide/index.html", "docs/apple-touch-icon.png", "DOCS"},
		{"blog/index.html", "apple-touch-icon.png", "ROOT"},
	} {
		rec := fileGet(t, h, "/site/"+id+"/"+tc.page)
		want := strings.Replace(plainPage, "<head>", "<head>"+touchLink("/site/"+id+"/"+tc.icon+"?v="+iconVer(tc.content)), 1)
		if got := rec.Body.String(); got != want {
			t.Errorf("%s: body\n%s\nwant\n%s", tc.page, got, want)
		}
	}
	touch := fileGet(t, h, "/site/"+id+"/apple-touch-icon.png?v="+iconVer("ROOT"))
	if touch.Code != 200 || touch.Body.String() != "ROOT" {
		t.Fatalf("touch icon = %d %q", touch.Code, touch.Body)
	}
}

// The nearest icon wins: the page's own folder first, then each folder up
// to the share root, and inside one folder favicon.ico before favicon.svg
// before favicon.png.
func TestThePageLinksTheNearestIcon(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := sitePage(t, h,
		"index.html", plainPage,
		"favicon.svg", "<svg/>",
		"docs/favicon.png", "PNG",
		"docs/favicon.ico", "ICO",
		"docs/guide/index.html", plainPage,
		"blog/index.html", plainPage,
	)
	for _, tc := range []struct{ page, icon, content string }{
		{"index.html", "favicon.svg", "<svg/>"},
		{"docs/guide/index.html", "docs/favicon.ico", "ICO"},
		{"blog/index.html", "favicon.svg", "<svg/>"},
	} {
		body := fileGet(t, h, "/site/"+id+"/"+tc.page).Body.String()
		want := `<link rel="icon" href="/site/` + id + `/` + tc.icon + `?v=` + iconVer(tc.content) + `">`
		if !strings.Contains(body, want) {
			t.Errorf("%s: body %q, want %s", tc.page, body, want)
		}
	}
}

// A page that declares its own icon of any kind is given no touch icon, the
// share's own included: the author's icon always wins. One that declares an
// icon link is served byte for byte; one that declares only a touch icon is
// still given the share's tab icon.
func TestAPageWithItsOwnIconIsUntouched(t *testing.T) {
	h := withDomain(t, "share.example.com")
	own := `<!DOCTYPE html><HTML><HEAD><Link REL="Shortcut Icon" href="me.png"></HEAD><body>x</body></HTML>`
	inBody := `<html><head><title>t</title></head><body><link rel="icon" href="b.png"></body></html>`
	both := `<html><head><link rel="icon" href="i.png"><link rel="APPLE-TOUCH-ICON-PRECOMPOSED" href="t.png"></head></html>`
	touch := `<html><head><link rel="apple-touch-icon" href="t.png"></head></html>`
	id := sitePage(t, h, "own.html", own, "inbody.html", inBody, "both.html", both, "touch.html", touch, "favicon.ico", "ICO")

	for p, body := range map[string]string{"own.html": own, "inbody.html": inBody, "both.html": both} {
		rec := fileGet(t, h, "/site/"+id+"/"+p)
		if rec.Body.String() != body {
			t.Errorf("%s: body %q, want it untouched", p, rec.Body)
		}
		sum := sha256.Sum256([]byte(body))
		if got := rec.Header().Get("ETag"); got != `"`+hex.EncodeToString(sum[:])+`"` {
			t.Errorf("%s: ETag %q, want the stored file's", p, got)
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
			t.Errorf("%s: Cache-Control = %q, want no-cache", p, got)
		}
	}
	// A touch icon of its own does not set the tab's icon: the share's is
	// linked, and no second touch icon.
	wantTouch := strings.Replace(touch, "<head>", `<head><link rel="icon" href="/site/`+id+`/favicon.ico?v=`+iconVer("ICO")+`">`, 1)
	if body := fileGet(t, h, "/site/"+id+"/touch.html").Body.String(); body != wantTouch {
		t.Errorf("touch.html = %q, want %q", body, wantTouch)
	}

	// The share's own touch icon joins none of them.
	uploadGetSlug(t, h, id, "apple-touch-icon.png", "TOUCH")
	for p, body := range map[string]string{"own.html": own, "inbody.html": inBody, "both.html": both} {
		rec := fileGet(t, h, "/site/"+id+"/"+p)
		if rec.Body.String() != body {
			t.Errorf("%s with a share touch icon: body %q, want it untouched", p, rec.Body)
		}
		sum := sha256.Sum256([]byte(body))
		if got := rec.Header().Get("ETag"); got != `"`+hex.EncodeToString(sum[:])+`"` {
			t.Errorf("%s with a share touch icon: ETag %q, want the stored file's", p, got)
		}
	}
	if body := fileGet(t, h, "/site/"+id+"/touch.html").Body.String(); body != wantTouch {
		t.Errorf("touch.html with a share touch icon = %q, want %q", body, wantTouch)
	}
}

// A touch icon link anywhere in the window is the page's own, in the body
// or a template as much as in the head, the way an icon link is: the page
// is served byte for byte.
func TestATouchIconAnywhereInTheWindowIsThePagesOwn(t *testing.T) {
	h := withDomain(t, "share.example.com")
	inBody := `<html><head><title>t</title></head><body><link rel="apple-touch-icon" href="t.png"></body></html>`
	inTemplate := `<html><head><template><link rel="apple-touch-icon" href="t.png"></template></head><body></body></html>`
	id := sitePage(t, h, "inbody.html", inBody, "intemplate.html", inTemplate)
	for p, page := range map[string]string{"inbody.html": inBody, "intemplate.html": inTemplate} {
		if got := fileGet(t, h, "/site/"+id+"/"+p).Body.String(); got != page {
			t.Errorf("%s = %q, want it untouched", p, got)
		}
	}
}

// A share holding no icon file on a page's path (its folder and those above
// it) links no tab icon, so the tab falls back to the server's own
// /favicon.ico; the page gets the server's touch icon alone, the same mark
// at the size iOS shows on the lock screen, on the page's own origin. Icon
// files in a folder off that path count for nothing.
func TestAShareWithNoIconLinksTheServersTouchIconAlone(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := sitePage(t, h, "index.html", plainPage, "docs/icon.ico", "not a favicon name",
		"docs/favicon.ico", "ICO", "docs/apple-touch-icon.png", "TOUCH", "blog/index.html", plainPage)
	want := strings.Replace(plainPage, "<head>", "<head>"+serverTouch, 1)
	if got := fileGet(t, h, "/site/"+id+"/blog/index.html").Body.String(); got != want {
		t.Errorf("blog/index.html = %q, want %q", got, want)
	}
	rec := fileGet(t, h, "/site/"+id+"/index.html")
	if rec.Body.String() != want {
		t.Fatalf("body = %q, want %q", rec.Body, want)
	}
	if touch := fileGet(t, h, "/apple-touch-icon.png"); touch.Code != 200 || touch.Body.String() != string(iconTouch) {
		t.Fatalf("touch icon on the files origin = %d", touch.Code)
	}
	sum := sha256.Sum256([]byte(plainPage))
	if got := rec.Header().Get("ETag"); got == `"`+hex.EncodeToString(sum[:])+`"` || got == "" {
		t.Errorf("ETag = %q: a rewritten page must not carry the stored file's tag", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache: an icon added later must reach a cached page", got)
	}
}

// Only a top-level document load is rewritten: a page a site's own script
// fetches (Sec-Fetch-Dest empty) or frames is served byte for byte under
// the stored file's entity tag, so a fragment a template inserts keeps its
// one root and a script comparing the text sees the file. A request with
// no Sec-Fetch-Dest is a document. Both answers vary by the header, and the
// two representations never share an entity tag.
func TestOnlyADocumentLoadIsRewritten(t *testing.T) {
	h := withDomain(t, "share.example.com")
	part := `<div class="card">part</div>`
	id := sitePage(t, h, "index.html", plainPage, "part.html", part)
	sum := sha256.Sum256([]byte(part))
	stored := `"` + hex.EncodeToString(sum[:]) + `"`

	fetched := fileGetWith(t, h, "/site/"+id+"/part.html", map[string]string{
		"Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin"}, nil)
	if fetched.Code != 200 || fetched.Body.String() != part {
		t.Fatalf("fetched fragment = %d %q, want the stored bytes", fetched.Code, fetched.Body)
	}
	if got := fetched.Header().Get("ETag"); got != stored {
		t.Errorf("fetched fragment ETag = %q, want the stored file's %s", got, stored)
	}
	for _, dest := range []string{"iframe", "frame"} {
		framed := fileGetWith(t, h, "/site/"+id+"/index.html", map[string]string{"Sec-Fetch-Dest": dest}, nil)
		if framed.Body.String() != plainPage {
			t.Errorf("Sec-Fetch-Dest %s = %q, want the stored bytes", dest, framed.Body)
		}
	}

	want := serverTouch + part
	doc := fileGetWith(t, h, "/site/"+id+"/part.html", map[string]string{"Sec-Fetch-Dest": "document"}, nil)
	if doc.Body.String() != want {
		t.Errorf("document load = %q, want %q", doc.Body, want)
	}
	plain := fileGet(t, h, "/site/"+id+"/part.html")
	if plain.Body.String() != want {
		t.Errorf("no Sec-Fetch-Dest = %q, want %q", plain.Body, want)
	}
	if doc.Header().Get("ETag") == fetched.Header().Get("ETag") || doc.Header().Get("ETag") == "" {
		t.Errorf("the document and the fetched fragment share the ETag %q", doc.Header().Get("ETag"))
	}
	if doc.Header().Get("ETag") != plain.Header().Get("ETag") {
		t.Errorf("document ETag %q, no-header ETag %q: one representation", doc.Header().Get("ETag"), plain.Header().Get("ETag"))
	}
	for name, rec := range map[string]*httptest.ResponseRecorder{"fetched": fetched, "document": doc, "no header": plain} {
		if !varies(rec, "Sec-Fetch-Dest") {
			t.Errorf("%s: Vary %q, want Sec-Fetch-Dest", name, rec.Header().Values("Vary"))
		}
	}

	// The fragment's cached tag never validates the document, nor the
	// reverse.
	if rec := fileGetWith(t, h, "/site/"+id+"/part.html", map[string]string{"If-None-Match": stored}, nil); rec.Code != 200 {
		t.Errorf("document revalidated with the fragment's tag = %d, want 200", rec.Code)
	}
	if rec := fileGetWith(t, h, "/site/"+id+"/part.html", map[string]string{
		"Sec-Fetch-Dest": "empty", "If-None-Match": doc.Header().Get("ETag")}, nil); rec.Code != 200 {
		t.Errorf("fragment revalidated with the document's tag = %d, want 200", rec.Code)
	}

	// The share's own tab icon follows the same rule, and so does /view.
	uploadGetSlug(t, h, id, "favicon.ico", "ICO")
	if got := fileGetWith(t, h, "/site/"+id+"/part.html", map[string]string{"Sec-Fetch-Dest": "empty"}, nil).Body.String(); got != part {
		t.Errorf("fetched fragment with a share favicon = %q, want the stored bytes", got)
	}
	if got := fileGet(t, h, "/site/"+id+"/part.html").Body.String(); !strings.Contains(got, `<link rel="icon"`) {
		t.Errorf("document with a share favicon = %q, want its icon link", got)
	}
	viewSlug := uploadGetSlug(t, h, id, "frag.html", part)
	view := "/view/" + id + "/" + viewSlug
	if got := fileGetWith(t, h, view, map[string]string{"Sec-Fetch-Dest": "empty"}, nil).Body.String(); got != part {
		t.Errorf("/view fetched = %q, want the stored bytes", got)
	}
	if got := fileGetWith(t, h, view, map[string]string{"Sec-Fetch-Dest": "document"}, nil).Body.String(); !strings.Contains(got, `<link rel="icon"`) {
		t.Errorf("/view document = %q, want its icon link", got)
	}
}

// varies reports whether a response's Vary names header.
func varies(rec *httptest.ResponseRecorder, header string) bool {
	for _, v := range rec.Header().Values("Vary") {
		for _, name := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(name), header) {
				return true
			}
		}
	}
	return false
}

// Adding the share's own touch icon changes the injected markup, and with it
// the entity tag, so a cached page revalidates to the new link.
func TestATouchIconAddedLaterIsANewRepresentation(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := sitePage(t, h, "index.html", plainPage)
	page := "/site/" + id + "/index.html"
	bare := fileGet(t, h, page)
	uploadGetSlug(t, h, id, "apple-touch-icon.png", "T1")
	after := fileGetWith(t, h, page, map[string]string{"If-None-Match": bare.Header().Get("ETag")}, nil)
	if after.Code != 200 {
		t.Fatalf("revalidating after a touch icon appeared = %d, want 200", after.Code)
	}
	if after.Header().Get("ETag") == bare.Header().Get("ETag") {
		t.Fatalf("both answers carry the ETag %q", after.Header().Get("ETag"))
	}
	if want := touchLink("/site/" + id + "/apple-touch-icon.png?v=" + iconVer("T1")); !strings.Contains(after.Body.String(), want) {
		t.Fatalf("body %q, want %s", after.Body, want)
	}
}

var iconHrefRe = regexp.MustCompile(`<link rel="icon" href="([^"]+)">`)

// Adding or replacing the icon changes the page: a new href, a new entity
// tag, so the browser's revalidation of the cached page answers 200 with
// the new address rather than 304.
func TestAReplacedIconIsANewAddress(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := sitePage(t, h, "index.html", plainPage)
	page := "/site/" + id + "/index.html"

	bare := fileGet(t, h, page)
	uploadGetSlug(t, h, id, "favicon.ico", "first")
	first := fileGetWith(t, h, page, map[string]string{"If-None-Match": bare.Header().Get("ETag")}, nil)
	if first.Code != 200 {
		t.Fatalf("revalidating after an icon appeared = %d, want 200", first.Code)
	}
	uploadGetSlug(t, h, id, "favicon.ico", "second")
	second := fileGetWith(t, h, page, map[string]string{"If-None-Match": first.Header().Get("ETag")}, nil)
	if second.Code != 200 {
		t.Fatalf("revalidating after the icon changed = %d, want 200", second.Code)
	}
	a := iconHrefRe.FindStringSubmatch(first.Body.String())
	b := iconHrefRe.FindStringSubmatch(second.Body.String())
	if a == nil || b == nil || a[1] == b[1] {
		t.Fatalf("hrefs %v then %v, want two different addresses", a, b)
	}
	if !strings.HasSuffix(b[1], "?v="+iconVer("second")) {
		t.Errorf("href %q, want the new icon's version", b[1])
	}
	again := fileGetWith(t, h, page, map[string]string{"If-None-Match": second.Header().Get("ETag")}, nil)
	if again.Code != http.StatusNotModified {
		t.Errorf("an unchanged page and icon revalidate as %d, want 304", again.Code)
	}
}

// /view serves a page by slug, so its icon is addressed by slug too.
func TestAPageOpenedByItsSlugLinksTheIconBySlug(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "page")
	pageSlug := uploadGetSlug(t, h, id, "page.html", plainPage)
	iconSlug := uploadGetSlug(t, h, id, "favicon.png", "PNG")
	touchSlug := uploadGetSlug(t, h, id, "apple-touch-icon.png", "TOUCH")
	body := doReq(t, h, "GET", "/view/"+id+"/"+pageSlug, "", "").Body.String()
	want := `<link rel="icon" href="/view/` + id + `/` + iconSlug + `?v=` + iconVer("PNG") + `">` +
		touchLink("/view/"+id+"/"+touchSlug+"?v="+iconVer("TOUCH"))
	if !strings.Contains(body, want) {
		t.Fatalf("body %q, want %s", body, want)
	}
	// The download route is not a page and is never rewritten.
	if got := doReq(t, h, "GET", "/download/"+id+"/"+pageSlug, "", "").Body.String(); got != plainPage {
		t.Errorf("/download body = %q, want the stored bytes", got)
	}
}

// A linked share's icon is one of its source folder's entries, found and
// served the same way; a page with no <head> gets the link at its start.
func TestALinkedSharesIconIsLinked(t *testing.T) {
	h, b, vol := linkedTestAPI(t)
	if err := os.WriteFile(filepath.Join(vol, "public-share", "favicon.svg"), []byte("<svg/>"), 0o644); err != nil {
		t.Fatal(err)
	}
	id := linkedShare(t, b, "public-share")

	body := doReq(t, h, "GET", "/site/"+id+"/index.html", "", "").Body.String()
	m := regexp.MustCompile(`^<link rel="icon" href="/site/` + id + `/favicon.svg\?v=[0-9a-f]{16}"><h1>hi</h1>$`)
	if !m.MatchString(body) {
		t.Fatalf("/site body = %q", body)
	}
	page, icon := linkedEntry(t, h, id, "index.html"), linkedEntry(t, h, id, "favicon.svg")
	body = doReq(t, h, "GET", "/view/"+id+"/"+page.Slug, "", "").Body.String()
	if !strings.HasPrefix(body, `<link rel="icon" href="/view/`+id+`/`+icon.Slug+`?v=`) {
		t.Fatalf("/view body = %q", body)
	}
}

// The head is looked for within a bounded window. A page whose head starts
// beyond it is served unmodified; a large page whose head comes early is
// rewritten in full, its length counted.
func TestThePageWindowIsBounded(t *testing.T) {
	h := withDomain(t, "share.example.com")
	late := "<!--" + strings.Repeat("x", pageHeadWindow) + "--><html><head></head><body></body></html>"
	big := "<html><head></head><body>" + strings.Repeat("y", 3*pageHeadWindow) + "</body></html>"
	id := sitePage(t, h, "late.html", late, "big.html", big, "favicon.ico", "ICO")

	if got := fileGet(t, h, "/site/"+id+"/late.html").Body.String(); got != late {
		t.Errorf("a head past the window was rewritten (%d bytes, want %d)", len(got), len(late))
	}
	rec := fileGet(t, h, "/site/"+id+"/big.html")
	link := `<link rel="icon" href="/site/` + id + `/favicon.ico?v=` + iconVer("ICO") + `">`
	want := strings.Replace(big, "<head>", "<head>"+link, 1)
	if rec.Body.String() != want {
		t.Fatalf("big page: %d bytes, want %d rewritten", rec.Body.Len(), len(want))
	}
	if got := rec.Header().Get("Content-Length"); got != strconv.Itoa(len(want)) {
		t.Errorf("Content-Length = %q, want %d", got, len(want))
	}
}

// A Range request on a rewritten page is answered from the rewritten page,
// under its own entity tag, never from the stored file's bytes.
func TestARangeOfARewrittenPageCountsTheRewrittenBytes(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := sitePage(t, h, "index.html", plainPage, "favicon.ico", "ICO")
	full := fileGet(t, h, "/site/"+id+"/index.html")

	rec := fileGetWith(t, h, "/site/"+id+"/index.html", map[string]string{"Range": "bytes=10-60"}, nil)
	if rec.Code != http.StatusPartialContent {
		t.Fatalf("Range = %d, want 206", rec.Code)
	}
	if got, want := rec.Header().Get("Content-Range"), "bytes 10-60/"+strconv.Itoa(full.Body.Len()); got != want {
		t.Errorf("Content-Range = %q, want %q", got, want)
	}
	if got := rec.Body.String(); got != full.Body.String()[10:61] {
		t.Errorf("range body = %q, want %q", got, full.Body.String()[10:61])
	}
	// A resume validated against the stored file's tag gets the whole page.
	sum := sha256.Sum256([]byte(plainPage))
	stale := fileGetWith(t, h, "/site/"+id+"/index.html", map[string]string{
		"Range": "bytes=10-60", "If-Range": `"` + hex.EncodeToString(sum[:]) + `"`}, nil)
	if stale.Code != 200 || stale.Body.String() != full.Body.String() {
		t.Errorf("If-Range on the stored tag = %d %q, want the whole rewritten page", stale.Code, stale.Body)
	}
}

// A protected site's page links its icon under the grant its own address
// carries, which is the proof the tab's icon request can present.
func TestAProtectedSitesIconRidesTheGrant(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := sitePage(t, h, "index.html", plainPage, "favicon.ico", "ICO")
	if rec := setEntry(t, h, id, "index.html"); rec.Code != 200 {
		t.Fatalf("set entry = %d", rec.Code)
	}
	if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"password":"hunter2-share"}`); rec.Code != 200 {
		t.Fatalf("set password = %d", rec.Code)
	}
	grant, cookies := liveGrant(t, h, id, "hunter2-share")
	page := fileGetWith(t, h, "/site/"+id+"/"+grant+"/index.html", map[string]string{"Sec-Fetch-Dest": "document"}, cookies)
	m := iconHrefRe.FindStringSubmatch(page.Body.String())
	if m == nil || m[1] != "/site/"+id+"/"+grant+"/favicon.ico?v="+iconVer("ICO") {
		t.Fatalf("href %v, want the icon under the grant", m)
	}
	if strings.Contains(page.Body.String(), "apple-touch-icon") {
		t.Errorf("body %q: a share holding a favicon gets no touch icon", page.Body)
	}
	if got := page.Header().Get("Cache-Control"); got != "private, no-cache" {
		t.Errorf("Cache-Control = %q, want private, no-cache", got)
	}
	icon := fileGetWith(t, h, m[1], map[string]string{
		"Sec-Fetch-Dest": "image", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Site": "cross-site"}, nil)
	if icon.Code != 200 || icon.Body.String() != "ICO" {
		t.Errorf("icon on the grant alone = %d %q", icon.Code, icon.Body)
	}

	// A protected site holding no icon file links the server's touch icon,
	// which answers with no grant at all.
	bare := sitePage(t, h, "index.html", plainPage)
	if rec := setEntry(t, h, bare, "index.html"); rec.Code != 200 {
		t.Fatalf("set entry = %d", rec.Code)
	}
	if rec := doReq(t, h, "PATCH", "/api/shares/"+bare, testToken, `{"password":"hunter2-share"}`); rec.Code != 200 {
		t.Fatalf("set password = %d", rec.Code)
	}
	grant, cookies = liveGrant(t, h, bare, "hunter2-share")
	page = fileGetWith(t, h, "/site/"+bare+"/"+grant+"/index.html", map[string]string{"Sec-Fetch-Dest": "document"}, cookies)
	if want := strings.Replace(plainPage, "<head>", "<head>"+serverTouch, 1); page.Body.String() != want {
		t.Errorf("body %q, want %q", page.Body, want)
	}
	touch := fileGetWith(t, h, "/apple-touch-icon.png", map[string]string{
		"Sec-Fetch-Dest": "image", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Site": "cross-site"}, nil)
	if touch.Code != 200 || touch.Body.String() != string(iconTouch) {
		t.Errorf("the server's touch icon with no grant = %d", touch.Code)
	}
}

// An inbox holding a page and an icon still answers nothing publicly.
func TestAnInboxPageIsStillHidden(t *testing.T) {
	h, b := newTestAPIBackend(t)
	id := createInbox(t, h, `{"name":"drop","receive":true}`)
	commitFile(t, b, id, "index.html", plainPage)
	commitFile(t, b, id, "favicon.ico", "ICO")
	commitFile(t, b, id, "apple-touch-icon.png", "TOUCH")
	f, err := b.DB.File(id, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/site/" + id + "/index.html", "/site/" + id + "/favicon.ico", "/site/" + id + "/apple-touch-icon.png", "/view/" + id + "/" + f.Slug} {
		if rec := doReq(t, h, "GET", p, "", ""); rec.Code != 404 {
			t.Errorf("%s = %d, want 404", p, rec.Code)
		}
	}
}

// Where the links go and which icons the page declares, decided on a page's
// first bytes alone.
func TestPageIconInsert(t *testing.T) {
	bom := "\xef\xbb\xbf"
	for _, tc := range []struct {
		name, doc   string
		at          int
		icon, touch bool // what the page declares
	}{
		{"after head", "<!doctype html><html><head><title>t</title></head>", len("<!doctype html><html><head>"), false, false},
		{"head with attributes", `<html lang="en"><HEAD profile="x"><meta charset="utf-8">`, len(`<html lang="en"><HEAD profile="x">`), false, false},
		{"no head: after html", "<!DOCTYPE html>\n<html><body>x", len("<!DOCTYPE html>\n<html>"), false, false},
		{"no head or html: after the doctype", "<!DOCTYPE html><p>x", len("<!DOCTYPE html>"), false, false},
		{"nothing: the start", "<p>x</p>", 0, false, false},
		{"byte order mark kept first", bom + "<p>x</p>", len(bom), false, false},
		{"a link in a title is text", "<head><title><link rel=icon></title></head>", len("<head>"), false, false},
		{"a link in a script is text", `<head><script>"<link rel=icon>"</script></head>`, len("<head>"), false, false},
		{"declared", "<head><link rel=icon href=a.png></head>", len("<head>"), true, false},
		{"declared in mixed case, among tokens", `<head><link rel="ALTERNATE  icon" href=a.png></head>`, len("<head>"), true, false},
		{"declared in the body", "<head></head><body><link rel=icon href=a.png>", len("<head>"), true, false},
		{"mask-icon is not an icon link", `<head><link rel="mask-icon" href=a.svg></head>`, len("<head>"), false, false},
		{"a touch icon", `<head><link rel="apple-touch-icon" href=t.png></head>`, len("<head>"), false, true},
		{"a precomposed touch icon", `<head><link rel="Apple-Touch-Icon-Precomposed" href=t.png></head>`, len("<head>"), false, true},
		{"a touch icon in an implied head", `<!doctype html><link rel=apple-touch-icon href=t.png><p>x`, len("<!doctype html>"), false, true},
		{"a touch icon in the body", `<head></head><body><link rel=apple-touch-icon href=t.png>`, len("<head>"), false, true},
		{"a touch icon in a template", `<head><template><link rel=apple-touch-icon href=t.png></template></head>`, len("<head>"), false, true},
		{"both", `<head><link rel=apple-touch-icon href=t.png><link rel=icon href=i.png></head>`, len("<head>"), true, true},
	} {
		at, declared, ok := pageIconInsert([]byte(tc.doc), true)
		if !ok || at != tc.at || declared.icon != tc.icon || declared.touch != tc.touch {
			t.Errorf("%s: (%d, %+v, %v), want (%d, icon %v, touch %v)", tc.name, at, declared, ok, tc.at, tc.icon, tc.touch)
		}
	}
	// A window that ends inside the head decides nothing: a link may come
	// after it.
	if _, _, ok := pageIconInsert([]byte("<html><head><title>t</title><meta name=a"), false); ok {
		t.Error("a window ending inside the head inserted a link")
	}
	if at, _, ok := pageIconInsert([]byte("<html><head></head><body><p>lots"), false); !ok || at != len("<html><head>") {
		t.Errorf("a window past the head's end: (%d, %v)", at, ok)
	}
	for _, doc := range []string{"\xfe\xff\x00<", "\xff\xfe<\x00"} {
		if _, _, ok := pageIconInsert([]byte(doc), true); ok {
			t.Errorf("a UTF-16 page %q took a link", doc)
		}
	}
}
