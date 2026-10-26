package api

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
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

// A page that names no icon of its own gets the share's, right after its
// <head>, addressed through the route the page was served on and versioned
// by the icon's bytes; the response's length is the rewritten page's.
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

// A page that declares its own icon is served byte for byte. Only an icon
// link counts: an apple-touch-icon does not set the tab's icon.
func TestAPageWithItsOwnIconIsUntouched(t *testing.T) {
	h := withDomain(t, "share.example.com")
	own := `<!DOCTYPE html><HTML><HEAD><Link REL="Shortcut Icon" href="me.png"></HEAD><body>x</body></HTML>`
	inBody := `<html><head><title>t</title></head><body><link rel="icon" href="b.png"></body></html>`
	touch := `<html><head><link rel="apple-touch-icon" href="t.png"></head></html>`
	id := sitePage(t, h, "own.html", own, "inbody.html", inBody, "touch.html", touch, "favicon.ico", "ICO")

	for p, body := range map[string]string{"own.html": own, "inbody.html": inBody} {
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
	if body := fileGet(t, h, "/site/"+id+"/touch.html").Body.String(); !strings.Contains(body, `<link rel="icon" href="/site/`+id+`/favicon.ico?v=`) {
		t.Errorf("an apple-touch-icon alone kept the share's icon out: %q", body)
	}
}

// A share holding no icon serves its pages unmodified, so the tab falls back
// to the server's own /favicon.ico.
func TestAShareWithNoIconServesThePageUnmodified(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := sitePage(t, h, "index.html", plainPage, "docs/icon.ico", "not a favicon name")
	rec := fileGet(t, h, "/site/"+id+"/index.html")
	if rec.Body.String() != plainPage {
		t.Fatalf("body = %q, want it unmodified", rec.Body)
	}
	sum := sha256.Sum256([]byte(plainPage))
	if got := rec.Header().Get("ETag"); got != `"`+hex.EncodeToString(sum[:])+`"` {
		t.Errorf("ETag = %q, want the stored file's", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache: an icon added later must reach a cached page", got)
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
	body := doReq(t, h, "GET", "/view/"+id+"/"+pageSlug, "", "").Body.String()
	want := `<link rel="icon" href="/view/` + id + `/` + iconSlug + `?v=` + iconVer("PNG") + `">`
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
	if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"password":"hunter2"}`); rec.Code != 200 {
		t.Fatalf("set password = %d", rec.Code)
	}
	grant, cookies := liveGrant(t, h, id, "hunter2")
	page := fileGetWith(t, h, "/site/"+id+"/"+grant+"/index.html", map[string]string{"Sec-Fetch-Dest": "document"}, cookies)
	m := iconHrefRe.FindStringSubmatch(page.Body.String())
	if m == nil || m[1] != "/site/"+id+"/"+grant+"/favicon.ico?v="+iconVer("ICO") {
		t.Fatalf("href %v, want the icon under the grant", m)
	}
	if got := page.Header().Get("Cache-Control"); got != "private, no-cache" {
		t.Errorf("Cache-Control = %q, want private, no-cache", got)
	}
	icon := fileGetWith(t, h, m[1], map[string]string{
		"Sec-Fetch-Dest": "image", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Site": "cross-site"}, nil)
	if icon.Code != 200 || icon.Body.String() != "ICO" {
		t.Errorf("icon on the grant alone = %d %q", icon.Code, icon.Body)
	}
}

// An inbox holding a page and an icon still answers nothing publicly.
func TestAnInboxPageIsStillHidden(t *testing.T) {
	h, b := newTestAPIBackend(t)
	id := createInbox(t, h, `{"name":"drop","receive":true}`)
	commitFile(t, b, id, "index.html", plainPage)
	commitFile(t, b, id, "favicon.ico", "ICO")
	f, err := b.DB.File(id, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/site/" + id + "/index.html", "/site/" + id + "/favicon.ico", "/view/" + id + "/" + f.Slug} {
		if rec := doReq(t, h, "GET", p, "", ""); rec.Code != 404 {
			t.Errorf("%s = %d, want 404", p, rec.Code)
		}
	}
}

// Where the link goes, decided on a page's first bytes alone.
func TestPageIconInsert(t *testing.T) {
	bom := "\xef\xbb\xbf"
	for _, tc := range []struct {
		name, doc string
		at        int // -1: nothing is inserted
	}{
		{"after head", "<!doctype html><html><head><title>t</title></head>", len("<!doctype html><html><head>")},
		{"head with attributes", `<html lang="en"><HEAD profile="x"><meta charset="utf-8">`, len(`<html lang="en"><HEAD profile="x">`)},
		{"no head: after html", "<!DOCTYPE html>\n<html><body>x", len("<!DOCTYPE html>\n<html>")},
		{"no head or html: after the doctype", "<!DOCTYPE html><p>x", len("<!DOCTYPE html>")},
		{"nothing: the start", "<p>x</p>", 0},
		{"byte order mark kept first", bom + "<p>x</p>", len(bom)},
		{"a link in a title is text", "<head><title><link rel=icon></title></head>", len("<head>")},
		{"a link in a script is text", `<head><script>"<link rel=icon>"</script></head>`, len("<head>")},
		{"declared", "<head><link rel=icon href=a.png></head>", -1},
		{"declared in mixed case, among tokens", `<head><link rel="ALTERNATE  icon" href=a.png></head>`, -1},
		{"declared in the body", "<head></head><body><link rel=icon href=a.png>", -1},
		{"mask-icon is not an icon link", `<head><link rel="mask-icon" href=a.svg></head>`, len("<head>")},
	} {
		at, ok := pageIconInsert([]byte(tc.doc), true)
		if tc.at < 0 {
			if ok {
				t.Errorf("%s: inserted at %d, want nothing", tc.name, at)
			}
			continue
		}
		if !ok || at != tc.at {
			t.Errorf("%s: (%d, %v), want %d", tc.name, at, ok, tc.at)
		}
	}
	// A window that ends inside the head decides nothing: the icon link may
	// come after it.
	if _, ok := pageIconInsert([]byte("<html><head><title>t</title><meta name=a"), false); ok {
		t.Error("a window ending inside the head inserted a link")
	}
	if at, ok := pageIconInsert([]byte("<html><head></head><body><p>lots"), false); !ok || at != len("<html><head>") {
		t.Errorf("a window past the head's end: (%d, %v)", at, ok)
	}
}
