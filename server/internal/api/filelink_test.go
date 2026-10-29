package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/liveshare"
	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/shareid"
)

// mintFileKey answers the direct-link key of one file, minted through the
// owner's route.
func mintFileKey(t *testing.T, h http.Handler, token, id, slug string) string {
	t.Helper()
	rec := doReq(t, h, "POST", "/api/shares/"+id+"/file-links", token, `{"slugs":["`+slug+`"]}`)
	if rec.Code != 200 {
		t.Fatalf("mint: %d %s", rec.Code, rec.Body)
	}
	var out mintAnswer
	unmarshal(t, rec, &out)
	if len(out.Links) != 1 || !shareid.ValidFileKey(out.Links[0].FileKey) {
		t.Fatalf("mint answer: %s", rec.Body)
	}
	return out.Links[0].FileKey
}

// fileLinkReq sends one request with the given headers and cookies.
func fileLinkReq(t *testing.T, h http.Handler, method, path string, headers map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// fileLinkUnlock posts the file link's password form.
func fileLinkUnlock(t *testing.T, h http.Handler, key, password, next string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"password": {password}, "next": {next}}.Encode()
	return doReqForm(t, h, "POST", "/f/"+key+"/unlock", form)
}

// cookieNamed answers the cookie of that name an answer sets, or nil.
func cookieNamed(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// namesNothing fails when any header value or the body of an answer holds
// one of the words.
func namesNothing(t *testing.T, what string, rec *httptest.ResponseRecorder, words ...string) {
	t.Helper()
	for name, values := range rec.Header() {
		for _, v := range values {
			for _, w := range words {
				if strings.Contains(v, w) {
					t.Errorf("%s: header %s %q names %q", what, name, v, w)
				}
			}
		}
	}
	for _, w := range words {
		if strings.Contains(rec.Body.String(), w) {
			t.Errorf("%s: body names %q", what, w)
		}
	}
}

func TestFileLinkServesItsFileOnly(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "Quarterly")
	slug := uploadGetSlug(t, h, id, "a/secret-folder/report.txt", "the report")
	other := uploadGetSlug(t, h, id, "other.txt", "sibling")
	binSlug := uploadGetSlug(t, h, id, "blob.bin", "\x00\x01\x02")
	key := mintFileKey(t, h, testToken, id, slug)
	binKey := mintFileKey(t, h, testToken, id, binSlug)
	words := []string{id, other, "secret-folder", "other.txt", "Quarterly", slug}

	for _, tc := range []struct {
		method, path, disp, body string
	}{
		{"GET", "/f/" + key, `inline; filename=report.txt`, "the report"},
		{"HEAD", "/f/" + key, `inline; filename=report.txt`, ""},
		{"GET", "/f/" + key + "/download", `attachment; filename=report.txt`, "the report"},
		{"HEAD", "/f/" + key + "/download", `attachment; filename=report.txt`, ""},
		{"GET", "/f/" + binKey, `attachment; filename=blob.bin`, "\x00\x01\x02"},
	} {
		rec := fileLinkReq(t, h, tc.method, tc.path, nil)
		if rec.Code != 200 || rec.Body.String() != tc.body {
			t.Fatalf("%s %s = %d %q", tc.method, tc.path, rec.Code, rec.Body)
		}
		if got := rec.Header().Get("Content-Disposition"); got != tc.disp {
			t.Errorf("%s %s disposition = %q, want %q", tc.method, tc.path, got, tc.disp)
		}
		if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
			t.Errorf("%s %s Referrer-Policy = %q", tc.method, tc.path, got)
		}
		if got := rec.Header().Get("X-Robots-Tag"); got != "noindex" {
			t.Errorf("%s %s X-Robots-Tag = %q", tc.method, tc.path, got)
		}
		namesNothing(t, tc.method+" "+tc.path, rec, words...)
	}

	// An unfurler gets a card, never the bytes, and the card names only the
	// file.
	rec := fileLinkReq(t, h, "GET", "/f/"+key, map[string]string{"User-Agent": "Slackbot-LinkExpanding 1.0"})
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "the report") {
		t.Fatalf("unfurler = %d %q", rec.Code, rec.Body)
	}
	namesNothing(t, "unfurler card", rec, words...)
}

func TestFileLinkBareDomainRedirects(t *testing.T) {
	h := domainAPI(t, "share.example.com")
	id := createShare(t, h, "s")
	slug := uploadGetSlug(t, h, id, "a.txt", "A")
	key := mintFileKey(t, h, testToken, id, slug)
	for _, method := range []string{"GET", "HEAD"} {
		for _, p := range []string{"/f/" + key, "/f/" + key + "/download", "/f/" + key + "/status"} {
			req := httptest.NewRequest(method, p, nil)
			req.Host = "share.example.com"
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusPermanentRedirect || rec.Header().Get("Location") != "https://files.share.example.com"+p {
				t.Errorf("%s %s on the app origin = %d %q", method, p, rec.Code, rec.Header().Get("Location"))
			}
		}
	}
	req := httptest.NewRequest("POST", "/f/"+key+"/unlock", strings.NewReader("password=x"))
	req.Host = "share.example.com"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 404 {
		t.Errorf("POST unlock on the app origin = %d, want 404", rec.Code)
	}
	req = httptest.NewRequest("GET", "/f/"+key, nil)
	req.Host = "files.share.example.com"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || rec.Body.String() != "A" {
		t.Errorf("GET on the file origin = %d %q", rec.Code, rec.Body)
	}
}

func TestFileLinkGateRefusals(t *testing.T) {
	h, um, b := newMultiUserAPI(t)

	past := time.Now().Add(-time.Hour).UTC()
	d, err := b.DB.CreateShare(metadb.CreateOptions{Name: "x", Owner: metadb.DefaultAdminName, ExpiresAt: &past})
	if err != nil {
		t.Fatal(err)
	}
	commitFile(t, b, d.ID, "a.txt", "data")
	held, err := b.DB.Share(d.ID)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := b.DB.MintFileKeys(d.ID, []string{held.Files[0].Slug}, time.Now())
	if err != nil || len(keys) != 1 {
		t.Fatalf("mint on the expired share: %v %v", keys, err)
	}
	expired := keys[held.Files[0].Slug]

	alice := seedUser(t, um, "alice")
	aliceShare := createShareAs(t, h, alice, `{"name":"a"}`)
	suspended := mintFileKey(t, h, alice, aliceShare, uploadGetSlugAs(t, h, alice, aliceShare, "a.txt", "A"))
	if rec := doReq(t, h, "PATCH", "/api/users/alice", testToken, `{"disabled":true}`); rec.Code != 200 {
		t.Fatalf("suspend: %d %s", rec.Code, rec.Body)
	}

	id := createShare(t, h, "s")
	deleted := mintFileKey(t, h, testToken, id, uploadGetSlug(t, h, id, "a.txt", "A"))
	uploadGetSlug(t, h, id, "b.txt", "B")
	if rec := doReq(t, h, "DELETE", "/api/shares/"+id+"/files/a.txt", testToken, ""); rec.Code != 200 {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	cSlug := uploadGetSlug(t, h, id, "c.txt", "C")
	stopped := mintFileKey(t, h, testToken, id, cSlug)
	if rec := doReq(t, h, "DELETE", "/api/shares/"+id+"/file-links/"+cSlug, testToken, ""); rec.Code != 204 {
		t.Fatalf("stop: %d", rec.Code)
	}

	cases := map[string]string{
		"expired share":   expired,
		"suspended owner": suspended,
		"deleted file":    deleted,
		"stopped key":     stopped,
		"short":           "abc",
		"bad alphabet":    strings.Repeat("0", shareid.FileKeyLen),
		"unknown":         shareid.NewFileKey(),
		"a share id":      id,
	}
	var page, status string
	for name, key := range cases {
		for _, p := range []string{"/f/" + key, "/f/" + key + "/download"} {
			rec := fileLinkReq(t, h, "GET", p, nil)
			if rec.Code != 404 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
				t.Errorf("%s: GET %s = %d %q", name, p, rec.Code, rec.Header().Get("Content-Type"))
			}
			if page == "" {
				page = rec.Body.String()
			} else if rec.Body.String() != page {
				t.Errorf("%s: GET %s answers a different 404 page", name, p)
			}
			if rec.Header().Get("Referrer-Policy") != "no-referrer" {
				t.Errorf("%s: GET %s has no Referrer-Policy", name, p)
			}
		}
		rec := fileLinkReq(t, h, "GET", "/f/"+key+"/status", nil)
		if rec.Code != 404 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
			t.Errorf("%s: status = %d %q", name, rec.Code, rec.Header().Get("Content-Type"))
		}
		if status == "" {
			status = rec.Body.String()
		} else if rec.Body.String() != status {
			t.Errorf("%s: status answers a different 404: %s", name, rec.Body)
		}
		if rec := fileLinkUnlock(t, h, key, "x", ""); rec.Code != 404 || rec.Body.String() != page {
			t.Errorf("%s: unlock = %d", name, rec.Code)
		}
	}
}

// protectedFileLink is a password-protected share holding a.txt, its id, the
// file's slug and its key.
func protectedFileLink(t *testing.T, h http.Handler) (id, slug, key string) {
	t.Helper()
	id = createProtectedShare(t, h, "hunter2")
	slug = uploadGetSlug(t, h, id, "a.txt", "data")
	return id, slug, mintFileKey(t, h, testToken, id, slug)
}

func TestFileLinkPassword(t *testing.T) {
	h := newTestAPI(t)
	id, _, key := protectedFileLink(t, h)

	rec := fileLinkReq(t, h, "GET", "/f/"+key, nil)
	if rec.Code != 200 || rec.Body.String() == "data" || !strings.Contains(rec.Body.String(), `action="/f/`+key+`/unlock"`) {
		t.Fatalf("form = %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `value="/f/`+key+`"`) {
		t.Errorf("the form's next is not the address asked for: %s", rec.Body)
	}
	namesNothing(t, "form", rec, id, "secret")
	rec = fileLinkReq(t, h, "GET", "/f/"+key+"/download?x=1", nil)
	if !strings.Contains(rec.Body.String(), `value="/f/`+key+`/download"`) {
		t.Errorf("the download form's next: %s", rec.Body)
	}

	rec = fileLinkUnlock(t, h, key, "nope", "/f/"+key)
	if rec.Code != 401 || !strings.Contains(rec.Body.String(), "Incorrect password. Try again.") {
		t.Fatalf("wrong = %d %s", rec.Code, rec.Body)
	}
	if cookieNamed(rec, "hdf_"+key) != nil {
		t.Fatal("a wrong guess set the cookie")
	}

	rec = fileLinkUnlock(t, h, key, "hunter2", "/f/"+key+"/download")
	if rec.Code != 303 || rec.Header().Get("Location") != "/f/"+key+"/download" {
		t.Fatalf("right = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	c := cookieNamed(rec, "hdf_"+key)
	if c == nil || c.Path != "/f/"+key || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Domain != "" {
		t.Fatalf("cookie: %+v", c)
	}
	wantLifetime(t, "cookie", c, accessTTL)
	namesNothing(t, "unlock", rec, id)
	if got := fileLinkReq(t, h, "GET", "/f/"+key, nil, c); got.Code != 200 || got.Body.String() != "data" {
		t.Fatalf("with the cookie = %d %q", got.Code, got.Body)
	}

	for _, next := range []string{"/share/x", "/share/" + id, "/f/" + key + "?pw=x", "//evil.example/f/" + key,
		"https://evil.example/f/" + key, "/f/" + key + "/status", "/f/" + shareid.NewFileKey(), ""} {
		rec = fileLinkUnlock(t, h, key, "hunter2", next)
		if rec.Code != 303 || rec.Header().Get("Location") != "/f/"+key {
			t.Errorf("next %q = %d %q, want /f/<key>", next, rec.Code, rec.Header().Get("Location"))
		}
	}

	nav := map[string]string{"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}
	rec = fileLinkReq(t, h, "GET", "/f/"+key+"/download?pw=hunter2", nav)
	if rec.Code != 303 || rec.Header().Get("Location") != "/f/"+key+"/download" || cookieNamed(rec, "hdf_"+key) == nil {
		t.Fatalf("?pw= navigation = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec = fileLinkReq(t, h, "GET", "/f/"+key+"?pw=hunter2", nil); rec.Code != 200 || rec.Body.String() != "data" {
		t.Fatalf("?pw= without Fetch Metadata = %d %q", rec.Code, rec.Body)
	}
	if rec = fileLinkReq(t, h, "GET", "/f/"+key+"?pw=nope", nil); rec.Body.String() == "data" {
		t.Fatal("a wrong ?pw= served the file")
	}

	wrong := url.Values{"password": {"nope"}}.Encode()
	for i := 0; i < pwFailLimit-1; i++ {
		if rec := doReqFormFrom(t, h, "/f/"+key+"/unlock", wrong, "203.0.113.50:1"); rec.Code != 401 {
			t.Fatalf("guess %d = %d", i+1, rec.Code)
		}
	}
	if rec := doReqFormFrom(t, h, "/f/"+key+"/unlock", wrong, "203.0.113.50:1"); rec.Code != 429 {
		t.Fatalf("guess %d = %d, want 429", pwFailLimit, rec.Code)
	}
	right := url.Values{"password": {"hunter2"}}.Encode()
	if rec := doReqFormFrom(t, h, "/f/"+key+"/unlock", right, "203.0.113.50:2"); rec.Code != 429 || cookieNamed(rec, "hdf_"+key) != nil {
		t.Fatalf("the right password while locked out = %d", rec.Code)
	}
}

func TestFileLinkCookieDiesWithAPasswordChange(t *testing.T) {
	h := newTestAPI(t)
	id, _, key := protectedFileLink(t, h)
	c := cookieNamed(fileLinkUnlock(t, h, key, "hunter2", ""), "hdf_"+key)
	if c == nil {
		t.Fatal("no cookie")
	}
	if rec := fileLinkReq(t, h, "GET", "/f/"+key, nil, c); rec.Body.String() != "data" {
		t.Fatalf("before the change: %d", rec.Code)
	}
	if rec := patchShare(t, h, id, `{"password":"another"}`); rec.Code != 200 {
		t.Fatalf("change: %d %s", rec.Code, rec.Body)
	}
	if rec := fileLinkReq(t, h, "GET", "/f/"+key, nil, c); rec.Body.String() == "data" || !strings.Contains(rec.Body.String(), "/unlock") {
		t.Fatalf("after the change: %d %q", rec.Code, rec.Body)
	}
	if rec := fileLinkReq(t, h, "GET", "/f/"+key+"/status", nil, c); rec.Code != 401 {
		t.Fatalf("status after the change: %d", rec.Code)
	}
}

func TestShareCookieDoesNotOpenAFileLinkNorTheReverse(t *testing.T) {
	h := newTestAPI(t)
	id, slug, key := protectedFileLink(t, h)

	rec := doReqForm(t, h, "POST", "/unlock/"+id, url.Values{"password": {"hunter2"}}.Encode())
	share := cookieNamed(rec, "hd_"+id)
	if share == nil {
		t.Fatalf("the share's unlock set no cookie: %d", rec.Code)
	}
	if got := fileLinkReq(t, h, "GET", "/download/"+id+"/"+slug, nil, share); got.Body.String() != "data" {
		t.Fatalf("the share cookie does not open its own share: %d", got.Code)
	}
	if got := fileLinkReq(t, h, "GET", "/f/"+key, nil, share); got.Body.String() == "data" {
		t.Fatal("the share's cookie opened the file link")
	}
	if got := fileLinkReq(t, h, "GET", "/f/"+key, nil, &http.Cookie{Name: "hdf_" + key, Value: share.Value}); got.Body.String() == "data" {
		t.Fatal("the share cookie's value opened the file link under its name")
	}

	rec = fileLinkUnlock(t, h, key, "hunter2", "")
	file := cookieNamed(rec, "hdf_"+key)
	if file == nil {
		t.Fatal("no file cookie")
	}
	for _, c := range rec.Result().Cookies() {
		if strings.HasPrefix(c.Name, "hd_") {
			t.Errorf("the file link's unlock set %s", c.Name)
		}
	}
	for _, p := range []string{"/download/" + id + "/" + slug, "/view/" + id + "/" + slug, "/share/" + id, "/zip/" + id} {
		if got := fileLinkReq(t, h, "GET", p, nil, file); got.Body.String() == "data" || got.Code == 302 {
			t.Errorf("the file cookie opened %s: %d", p, got.Code)
		}
		as := &http.Cookie{Name: "hd_" + id, Value: file.Value}
		if got := fileLinkReq(t, h, "GET", p, nil, as); got.Body.String() == "data" {
			t.Errorf("the file cookie's value opened %s as the share cookie", p)
		}
	}
}

func TestFileLinkStatusNeedsTheCookie(t *testing.T) {
	h := newTestAPI(t)
	_, _, key := protectedFileLink(t, h)
	for _, p := range []string{"/f/" + key + "/status", "/f/" + key + "/status?pw=hunter2"} {
		rec := fileLinkReq(t, h, "GET", p, nil)
		if rec.Code != 401 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
			t.Fatalf("%s = %d %s", p, rec.Code, rec.Body)
		}
		if cookieNamed(rec, "hdf_"+key) != nil {
			t.Fatalf("%s set the cookie", p)
		}
	}
	c := cookieNamed(fileLinkUnlock(t, h, key, "hunter2", ""), "hdf_"+key)
	poll := map[string]string{"Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin"}
	rec := fileLinkReq(t, h, "GET", "/f/"+key+"/status", poll, c)
	if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("the page's own poll = %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Complete bool `json:"complete"`
		File     struct {
			Size     int64 `json:"size"`
			Bytes    int64 `json:"bytes"`
			Complete bool  `json:"complete"`
		} `json:"file"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || !out.Complete || !out.File.Complete || out.File.Size != 4 || out.File.Bytes != 4 {
		t.Fatalf("status: %s", rec.Body)
	}
	poll["Sec-Fetch-Site"] = "cross-site"
	if rec := fileLinkReq(t, h, "GET", "/f/"+key+"/status", poll, c); rec.Code != 401 {
		t.Fatalf("a cross-site fetch with the cookie = %d", rec.Code)
	}
}

func TestFileLinkIgnoresOpensAs(t *testing.T) {
	h := newTestAPI(t)
	files := map[string]string{}

	listing := createShare(t, h, "l")
	files["listing"] = mintFileKey(t, h, testToken, listing, uploadGetSlug(t, h, listing, "a.txt", "listing"))
	uploadGetSlug(t, h, listing, "b.txt", "B")
	if rec := patchShare(t, h, listing, `{"listing":true}`); rec.Code != 200 {
		t.Fatalf("listing: %d %s", rec.Code, rec.Body)
	}

	site := createShare(t, h, "site")
	uploadGetSlug(t, h, site, "index.html", "<p>page</p>")
	files["page"] = mintFileKey(t, h, testToken, site, uploadGetSlug(t, h, site, "notes.txt", "page"))
	if rec := patchShare(t, h, site, `{"entry":"index.html"}`); rec.Code != 200 {
		t.Fatalf("entry: %d %s", rec.Code, rec.Body)
	}

	gallery := newMediaShare(t, h, map[string]string{"a.jpg": string(aJPEG(t, 8, 6))})
	var g fileLinkShare
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+gallery, testToken, ""), &g)
	files["gallery"] = mintFileKey(t, h, testToken, gallery, g.Files[0].Slug)

	text := createTextShare(t, h)
	if rec := doReq(t, h, "PUT", "/api/shares/"+text+"/files/note.txt", testToken, "text"); rec.Code != 201 {
		t.Fatalf("note: %d %s", rec.Code, rec.Body)
	}
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+text, testToken, ""), &g)
	files["text"] = mintFileKey(t, h, testToken, text, g.Files[0].Slug)

	for kind, key := range files {
		for _, p := range []string{"/f/" + key, "/f/" + key + "/download"} {
			rec := fileLinkReq(t, h, "GET", p, nil)
			if rec.Code != 200 || rec.Header().Get("Location") != "" {
				t.Errorf("%s: %s = %d", kind, p, rec.Code)
				continue
			}
			if want := map[string]string{"listing": "listing", "page": "page", "text": "text"}[kind]; want != "" && rec.Body.String() != want {
				t.Errorf("%s: %s served %q", kind, p, rec.Body)
			}
			if kind == "gallery" && rec.Body.Len() == 0 {
				t.Errorf("gallery: %s served nothing", p)
			}
		}
	}
}

func TestFileLinkDocumentIsSandboxed(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "s")
	for name, body := range map[string]string{
		"page.html": "<script>document.cookie</script>",
		"pic.svg":   `<svg xmlns="http://www.w3.org/2000/svg"><script>1</script></svg>`,
	} {
		key := mintFileKey(t, h, testToken, id, uploadGetSlug(t, h, id, name, body))
		for _, p := range []string{"/f/" + key, "/f/" + key + "/download"} {
			rec := fileLinkReq(t, h, "GET", p, nil)
			csp := rec.Header().Get("Content-Security-Policy")
			if rec.Code != 200 || csp != sandboxCSP {
				t.Errorf("%s %s = %d, CSP %q", name, p, rec.Code, csp)
			}
			if strings.Contains(csp, "allow-same-origin") || strings.Contains(csp, "allow-popups-to-escape-sandbox") {
				t.Errorf("%s %s: CSP %q hands the origin back", name, p, csp)
			}
			if strings.Contains(rec.Body.String(), "<link rel=\"icon\"") {
				t.Errorf("%s %s: a page icon was inserted", name, p)
			}
		}
	}
}

func TestFileLinkCrossSiteEmbedIs403(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	view := noEmbedFixture(t, h, um)
	parts := strings.Split(view, "/") // /view/<id>/<slug>
	alice, err := um.MintToken("alice", "test")
	if err != nil {
		t.Fatal(err)
	}
	key := mintFileKey(t, h, alice, parts[2], parts[3])
	for _, p := range []string{"/f/" + key, "/f/" + key + "/download"} {
		rec := fileLinkReq(t, h, "GET", p, nil)
		if rec.Code != 200 || rec.Header().Get("Cross-Origin-Resource-Policy") != "same-origin" {
			t.Fatalf("direct open %s = %d CORP %q", p, rec.Code, rec.Header().Get("Cross-Origin-Resource-Policy"))
		}
		rec = fileLinkReq(t, h, "GET", p, map[string]string{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Dest": "image"})
		if rec.Code != 403 || rec.Body.Len() != 0 || rec.Header().Get("Location") != "" {
			t.Fatalf("cross-site embed %s = %d %q %q", p, rec.Code, rec.Header().Get("Location"), rec.Body)
		}
		namesNothing(t, "embed refusal", rec, parts[2], parts[3])
		rec = fileLinkReq(t, h, "GET", p, map[string]string{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Dest": "document"})
		if rec.Code != 200 {
			t.Fatalf("cross-site navigation %s = %d", p, rec.Code)
		}
	}
}

func TestFileLinkOnALiveShare(t *testing.T) {
	h := newTestLiveShareHandler(t)
	mux := h.routes()
	rec := doReq(t, mux, "POST", "/api/live-share", testToken, liveShareKeysBody)
	var created liveShareKeyedOut
	unmarshal(t, rec, &created)
	key := created.Files[0].FileKey
	serveLiveShareBody(t, h, created.ID, metadb.DefaultAdminName, "hello")
	got := doLiveShareGet(t, mux, "/f/"+key+"/download", nil)
	if got.Code != 200 || got.Body.String() != "hello" ||
		got.Header().Get("Content-Disposition") != "attachment; filename=a.txt" {
		t.Fatalf("online = %d %q %q", got.Code, got.Body, got.Header().Get("Content-Disposition"))
	}
	namesNothing(t, "live download", got, created.ID, created.Files[1].Slug, "b.txt")

	now := time.Now()
	off := newTestHandlerLiveShare(t, liveshareConfigAt(&now))
	offMux := off.routes()
	rec = doReq(t, offMux, "POST", "/api/live-share", testToken, liveShareKeysBody)
	unmarshal(t, rec, &created)
	now = now.Add(15 * time.Second)
	got = doReq(t, offMux, "GET", "/f/"+created.Files[0].FileKey, "", "")
	if got.Code != http.StatusServiceUnavailable {
		t.Fatalf("offline = %d %s", got.Code, got.Body)
	}
	namesNothing(t, "live offline", got, created.ID, "b.txt")
}

// liveshareConfigAt is a registry configuration on a clock the test moves.
func liveshareConfigAt(now *time.Time) liveshare.Config {
	return liveshare.Config{OfflineAfter: 10 * time.Second, Now: func() time.Time { return *now }}
}

// Every /f/ answer past the password is revalidated, and private on a
// protected share, the unfurler's card included: a stopped link or a
// password added later must reach a cache that holds the answer.
func TestFileLinkAnswersAreRevalidated(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "open")
	key := mintFileKey(t, h, testToken, id, uploadGetSlug(t, h, id, "a.txt", "data"))
	pageKey := mintFileKey(t, h, testToken, id, uploadGetSlug(t, h, id, "p.html", "<p>hi</p>"))
	unfurler := map[string]string{"User-Agent": "Slackbot-LinkExpanding 1.0"}
	check := func(what string, rec *httptest.ResponseRecorder, want string) {
		t.Helper()
		if rec.Code != 200 {
			t.Fatalf("%s = %d %s", what, rec.Code, rec.Body)
		}
		if got := rec.Header().Get("Cache-Control"); got != want {
			t.Errorf("%s Cache-Control = %q, want %q", what, got, want)
		}
	}
	for _, p := range []string{"/f/" + key, "/f/" + key + "/download", "/f/" + pageKey} {
		check("GET "+p, fileLinkReq(t, h, "GET", p, nil), "no-cache")
		check("HEAD "+p, fileLinkReq(t, h, "HEAD", p, nil), "no-cache")
	}
	check("open card", fileLinkReq(t, h, "GET", "/f/"+key, unfurler), "no-cache")

	_, _, locked := protectedFileLink(t, h)
	c := cookieNamed(fileLinkUnlock(t, h, locked, "hunter2", ""), "hdf_"+locked)
	if c == nil {
		t.Fatal("no cookie")
	}
	check("protected view", fileLinkReq(t, h, "GET", "/f/"+locked, nil, c), "private, no-cache")
	check("protected download", fileLinkReq(t, h, "GET", "/f/"+locked+"/download", nil, c), "private, no-cache")
	check("protected card", fileLinkReq(t, h, "GET", "/f/"+locked, unfurler, c), "private, no-cache")
	check("protected ?pw=", fileLinkReq(t, h, "GET", "/f/"+locked+"?pw=hunter2", nil), "private, no-cache")

	lh := newTestLiveShareHandler(t)
	mux := lh.routes()
	rec := doReq(t, mux, "POST", "/api/live-share", testToken, liveShareKeysBody)
	var created liveShareKeyedOut
	unmarshal(t, rec, &created)
	serveLiveShareBody(t, lh, created.ID, metadb.DefaultAdminName, "hello")
	check("live download", doLiveShareGet(t, mux, "/f/"+created.Files[0].FileKey+"/download", nil), "no-cache")
	check("live view", doLiveShareGet(t, mux, "/f/"+created.Files[0].FileKey, nil), "no-cache")
}

// A file link's cookie is bound to its own key: A's valid value carried under
// B's name does not open B, though both files sit behind the same password.
func TestFileLinkCookieOpensOnlyItsOwnKey(t *testing.T) {
	h := newTestAPI(t)
	id, _, keyA := protectedFileLink(t, h)
	keyB := mintFileKey(t, h, testToken, id, uploadGetSlug(t, h, id, "b.txt", "bees"))
	a := cookieNamed(fileLinkUnlock(t, h, keyA, "hunter2", ""), "hdf_"+keyA)
	if a == nil {
		t.Fatal("no cookie for A")
	}
	if got := fileLinkReq(t, h, "GET", "/f/"+keyA, nil, a); got.Body.String() != "data" {
		t.Fatalf("A's cookie does not open A: %d", got.Code)
	}
	forged := &http.Cookie{Name: "hdf_" + keyB, Value: a.Value}
	for _, p := range []string{"/f/" + keyB, "/f/" + keyB + "/download"} {
		got := fileLinkReq(t, h, "GET", p, nil, forged)
		if got.Body.String() == "bees" || !strings.Contains(got.Body.String(), "/f/"+keyB+"/unlock") {
			t.Fatalf("A's value under B's name opened %s: %d %q", p, got.Code, got.Body)
		}
	}
	if got := fileLinkReq(t, h, "GET", "/f/"+keyB+"/status", nil, forged); got.Code != 401 {
		t.Fatalf("A's value under B's name read B's status: %d", got.Code)
	}
}
