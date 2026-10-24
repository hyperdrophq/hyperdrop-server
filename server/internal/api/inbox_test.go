package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"hyperdrop/server/internal/metadb"
)

// createInbox makes an inbox and returns its id.
func createInbox(t *testing.T, h http.Handler, body string) string {
	t.Helper()
	rec := doReq(t, h, "POST", "/api/shares", testToken, body)
	if rec.Code != 201 {
		t.Fatalf("create request = %d %s", rec.Code, rec.Body)
	}
	var resp struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	return resp.ID
}

func TestCreateInboxFieldsAndDefaults(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"name":"logs from alex","receive":true,"note":"the crash logs please"}`)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Inbox    bool   `json:"receive"`
		Note     string `json:"note"`
		Closed   bool   `json:"closed"`
		MaxBytes int64  `json:"maxBytes"`
		MaxFiles int    `json:"maxFiles"`
	}
	unmarshal(t, rec, &out)
	if !out.Inbox || out.Note != "the crash logs please" || out.Closed {
		t.Fatalf("fields = %+v", out)
	}
	// The caps are OPT-IN: unset stays 0 (unlimited), the owner's quota
	// being the standing bound.
	if out.MaxBytes != 0 || out.MaxFiles != 0 {
		t.Fatalf("caps should default to unlimited: %+v", out)
	}
}

func TestCreateInboxRefusals(t *testing.T) {
	h := newTestAPI(t)
	for name, body := range map[string]string{
		"manifest":       `{"name":"x","receive":true,"files":[{"path":"a.txt","size":1}]}`,
		"entry":          `{"name":"x","receive":true,"entry":"index.html"}`,
		"expiry":         `{"name":"x","receive":true,"expiresInSeconds":60}`,
		"reservation":    `{"name":"x","receive":true,"reserveBytes":10}`,
		"no name":        `{"receive":true}`,
		"caps off inbox": `{"name":"x","maxFiles":5}`,
		"note off inbox": `{"name":"x","note":"hi"}`,
		"negative cap":   `{"name":"x","receive":true,"maxFiles":-1}`,
		"note too long":  `{"name":"x","receive":true,"note":"` + strings.Repeat("n", 501) + `"}`,
	} {
		if rec := doReq(t, h, "POST", "/api/shares", testToken, body); rec.Code != 400 {
			t.Errorf("%s: code = %d %s", name, rec.Code, rec.Body)
		}
	}
}

// The default listing is ordinary shares only; ?kind=receive is the
// requests scope; anything else is refused rather than silently everything.
func TestListingScopesInboxesOut(t *testing.T) {
	h := newTestAPI(t)
	createShare(t, h, "plain")
	reqID := createInbox(t, h, `{"name":"inbox","receive":true}`)
	rec := doReq(t, h, "GET", "/api/shares", testToken, "")
	if rec.Code != 200 || strings.Contains(rec.Body.String(), reqID) {
		t.Fatalf("default listing leaked the request: %d %s", rec.Code, rec.Body)
	}
	rec = doReq(t, h, "GET", "/api/shares?kind=receive", testToken, "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), reqID) ||
		strings.Contains(rec.Body.String(), `"name":"plain"`) {
		t.Fatalf("inbox listing = %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "GET", "/api/shares?kind=bogus", testToken, ""); rec.Code != 400 {
		t.Fatalf("bogus kind = %d", rec.Code)
	}
}

func TestPatchInboxCloseReopenAndNote(t *testing.T) {
	h := newTestAPI(t)
	id := createInbox(t, h, `{"name":"inbox","receive":true}`)
	rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"closed":true}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"closed":true`) {
		t.Fatalf("close = %d %s", rec.Code, rec.Body)
	}
	rec = doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"closed":false,"note":"updated"}`)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), `"closed":true`) ||
		!strings.Contains(rec.Body.String(), `"note":"updated"`) {
		t.Fatalf("reopen = %d %s", rec.Code, rec.Body)
	}
	// The publish-side fields cannot apply to an inbox.
	for name, body := range map[string]string{
		"entry":     `{"entry":"index.html"}`,
		"expiry":    `{"expiresInSeconds":60}`,
		"scheduled": `{"password":"pw","applyInSeconds":60}`,
	} {
		if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, body); rec.Code != 400 {
			t.Errorf("%s on request = %d %s", name, rec.Code, rec.Body)
		}
	}
	// And the inbox-side fields cannot apply to an ordinary share.
	plain := createShare(t, h, "plain")
	for name, body := range map[string]string{
		"closed": `{"closed":true}`,
		"note":   `{"note":"hi"}`,
	} {
		if rec := doReq(t, h, "PATCH", "/api/shares/"+plain, testToken, body); rec.Code != 400 {
			t.Errorf("%s on share = %d %s", name, rec.Code, rec.Body)
		}
	}
}

// The heart of the feature: an anonymous PUT lands a file in the request,
// a colliding name is renamed rather than overwritten, and the response
// carries nothing an uploader could fetch back.
func TestInboxUploadAndAutoRename(t *testing.T) {
	h := newTestAPI(t)
	id := createInbox(t, h, `{"name":"inbox","receive":true}`)
	rec := doReq(t, h, "PUT", "/receive/"+id+"/files/report.pdf", "", "first sender")
	if rec.Code != 201 {
		t.Fatalf("upload = %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "slug") {
		t.Fatalf("upload response leaks a slug: %s", rec.Body)
	}
	rec = doReq(t, h, "PUT", "/receive/"+id+"/files/report.pdf", "", "second sender!")
	if rec.Code != 201 || !strings.Contains(rec.Body.String(), "report 2.pdf") {
		t.Fatalf("collision = %d %s", rec.Code, rec.Body)
	}
	// The owner sees both, intact.
	rec = doReq(t, h, "GET", "/api/shares/"+id, testToken, "")
	if !strings.Contains(rec.Body.String(), "report.pdf") ||
		!strings.Contains(rec.Body.String(), "report 2.pdf") {
		t.Fatalf("owner view = %s", rec.Body)
	}
}

func TestInboxUploadRefusals(t *testing.T) {
	h := newTestAPI(t)
	id := createInbox(t, h, `{"name":"inbox","receive":true}`)
	// Bad names never commit: a slash smuggled percent-encoded is a 400
	// here; a plain dot segment is the mux's own clean-and-redirect, which
	// is equally not an accepted upload.
	if rec := doReq(t, h, "PUT", "/receive/"+id+"/files/a%2Fb.txt", "", "x"); rec.Code != 400 {
		t.Errorf("encoded slash = %d", rec.Code)
	}
	for _, path := range []string{
		"/receive/" + id + "/files/..",
		"/receive/" + id + "/files/%2E%2E",
	} {
		if rec := doReq(t, h, "PUT", path, "", "x"); rec.Code == 201 {
			t.Errorf("%s was accepted", path)
		}
	}
	// A missing Content-Length cannot be cap-checked and is refused.
	req := httptest.NewRequest("PUT", "/receive/"+id+"/files/a.txt", nil)
	req.Body = http.NoBody
	req.ContentLength = -1
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusLengthRequired {
		t.Fatalf("no length = %d", rec.Code)
	}
	// Unknown id and an ORDINARY share's id are the same 404.
	if rec := doReq(t, h, "PUT", "/receive/zzzzzzzzzz/files/a.txt", "", "x"); rec.Code != 404 {
		t.Fatalf("unknown id = %d", rec.Code)
	}
	plain := createShare(t, h, "plain")
	if rec := doReq(t, h, "PUT", "/receive/"+plain+"/files/a.txt", "", "x"); rec.Code != 404 {
		t.Fatalf("share id on /receive = %d", rec.Code)
	}
	// Closed refuses with its own code.
	doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"closed":true}`)
	if rec := doReq(t, h, "PUT", "/receive/"+id+"/files/a.txt", "", "x"); rec.Code != 403 {
		t.Fatalf("closed = %d %s", rec.Code, rec.Body)
	}
}

func TestInboxCapsRefuseBeforeBytes(t *testing.T) {
	h := newTestAPI(t)
	id := createInbox(t, h, `{"name":"inbox","receive":true,"maxFiles":1,"maxBytes":100}`)
	if rec := doReq(t, h, "PUT", "/receive/"+id+"/files/big.bin", "", strings.Repeat("x", 101)); rec.Code != 413 {
		t.Fatalf("over byte cap = %d", rec.Code)
	}
	if rec := doReq(t, h, "PUT", "/receive/"+id+"/files/a.txt", "", "ok"); rec.Code != 201 {
		t.Fatalf("first = %d %s", rec.Code, rec.Body)
	}
	rec := doReq(t, h, "PUT", "/receive/"+id+"/files/b.txt", "", "no")
	if rec.Code != 413 || !strings.Contains(rec.Body.String(), "receive-full") {
		t.Fatalf("over file cap = %d %s", rec.Code, rec.Body)
	}
}

// The containment rule: a request answers 404 on EVERY public read route.
// Its only public surface is the upload page and the upload PUT.
func TestInboxShareIsInvisibleOnPublicReadRoutes(t *testing.T) {
	h := newTestAPI(t)
	id := createInbox(t, h, `{"name":"inbox","receive":true}`)
	if rec := doReq(t, h, "PUT", "/receive/"+id+"/files/secret.txt", "", "private"); rec.Code != 201 {
		t.Fatalf("upload = %d", rec.Code)
	}
	// The slug, via the owner API, to probe the payload routes with a REAL one.
	var sh struct {
		Files []struct {
			Slug string `json:"slug"`
		} `json:"files"`
	}
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+id, testToken, ""), &sh)
	slug := sh.Files[0].Slug
	for _, path := range []string{
		"/share/" + id,
		"/share/" + id + "/status",
		"/view/" + id + "/" + slug,
		"/download/" + id + "/" + slug,
		"/zip/" + id,
		"/card/" + id + "/poster.jpg",
		"/site/" + id + "/index.html",
		"/thumb/" + id + "/" + slug,
	} {
		if rec := doReq(t, h, "GET", path, "", ""); rec.Code != 404 {
			t.Errorf("%s = %d, want 404", path, rec.Code)
		}
	}
	// The one exception: the OWNER's bearer fetch on the download route
	// (Quick Look, `hyperdrop fetch`) is authenticated, not public, and
	// without it received files could never be opened. /view stays 404
	// even with the bearer.
	rec := doReq(t, h, "GET", "/download/"+id+"/"+slug, testToken, "")
	if rec.Code != 200 || rec.Body.String() != "private" {
		t.Fatalf("owner bearer download = %d %q", rec.Code, rec.Body.String())
	}
	if rec := doReq(t, h, "GET", "/view/"+id+"/"+slug, testToken, ""); rec.Code != 404 {
		t.Fatalf("bearer on /view = %d, want 404", rec.Code)
	}
}

func TestInboxPageStates(t *testing.T) {
	h := newTestAPI(t)
	id := createInbox(t, h, `{"name":"logs from alex","receive":true,"note":"crash logs please"}`)
	if rec := doReq(t, h, "PUT", "/receive/"+id+"/files/already-there.txt", "", "x"); rec.Code != 201 {
		t.Fatalf("seed upload = %d", rec.Code)
	}
	rec := doReq(t, h, "GET", "/receive/"+id, "", "")
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, "logs from alex") ||
		!strings.Contains(body, "crash logs please") {
		t.Fatalf("page = %d %s", rec.Code, body)
	}
	// Blind share: the page never lists what the request already holds.
	if strings.Contains(body, "already-there.txt") {
		t.Fatal("upload page leaks received file names")
	}
	doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"closed":true}`)
	rec = doReq(t, h, "GET", "/receive/"+id, "", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "no longer accepting") {
		t.Fatalf("closed page = %d", rec.Code)
	}
	// An ordinary share's id renders nothing here.
	plain := createShare(t, h, "plain")
	if rec := doReq(t, h, "GET", "/receive/"+plain, "", ""); rec.Code != 404 {
		t.Fatalf("share id on /receive page = %d", rec.Code)
	}
}

// A protected request gates the page behind the shared password form, the
// PUT behind the unlock cookie, and the unlock POST keeps working for it.
func TestInboxPasswordGate(t *testing.T) {
	h := newTestAPI(t)
	id := createInbox(t, h, `{"name":"inbox","receive":true,"password":"pw1"}`)
	rec := doReq(t, h, "GET", "/receive/"+id, "", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "password") {
		t.Fatalf("protected page = %d", rec.Code)
	}
	if rec := doReq(t, h, "PUT", "/receive/"+id+"/files/a.txt", "", "x"); rec.Code != 401 {
		t.Fatalf("PUT without cookie = %d", rec.Code)
	}
	// ?pw= on the request's OWN page mints the cookie (the /share route
	// rightly 404s a request, so the shared unlockCookies helper cannot).
	unlock := httptest.NewRequest("GET", "/receive/"+id+"?pw=pw1", nil)
	unlockRec := httptest.NewRecorder()
	h.ServeHTTP(unlockRec, unlock)
	cookies := unlockRec.Result().Cookies()
	if unlockRec.Code != 200 || len(cookies) == 0 {
		t.Fatalf("no cookie from /receive?pw= (code %d)", unlockRec.Code)
	}
	req := httptest.NewRequest("PUT", "/receive/"+id+"/files/a.txt", strings.NewReader("x"))
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 201 {
		t.Fatalf("PUT with cookie = %d %s", rec.Code, rec.Body)
	}
}

// The owner sees an upload HAPPENING: a live claim surfaces as `incoming`
// on the authed reads (with the sender's declared total) and disappears
// when the upload settles.
func TestIncomingSurfacesOnAuthedReads(t *testing.T) {
	h, hd := newTestAPIParts(t)
	id := createInbox(t, h, `{"name":"inbox","receive":true}`)
	up, _ := hd.claims.claim(id, metadb.DefaultAdminName, "big.bin", heldBy(func(string) bool { return false }), 1000, "")
	rec := doReq(t, h, "GET", "/api/shares/"+id, testToken, "")
	if !strings.Contains(rec.Body.String(), `"incoming"`) ||
		!strings.Contains(rec.Body.String(), `"big.bin"`) ||
		!strings.Contains(rec.Body.String(), `"total":1000`) {
		t.Fatalf("getShare incoming: %s", rec.Body)
	}
	rec = doReq(t, h, "GET", "/api/shares?kind=receive", testToken, "")
	if !strings.Contains(rec.Body.String(), `"big.bin"`) {
		t.Fatalf("listing incoming: %s", rec.Body)
	}
	up.Release()
	rec = doReq(t, h, "GET", "/api/shares/"+id, testToken, "")
	if strings.Contains(rec.Body.String(), `"incoming"`) {
		t.Fatalf("incoming should clear on release: %s", rec.Body)
	}
}

// A pasted inbox link unfurls: bots get an Open Graph card carrying the
// name and note, never the upload page and never received content.
func TestInboxPageUnfurlerCard(t *testing.T) {
	h := newTestAPI(t)
	id := createInbox(t, h, `{"name":"logs from alex","receive":true,"note":"crash logs please"}`)
	if rec := doReq(t, h, "PUT", "/receive/"+id+"/files/secret.txt", "", "private"); rec.Code != 201 {
		t.Fatalf("seed upload = %d", rec.Code)
	}
	rec := doReqUA(t, h, "/receive/"+id, "Slackbot-LinkExpanding 1.0")
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, `og:title`) ||
		!strings.Contains(body, "logs from alex") || !strings.Contains(body, "crash logs please") {
		t.Fatalf("card = %d %s", rec.Code, body)
	}
	if strings.Contains(body, "secret.txt") || strings.Contains(body, "Drop files here") {
		t.Fatal("card leaks content or renders the upload page")
	}
}

// doReqCookies is doReq with a cookie jar, which is how a browser's second
// request to an inbox carries what the first one handed it.
func doReqCookies(t *testing.T, h http.Handler, method, path, body string,
	cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestUploadPageMintsAVisitorCookie(t *testing.T) {
	h := newTestAPI(t)
	id := createInbox(t, h, `{"name":"inbox","receive":true}`)
	rec := doReq(t, h, "GET", "/receive/"+id, "", "")
	if rec.Code != 200 {
		t.Fatalf("page = %d", rec.Code)
	}
	var got *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == visitorCookieName(id) {
			got = c
		}
	}
	if got == nil {
		t.Fatal("no visitor cookie set")
	}
	if !got.HttpOnly || got.SameSite != http.SameSiteLaxMode {
		t.Fatalf("weak cookie flags: %+v", got)
	}
	if got.Path != "/receive/"+id {
		t.Fatalf("path %q must scope the cookie to this link alone", got.Path)
	}
	// Host-only: the grouping token has no business on the file origin.
	if got.Domain != "" {
		t.Fatalf("domain %q, want host-only", got.Domain)
	}
	if !validVisitor(got.Value) {
		t.Fatalf("minted value %q does not satisfy validVisitor", got.Value)
	}
}

// A sender that already has a token keeps it, or every page reload would
// look like a new sender.
func TestVisitorCookieIsReusedNotReminted(t *testing.T) {
	h := newTestAPI(t)
	id := createInbox(t, h, `{"name":"inbox","receive":true}`)
	first := doReq(t, h, "GET", "/receive/"+id, "", "")
	jar := first.Result().Cookies()
	second := doReqCookies(t, h, "GET", "/receive/"+id, "", jar)
	for _, c := range second.Result().Cookies() {
		if c.Name == visitorCookieName(id) {
			t.Fatalf("re-minted a token the sender already had: %q", c.Value)
		}
	}
}

// The visitor cookie carries NO authority: it must not be readable as an
// access cookie, and holding one must not open a protected link.
func TestVisitorCookieGrantsNoAccess(t *testing.T) {
	h := newTestAPI(t)
	id := createInbox(t, h, `{"name":"inbox","receive":true,"password":"hunter2"}`)
	if visitorCookieName(id) == "hd_"+id {
		t.Fatal("visitor and access cookie names collide")
	}
	// A protected link hands out no visitor cookie until the password is
	// answered, and an upload carrying only a hand-made one is still 401.
	forged := &http.Cookie{Name: visitorCookieName(id), Value: "AbC-_0123456789abcdefg"}
	rec := doReqCookies(t, h, "PUT", "/receive/"+id+"/files/a.txt", "hello",
		[]*http.Cookie{forged})
	if rec.Code != 401 {
		t.Fatalf("upload with only a visitor cookie = %d, want 401", rec.Code)
	}
}

// A hand-crafted cookie must not smuggle an arbitrary string into share meta.
func TestVisitorValueIsValidated(t *testing.T) {
	for _, bad := range []string{"", "short", strings.Repeat("a", 23),
		"has spaces here!!!!!!!", "twenty-two-chars-but/x"} {
		if validVisitor(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
	if !validVisitor("AbC-_0123456789abcdefg") {
		t.Error("rejected a well-formed value")
	}
}

func TestInboxUploadRecordsTheSender(t *testing.T) {
	h := newTestAPI(t)
	id := createInbox(t, h, `{"name":"inbox","receive":true}`)
	jar := doReq(t, h, "GET", "/receive/"+id, "", "").Result().Cookies()
	if rec := doReqCookies(t, h, "PUT", "/receive/"+id+"/files/a.txt", "hello", jar); rec.Code != 201 {
		t.Fatalf("upload = %d %s", rec.Code, rec.Body)
	}
	rec := doReq(t, h, "GET", "/api/shares/"+id, testToken, "")
	var out struct {
		Files []struct {
			Path       string `json:"path"`
			UploadedBy string `json:"uploadedBy"`
		} `json:"files"`
	}
	unmarshal(t, rec, &out)
	if len(out.Files) != 1 {
		t.Fatalf("files = %+v", out.Files)
	}
	if !validVisitor(out.Files[0].UploadedBy) {
		t.Fatalf("sender %q is not a minted token", out.Files[0].UploadedBy)
	}
}

// A sender with no cookie still uploads; it is simply its own group.
func TestInboxUploadWithoutACookieStillCommits(t *testing.T) {
	h := newTestAPI(t)
	id := createInbox(t, h, `{"name":"inbox","receive":true}`)
	if rec := doReq(t, h, "PUT", "/receive/"+id+"/files/a.txt", "", "hello"); rec.Code != 201 {
		t.Fatalf("upload = %d %s", rec.Code, rec.Body)
	}
	rec := doReq(t, h, "GET", "/api/shares/"+id, testToken, "")
	if strings.Contains(rec.Body.String(), "uploadedBy") {
		t.Fatalf("invented a sender for a cookieless upload: %s", rec.Body)
	}
}

// uploadedBy is an inbox field: an owner's own upload session must not
// ride an ordinary share's rows.
func TestUploadedByIsInboxOnly(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "docs")
	if rec := doReqWithHeader(t, h, "PUT", "/api/shares/"+id+"/files/doc.txt",
		"Upload-Session", "OWNERSESSION1234567890"); rec.Code == 500 {
		t.Fatalf("upload = %d %s", rec.Code, rec.Body)
	}
	rec := doReq(t, h, "GET", "/api/shares/"+id, testToken, "")
	if strings.Contains(rec.Body.String(), "uploadedBy") {
		t.Fatalf("ordinary share leaks uploadedBy: %s", rec.Body)
	}
}

// The owner watching an upload happen sees WHICH sender it belongs to.
func TestIncomingCarriesTheSender(t *testing.T) {
	h, hd := newTestAPIParts(t)
	id := createInbox(t, h, `{"name":"inbox","receive":true}`)
	up, _ := hd.claims.claim(id, metadb.DefaultAdminName, "big.bin", heldBy(func(string) bool { return false }), 1000, "SENDER0123456789012345")
	defer up.Release()
	rec := doReq(t, h, "GET", "/api/shares/"+id, testToken, "")
	var out struct {
		Incoming []struct {
			Name string `json:"name"`
			By   string `json:"by"`
		} `json:"incoming"`
	}
	unmarshal(t, rec, &out)
	if len(out.Incoming) != 1 || out.Incoming[0].By != "SENDER0123456789012345" {
		t.Fatalf("incoming = %+v", out.Incoming)
	}
}

// An inbox exists to receive files, so notifications start ON, and a link
// created before the field reads the same way (the meta field is inverted).
func TestNotifyDefaultsOn(t *testing.T) {
	h := newTestAPI(t)
	id := createInbox(t, h, `{"name":"inbox","receive":true}`)
	rec := doReq(t, h, "GET", "/api/shares/"+id, testToken, "")
	var out struct {
		Notify *bool `json:"notify"`
	}
	unmarshal(t, rec, &out)
	if out.Notify == nil || !*out.Notify {
		t.Fatalf("notify = %v, want true", out.Notify)
	}
}

func TestNotifyIsSettable(t *testing.T) {
	h := newTestAPI(t)
	id := createInbox(t, h, `{"name":"inbox","receive":true}`)
	if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"notify":false}`); rec.Code != 200 {
		t.Fatalf("patch = %d %s", rec.Code, rec.Body)
	}
	rec := doReq(t, h, "GET", "/api/shares/"+id, testToken, "")
	var out struct {
		Notify *bool `json:"notify"`
	}
	unmarshal(t, rec, &out)
	if out.Notify == nil || *out.Notify {
		t.Fatalf("notify = %v, want false", out.Notify)
	}
}

// notify and seenAt are inbox fields, exactly as closed and note are.
func TestNotifyAndSeenAtRefusedOnAnOrdinaryShare(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "docs")
	for _, body := range []string{`{"notify":false}`, `{"seenAt":"2026-08-23T10:00:00Z"}`} {
		if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, body); rec.Code != 400 {
			t.Errorf("patch %s = %d, want 400", body, rec.Code)
		}
	}
	rec := doReq(t, h, "GET", "/api/shares/"+id, testToken, "")
	if strings.Contains(rec.Body.String(), "notify") || strings.Contains(rec.Body.String(), "seenAt") {
		t.Fatalf("ordinary share reports inbox-only fields: %s", rec.Body)
	}
}

func TestSeenAtRoundTripsAndNeverGoesBackwards(t *testing.T) {
	h := newTestAPI(t)
	id := createInbox(t, h, `{"name":"inbox","receive":true}`)
	late := "2026-08-23T10:00:00Z"
	early := "2026-08-23T09:00:00Z"
	if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"seenAt":"`+late+`"}`); rec.Code != 200 {
		t.Fatalf("patch = %d %s", rec.Code, rec.Body)
	}
	// A client running behind must not rewind the badge for one running ahead.
	if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"seenAt":"`+early+`"}`); rec.Code != 200 {
		t.Fatalf("second patch = %d %s", rec.Code, rec.Body)
	}
	rec := doReq(t, h, "GET", "/api/shares/"+id, testToken, "")
	var out struct {
		SeenAt string `json:"seenAt"`
	}
	unmarshal(t, rec, &out)
	if out.SeenAt != late {
		t.Fatalf("seenAt = %q, want the later %q", out.SeenAt, late)
	}
}

// A stranger's commit onto a path holding the owner's committed file (the
// owner uploaded that name between the stranger's claim and commit) is
// refused under the path's lock before the rename, so the owner's bytes
// never move, whatever the filesystem keeps aside.
func TestAnAnonymousCommitNeverMovesTheOwnersFile(t *testing.T) {
	_, hd := newTestAPIParts(t)
	h := hd.routes()
	id := createInbox(t, h, `{"name":"in","receive":true}`)
	uploadFile(t, h, testToken, id, "a.txt", "owner's")
	path, err := hd.fs.FilePath(id, "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hd.fs.Write(id, "a.txt", strings.NewReader("stranger's")); err != nil {
		t.Fatal(err)
	}
	_, err = hd.commitUpload(metadb.CommitInput{ShareID: id, Path: "a.txt", Anonymous: true}, int64(len("stranger's")))
	if !errors.Is(err, metadb.ErrPathTaken) {
		t.Fatalf("anonymous commit = %v, want ErrPathTaken", err)
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("the owner's file moved: %v", err)
	}
	if n, err := hd.fs.PartSize(id, "a.txt"); err != nil || n != int64(len("stranger's")) {
		t.Fatalf("part = %d, %v: the commit renamed the stranger's bytes before refusing", n, err)
	}
	if data, _ := os.ReadFile(path); string(data) != "owner's" {
		t.Fatalf("the path holds %q", data)
	}
}
