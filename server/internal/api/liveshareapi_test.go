package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/liveshare"
	"hyperdrop/server/internal/shareid"
)

// liveShareCreateBody is the manifest for a two-file live share, used by most
// tests here. Two files (not one) so /share renders the listing page instead of
// 302ing to the lone file's /view URL.
const liveShareCreateBody = `{"name":"demo","files":[` +
	`{"path":"a.txt","size":5,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"},` +
	`{"path":"b.txt","size":7,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"}` +
	`]}`

// liveShareCreateBodyOne is a single-file manifest, used where the test wants the
// file's own slug (for /view and /download URLs) and does not care about /share.
const liveShareCreateBodyOne = `{"name":"demo","files":[` +
	`{"path":"a.txt","size":5,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"}` +
	`]}`

type liveShareOut struct {
	ID    string `json:"id"`
	Entry string `json:"entry"`
	Files []struct {
		Path string `json:"path"`
		Slug string `json:"slug"`
	} `json:"files"`
}

func createLiveShare(t *testing.T, h http.Handler, token, body string) liveShareOut {
	t.Helper()
	rec := doReq(t, h, "POST", "/api/live-share", token, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create live share: %d %s", rec.Code, rec.Body)
	}
	var sh liveShareOut
	unmarshal(t, rec, &sh)
	return sh
}

// TestLiveShareCreatePollTransferRoundTrip drives the whole owner-facing surface:
// create, poll for a job, and send its bytes. Task 4 added the route that
// CREATES a job (GET /download, /view, /zip), so the "visitor" here is a real GET
// request through the real route (liveshareserve.go's serveLiveShareFile) rather than
// a direct h.liveShareReg.NewJob call standing in for one, and the delivered
// bytes are read off that response instead of off the job's own Body().
func TestLiveShareCreatePollTransferRoundTrip(t *testing.T) {
	h := newTestLiveShareHandler(t)
	mux := h.routes()

	sh := createLiveShare(t, mux, testToken, liveShareCreateBodyOne)
	slug := sh.Files[0].Slug

	visitor := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest("GET", "/download/"+sh.ID+"/"+slug, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		visitor <- rec
	}()

	// Sharer: poll, claim, send.
	rec := doReq(t, mux, "GET", "/api/live-share/"+sh.ID+"/jobs", testToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("poll: %d %s", rec.Code, rec.Body)
	}
	var poll struct {
		Jobs []struct {
			Job  string `json:"job"`
			Path string `json:"path"`
		} `json:"jobs"`
	}
	unmarshal(t, rec, &poll)
	if len(poll.Jobs) != 1 || poll.Jobs[0].Path != "a.txt" {
		t.Fatalf("poll: %+v", poll)
	}
	rec = doReq(t, mux, "POST", "/api/live-share/jobs/"+poll.Jobs[0].Job, testToken, "hello")
	if rec.Code != http.StatusOK {
		t.Fatalf("send: %d %s", rec.Code, rec.Body)
	}

	select {
	case got := <-visitor:
		if got.Code != http.StatusOK || got.Body.String() != "hello" {
			t.Fatalf("visitor got %d %q, want 200 %q", got.Code, got.Body.String(), "hello")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the visitor's GET /download to complete")
	}
}

// TestLiveSharePerOwnerCapIs429 pins the per-owner cap (default 3, liveshare.go's
// defaultMaxPerOwner) and the machine-readable code a client reacts to.
func TestLiveSharePerOwnerCapIs429(t *testing.T) {
	h := newTestLiveShareHandler(t)
	mux := h.routes()

	for i := 0; i < 3; i++ {
		body := fmt.Sprintf(`{"name":"live-%d","files":[{"path":"a.txt","size":5,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"}]}`, i)
		rec := doReq(t, mux, "POST", "/api/live-share", testToken, body)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create %d: %d %s", i, rec.Code, rec.Body)
		}
	}
	rec := doReq(t, mux, "POST", "/api/live-share", testToken, liveShareCreateBodyOne)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("4th create: %d, want 429", rec.Code)
	}
	var out struct {
		Code string `json:"code"`
	}
	unmarshal(t, rec, &out)
	if out.Code != "too-many-live-shares" {
		t.Fatalf("code = %q, want too-many-live-shares", out.Code)
	}
}

func TestLiveShareResumePreservesIDAndSlug(t *testing.T) {
	h := newTestLiveShareHandler(t)
	mux := h.routes()
	sh := createLiveShare(t, mux, testToken, liveShareCreateBodyOne)
	body := fmt.Sprintf(`{"resume":%q,"name":"ignored","files":[`+
		`{"path":"a.txt","size":5,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"}]}`, sh.ID)
	rec := doReq(t, mux, "POST", "/api/live-share", testToken, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("resume: %d %s", rec.Code, rec.Body)
	}
	var resumed liveShareOut
	unmarshal(t, rec, &resumed)
	if resumed.ID != sh.ID || resumed.Files[0].Slug != sh.Files[0].Slug {
		t.Fatalf("resume changed links: before=%+v after=%+v", sh, resumed)
	}
}

func TestLiveShareResumeRejectsChangedManifestAndAnotherOwner(t *testing.T) {
	h := newTestLiveShareHandler(t)
	mux := h.routes()
	sh := createLiveShare(t, mux, testToken, liveShareCreateBodyOne)
	changed := fmt.Sprintf(`{"resume":%q,"files":[`+
		`{"path":"a.txt","size":6,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"}]}`, sh.ID)
	rec := doReq(t, mux, "POST", "/api/live-share", testToken, changed)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "live-share-resume-mismatch") {
		t.Fatalf("changed resume: %d %s", rec.Code, rec.Body)
	}

	bobToken := seedUser(t, h.db, "bob")
	unchanged := fmt.Sprintf(`{"resume":%q,"files":[`+
		`{"path":"a.txt","size":5,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"}]}`, sh.ID)
	if rec := doReq(t, mux, "POST", "/api/live-share", bobToken, unchanged); rec.Code != http.StatusNotFound {
		t.Fatalf("cross-owner resume: %d %s", rec.Code, rec.Body)
	}
}

// TestAJobBodyNeverCrossesAccounts is a security test: a second account must
// not be able to see or claim jobs on a live share it does not own, and a
// visitor parked on the real job must catch ZERO bytes from the attempt,
// asserted on the delivered bytes, not just the HTTP status of the attempt.
//
// As in the round-trip test above, the "visitor parked on /download" is simulated by
// creating the job directly on the registry (Task 4 builds the real /download
// route); everything else runs over real HTTP with real bearer tokens.
func TestAJobBodyNeverCrossesAccounts(t *testing.T) {
	h := newTestLiveShareHandler(t)
	mux := h.routes()
	bobToken := seedUser(t, h.db, "bob")

	sh := createLiveShare(t, mux, testToken, liveShareCreateBodyOne)

	job, err := h.liveShareReg.NewJob(context.Background(), sh.ID, "203.0.113.1", "download", "a.txt", 0, 5)
	if err != nil {
		t.Fatalf("NewJob: %v", err)
	}
	delivered := make(chan string, 1)
	go func() {
		rc, err := job.Body(context.Background(), 5*time.Second)
		if err != nil {
			delivered <- "ERR:" + err.Error()
			return
		}
		b, _ := io.ReadAll(rc)
		delivered <- string(b)
	}()

	// Bob cannot even poll admin's share.
	rec := doReq(t, mux, "GET", "/api/live-share/"+sh.ID+"/jobs", bobToken, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("bob poll: %d, want 404", rec.Code)
	}

	// Admin learns the real job id honestly, from admin's own poll.
	rec = doReq(t, mux, "GET", "/api/live-share/"+sh.ID+"/jobs", testToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("admin poll: %d %s", rec.Code, rec.Body)
	}
	var poll struct {
		Jobs []struct {
			Job string `json:"job"`
		} `json:"jobs"`
	}
	unmarshal(t, rec, &poll)
	if len(poll.Jobs) != 1 {
		t.Fatalf("admin poll: %+v", poll)
	}
	jobID := poll.Jobs[0].Job

	// Bob POSTs bytes to admin's job id with BOB's own valid token.
	rec = doReq(t, mux, "POST", "/api/live-share/jobs/"+jobID, bobToken, "evil-bytes")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("bob claim: %d, want 404", rec.Code)
	}

	// The visitor must still be waiting: nothing has been delivered yet.
	select {
	case got := <-delivered:
		t.Fatalf("visitor received bytes before the real owner sent any: %q", got)
	default:
	}

	// The real owner completes the transfer; the visitor gets exactly that,
	// proof bob's attempt never reached the pipe.
	rec = doReq(t, mux, "POST", "/api/live-share/jobs/"+jobID, testToken, "hello")
	if rec.Code != http.StatusOK {
		t.Fatalf("admin send: %d %s", rec.Code, rec.Body)
	}
	if got := <-delivered; got != "hello" {
		t.Fatalf("visitor got %q, want %q (bob's bytes must never cross accounts)", got, "hello")
	}
}

// TestLiveShareDeleteEndsEveryLink: DELETE ends every public route for the share,
// including the ones Task 4 has not wired a live relay into yet, since they
// 404 via visibleShareVia finding nothing in either the database or the registry.
func TestLiveShareDeleteEndsEveryLink(t *testing.T) {
	h := newTestAPI(t)
	sh := createLiveShare(t, h, testToken, liveShareCreateBodyOne)
	slug := sh.Files[0].Slug

	rec := doReq(t, h, "DELETE", "/api/live-share/"+sh.ID, testToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}

	for _, path := range []string{
		"/share/" + sh.ID,
		"/view/" + sh.ID + "/" + slug,
		"/download/" + sh.ID + "/" + slug,
		"/zip/" + sh.ID,
	} {
		rec := doReq(t, h, "GET", path, "", "")
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s after delete = %d, want 404", path, rec.Code)
		}
	}
}

// TestLiveShareIsInvisibleToTheListing: a live share has no row in the
// database, so both the paged listing and the by-id read must 404/omit it,
// exactly as if it never existed on disk, because it never did.
func TestLiveShareIsInvisibleToTheListing(t *testing.T) {
	h := newTestAPI(t)
	sh := createLiveShare(t, h, testToken, liveShareCreateBodyOne)

	rec := doReq(t, h, "GET", "/api/shares", testToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("listing: %d %s", rec.Code, rec.Body)
	}
	var listing struct {
		Shares []struct {
			ID string `json:"id"`
		} `json:"shares"`
	}
	unmarshal(t, rec, &listing)
	for _, s := range listing.Shares {
		if s.ID == sh.ID {
			t.Fatalf("live share %s leaked into GET /api/shares", sh.ID)
		}
	}

	rec = doReq(t, h, "GET", "/api/shares/"+sh.ID, testToken, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /api/shares/{id} for a live share = %d, want 404", rec.Code)
	}
}

// A one-file live share redirects /share/{id} to the file, unless listing
// is set: that flag is the only way a live share of one file gets a listing
// page, matching a stored share.
func TestLiveShareListingOpensThePage(t *testing.T) {
	h := newTestAPI(t)
	sh := createLiveShare(t, h, testToken, `{"listing":true,"files":[`+
		`{"path":"a.txt","size":5,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"}`+
		`]}`)

	rec := doReq(t, h, "GET", "/share/"+sh.ID, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("listed live share: %d, want 200: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "a.txt") {
		t.Fatalf("listing page missing file name: %s", rec.Body)
	}
}

func TestLiveShareOneFileRedirectsWithoutListing(t *testing.T) {
	h := newTestAPI(t)
	sh := createLiveShare(t, h, testToken, liveShareCreateBodyOne)

	rec := doReq(t, h, "GET", "/share/"+sh.ID, "", "")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302: %s", rec.Code, rec.Body)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "/view/"+sh.ID+"/") {
		t.Fatalf("Location = %q, want /view/{id}/{slug}", loc)
	}
}

func TestPatchLiveShareListingOpensThePage(t *testing.T) {
	h := newTestAPI(t)
	sh := createLiveShare(t, h, testToken, liveShareCreateBodyOne)

	rec := doReq(t, h, "PATCH", "/api/live-share/"+sh.ID, testToken, `{"listing":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH listing: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Listing bool `json:"listing"`
	}
	unmarshal(t, rec, &out)
	if !out.Listing {
		t.Fatal("PATCH did not echo listing")
	}

	rec = doReq(t, h, "GET", "/share/"+sh.ID, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("after PATCH: %d, want 200: %s", rec.Code, rec.Body)
	}
}

func TestPatchLiveShareNothingToChangeIs400(t *testing.T) {
	h := newTestAPI(t)
	sh := createLiveShare(t, h, testToken, liveShareCreateBodyOne)
	rec := doReq(t, h, "PATCH", "/api/live-share/"+sh.ID, testToken, `{}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty PATCH: %d, want 400", rec.Code)
	}
}

func TestPatchLiveSharePasswordAndExpiry(t *testing.T) {
	h := newTestAPI(t)
	sh := createLiveShare(t, h, testToken, liveShareCreateBodyOne)
	rec := doReq(t, h, "PATCH", "/api/live-share/"+sh.ID, testToken,
		`{"password":"secret","expiresInSeconds":3600}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		HasPassword bool   `json:"hasPassword"`
		ExpiresAt   string `json:"expiresAt"`
	}
	unmarshal(t, rec, &out)
	if !out.HasPassword {
		t.Fatal("password not set")
	}
	if out.ExpiresAt == "" {
		t.Fatal("expiry not set")
	}
}

// A visitor's access cookie is signed over the share's password generation,
// so a new password on a live share must void the cookies the old one issued,
// as it does for a stored share (TestPasswordChangeRevokesCookies).
func TestLivePasswordChangeRevokesCookies(t *testing.T) {
	h := newTestAPI(t)
	sh := createLiveShare(t, h, testToken, `{"name":"demo","password":"first","files":[`+
		`{"path":"a.txt","size":5,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"}]}`)

	rec := doReqForm(t, h, "POST", "/unlock/"+sh.ID, "password=first&next=/share/"+sh.ID)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("unlock status = %d: %s", rec.Code, rec.Body)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no access cookie set")
	}
	withCookie := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/share/"+sh.ID, nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	// A one-file share redirects to the file once access is granted.
	if w := withCookie(); w.Code != http.StatusFound {
		t.Fatalf("cookie should grant access (302 to the file): %d %s", w.Code, w.Body)
	}

	for _, body := range []string{`{"password":"second"}`, `{"password":""}`, `{"password":"first"}`} {
		if rec := doReq(t, h, "PATCH", "/api/live-share/"+sh.ID, testToken, body); rec.Code != http.StatusOK {
			t.Fatalf("PATCH %s: %d %s", body, rec.Code, rec.Body)
		}
	}
	// Removed and set again, even to the first password: the cookie is
	// still from an earlier generation.
	if w := withCookie(); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "password-protected") {
		t.Fatalf("old cookie survived a password change: %d", w.Code)
	}
}

func TestPatchStreamAddFilesWidensTheShare(t *testing.T) {
	h := newTestAPI(t)
	sh := createLiveShare(t, h, testToken, liveShareCreateBodyOne)
	rec := doReq(t, h, "PATCH", "/api/live-share/"+sh.ID, testToken,
		`{"addFiles":[{"path":"b.txt","size":2,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH addFiles: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Files []struct {
			Path string `json:"path"`
		} `json:"files"`
	}
	unmarshal(t, rec, &out)
	if len(out.Files) != 2 {
		t.Fatalf("files = %+v, want two", out.Files)
	}
	rec = doReq(t, h, "GET", "/share/"+sh.ID, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("listing after add: %d, want 200: %s", rec.Code, rec.Body)
	}
}

// The file cap is on the share, not on one request: PATCHes that each name
// few files still stop where the share would describe more than the cap,
// with the code create uses, and the refused PATCH adds nothing.
func TestPatchLiveShareCapsTheWholeShare(t *testing.T) {
	h := newTestHandlerLiveShare(t, liveshare.Config{MaxFiles: 2})
	mux := h.routes()
	sh := createLiveShare(t, mux, testToken, liveShareCreateBodyOne)
	add := func(path string) *httptest.ResponseRecorder {
		return doReq(t, mux, "PATCH", "/api/live-share/"+sh.ID, testToken,
			`{"addFiles":[{"path":"`+path+`","size":2,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"}]}`)
	}
	if rec := add("b.txt"); rec.Code != http.StatusOK {
		t.Fatalf("up to the cap: %d %s", rec.Code, rec.Body)
	}
	rec := add("c.txt")
	if rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rec.Body.String(), `"code":"manifest-too-big"`) {
		t.Fatalf("past the cap: %d %s, want 413 manifest-too-big", rec.Code, rec.Body)
	}
	if got, _ := h.liveShareReg.Get(sh.ID); len(got.Files) != 2 {
		t.Fatalf("a refused PATCH left %d files, want 2", len(got.Files))
	}
}

// A PATCH refused on a later check changes nothing it carried: files that
// would make the share a gallery it cannot be are not added, and a page
// naming no file leaves the files and the name as they were.
func TestPatchLiveShareRefusedChangesNothing(t *testing.T) {
	h := newTestLiveShareHandler(t)
	mux := h.routes()
	sh := createLiveShare(t, mux, testToken, liveShareCreateBodyOne)
	before, _ := h.liveShareReg.Get(sh.ID)
	for _, body := range []string{
		`{"media":true,"addFiles":[{"path":"b.bin","size":2,"mime":"application/octet-stream","mtime":"2026-08-06T10:00:00Z"}]}`,
		`{"name":"renamed","entry":"missing.html","addFiles":[{"path":"c.txt","size":2,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"}]}`,
	} {
		rec := doReq(t, mux, "PATCH", "/api/live-share/"+sh.ID, testToken, body)
		if rec.Code < 400 || rec.Code >= 500 {
			t.Fatalf("PATCH %s = %d %s, want a refusal", body, rec.Code, rec.Body)
		}
		got, _ := h.liveShareReg.Get(sh.ID)
		if len(got.Files) != 1 || got.Name != before.Name || got.Media || got.Entry != "" {
			t.Fatalf("a refused PATCH %s changed the share: %+v", body, got)
		}
	}
	// The page may be one of the files the same request adds.
	rec := doReq(t, mux, "PATCH", "/api/live-share/"+sh.ID, testToken,
		`{"entry":"index.html","addFiles":[{"path":"index.html","size":2,"mime":"text/html","mtime":"2026-08-06T10:00:00Z"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("a page this request adds: %d %s", rec.Code, rec.Body)
	}
}

// TestVisibleShareFallsBackToStream is the public-route half of the same
// contract: /share/{id} renders the ordinary listing page for a live share,
// with no password, exactly as it would for a stored one.
func TestVisibleShareFallsBackToStream(t *testing.T) {
	h := newTestAPI(t)
	sh := createLiveShare(t, h, testToken, liveShareCreateBody)

	rec := doReq(t, h, "GET", "/share/"+sh.ID, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("content-type = %q, want text/html", ct)
	}
	if !strings.Contains(rec.Body.String(), "a.txt") {
		t.Fatalf("listing page missing file name: %s", rec.Body)
	}
}

// TestLiveShareFailJobSurfacesAsVisitorError is the happy path for POST
// /api/live-share/jobs/{job}/error: the sharer reports a job it cannot fulfil, and
// the visitor parked on that job's Body() sees the failure instead of
// hanging until the claim timeout.
func TestLiveShareFailJobSurfacesAsVisitorError(t *testing.T) {
	h := newTestLiveShareHandler(t)
	mux := h.routes()
	sh := createLiveShare(t, mux, testToken, liveShareCreateBodyOne)

	job, err := h.liveShareReg.NewJob(context.Background(), sh.ID, "203.0.113.1", "download", "a.txt", 0, 5)
	if err != nil {
		t.Fatalf("NewJob: %v", err)
	}
	failed := make(chan error, 1)
	go func() {
		_, err := job.Body(context.Background(), 5*time.Second)
		failed <- err
	}()

	rec := doReq(t, mux, "GET", "/api/live-share/"+sh.ID+"/jobs", testToken, "")
	var poll struct {
		Jobs []struct {
			Job string `json:"job"`
		} `json:"jobs"`
	}
	unmarshal(t, rec, &poll)
	if len(poll.Jobs) != 1 {
		t.Fatalf("poll: %+v", poll)
	}

	rec = doReq(t, mux, "POST", "/api/live-share/jobs/"+poll.Jobs[0].Job+"/error", testToken, `{"code":"file-vanished"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("fail: %d %s", rec.Code, rec.Body)
	}

	err = <-failed
	if err == nil || !strings.Contains(err.Error(), "file-vanished") {
		t.Fatalf("visitor error = %v, want it to name file-vanished", err)
	}
}

// TestLiveShareFailJobRefusesAnOversizedBody is FINDING 1's regression test:
// liveShareFailJob decoding the request body with no size cap at all lets any
// authenticated account POST an unbounded body at
// /api/live-share/jobs/{anything}/error and run the server out of memory. It
// refuses a body past liveShareFailBodyLimit rather than trying to buffer it.
// decodeJSONBody's limit is enforced before any job lookup, so no share or
// job needs to exist for this to matter: an arbitrary path segment exercises
// the same code path a real job id would.
func TestLiveShareFailJobRefusesAnOversizedBody(t *testing.T) {
	h := newTestLiveShareHandler(t)
	mux := h.routes()

	oversized := `{"code":"` + strings.Repeat("x", liveShareFailBodyLimit+1) + `"}`
	rec := doReq(t, mux, "POST", "/api/live-share/jobs/whatever/error", testToken, oversized)
	if rec.Code == http.StatusOK {
		t.Fatalf("oversized /error body was accepted: %d %s", rec.Code, rec.Body)
	}
}

// TestLiveShareCreateRejectsBadManifest is FINDING 2's regression test:
// createLiveShare must reject the same manifest shapes metadb.CreateShare
// does, a duplicate path and a negative size, rather than letting either
// through to feed the Range and ETag math with garbage.
func TestLiveShareCreateRejectsBadManifest(t *testing.T) {
	h := newTestLiveShareHandler(t)
	mux := h.routes()

	cases := []struct {
		name string
		body string
	}{
		{"duplicate path", `{"name":"dup","files":[` +
			`{"path":"a.txt","size":5,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"},` +
			`{"path":"a.txt","size":7,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"}` +
			`]}`},
		{"negative size", `{"name":"neg","files":[` +
			`{"path":"a.txt","size":-1,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"}` +
			`]}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := doReq(t, mux, "POST", "/api/live-share", testToken, c.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s: status = %d, want 400: %s", c.name, rec.Code, rec.Body)
			}
		})
	}
}

// TestNewLiveShareIDSkipsAStoreCollision is FINDING 3's regression test. It
// cannot force a real shareid.NewID collision (crypto/rand gives no seam for
// that), so it tests newLiveShareID's own loop directly: mint is a fake returning
// a colliding id first and a fresh one second, exists reports the first as
// already taken, and the loop must skip past it rather than handing out an
// id the database already holds.
func TestNewLiveShareIDSkipsAStoreCollision(t *testing.T) {
	ids := []string{"AAAAAAAAAA", "BBBBBBBBBB"}
	calls := 0
	mint := func() string {
		id := ids[calls]
		calls++
		return id
	}
	taken := map[string]bool{"AAAAAAAAAA": true}
	exists := func(id string) bool { return taken[id] }

	got := newLiveShareID(mint, exists)()
	if got != "BBBBBBBBBB" {
		t.Fatalf("newLiveShareID() = %q, want BBBBBBBBBB (the colliding id must be skipped)", got)
	}
	if calls != 2 {
		t.Fatalf("mint called %d times, want 2", calls)
	}
}

// newTestLiveShareHandler builds the handler directly (like newTestWatchAPI),
// giving tests access to h.liveShareReg for the simulated-visitor jobs above.
func newTestLiveShareHandler(t *testing.T) *handler {
	t.Helper()
	return newHandler(testBackend(t), "2.0.0", testDomain(t), nil, Deployment{})
}

// newTestHandlerLiveShare is newTestLiveShareHandler with the caller's own
// liveshare.Config, so a test can inject a movable clock (cfg.Now) to drive
// Online() past OfflineAfter without a real sleep (liveserve_test.go's
// offline test). ID and slug minting fall back to shareid's real ones when
// the caller leaves them nil, matching newHandler's own wiring.
func newTestHandlerLiveShare(t *testing.T, cfg liveshare.Config) *handler {
	t.Helper()
	h := newTestLiveShareHandler(t)
	if cfg.NewID == nil {
		cfg.NewID = shareid.NewID
	}
	if cfg.NewSlug == nil {
		cfg.NewSlug = shareid.NewSlug
	}
	h.liveShareReg = liveshare.NewRegistry(cfg)
	return h
}

// The jobs poll carries the visitor count beside the offers, so the sharer's
// client learns it without a second route.
func TestLiveSharePollCarriesVisitors(t *testing.T) {
	h := newTestLiveShareHandler(t)
	h.liveSharePollPark = time.Millisecond // no job is offered: answer "nothing yet" at once
	mux := h.routes()
	sh := createLiveShare(t, mux, testToken, liveShareCreateBody)
	var tok [32]byte
	tok[0] = 7
	h.liveShareReg.Visit(sh.ID, tok)
	rec := doReq(t, mux, "GET", "/api/live-share/"+sh.ID+"/jobs", testToken, "")
	if rec.Code != 200 {
		t.Fatalf("poll = %d %s", rec.Code, rec.Body)
	}
	var poll struct {
		Jobs     []struct{} `json:"jobs"`
		Visitors int        `json:"visitors"`
	}
	unmarshal(t, rec, &poll)
	if poll.Visitors != 1 {
		t.Fatalf("visitors = %d, want 1: %s", poll.Visitors, rec.Body)
	}
	if poll.Jobs == nil {
		t.Fatalf("jobs must be an array, never null: %s", rec.Body)
	}
}
