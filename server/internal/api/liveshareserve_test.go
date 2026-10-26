package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/liveshare"
	"hyperdrop/server/internal/metadb"
)

// serveLiveShareBody plays the sharer side of the job rendezvous for shareID, in
// the background, for as long as the test runs: poll the registry for
// offers and answer each one with the slice of content its start/end names
// (end < 0 means "to EOF"). It talks to h.liveShareReg directly rather than
// through the /api/live-share routes: those routes and their poll/claim/send
// wiring are Task 3's territory and are pinned there, and everything new in
// this file is on the VISITOR side (serveLiveShareFile/serveLiveShareZip), which every
// test below reaches through a real GET /view, /download or /zip. A wrong start/end
// would still show up here, in the bytes the visitor actually receives.
//
// Talking to h.liveShareReg directly rather than through the authenticated
// /api/live-share routes also means this helper never authenticates anyone,
// which matters to TestALiveShareNeverWritesToTheVolume below: it is not what
// could trip that test's assertion either way.
func serveLiveShareBody(t *testing.T, h *handler, shareID, owner, content string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		for {
			offers, err := h.liveShareReg.Poll(ctx, shareID, owner, time.Second)
			if err != nil {
				return
			}
			for _, o := range offers {
				c, ok := h.liveShareReg.Claim(owner, o.Job)
				if !ok {
					continue
				}
				chunk := content[o.Start:]
				if o.End >= 0 {
					chunk = content[o.Start : o.End+1]
				}
				io.WriteString(c, chunk)
				c.Close()
			}
			if ctx.Err() != nil {
				return
			}
		}
	}()
}

// doLiveShareGet issues a request that may block on a live job's rendezvous, so
// it runs the request in its own goroutine and times out rather than
// hanging the suite when something above is broken.
func doLiveShareGet(t *testing.T, h http.Handler, path string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		h.ServeHTTP(rec, req)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for a live response")
	}
	return rec
}

func TestLiveShareRangeRequest(t *testing.T) {
	h := newTestLiveShareHandler(t)
	mux := h.routes()
	body := `{"name":"demo","files":[` +
		`{"path":"f.txt","size":26,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"}]}`
	sh := createLiveShare(t, mux, testToken, body)
	slug := sh.Files[0].Slug
	content := "abcdefghijklmnopqrstuvwxyz"

	serveLiveShareBody(t, h, sh.ID, metadb.DefaultAdminName, content)

	rec := doLiveShareGet(t, mux, "/download/"+sh.ID+"/"+slug, map[string]string{"Range": "bytes=10-19"})
	if rec.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206: %s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Content-Range"); got != "bytes 10-19/26" {
		t.Fatalf("Content-Range = %q, want %q", got, "bytes 10-19/26")
	}
	if got := rec.Header().Get("Content-Length"); got != "10" {
		t.Fatalf("Content-Length = %q, want 10", got)
	}
	// This is what proves the job the sharer saw actually carried start=10
	// end=19: serveLiveShareBody slices its content by exactly those fields, so a
	// wrong offer would deliver the wrong substring here.
	if got := rec.Body.String(); got != "klmnopqrst" {
		t.Fatalf("body = %q, want %q", got, "klmnopqrst")
	}
}

func TestLiveShareETagIsStrongAndStable(t *testing.T) {
	h := newTestLiveShareHandler(t)
	mux := h.routes()
	body := `{"name":"demo","files":[` +
		`{"path":"f.txt","size":26,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"}]}`
	sh := createLiveShare(t, mux, testToken, body)
	slug := sh.Files[0].Slug
	content := "abcdefghijklmnopqrstuvwxyz"

	serveLiveShareBody(t, h, sh.ID, metadb.DefaultAdminName, content)

	rec1 := doLiveShareGet(t, mux, "/download/"+sh.ID+"/"+slug, nil)
	etag1 := rec1.Header().Get("ETag")
	if etag1 == "" {
		t.Fatal("no ETag on the first response")
	}

	rec2 := doLiveShareGet(t, mux, "/download/"+sh.ID+"/"+slug, nil)
	if etag2 := rec2.Header().Get("ETag"); etag2 != etag1 {
		t.Fatalf("ETag changed across requests: %q then %q", etag1, etag2)
	}

	rec3 := doLiveShareGet(t, mux, "/download/"+sh.ID+"/"+slug, map[string]string{
		"Range": "bytes=0-4", "If-Range": etag1,
	})
	if rec3.Code != http.StatusPartialContent {
		t.Fatalf("If-Range matching the ETag: status = %d, want 206: %s", rec3.Code, rec3.Body)
	}

	rec4 := doLiveShareGet(t, mux, "/download/"+sh.ID+"/"+slug, map[string]string{
		"Range": "bytes=0-4", "If-Range": `"bogus-999"`,
	})
	if rec4.Code != http.StatusOK {
		t.Fatalf("If-Range not matching the ETag: status = %d, want 200: %s", rec4.Code, rec4.Body)
	}
	if rec4.Body.String() != content {
		t.Fatalf("If-Range mismatch body = %q, want the whole file %q", rec4.Body.String(), content)
	}
}

func TestLiveShareNeverNegotiatesEncoding(t *testing.T) {
	h := newTestLiveShareHandler(t)
	mux := h.routes()
	body := `{"name":"demo","files":[` +
		`{"path":"f.txt","size":5,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"}]}`
	sh := createLiveShare(t, mux, testToken, body)
	slug := sh.Files[0].Slug

	serveLiveShareBody(t, h, sh.ID, metadb.DefaultAdminName, "hello")

	rec := doLiveShareGet(t, mux, "/view/"+sh.ID+"/"+slug, map[string]string{"Accept-Encoding": "zstd, gzip"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want none", got)
	}
	if rec.Body.String() != "hello" {
		t.Fatalf("body = %q, want identity bytes %q", rec.Body.String(), "hello")
	}
}

func TestOfflineIs503AndListingBanner(t *testing.T) {
	now := time.Now()
	h := newTestHandlerLiveShare(t, liveshare.Config{
		OfflineAfter: 10 * time.Second,
		Now:          func() time.Time { return now },
	})
	mux := h.routes()

	sh := createLiveShare(t, mux, testToken, liveShareCreateBody) // two files, so /share renders instead of redirecting
	slug := sh.Files[0].Slug

	// Nothing ever polls this share, so once OfflineAfter passes it reads as
	// offline with no sleep required.
	now = now.Add(15 * time.Second)

	rec := doReq(t, mux, "GET", "/download/"+sh.ID+"/"+slug, "", "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: %s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Retry-After"); got != "30" {
		t.Fatalf("Retry-After = %q, want 30", got)
	}

	rec = doReq(t, mux, "GET", "/share/"+sh.ID, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("listing status = %d, want 200: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(strings.ToLower(rec.Body.String()), "offline") {
		t.Fatalf("listing page has no offline note: %s", rec.Body)
	}
}

// TestSharerFailureTruncatesTheDownload needs a real network round trip: an
// httptest.ResponseRecorder just accumulates whatever bytes a handler wrote
// into a buffer, so it has no way to notice "fewer bytes than the declared
// Content-Length" the way a real client does. Only a genuine
// httptest.Server, talked to with a real http.Client, can observe the
// truncation this test is about.
func TestSharerFailureTruncatesTheDownload(t *testing.T) {
	h := newTestLiveShareHandler(t)
	mux := h.routes()
	body := `{"name":"demo","files":[` +
		`{"path":"f.txt","size":10,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"}]}`
	sh := createLiveShare(t, mux, testToken, body)
	slug := sh.Files[0].Slug

	srv := httptest.NewUnstartedServer(mux)
	// The short write below is deliberate; keep the server's own log of it
	// out of the test's output.
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.Start()
	defer srv.Close()

	// The sharer claims the job, writes 4 of the 10 declared bytes, and then
	// fails outright (a source read error, a dropped connection): exactly
	// what a real hyperdrop CLI does when its own upload breaks mid-file.
	// This goes straight through h.liveShareReg rather than the /api/live-share/jobs
	// HTTP route, so the failure is exact and not at the mercy of how Go's
	// http.Client happens to buffer a request body that errors mid-stream.
	go func() {
		offers, err := h.liveShareReg.Poll(context.Background(), sh.ID, metadb.DefaultAdminName, 5*time.Second)
		if err != nil || len(offers) != 1 {
			return
		}
		c, ok := h.liveShareReg.Claim(metadb.DefaultAdminName, offers[0].Job)
		if !ok {
			return
		}
		io.WriteString(c, "abcd")
		c.CloseWithError(errors.New("source read failed"))
	}()

	resp, err := srv.Client().Get(srv.URL + "/download/" + sh.ID + "/" + slug)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.ContentLength != 10 {
		t.Fatalf("Content-Length = %d, want 10 (the declared size, not what actually arrived)", resp.ContentLength)
	}
	if _, err := io.ReadAll(resp.Body); err == nil {
		t.Fatal("visitor read a clean body despite the sharer's failure; truncation must surface as an error")
	}
}

func TestLiveShareZipHasExactLength(t *testing.T) {
	h := newTestLiveShareHandler(t)
	mux := h.routes()
	body := `{"name":"demo","zipSize":12,"files":[` +
		`{"path":"a.txt","size":5,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"},` +
		`{"path":"b.txt","size":7,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"}` +
		`]}`
	sh := createLiveShare(t, mux, testToken, body)
	zipContent := "zippedbytes!"
	if len(zipContent) != 12 {
		t.Fatalf("fixture bug: %q is %d bytes, want 12", zipContent, len(zipContent))
	}

	serveLiveShareBody(t, h, sh.ID, metadb.DefaultAdminName, zipContent)

	rec := doLiveShareGet(t, mux, "/zip/"+sh.ID, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Content-Length"); got != "12" {
		t.Fatalf("Content-Length = %q, want 12", got)
	}
	if got := rec.Header().Get("Accept-Ranges"); got != "" {
		t.Fatalf("Accept-Ranges = %q, want none for /zip", got)
	}
	if rec.Body.String() != zipContent {
		t.Fatalf("body = %q, want %q", rec.Body.String(), zipContent)
	}
}

// TestUnfurlerNeverCreatesAJob covers the original claim (a bot GET of an
// ordinary file never creates a job) plus FINDING 2's extension: a live
// MP4's card must never advertise a playable video (og:video), since
// og:video is fetched by an anonymous bot with no cookies and no way to be
// gated, and unlike a stored file's, a live file's bytes come off the
// sharer's own uplink. A stray or adversarial request that names the
// ?ogmedia=1 escape hatch explicitly must still get the card, never bytes,
// and must never create a job either.
func TestUnfurlerNeverCreatesAJob(t *testing.T) {
	h := newTestLiveShareHandler(t)
	h.liveSharePollPark = 30 * time.Millisecond
	mux := h.routes()
	body := `{"name":"demo","files":[` +
		`{"path":"f.txt","size":5,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"}]}`
	sh := createLiveShare(t, mux, testToken, body)
	slug := sh.Files[0].Slug

	req := httptest.NewRequest("GET", "/view/"+sh.ID+"/"+slug, nil)
	req.Header.Set("User-Agent", "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)")
	rec := httptest.NewRecorder()
	// No goroutine and no timeout needed: an unfurler must never reach the
	// job rendezvous at all, so this call must return immediately on its
	// own.
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unfurler status = %d, want 200: %s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("unfurler content-type = %q, want an HTML card", ct)
	}

	offers, err := h.liveShareReg.Poll(context.Background(), sh.ID, metadb.DefaultAdminName, h.liveSharePark())
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(offers) != 0 {
		t.Fatalf("the unfurler request created a job: %+v (the sharer's uplink must never be touched)", offers)
	}

	// FINDING 2: a live, otherwise-playable MP4.
	videoBody := `{"name":"clip","files":[` +
		`{"path":"clip.mp4","size":1000000,"mime":"video/mp4","mtime":"2026-08-06T10:00:00Z"}]}`
	videoSh := createLiveShare(t, mux, testToken, videoBody)
	videoSlug := videoSh.Files[0].Slug

	req = httptest.NewRequest("GET", "/view/"+videoSh.ID+"/"+videoSlug, nil)
	req.Header.Set("User-Agent", "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("video card status = %d, want 200: %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "og:video") {
		t.Fatalf("a live share's card advertised og:video, which a bot can fetch with no gate: %s", rec.Body)
	}

	// The escape hatch named explicitly, with a bot UA: still the card, not
	// bytes, and still zero jobs.
	req = httptest.NewRequest("GET", "/view/"+videoSh.ID+"/"+videoSlug+"?ogmedia=1", nil)
	req.Header.Set("User-Agent", "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ogmedia=1 status = %d, want 200: %s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("ogmedia=1 content-type = %q, want an HTML card (bytes must never be served)", ct)
	}

	offers, err = h.liveShareReg.Poll(context.Background(), videoSh.ID, metadb.DefaultAdminName, h.liveSharePark())
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(offers) != 0 {
		t.Fatalf("a bot GET with ?ogmedia=1 created a job: %+v", offers)
	}
}

// TestHeadNeverCreatesAJob is FINDING 1's regression test. Go's ServeMux
// answers a HEAD request from a registered GET pattern, and http.ServeContent
// already short-circuits HEAD for a stored file, but serveLiveShareFile's own
// Range/job logic does not come free: unguarded, a HEAD mints a job, pulls
// the WHOLE file over the sharer's uplink, and (with nobody polling) parks
// the visitor for the full claim wait. Every header a HEAD needs (type, length, ETag,
// Accept-Ranges, disposition) is pure manifest data, so it must be answered
// without ever reaching NewJob.
func TestHeadNeverCreatesAJob(t *testing.T) {
	h := newTestLiveShareHandler(t)
	h.liveSharePollPark = 30 * time.Millisecond
	mux := h.routes()
	body := `{"name":"demo","files":[` +
		`{"path":"f.txt","size":26,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"}]}`
	sh := createLiveShare(t, mux, testToken, body)
	slug := sh.Files[0].Slug

	req := httptest.NewRequest(http.MethodHead, "/download/"+sh.ID+"/"+slug, nil)
	rec := httptest.NewRecorder()
	// No goroutine, no timeout: a HEAD must answer entirely from the
	// manifest, with no job and no wait on the sharer at all.
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HEAD status = %d, want 200: %s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Content-Length"); got != "26" {
		t.Fatalf("Content-Length = %q, want 26", got)
	}
	if rec.Header().Get("ETag") == "" {
		t.Fatal("HEAD response carries no ETag")
	}
	if rec.Header().Get("Accept-Ranges") != "bytes" {
		t.Fatalf("Accept-Ranges = %q, want bytes", rec.Header().Get("Accept-Ranges"))
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("HEAD response has a body: %q", rec.Body.String())
	}

	offers, err := h.liveShareReg.Poll(context.Background(), sh.ID, metadb.DefaultAdminName, h.liveSharePark())
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(offers) != 0 {
		t.Fatalf("the HEAD request created a job: %+v", offers)
	}
}

// TestRangedHeadAnswersWithContentRange checks the ranged HEAD case
// specifically named in FINDING 1: Content-Range must be present and
// correct on a 206 HEAD, exactly as it would be on the GET, still with no
// job ever created.
func TestRangedHeadAnswersWithContentRange(t *testing.T) {
	h := newTestLiveShareHandler(t)
	h.liveSharePollPark = 30 * time.Millisecond
	mux := h.routes()
	body := `{"name":"demo","files":[` +
		`{"path":"f.txt","size":26,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"}]}`
	sh := createLiveShare(t, mux, testToken, body)
	slug := sh.Files[0].Slug

	req := httptest.NewRequest(http.MethodHead, "/download/"+sh.ID+"/"+slug, nil)
	req.Header.Set("Range", "bytes=10-19")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusPartialContent {
		t.Fatalf("HEAD status = %d, want 206: %s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Content-Range"); got != "bytes 10-19/26" {
		t.Fatalf("Content-Range = %q, want %q", got, "bytes 10-19/26")
	}
	if got := rec.Header().Get("Content-Length"); got != "10" {
		t.Fatalf("Content-Length = %q, want 10", got)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("HEAD response has a body: %q", rec.Body.String())
	}

	offers, err := h.liveShareReg.Poll(context.Background(), sh.ID, metadb.DefaultAdminName, h.liveSharePark())
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(offers) != 0 {
		t.Fatalf("the ranged HEAD request created a job: %+v", offers)
	}
}

// TestHeadOnZipNeverCreatesAJob is TestHeadNeverCreatesAJob's /zip sibling.
func TestHeadOnZipNeverCreatesAJob(t *testing.T) {
	h := newTestLiveShareHandler(t)
	h.liveSharePollPark = 30 * time.Millisecond
	mux := h.routes()
	body := `{"name":"demo","zipSize":12,"files":[` +
		`{"path":"a.txt","size":5,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"},` +
		`{"path":"b.txt","size":7,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"}` +
		`]}`
	sh := createLiveShare(t, mux, testToken, body)

	req := httptest.NewRequest(http.MethodHead, "/zip/"+sh.ID, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HEAD status = %d, want 200: %s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Content-Length"); got != "12" {
		t.Fatalf("Content-Length = %q, want 12", got)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/zip" {
		t.Fatalf("Content-Type = %q, want application/zip", got)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("HEAD response has a body: %q", rec.Body.String())
	}

	offers, err := h.liveShareReg.Poll(context.Background(), sh.ID, metadb.DefaultAdminName, h.liveSharePark())
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(offers) != 0 {
		t.Fatalf("the HEAD request created a job: %+v", offers)
	}
}

// TestLiveShareJobFailureCodeMapsToStatus is FINDING 4's regression test: a
// sharer-reported failure must not flatten into the generic offline 503 when
// the code names something the recipient can actually be told.
// liveshare.FailedError's Code drives the status and the wording, exercised
// through the real /download route end to end.
func TestLiveShareJobFailureCodeMapsToStatus(t *testing.T) {
	cases := []struct {
		name       string
		code       string
		wantStatus int
		wantBody   string
	}{
		{"the share itself is gone", "live-share-ended", http.StatusNotFound, ""},
		{"the source changed mid-send", "source-changed", http.StatusConflict, "changed on the sharer's device"},
		{"the source is gone", "source-gone", http.StatusConflict, "no longer on the sharer's device"},
		{"an unrecognized code reads as offline", "some-future-code", http.StatusServiceUnavailable, "offline"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newTestLiveShareHandler(t)
			mux := h.routes()
			body := `{"name":"demo","files":[` +
				`{"path":"f.txt","size":10,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"}]}`
			sh := createLiveShare(t, mux, testToken, body)
			slug := sh.Files[0].Slug

			go func() {
				offers, err := h.liveShareReg.Poll(context.Background(), sh.ID, metadb.DefaultAdminName, 5*time.Second)
				if err != nil || len(offers) != 1 {
					return
				}
				h.liveShareReg.Fail(metadb.DefaultAdminName, offers[0].Job, c.code)
			}()

			rec := doLiveShareGet(t, mux, "/download/"+sh.ID+"/"+slug, nil)
			if rec.Code != c.wantStatus {
				t.Fatalf("status = %d, want %d: %s", rec.Code, c.wantStatus, rec.Body)
			}
			if c.wantBody != "" && !strings.Contains(rec.Body.String(), c.wantBody) {
				t.Fatalf("body = %q, want it to contain %q", rec.Body, c.wantBody)
			}
		})
	}
}

// dirEntrySnapshot is one path's recorded state under snapshotDir: a
// directory records only that it exists (IsDir), and a file records its
// size AND a SHA-256 of its content, so a same-size rewrite is caught and
// not just a resize.
type dirEntrySnapshot struct {
	IsDir  bool
	Size   int64
	SHA256 string
}

// snapshotDir walks dir and records every entry, files AND directories,
// under it. Two snapshots that compare equal mean nothing was created,
// removed, or rewritten anywhere under dir: not a file's bytes, not its
// size, and not an empty directory a file-only snapshot would miss
// entirely. Follows TestAnIdlePassNeverTouchesTheVolume's shape (two states
// proven equal) without its chmod-sealing mechanism, since the calls this
// test makes legitimately need to READ the volume (an authenticated lookup,
// an index check): only a CREATE, DELETE or REWRITE is what must be caught
// here.
func snapshotDir(t *testing.T, dir string) map[string]dirEntrySnapshot {
	t.Helper()
	snap := map[string]dirEntrySnapshot{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == dir {
			return nil // the root itself carries no state worth recording
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		if d.IsDir() {
			snap[rel] = dirEntrySnapshot{IsDir: true}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		hasher := sha256.New()
		if _, err := io.Copy(hasher, f); err != nil {
			return err
		}
		snap[rel] = dirEntrySnapshot{Size: info.Size(), SHA256: hex.EncodeToString(hasher.Sum(nil))}
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot %s: %v", dir, err)
	}
	return snap
}

// shareIDsOf is the row-side half of the no-writes claim: every share id the
// database holds, in the ascending order ShareIDs answers in.
func shareIDsOf(t *testing.T, db *metadb.DB) []string {
	t.Helper()
	ids, err := db.ShareIDs()
	if err != nil {
		t.Fatalf("share ids: %v", err)
	}
	return ids
}

// TestALiveShareNeverWritesToTheVolume is the headline claim: a live share
// stores nothing, so an ANONYMOUS visitor's GET /share, /download and /zip,
// plus the poll/claim that answers them, must leave the share store exactly
// as they found it.
//
// "Stores nothing" is asked of the two places a stored byte could land, and
// of nothing else. The data directory also holds the metadata database, and
// the database writes its own pages, journal and WAL on a schedule of its
// own that has nothing to do with any request, so snapshotting the whole
// directory would test SQLite's bookkeeping rather than this claim. The two
// halves asked instead are exact: shares/ must be byte-for-byte identical,
// down to a new empty directory, and the set of share ids the database holds
// must be unchanged. A live share that stored anything at all would have to
// move one of them.
//
// Creating and deleting the share are AUTHENTICATED calls, and authenticating
// a bearer records the token's last use, like any other authenticated
// request anywhere in this server, not a property of live shares. That write
// is real and expected, and it is NOT what this test is about, so create and
// delete happen OUTSIDE the snapshotted window.
func TestALiveShareNeverWritesToTheVolume(t *testing.T) {
	dir := t.TempDir()
	b := testBackendAt(t, dir)
	h := newHandler(b, "2.0.0", testDomain(t), nil, Deployment{})
	h.liveSharePollPark = 50 * time.Millisecond
	mux := h.routes()
	sharesDir := filepath.Join(dir, "shares")

	body := `{"name":"vol-test","zipSize":8,"files":[` +
		`{"path":"a.txt","size":5,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"},` +
		`{"path":"b.txt","size":7,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"}` +
		`]}`
	// Authenticated, outside the window: these are the calls expected to
	// record the token's last use.
	//
	// An ordinary stored share, holding one committed file, goes in first so
	// neither half of the claim is vacuous: shares/ then holds a real
	// directory with real bytes in it, and the id set is non-empty, so a
	// relay that rewrote or removed either would be caught rather than
	// compared empty against empty.
	stored := createShare(t, mux, "stored-neighbour")
	uploadFile(t, mux, testToken, stored, "kept.txt", "kept")
	sh := createLiveShare(t, mux, testToken, body)

	// One content string covers every job created below: the a.txt download
	// (5 bytes) and the zip (8 bytes) each take a prefix of it. Correctness
	// of the bytes themselves is pinned by the other tests above; this one
	// only cares whether the volume moved.
	serveLiveShareBody(t, h, sh.ID, metadb.DefaultAdminName, "abcdefgh")

	before := snapshotDir(t, sharesDir)
	beforeIDs := shareIDsOf(t, b.DB)
	if len(before) == 0 || len(beforeIDs) == 0 {
		t.Fatalf("nothing to protect: shares/ holds %d entries and the database %d shares", len(before), len(beforeIDs))
	}

	if rec := doLiveShareGet(t, mux, "/download/"+sh.ID+"/"+sh.Files[0].Slug, nil); rec.Code != http.StatusOK {
		t.Fatalf("/download = %d, want 200: %s", rec.Code, rec.Body)
	}
	if rec := doLiveShareGet(t, mux, "/zip/"+sh.ID, nil); rec.Code != http.StatusOK {
		t.Fatalf("/zip = %d, want 200: %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, mux, "GET", "/share/"+sh.ID, "", ""); rec.Code != http.StatusOK {
		t.Fatalf("/share = %d, want 200: %s", rec.Code, rec.Body)
	}

	after := snapshotDir(t, sharesDir)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("the anonymous relay path wrote to shares/:\nbefore: %+v\nafter:  %+v", before, after)
	}
	if afterIDs := shareIDsOf(t, b.DB); !reflect.DeepEqual(beforeIDs, afterIDs) {
		t.Fatalf("the anonymous relay path changed the share rows: before %v, after %v", beforeIDs, afterIDs)
	}

	// Authenticated again, outside the window.
	if rec := doReq(t, mux, "DELETE", "/api/live-share/"+sh.ID, testToken, ""); rec.Code != http.StatusOK {
		t.Fatalf("DELETE = %d, want 200: %s", rec.Code, rec.Body)
	}
}

// TestSiteRouteRefusesALiveShare pins the design spec's exclusion ("no /site
// site route and no Entry page selection") for a live share: a live share's
// public scope is password and name only, so /site must 404 outright rather
// than relay index.html the way it would for a stored share holding one.
// /view and /download, the ordinary slug routes, must still serve the identical bytes.

// A sharer that claims a job and then sends nothing must not pin the
// visitor's request once the visitor has gone: the visitor's handler
// returns, and the sharer's next write fails, which ends its upload too.
func TestAVisitorLeavingEndsAClaimedTransfer(t *testing.T) {
	h := newTestLiveShareHandler(t)
	mux := h.routes()
	sh := createLiveShare(t, mux, testToken, `{"name":"demo","files":[`+
		`{"path":"f.txt","size":10,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"}]}`)
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() {
		defer close(served)
		req := httptest.NewRequest("GET", "/download/"+sh.ID+"/"+sh.Files[0].Slug, nil).WithContext(ctx)
		mux.ServeHTTP(httptest.NewRecorder(), req)
	}()
	offers, err := h.liveShareReg.Poll(context.Background(), sh.ID, metadb.DefaultAdminName, 5*time.Second)
	if err != nil || len(offers) != 1 {
		t.Fatalf("poll: %v %v", offers, err)
	}
	c, ok := h.liveShareReg.Claim(metadb.DefaultAdminName, offers[0].Job)
	if !ok {
		t.Fatal("claim refused")
	}
	time.Sleep(50 * time.Millisecond) // the visitor is now copying from the pipe
	cancel()
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("the visitor's request outlived the visitor")
	}
	if _, err := io.WriteString(c, "abcd"); err == nil {
		t.Fatal("the sharer's write after the visitor left succeeded")
	}
}

// An empty file has no last bytes to name: a suffix range of it is served
// as the whole (empty) file, never a 206 whose range ends before it starts.
func TestASuffixRangeOfAnEmptyLiveFileIsTheWholeFile(t *testing.T) {
	if _, _, partial, ok := parseLiveShareRange("bytes=-5", 0); partial || ok {
		t.Fatalf("bytes=-5 of an empty file: partial=%v ok=%v, want the whole file", partial, ok)
	}
	if s, e, partial, ok := parseLiveShareRange("bytes=-5", 10); !ok || !partial || s != 5 || e != 9 {
		t.Fatalf("bytes=-5 of ten bytes = %d-%d partial=%v ok=%v", s, e, partial, ok)
	}
}
