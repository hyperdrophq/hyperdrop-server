package api

import (
	"strings"
	"testing"
)

// TestViewPendingShowsWaitingPage: manifest share, nothing uploaded.
// GET /view/{id}/{slug} → 200, Content-Type text/html, body contains the
// file name, "uploading", and "/share/<id>/status" (the poll URL).
// GET /download/{id}/{slug} → same waiting page (a download can't start yet).
func TestViewPendingShowsWaitingPage(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"name":"s","files":[{"path":"report.pdf","size":100}]}`)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	var cr struct {
		ID    string `json:"id"`
		Files []struct {
			Path string `json:"path"`
			Slug string `json:"slug"`
		} `json:"files"`
	}
	unmarshal(t, rec, &cr)
	if len(cr.Files) != 1 || cr.Files[0].Slug == "" {
		t.Fatalf("expected 1 pending file with a pre-minted slug: %+v", cr.Files)
	}
	slug := cr.Files[0].Slug

	for _, path := range []string{"/view/" + cr.ID + "/" + slug, "/download/" + cr.ID + "/" + slug} {
		got := doReq(t, h, "GET", path, "", "")
		if got.Code != 200 {
			t.Fatalf("GET %s = %d %s", path, got.Code, got.Body)
		}
		if ct := got.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Fatalf("GET %s Content-Type = %q, want text/html", path, ct)
		}
		body := got.Body.String()
		if !strings.Contains(body, "report.pdf") {
			t.Fatalf("GET %s body missing file name: %s", path, body)
		}
		if !strings.Contains(strings.ToLower(body), "uploading") {
			t.Fatalf("GET %s body missing 'uploading': %s", path, body)
		}
		// The poll URL is assembled client-side as "/share/" + shareID + "/status";
		// check the literal fetch pattern and that shareID is set to this
		// share's ID (the two together are the actual poll URL contract).
		if !strings.Contains(body, `fetch("/share/" + shareID + "/status"`) {
			t.Fatalf("GET %s body missing the /share/{id}/status poll fetch: %s", path, body)
		}
		if !strings.Contains(body, `const shareID = "`+cr.ID+`"`) {
			t.Fatalf("GET %s body missing shareID = %q: %s", path, cr.ID, body)
		}
		// The status line tells the visitor what to expect when the upload
		// finishes: /view of a viewable file shows it in place, /download downloads.
		want := "the file will appear right here"
		if strings.HasPrefix(path, "/download/") {
			want = "your download will start automatically"
		}
		if !strings.Contains(body, want) {
			t.Fatalf("GET %s body missing %q: %s", path, want, body)
		}
		// The mid-wait 404 message explains WHY (sender canceled/removed),
		// embedded for the poller to show.
		if !strings.Contains(body, "canceled or the share was removed") {
			t.Fatalf("GET %s body missing the cancel explanation: %s", path, body)
		}
	}
}

// The page carries the preparing phase's two sentences and reads the poll's
// preparing fields: the script decides the phase in the browser, so the
// served HTML is what a test can pin.
func TestWaitingPageCarriesThePreparingCopy(t *testing.T) {
	h := newTestAPI(t)
	id, slug := declaredShare(t, h, 100)
	for _, path := range []string{"/view/" + id + "/" + slug, "/share/" + id} {
		body := doReq(t, h, "GET", path, "", "").Body.String()
		for _, want := range []string{
			"The sender is preparing the video",
			"Uploading starts when it's ready.",
			`id="phase"`,
			"f.preparing",
			"st.preparing",
		} {
			if !strings.Contains(body, want) {
				t.Fatalf("GET %s body missing %q", path, want)
			}
		}
	}
}

// A pending file that WON'T render inline (extension guess) tells the /view
// visitor a download will start: /view degrades to attachment for it anyway.
func TestWaitingCopyNonViewableFile(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"name":"s","files":[{"path":"setup.exe","size":100}]}`)
	var cr struct {
		ID    string `json:"id"`
		Files []struct {
			Slug string `json:"slug"`
		} `json:"files"`
	}
	unmarshal(t, rec, &cr)
	got := doReq(t, h, "GET", "/view/"+cr.ID+"/"+cr.Files[0].Slug, "", "")
	if !strings.Contains(got.Body.String(), "your download will start automatically") {
		t.Fatalf("non-viewable /view waiting copy: %s", got.Body)
	}
}

// TestViewCommittedUnaffected: after the PUT commits, GET /view/{id}/{slug}
// serves the file bytes with the real Content-Type (existing behavior).
func TestViewCommittedUnaffected(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"name":"s","files":[{"path":"note.txt","size":5}]}`)
	var cr struct {
		ID    string `json:"id"`
		Files []struct {
			Path string `json:"path"`
			Slug string `json:"slug"`
		} `json:"files"`
	}
	unmarshal(t, rec, &cr)
	slug := cr.Files[0].Slug

	up := doReq(t, h, "PUT", "/api/shares/"+cr.ID+"/files/note.txt", testToken, "hello")
	if up.Code != 201 {
		t.Fatalf("upload = %d %s", up.Code, up.Body)
	}

	got := doReq(t, h, "GET", "/view/"+cr.ID+"/"+slug, "", "")
	if got.Code != 200 {
		t.Fatalf("view committed = %d %s", got.Code, got.Body)
	}
	if body := got.Body.String(); body != "hello" {
		t.Fatalf("view committed body = %q, want file bytes %q", body, "hello")
	}
	if ct := got.Header().Get("Content-Type"); strings.HasPrefix(ct, "text/html") {
		t.Fatalf("view committed Content-Type = %q, want the file's real type, not html", ct)
	}
}

// TestZipPendingShowsWaitingPage: manifest share (2 files), 1 committed → GET
// /zip/{id} → 200 text/html containing "/share/<id>/status" (waiting page),
// NOT a zip (Content-Type not application/zip). After both commit → GET
// /zip/{id} streams a zip (existing behavior).
func TestZipPendingShowsWaitingPage(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"name":"bundle","files":[{"path":"a.txt","size":5},{"path":"b.txt","size":5}]}`)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	var cr shareResp
	unmarshal(t, rec, &cr)
	if len(cr.Files) != 2 {
		t.Fatalf("expected 2 pending files: %+v", cr.Files)
	}

	up := doReq(t, h, "PUT", "/api/shares/"+cr.ID+"/files/a.txt", testToken, "hello")
	if up.Code != 201 {
		t.Fatalf("upload a.txt = %d %s", up.Code, up.Body)
	}

	got := doReq(t, h, "GET", "/zip/"+cr.ID, "", "")
	if got.Code != 200 {
		t.Fatalf("GET /zip (pending) = %d %s", got.Code, got.Body)
	}
	if ct := got.Header().Get("Content-Type"); strings.HasPrefix(ct, "application/zip") {
		t.Fatalf("GET /zip (pending) Content-Type = %q, want NOT application/zip", ct)
	}
	if !strings.HasPrefix(got.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("GET /zip (pending) Content-Type = %q, want text/html", got.Header().Get("Content-Type"))
	}
	body := got.Body.String()
	if !strings.Contains(body, "/share/"+cr.ID+"/status") && !strings.Contains(body, `const shareID = "`+cr.ID+`"`) {
		t.Fatalf("GET /zip (pending) body missing the /share/{id}/status poll wiring: %s", body)
	}

	up2 := doReq(t, h, "PUT", "/api/shares/"+cr.ID+"/files/b.txt", testToken, "world")
	if up2.Code != 201 {
		t.Fatalf("upload b.txt = %d %s", up2.Code, up2.Body)
	}
	done := doReq(t, h, "GET", "/zip/"+cr.ID, "", "")
	if done.Code != 200 {
		t.Fatalf("GET /zip (complete) = %d %s", done.Code, done.Body)
	}
	if ct := done.Header().Get("Content-Type"); ct != "application/zip" {
		t.Fatalf("GET /zip (complete) Content-Type = %q, want application/zip", ct)
	}
}

// TestWaitingPagePasswordGated: password share + pending file, no cookie →
// GET /view/{id}/{slug} renders the password form, NOT the waiting page or
// the file.
func TestWaitingPagePasswordGated(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"name":"secret","password":"hunter2","files":[{"path":"a.txt","size":5}]}`)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	var cr struct {
		ID    string `json:"id"`
		Files []struct {
			Path string `json:"path"`
			Slug string `json:"slug"`
		} `json:"files"`
	}
	unmarshal(t, rec, &cr)
	slug := cr.Files[0].Slug

	got := doReq(t, h, "GET", "/view/"+cr.ID+"/"+slug, "", "")
	if got.Code != 200 {
		t.Fatalf("GET without cookie = %d %s", got.Code, got.Body)
	}
	body := strings.ToLower(got.Body.String())
	if !strings.Contains(body, "<form") {
		t.Fatalf("expected the password form, got: %s", got.Body)
	}
	if strings.Contains(body, "uploading") {
		t.Fatalf("password form must not leak the waiting page: %s", got.Body)
	}
}
