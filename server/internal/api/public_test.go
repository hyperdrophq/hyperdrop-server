package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// shareWithFiles creates a share, uploads the files, and returns the share
// id plus each file's public slug (public URLs carry ONLY slugs).
func shareWithFiles(t *testing.T, h http.Handler, name string, files map[string]string) (string, map[string]string) {
	t.Helper()
	id := createShare(t, h, name)
	slugs := map[string]string{}
	for path, content := range files {
		slugs[path] = uploadGetSlug(t, h, id, path, content)
	}
	return id, slugs
}

func TestViewKnownExtension(t *testing.T) {
	h := newTestAPI(t)
	id, slugs := shareWithFiles(t, h, "pics", map[string]string{"a.png": "\x89PNG fake"})
	rec := doReq(t, h, "GET", "/view/"+id+"/"+slugs["a.png"], "", "")
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "image/png" {
		t.Errorf("Content-Type = %q, want image/png", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); cd != `inline; filename=a.png` {
		t.Errorf("Content-Disposition = %q", cd)
	}
}

func TestViewUnknownExtensionSniffsText(t *testing.T) {
	h := newTestAPI(t)
	id, slugs := shareWithFiles(t, h, "logs", map[string]string{"file.xyz123": "plain text content here"})
	rec := doReq(t, h, "GET", "/view/"+id+"/"+slugs["file.xyz123"], "", "")
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain*", ct)
	}
}

func TestViewUnknownBinaryIsOctetStream(t *testing.T) {
	h := newTestAPI(t)
	bin := string([]byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0x00, 0x10})
	id, slugs := shareWithFiles(t, h, "bin", map[string]string{"blob.qqq": bin})
	rec := doReq(t, h, "GET", "/view/"+id+"/"+slugs["blob.qqq"], "", "")
	if ct := rec.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("Content-Type = %q, want application/octet-stream", ct)
	}
}

func TestDownloadIsAttachment(t *testing.T) {
	h := newTestAPI(t)
	id, slugs := shareWithFiles(t, h, "dl", map[string]string{"a.png": "x"})
	rec := doReq(t, h, "GET", "/download/"+id+"/"+slugs["a.png"], "", "")
	if cd := rec.Header().Get("Content-Disposition"); cd != `attachment; filename=a.png` {
		t.Errorf("Content-Disposition = %q", cd)
	}
}

func TestNonASCIIFilenameEncoded(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "ru")
	rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/%D0%BE%D1%82%D1%87%D1%91%D1%82.txt", testToken, "данные")
	if rec.Code != 201 {
		t.Fatalf("upload = %d %s", rec.Code, rec.Body)
	}
	sh := doReq(t, h, "GET", "/share/"+id, "", "")
	slug := strings.TrimPrefix(sh.Header().Get("Location"), "/view/"+id+"/")
	rec = doReq(t, h, "GET", "/download/"+id+"/"+slug, "", "")
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	cd := rec.Header().Get("Content-Disposition")
	if !strings.Contains(cd, "filename*=utf-8''") {
		t.Errorf("Content-Disposition = %q, want RFC2231 filename*", cd)
	}
}

func TestRangeRequest(t *testing.T) {
	h := newTestAPI(t)
	id, slugs := shareWithFiles(t, h, "range", map[string]string{"data.bin": "0123456789"})
	req := doReqWithHeader(t, h, "GET", "/view/"+id+"/"+slugs["data.bin"], "Range", "bytes=0-1")
	if req.Code != 206 {
		t.Fatalf("status = %d, want 206", req.Code)
	}
	if body := req.Body.String(); body != "01" {
		t.Errorf("body = %q, want 01", body)
	}
}

// The headers a browser needs to RESUME an interrupted download: a full
// response advertises Accept-Ranges and carries Last-Modified (the If-Range
// validator), and a mid-file range comes back 206 with the right
// Content-Range slice.
func TestDownloadResumeHeaders(t *testing.T) {
	h := newTestAPI(t)
	id, slugs := shareWithFiles(t, h, "resume", map[string]string{"data.bin": "0123456789"})

	full := doReq(t, h, "GET", "/download/"+id+"/"+slugs["data.bin"], "", "")
	if ar := full.Header().Get("Accept-Ranges"); ar != "bytes" {
		t.Errorf("Accept-Ranges = %q, want bytes", ar)
	}
	if lm := full.Header().Get("Last-Modified"); lm == "" {
		t.Error("no Last-Modified: browsers can't send If-Range to resume safely")
	}

	part := doReqWithHeader(t, h, "GET", "/download/"+id+"/"+slugs["data.bin"], "Range", "bytes=4-")
	if part.Code != 206 {
		t.Fatalf("status = %d, want 206", part.Code)
	}
	if cr := part.Header().Get("Content-Range"); cr != "bytes 4-9/10" {
		t.Errorf("Content-Range = %q, want bytes 4-9/10", cr)
	}
	if body := part.Body.String(); body != "456789" {
		t.Errorf("body = %q, want 456789", body)
	}
}

// Range also works through the password gate once the access cookie is set.
func TestDownloadResumeThroughPasswordGate(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"secret","password":"hunter2"}`)
	var cr struct{ ID string }
	unmarshal(t, rec, &cr)
	slug := uploadGetSlug(t, h, cr.ID, "data.bin", "0123456789")

	body := url.Values{"password": {"hunter2"}, "next": {"/share/" + cr.ID}}.Encode()
	sub := doReqForm(t, h, "POST", "/unlock/"+cr.ID, body)
	cookie := strings.SplitN(sub.Header().Get("Set-Cookie"), ";", 2)[0]

	req := httptest.NewRequest("GET", "/download/"+cr.ID+"/"+slug, nil)
	req.Header.Set("Cookie", cookie)
	req.Header.Set("Range", "bytes=5-")
	out := httptest.NewRecorder()
	h.ServeHTTP(out, req)
	if out.Code != 206 || out.Body.String() != "56789" {
		t.Fatalf("gated range = %d %q, want 206 %q", out.Code, out.Body.String(), "56789")
	}
}

func TestPublicRoutes404(t *testing.T) {
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "x", map[string]string{"a.txt": "x"})
	for _, p := range []string{
		"/view/zzzzzzzzzz/00000000-0000-4000-8000-000000000000",
		"/view/" + id + "/00000000-0000-4000-8000-000000000000", // unknown slug
		"/view/" + id + "/a.txt",                                // filenames are NOT routable
		"/download/zzzzzzzzzz/whatever",
	} {
		if rec := doReq(t, h, "GET", p, "", ""); rec.Code != 404 {
			t.Errorf("GET %s = %d, want 404", p, rec.Code)
		}
	}
}
