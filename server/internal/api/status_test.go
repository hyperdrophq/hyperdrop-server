package api

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestShareStatus creates a share with a manifest of 2 files (sizes 5 and
// 10), uploads only the first, and checks the poll endpoint reports partial
// progress with per-file detail, then uploads the second and checks it
// flips to complete.
func TestShareStatus(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"name":"s","files":[{"path":"a.txt","size":5},{"path":"b.txt","size":10}]}`)
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
	if len(cr.Files) != 2 {
		t.Fatalf("expected 2 files in manifest, got %d: %+v", len(cr.Files), cr.Files)
	}
	slugB := cr.Files[1].Slug
	if slugB == "" {
		t.Fatalf("pending file b.txt has no pre-minted slug: %+v", cr.Files)
	}

	// Upload the first file (5 bytes) only.
	up := doReq(t, h, "PUT", "/api/shares/"+cr.ID+"/files/a.txt", testToken, "aaaaa")
	if up.Code != 201 {
		t.Fatalf("upload a.txt = %d %s", up.Code, up.Body)
	}

	// Public poll, with no Authorization header.
	st := doReq(t, h, "GET", "/share/"+cr.ID+"/status", "", "")
	if st.Code != 200 {
		t.Fatalf("status = %d %s", st.Code, st.Body)
	}
	if cc := st.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cc)
	}
	var out struct {
		Complete      bool  `json:"complete"`
		UploadedBytes int64 `json:"uploadedBytes"`
		TotalBytes    int64 `json:"totalBytes"`
		Files         []struct {
			Slug     string `json:"slug"`
			Path     string `json:"path"`
			Size     int64  `json:"size"`
			Bytes    int64  `json:"bytes"`
			Complete bool   `json:"complete"`
		} `json:"files"`
	}
	unmarshal(t, st, &out)
	if out.Complete {
		t.Fatalf("expected incomplete, got complete: %+v", out)
	}
	if out.UploadedBytes != 5 || out.TotalBytes != 15 {
		t.Fatalf("uploadedBytes=%d totalBytes=%d, want 5/15", out.UploadedBytes, out.TotalBytes)
	}
	if len(out.Files) != 2 {
		t.Fatalf("expected 2 files, got %d: %+v", len(out.Files), out.Files)
	}
	if out.Files[0].Bytes != 5 || out.Files[0].Size != 5 || !out.Files[0].Complete {
		t.Fatalf("files[0] (committed a.txt) = %+v, want bytes=5 size=5 complete=true", out.Files[0])
	}
	if out.Files[1].Bytes != 0 || out.Files[1].Complete {
		t.Fatalf("files[1] (pending b.txt, no .part) = %+v, want bytes=0 complete=false", out.Files[1])
	}
	if out.Files[1].Slug != slugB {
		t.Fatalf("files[1].slug = %q, want create-response slug %q", out.Files[1].Slug, slugB)
	}

	// Upload the second file: status should flip to complete.
	up2 := doReq(t, h, "PUT", "/api/shares/"+cr.ID+"/files/b.txt", testToken, "0123456789")
	if up2.Code != 201 {
		t.Fatalf("upload b.txt = %d %s", up2.Code, up2.Body)
	}
	st2 := doReq(t, h, "GET", "/share/"+cr.ID+"/status", "", "")
	var out2 struct {
		Complete      bool  `json:"complete"`
		UploadedBytes int64 `json:"uploadedBytes"`
	}
	unmarshal(t, st2, &out2)
	if !out2.Complete || out2.UploadedBytes != 15 {
		t.Fatalf("after both uploads: complete=%v uploadedBytes=%d, want true/15", out2.Complete, out2.UploadedBytes)
	}
}

// TestShareStatusMidUpload starts a ranged upload partway and checks the
// poll endpoint reports the bytes staged in its .part.
func TestShareStatusMidUpload(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"name":"s","files":[{"path":"a.txt","size":10}]}`)
	var cr struct{ ID string }
	unmarshal(t, rec, &cr)

	req := doReqResume(t, h, "/api/shares/"+cr.ID+"/files/a.txt", "aaaa", "0", "10")
	if req.Code != 202 {
		t.Fatalf("partial upload = %d %s", req.Code, req.Body)
	}

	st := doReq(t, h, "GET", "/share/"+cr.ID+"/status", "", "")
	if st.Code != 200 {
		t.Fatalf("status = %d %s", st.Code, st.Body)
	}
	var out struct {
		Complete bool `json:"complete"`
		Files    []struct {
			Bytes    int64 `json:"bytes"`
			Complete bool  `json:"complete"`
		} `json:"files"`
	}
	unmarshal(t, st, &out)
	if out.Complete {
		t.Fatal("expected incomplete mid-upload")
	}
	if len(out.Files) != 1 || out.Files[0].Bytes != 4 || out.Files[0].Complete {
		t.Fatalf("files = %+v, want one entry bytes=4 complete=false", out.Files)
	}
}

// TestShareStatusPassword checks the 401 is JSON (never the HTML password
// form) without a valid access cookie, and that the endpoint serves normally
// once the cookie is set via POST /unlock/{id} (gate_test.go's flow).
func TestShareStatusPassword(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"secret","password":"hunter2"}`)
	var cr struct{ ID string }
	unmarshal(t, rec, &cr)

	// No cookie → 401 JSON, not the HTML form.
	bare := doReq(t, h, "GET", "/share/"+cr.ID+"/status", "", "")
	if bare.Code != 401 {
		t.Fatalf("status without cookie = %d, want 401", bare.Code)
	}
	if ct := bare.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	if strings.Contains(strings.ToLower(bare.Body.String()), "<form") {
		t.Fatalf("401 body looks like the HTML password form: %s", bare.Body)
	}

	// Obtain the access cookie the same way gate_test.go does.
	body := url.Values{"password": {"hunter2"}, "next": {"/share/" + cr.ID}}.Encode()
	sub := doReqForm(t, h, "POST", "/unlock/"+cr.ID, body)
	if sub.Code != 303 {
		t.Fatalf("password submit = %d, want 303", sub.Code)
	}
	cookie := sub.Header().Get("Set-Cookie")
	if cookie == "" {
		t.Fatal("no access cookie set")
	}

	authed := doReqWithHeader(t, h, "GET", "/share/"+cr.ID+"/status", "Cookie", strings.SplitN(cookie, ";", 2)[0])
	if authed.Code != 200 {
		t.Fatalf("status with cookie = %d %s", authed.Code, authed.Body)
	}
}

// TestShareStatusGone checks an unknown share id 404s with a JSON body.
func TestShareStatusGone(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "GET", "/share/doesnotexist/status", "", "")
	if rec.Code != 404 {
		t.Fatalf("status for unknown id = %d, want 404", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
}

// TestShareStatusUnavailableSource checks a linked share whose source folder
// is gone answers a plain JSON unavailable body on the poll route, 200 with
// {"unavailable":true}, not the HTML unavailable page: the waiting page's
// fetch() calls res.json() on every answer, and an HTML body would throw
// there instead of ever reaching the page that would show the visitor what
// happened.
func TestShareStatusUnavailableSource(t *testing.T) {
	h, b, vol := linkedTestAPI(t)
	id := linkedShare(t, b, "photo/2024")
	os.RemoveAll(filepath.Join(vol, "photo"))

	rec := doReq(t, h, "GET", "/share/"+id+"/status", "", "")
	if rec.Code != 200 {
		t.Fatalf("status = %d %s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	if body := strings.TrimSpace(rec.Body.String()); body != `{"unavailable":true}` {
		t.Fatalf("body = %s, want {\"unavailable\":true}", body)
	}
}

// A stored share past the file cap answers its totals for the WHOLE share from
// the lookup: the counters and the declared size of every pending file,
// though the listed window stops at statusFileLimit, and the file ?slug=
// names is found and measured outside that window.
func TestShareStatusOfAStoredSharePastTheCap(t *testing.T) {
	h := newTestAPI(t)
	var m strings.Builder
	m.WriteString(`{"name":"big","files":[`)
	for i := range statusFileLimit {
		fmt.Fprintf(&m, `{"path":"f%03d.txt","size":2},`, i)
	}
	m.WriteString(`{"path":"z-landed.bin","size":5},{"path":"z-partial.bin","size":10}]}`)
	id := createInbox(t, h, m.String())
	uploadGetSlug(t, h, id, "f000.txt", "ff")
	uploadGetSlug(t, h, id, "z-landed.bin", "lllll")
	if rec := doReqResume(t, h, "/api/shares/"+id+"/files/z-partial.bin", "ppp", "0", "10"); rec.Code != 202 {
		t.Fatalf("partial = %d %s", rec.Code, rec.Body)
	}
	slugs := slugsOf(t, h, id)
	type entry struct {
		Slug, Path  string
		Size, Bytes int64
		Complete    bool
	}
	var out struct {
		Complete      bool
		UploadedBytes int64
		TotalBytes    int64
		Counts        struct{ Total, Completed, Pending int }
		Files         []entry
		Truncated     bool
		File          *entry
	}
	unmarshal(t, doReq(t, h, "GET", "/share/"+id+"/status?slug="+slugs["z-partial.bin"], "", ""), &out)
	if out.Complete || !out.Truncated || len(out.Files) != statusFileLimit || out.Files[0].Path != "f000.txt" ||
		out.Files[statusFileLimit-1].Path != fmt.Sprintf("f%03d.txt", statusFileLimit-1) {
		t.Fatalf("complete=%v truncated=%v files=%d first=%+v", out.Complete, out.Truncated, len(out.Files), out.Files[0])
	}
	if out.Counts.Total != statusFileLimit+2 || out.Counts.Completed != 2 || out.Counts.Pending != statusFileLimit {
		t.Fatalf("counts = %+v", out.Counts)
	}
	if want := int64(2*statusFileLimit + 5 + 10); out.TotalBytes != want {
		t.Fatalf("totalBytes = %d, want %d", out.TotalBytes, want)
	}
	// Past the stat limit only the wanted partial is measured: two landed
	// files and its three bytes.
	if out.UploadedBytes != 2+5+3 {
		t.Fatalf("uploadedBytes = %d, want 10", out.UploadedBytes)
	}
	if f := out.File; f == nil || f.Path != "z-partial.bin" || f.Bytes != 3 || f.Size != 10 || f.Complete {
		t.Fatalf("file = %+v", out.File)
	}
	out.File = nil
	unmarshal(t, doReq(t, h, "GET", "/share/"+id+"/status?slug="+slugs["z-landed.bin"], "", ""), &out)
	if f := out.File; f == nil || f.Bytes != 5 || !f.Complete || out.UploadedBytes != 7 {
		t.Fatalf("landed outside the window: file=%+v uploaded=%d", out.File, out.UploadedBytes)
	}
}

// The status answer comes from the share's lookup: a stored share's from its
// rows in a window, whatever the gate's one-file view held, and a linked
// share's from its composed view, linked entries counted beside the uploads.
func TestStatusProgressComesFromTheLookup(t *testing.T) {
	h, hd, _ := lookupTestAPI(t)
	id := createInbox(t, h, `{"name":"rows","files":[{"path":"a.txt","size":1},{"path":"b.txt","size":2},{"path":"c.txt","size":4}]}`)
	uploadGetSlug(t, h, id, "a.txt", "a")
	slugs := slugsOf(t, h, id)
	meta, err := hd.viewMeta(id)
	if err != nil {
		t.Fatal(err)
	}
	files, err := hd.lookupFor(meta)
	if err != nil {
		t.Fatal(err)
	}
	p, err := files.progress(1, slugs["c.txt"])
	if err != nil {
		t.Fatal(err)
	}
	if p.files != 3 || p.committed != 1 || p.committedBytes != 1 || p.pendingBytes != 6 || len(p.window) != 1 ||
		p.window[0].Path != "a.txt" || p.wanted == nil || p.wanted.Path != "c.txt" {
		t.Fatalf("stored progress = %+v", p)
	}

	linkedID := createInbox(t, h, `{"source":"photo/2024"}`)
	uploadGetSlug(t, h, linkedID, "note.txt", "note")
	ls := slugsOf(t, h, linkedID)
	meta, _ = hd.viewMeta(linkedID)
	if files, err = hd.lookupFor(meta); err != nil {
		t.Fatal(err)
	}
	p, err = files.progress(statusFileLimit, ls["b.jpg"])
	if err != nil {
		t.Fatal(err)
	}
	if p.files != 3 || p.committed != 3 || p.committedBytes != 4+4+2 || p.pendingBytes != 0 || len(p.window) != 3 ||
		p.wanted == nil || !p.wanted.Linked || p.wanted.Path != "b.jpg" {
		t.Fatalf("linked progress = %+v", p)
	}
}
