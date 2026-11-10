package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hyperdrop/server/internal/linked"
	"hyperdrop/server/internal/shareid"
)

// lookupTestAPI is a handler over the linked fixture volume, with the struct
// behind it, so a test can drive the lookup directly as well as through the
// routes.
func lookupTestAPI(t *testing.T) (http.Handler, *handler, string) {
	t.Helper()
	vol := seedLinkedVolume(t)
	roots, err := linked.NewRoots(nil, []string{vol}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hd := newHandler(testBackendWithRoots(t, roots), "2.0.0", testDomain(t), nil, Deployment{})
	return hd.routes(), hd, vol
}

// slugsOf answers every file's slug by path, read through the owner's route.
func slugsOf(t *testing.T, h http.Handler, id string) map[string]string {
	t.Helper()
	var d struct {
		Files []struct{ Path, Slug string } `json:"files"`
	}
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+id, testToken, ""), &d)
	out := map[string]string{}
	for _, f := range d.Files {
		out[f.Path] = f.Slug
	}
	return out
}

// A stored share's lookup answers from its rows: the gate's view carries one
// file, and every file of the share is still found by slug and by path, the
// pending state comes from the counters, and the whole share is read only when
// asked for.
func TestAStoredSharesLookupAnswersFromItsRows(t *testing.T) {
	h, hd, _ := lookupTestAPI(t)
	id := createInbox(t, h, `{"name":"rows","files":[{"path":"a.txt","size":1},{"path":"m/b.txt","size":1},
		{"path":"z.txt","size":1},{"path":"y.bin","size":4}]}`)
	for _, p := range []string{"a.txt", "m/b.txt", "z.txt"} {
		uploadGetSlug(t, h, id, p, "x")
	}
	slugs := slugsOf(t, h, id)
	meta, err := hd.viewMeta(id)
	if err != nil || len(meta.Files) != 1 {
		t.Fatalf("the gate's view holds %d files, %v: want the one-file window", len(meta.Files), err)
	}
	files, err := hd.lookupFor(meta)
	if err != nil || files.db == nil {
		t.Fatalf("a stored share's lookup must answer from rows: db=%v err=%v", files.db != nil, err)
	}
	for path, slug := range slugs {
		f, ok := files.bySlug(slug)
		if !ok || f.Path != path || f.Linked {
			t.Errorf("bySlug(%s) = %+v, %v; want %s", slug, f, ok, path)
		}
		if f, ok := files.byPath(path); !ok || f.Slug != slug {
			t.Errorf("byPath(%s) = %+v, %v", path, f, ok)
		}
	}
	if f, _ := files.bySlug(slugs["y.bin"]); !f.Pending {
		t.Error("the pending row reads as landed")
	}
	for _, slug := range []string{"", shareid.NewSlug(), "../a.txt"} {
		if _, ok := files.bySlug(slug); ok {
			t.Errorf("bySlug(%q) found a file", slug)
		}
	}
	for _, rel := range []string{"", "nope.txt", "../a.txt", "m", "./a.txt"} {
		if _, ok := files.byPath(rel); ok {
			t.Errorf("byPath(%q) found a file", rel)
		}
	}
	if !files.anyPending() {
		t.Error("y.bin is still uploading, outside the view's window, and the lookup missed it")
	}
	if whole := files.whole(); len(whole.Files) != 4 {
		t.Errorf("whole holds %d files, want 4", len(whole.Files))
	}
	uploadGetSlug(t, h, id, "y.bin", "done")
	meta, _ = hd.viewMeta(id)
	if files, _ = hd.lookupFor(meta); files.anyPending() {
		t.Error("every file landed, and the lookup still reports one pending")
	}
}

// A linked share's lookup is its composed view: the walk's entries beside the
// stored uploads, a hidden entry absent, and a revoked or unreadable source
// reported as SourceMissing for the gate to answer.
func TestALinkedSharesLookupIsTheComposedView(t *testing.T) {
	h, hd, vol := lookupTestAPI(t)
	id := createInbox(t, h, `{"source":"photo/2024"}`)
	uploadGetSlug(t, h, id, "note.txt", "note")
	before := slugsOf(t, h, id)
	if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken,
		`{"linked":{"photo/2024":{"hide":["b.jpg"]}}}`); rec.Code != 200 {
		t.Fatalf("hide = %d %s", rec.Code, rec.Body)
	}
	meta, err := hd.viewMeta(id)
	if err != nil {
		t.Fatal(err)
	}
	files, err := hd.lookupFor(meta)
	if err != nil || files.db != nil || files.v.SourceMissing {
		t.Fatalf("lookup: db=%v missing=%v err=%v", files.db != nil, files.v.SourceMissing, err)
	}
	if f, ok := files.bySlug(before["a.jpg"]); !ok || !f.Linked || f.Path != "a.jpg" {
		t.Errorf("linked entry: %+v, %v", f, ok)
	}
	if f, ok := files.byPath("note.txt"); !ok || f.Linked {
		t.Errorf("stored upload beside the source: %+v, %v", f, ok)
	}
	if _, ok := files.bySlug(before["b.jpg"]); ok {
		t.Error("a hidden entry still resolves by its slug")
	}
	if _, ok := files.byPath("b.jpg"); ok {
		t.Error("a hidden entry still resolves by its path")
	}
	if rec := doReq(t, h, "GET", "/view/"+id+"/"+before["b.jpg"], "", ""); rec.Code != 404 {
		t.Errorf("hidden entry /view = %d, want 404", rec.Code)
	}
	if rec := doReq(t, h, "GET", "/view/"+id+"/"+before["a.jpg"], "", ""); rec.Code != 200 || rec.Body.String() != "AAAA" {
		t.Errorf("linked /view = %d %q", rec.Code, rec.Body)
	}

	os.RemoveAll(filepath.Join(vol, "photo"))
	meta, _ = hd.viewMeta(id)
	if files, _ = hd.lookupFor(meta); !files.v.SourceMissing {
		t.Error("the folder is gone and the lookup's view does not say so")
	}
	rec := doReq(t, h, "GET", "/view/"+id+"/"+before["note.txt"], "", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "not available on this server") {
		t.Errorf("a stored upload of a share whose folder is gone = %d, want the unavailable page", rec.Code)
	}
}

// The three single-file routes through the lookup, from the outside: a file
// outside the gate's one-file window serves, a pending one waits, a web page
// with an asset still uploading waits as a whole, an unfurler's card sees a
// video anywhere in the share, an inbox stays hidden but for its owner's
// download, a revoked source serves nothing, and a slug naming nothing is a
// 404.
func TestSingleFileRoutesResolveThroughTheLookup(t *testing.T) {
	h, _, _ := lookupTestAPI(t)
	id := createInbox(t, h, `{"name":"many","files":[{"path":"a.txt","size":1},{"path":"clip.mp4","size":4},
		{"path":"docs/z.txt","size":3},{"path":"zz.bin","size":9}]}`)
	uploadGetSlug(t, h, id, "a.txt", "a")
	uploadGetSlug(t, h, id, "clip.mp4", "mp4!")
	uploadGetSlug(t, h, id, "docs/z.txt", "zed")
	slugs := slugsOf(t, h, id)

	if rec := doReq(t, h, "GET", "/download/"+id+"/"+slugs["docs/z.txt"], "", ""); rec.Code != 200 || rec.Body.String() != "zed" {
		t.Errorf("stored /download = %d %q", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "GET", "/site/"+id+"/docs/z.txt", "", ""); rec.Code != 200 || rec.Body.String() != "zed" {
		t.Errorf("stored /site = %d %q", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "GET", "/view/"+id+"/"+slugs["zz.bin"], "", ""); rec.Code != 200 ||
		!strings.Contains(rec.Body.String(), "Still uploading") {
		t.Errorf("pending /view = %d, want the waiting page", rec.Code)
	}
	for _, p := range []string{"/view/" + id + "/" + shareid.NewSlug(), "/download/" + id + "/", "/site/" + id + "/nope.txt"} {
		if rec := doReq(t, h, "GET", p, "", ""); rec.Code != 404 {
			t.Errorf("%s = %d, want 404", p, rec.Code)
		}
	}
	rec := doReqWithHeader(t, h, "GET", "/view/"+id+"/"+slugs["a.txt"], "User-Agent", "Slackbot 1.0")
	if !strings.Contains(rec.Body.String(), "/card-video.png") {
		t.Errorf("the card for a share holding a video elsewhere lacks the video tile: %s", rec.Body)
	}

	site := createInbox(t, h, `{"name":"site","entry":"index.html","files":[{"path":"index.html","size":5},{"path":"zz.css","size":6}]}`)
	uploadGetSlug(t, h, site, "index.html", "<h1/>")
	if rec := doReq(t, h, "GET", "/site/"+site+"/index.html", "", ""); !strings.Contains(rec.Body.String(),
		"the share will open right here") {
		t.Errorf("a web page with an asset uploading = %d, want the whole-share waiting page", rec.Code)
	}

	c := createInbox(t, h, `{"name":"receive","receive":true}`)
	if rec := doReq(t, h, "PUT", "/receive/"+c+"/files/in.txt", "", "caught"); rec.Code != 201 {
		t.Fatalf("inbox upload = %d", rec.Code)
	}
	in := slugsOf(t, h, c)["in.txt"]
	for _, p := range []string{"/view/" + c + "/" + in, "/download/" + c + "/" + in, "/site/" + c + "/in.txt"} {
		if rec := doReq(t, h, "GET", p, "", ""); rec.Code != 404 {
			t.Errorf("inbox %s = %d, want 404", p, rec.Code)
		}
	}
	if rec := doReq(t, h, "GET", "/download/"+c+"/"+in, testToken, ""); rec.Code != 200 || rec.Body.String() != "caught" {
		t.Errorf("the owner's bearer download of an inbox = %d %q", rec.Code, rec.Body)
	}

	rid, rslug, _ := publicProbeRevokedShare(t, h, func(string, string, string) {})
	for _, p := range []string{"/view/" + rid + "/" + rslug, "/download/" + rid + "/" + rslug, "/site/" + rid + "/index.html"} {
		rec := doReq(t, h, "GET", p, "", "")
		if strings.Contains(rec.Body.String(), "<h1>hi</h1>") || !strings.Contains(rec.Body.String(), "not available on this server") {
			t.Errorf("revoked %s = %d, want the unavailable page and none of its bytes", p, rec.Code)
		}
	}
}
