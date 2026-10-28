package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestSingleFileShareRedirectsToView(t *testing.T) {
	h := newTestAPI(t)
	id, slugs := shareWithFiles(t, h, "one", map[string]string{"report%20final.pdf": "%PDF"})
	rec := doReq(t, h, "GET", "/share/"+id, "", "")
	if rec.Code != 302 {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/view/"+id+"/"+slugs["report%20final.pdf"] {
		t.Errorf("Location = %q, want slug URL", loc)
	}
}

func TestListingFilenameLinksToView(t *testing.T) {
	h := newTestAPI(t)
	id, slugs := shareWithFiles(t, h, "click", map[string]string{
		"IMG_1.jpg":      "a",
		"notes/day1.txt": "b",
	})
	for file, base := range map[string]string{"IMG_1.jpg": "IMG_1.jpg", "notes/day1.txt": "day1.txt"} {
		dir := ""
		if file == "notes/day1.txt" {
			dir = "?dir=notes"
		}
		body := doReq(t, h, "GET", "/share/"+id+dir, "", "").Body.String()
		want := `<a class="name" href="/view/` + id + `/` + slugs[file] + `">` + base + `</a>`
		if !strings.Contains(body, want) {
			t.Errorf("listing missing clickable name %q", want)
		}
	}
}

func TestListingPageMultiFile(t *testing.T) {
	h := newTestAPI(t)
	id, slugs := shareWithFiles(t, h, "vacation", map[string]string{
		"IMG_1.jpg":      "a",
		"notes/day1.txt": "b",
	})
	rec := doReq(t, h, "GET", "/share/"+id, "", "")
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"IMG_1.jpg",                          // root file basename
		`href="/share/` + id + `?dir=notes"`, // the folder is a link to its own page
		">notes<",
		`href="/view/` + id + `/` + slugs["IMG_1.jpg"] + `"`,
		`href="/download/` + id + `/` + slugs["IMG_1.jpg"] + `"`,
		`href="/zip/` + id + `"`,
		"<title>vacation",
		"Shared with", // footer
		"<svg",        // inline brand mark
	} {
		if !strings.Contains(body, want) {
			t.Errorf("root page missing %q", want)
		}
	}
	// The root page describes the folder and holds nothing from inside it.
	for _, leak := range []string{"day1.txt", "notes/day1.txt", slugs["notes/day1.txt"], "<details", "<script", `class="crumbs"`} {
		if strings.Contains(body, leak) {
			t.Errorf("root page must not contain %q", leak)
		}
	}
	if strings.Contains(body, "/view/"+id+"/IMG_1.jpg") {
		t.Errorf("listing leaks filename-based href")
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q", ct)
	}

	// The folder page holds the file, by basename, with breadcrumbs back.
	rec = doReq(t, h, "GET", "/share/"+id+"?dir=notes", "", "")
	if rec.Code != 200 {
		t.Fatalf("folder page status = %d: %s", rec.Code, rec.Body)
	}
	body = rec.Body.String()
	for _, want := range []string{
		"day1.txt",
		`href="/view/` + id + `/` + slugs["notes/day1.txt"] + `"`,
		`href="/download/` + id + `/` + slugs["notes/day1.txt"] + `"`,
		`class="crumbs"`,
		`<a href="/share/` + id + `">vacation</a>`,
		"<span>notes</span>",
		`href="/zip/` + id + `"`, // the zip stays the whole share
	} {
		if !strings.Contains(body, want) {
			t.Errorf("folder page missing %q", want)
		}
	}
	for _, leak := range []string{"IMG_1.jpg", "notes/day1.txt", "<script"} {
		if strings.Contains(body, leak) {
			t.Errorf("folder page must not contain %q", leak)
		}
	}
}

func TestListingEscapesFilenames(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "esc")
	// ServeMux decodes the upload path; escaped angle brackets belong to
	// the filename and must be escaped again when rendered as HTML.
	rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/%3Cb%3Eevil%3Ci%3E.txt", testToken, "x")
	if rec.Code != 201 {
		t.Fatalf("upload status = %d body %s", rec.Code, rec.Body)
	}
	doReq(t, h, "PUT", "/api/shares/"+id+"/files/second.txt", testToken, "y") // 2 files → listing, not redirect
	page := doReq(t, h, "GET", "/share/"+id, "", "")
	body := page.Body.String()
	if strings.Contains(body, "<b>evil<i>") {
		t.Errorf("filename not HTML-escaped")
	}
	if !strings.Contains(body, "&lt;b&gt;evil&lt;i&gt;.txt") {
		t.Errorf("escaped filename not shown; body: %s", body)
	}
}

// Folder rows and breadcrumbs escape folder names just like filenames.
func TestListingEscapesFolderNames(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "escdir")
	// %3Cimg%3E = "<img>" as the folder segment of a nested upload.
	rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/%3Cimg%3E/a.txt", testToken, "x")
	if rec.Code != 201 {
		t.Fatalf("upload status = %d body %s", rec.Code, rec.Body)
	}
	doReq(t, h, "PUT", "/api/shares/"+id+"/files/second.txt", testToken, "y") // 2 files → listing
	body := doReq(t, h, "GET", "/share/"+id, "", "").Body.String()
	if strings.Contains(body, "<img>") {
		t.Errorf("folder name not HTML-escaped")
	}
	if !strings.Contains(body, "&lt;img&gt;") {
		t.Errorf("escaped folder name not shown; body: %s", body)
	}
	page := doReq(t, h, "GET", "/share/"+id+"?dir="+url.QueryEscape("<img>"), "", "")
	if page.Code != 200 {
		t.Fatalf("folder page status = %d", page.Code)
	}
	folder := page.Body.String()
	if strings.Contains(folder, "<img>") || !strings.Contains(folder, "<span>&lt;img&gt;</span>") {
		t.Errorf("breadcrumb must show the escaped folder name; body: %s", folder)
	}
}

// TestListingShowsPendingRows: manifest share with 2 files, 1 committed →
// GET /share/{id} (multi-file → no redirect) contains: the committed file's
// /view link; the pending file's name WITHOUT an href (no /view/<pending-slug>
// anchor); data-slug="<pending-slug>"; the poller script. A share with all
// files committed contains no data-slug and no poller script.
// The share page waits while ANY file is still uploading, whatever the share
// would open as once complete: the waiting page carries the live progress
// bar and reloads into the listing the moment the last file lands. The
// listing's own address (?files=1) waits the same way, so no pending row is
// ever rendered anywhere.
func TestSharePageWaitsWhileAnyFileIsPending(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"name":"docs","files":[{"path":"a.txt","size":5},{"path":"b.txt","size":5}]}`)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	var cr shareResp
	unmarshal(t, rec, &cr)
	up := doReq(t, h, "PUT", "/api/shares/"+cr.ID+"/files/a.txt", testToken, "hello")
	if up.Code != 201 {
		t.Fatalf("upload a.txt = %d %s", up.Code, up.Body)
	}

	for _, path := range []string{"/share/" + cr.ID, "/share/" + cr.ID + "?files=1"} {
		got := doReq(t, h, "GET", path, "", "")
		if got.Code != 200 {
			t.Fatalf("GET %s (one pending) = %d %s", path, got.Code, got.Body)
		}
		body := got.Body.String()
		if !strings.Contains(body, "the share will open right here") ||
			!strings.Contains(body, `fetch("/share/" + shareID + "/status"`) ||
			!strings.Contains(body, `const shareID = "`+cr.ID+`"`) {
			t.Fatalf("GET %s did not serve the whole-share waiting page: %s", path, body)
		}
		if strings.Contains(body, "data-slug") || strings.Contains(body, "b.txt") {
			t.Fatalf("GET %s rendered listing rows while a file is pending: %s", path, body)
		}
	}

	up2 := doReq(t, h, "PUT", "/api/shares/"+cr.ID+"/files/b.txt", testToken, "world")
	if up2.Code != 201 {
		t.Fatalf("upload b.txt = %d %s", up2.Code, up2.Body)
	}
	body := doReq(t, h, "GET", "/share/"+cr.ID, "", "").Body.String()
	if !strings.Contains(body, "a.txt") || !strings.Contains(body, "b.txt") {
		t.Fatalf("completed share did not list its files: %s", body)
	}
	if strings.Contains(body, "/status") {
		t.Fatalf("completed listing still polls: %s", body)
	}
}

// A share of one pending file waits on its share page too, ahead of the
// single-file redirect: the visitor sees the same progress page every other
// kind shows, and the reload lands on the file.
func TestListingSingleFilePendingWaits(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"name":"solo","files":[{"path":"only.txt","size":5}]}`)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	var cr shareResp
	unmarshal(t, rec, &cr)
	if len(cr.Files) != 1 || cr.Files[0].Slug == "" {
		t.Fatalf("expected 1 pending file with a slug: %+v", cr.Files)
	}

	got := doReq(t, h, "GET", "/share/"+cr.ID, "", "")
	if got.Code != 200 || !strings.Contains(got.Body.String(), "the share will open right here") {
		t.Fatalf("pending single-file share = %d, want the waiting page: %s", got.Code, got.Body)
	}
	doReq(t, h, "PUT", "/api/shares/"+cr.ID+"/files/only.txt", testToken, "hello")
	got = doReq(t, h, "GET", "/share/"+cr.ID, "", "")
	if got.Code != 302 {
		t.Fatalf("completed status = %d, want 302", got.Code)
	}
	if loc := got.Header().Get("Location"); loc != "/view/"+cr.ID+"/"+cr.Files[0].Slug {
		t.Errorf("Location = %q, want /view/%s/%s", loc, cr.ID, cr.Files[0].Slug)
	}
}

func TestListingUnknown404(t *testing.T) {
	h := newTestAPI(t)
	if rec := doReq(t, h, "GET", "/share/zzzzzzzzzz", "", ""); rec.Code != 404 {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

// The header mark reflects what was shared: a folder icon for folder shares
// (created with "folder":true), a file icon for loose-file shares.
func TestListingHeaderIconMatchesShareKind(t *testing.T) {
	h := newTestAPI(t)

	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"tst","folder":true}`)
	if rec.Code != 201 {
		t.Fatalf("create status = %d body %s", rec.Code, rec.Body)
	}
	var resp struct {
		ID     string `json:"id"`
		Folder bool   `json:"folder"`
	}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if !resp.Folder {
		t.Errorf("create response folder = false, want true")
	}
	uploadGetSlug(t, h, resp.ID, "a.txt", "a")
	uploadGetSlug(t, h, resp.ID, "b.txt", "b")
	body := doReq(t, h, "GET", "/share/"+resp.ID, "", "").Body.String()
	if !strings.Contains(body, "gdir40") || strings.Contains(body, "gdoc40") {
		t.Errorf("folder share listing should use the folder mark, got neither/both")
	}

	id, _ := shareWithFiles(t, h, "loose", map[string]string{"a.txt": "a", "b.txt": "b"})
	body = doReq(t, h, "GET", "/share/"+id, "", "").Body.String()
	if !strings.Contains(body, "gdoc40") || strings.Contains(body, "gdir40") {
		t.Errorf("loose-file share listing should use the file mark, got neither/both")
	}
}

// The whole point of the listing flag: a one-file share told to open its
// listing must be SERVED the listing, not bounced to the file. Without this
// gate the client's /share/<id> link is a redirect back to where it started.
func TestSingleFileShareWithListingServesTheListing(t *testing.T) {
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "one", map[string]string{"report.pdf": "%PDF"})
	if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"listing":true}`); rec.Code != 200 {
		t.Fatalf("PATCH listing: %d %s", rec.Code, rec.Body.String())
	}

	rec := doReq(t, h, "GET", "/share/"+id, "", "")
	if rec.Code != 200 {
		t.Fatalf("status = %d, want the listing page", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "report.pdf") {
		t.Errorf("the listing must name the file: %s", rec.Body.String())
	}
}

// And with the flag off it still redirects, so nothing about the default
// changed.
func TestSingleFileShareWithoutListingStillRedirects(t *testing.T) {
	h := newTestAPI(t)
	id, slugs := shareWithFiles(t, h, "one", map[string]string{"report.pdf": "%PDF"})
	if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"listing":false}`); rec.Code != 200 {
		t.Fatalf("PATCH listing: %d %s", rec.Code, rec.Body.String())
	}

	rec := doReq(t, h, "GET", "/share/"+id, "", "")
	if rec.Code != 302 {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/view/"+id+"/"+slugs["report.pdf"] {
		t.Errorf("Location = %q", loc)
	}
}

// A share of one UNVIEWABLE file is the case that gains a page it never had.
func TestSingleUnviewableFileWithListingServesTheListing(t *testing.T) {
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "bin", map[string]string{unviewable: "\x00\x01\xff"})
	if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"listing":true}`); rec.Code != 200 {
		t.Fatalf("PATCH listing: %d %s", rec.Code, rec.Body.String())
	}

	rec := doReq(t, h, "GET", "/share/"+id, "", "")
	if rec.Code != 200 {
		t.Fatalf("status = %d, want the listing page", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, unviewable) {
		t.Errorf("the listing must name the file: %s", body)
	}
}

// One question, one answer: the four are refused in pairs on the RESULTING
// state, so a share can never claim to be a gallery and a file listing at
// once, whichever half a request supplies.
func TestListingIsRefusedAlongsideTheOtherAnswers(t *testing.T) {
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "site", map[string]string{"index.html": "<b>hi", "a.txt": "x"})

	if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken,
		`{"entry":"index.html","listing":true}`); rec.Code != 400 {
		t.Errorf("entry+listing in one request: %d %s", rec.Code, rec.Body.String())
	}
	// Half supplied, half already stored: the refusal reads the resulting
	// state, not the request.
	if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken,
		`{"entry":"index.html"}`); rec.Code != 200 {
		t.Fatalf("setting an entry: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken,
		`{"listing":true}`); rec.Code != 400 {
		t.Errorf("listing onto a stored entry: %d %s", rec.Code, rec.Body.String())
	}
	// Answering the question afresh is fine: one request can move a site
	// straight to a listing by stating both halves.
	if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken,
		`{"entry":"","listing":true}`); rec.Code != 200 {
		t.Errorf("entry cleared and listing set together: %d %s", rec.Code, rec.Body.String())
	}
}

// Every client states all three fields when it changes what the View link
// opens (api.SetOpens), so every swap between the four answers has to be
// accepted on the state it leaves behind, in either direction.
func TestTheViewAnswerCanBeSwappedInEitherDirection(t *testing.T) {
	answers := map[string]string{
		"file":    `{"entry":"","media":false,"listing":false}`,
		"listing": `{"entry":"","media":false,"listing":true}`,
		"gallery": `{"entry":"","media":true,"listing":false}`,
		"page":    `{"entry":"index.html","media":false,"listing":false}`,
	}
	for from, first := range answers {
		for to, second := range answers {
			if from == to {
				continue
			}
			t.Run(from+" to "+to, func(t *testing.T) {
				h := newTestAPI(t)
				id, _ := shareWithFiles(t, h, "trip",
					map[string]string{"index.html": "<b>hi", "beach.jpg": "photo-bytes"})
				if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, first); rec.Code != 200 {
					t.Fatalf("setting up %s: %d %s", from, rec.Code, rec.Body.String())
				}
				if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, second); rec.Code != 200 {
					t.Fatalf("%d %s", rec.Code, rec.Body.String())
				}
			})
		}
	}
}

// Creation refuses the same pairs, before anything exists to fix.
func TestCreateRefusesListingWithAnotherAnswer(t *testing.T) {
	h := newTestAPI(t)
	for _, body := range []string{
		`{"name":"x","listing":true,"media":true}`,
		`{"name":"x","listing":true,"entry":"index.html"}`,
		`{"name":"x","listing":true,"receive":true}`,
	} {
		if rec := doReq(t, h, "POST", "/api/shares", testToken, body); rec.Code != 400 {
			t.Errorf("%s -> %d %s", body, rec.Code, rec.Body.String())
		}
	}
}

// A folder row is counted and sized by everything beneath it, so a visitor
// knows what they are opening.
func TestListingFolderRowCarriesCountAndSize(t *testing.T) {
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "bundle", map[string]string{
		"root.txt":        "r",
		"docs/a.txt":      "aaaa",
		"docs/deep/b.txt": "bbbbbb",
	})
	body := doReq(t, h, "GET", "/share/"+id, "", "").Body.String()
	if !strings.Contains(body, `<span class="count">2 files</span>`) {
		t.Errorf("docs row should count the two files beneath it: %s", body)
	}
	if !strings.Contains(body, `<span class="size">`+humanSize(10)+`</span>`) {
		t.Errorf("docs row should size the ten bytes beneath it: %s", body)
	}
}

// An unknown folder is a share-scoped 404, like an unknown slug; so is a
// folder that is not a clean relpath.
func TestListingUnknownFolderIs404(t *testing.T) {
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "bundle", map[string]string{"a.txt": "a", "d/b.txt": "b"})
	for _, dir := range []string{"nope", "d/nope", "a.txt", ".", "..", "d/../d", "/d", "d/", "d//x", "d\\x", "d\x00"} {
		rec := doReq(t, h, "GET", "/share/"+id+"?dir="+url.QueryEscape(dir), "", "")
		if rec.Code != http.StatusNotFound {
			t.Errorf("dir %q: status = %d, want 404", dir, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "Powered by") {
			t.Errorf("dir %q: missing branded 404 page", dir)
		}
	}
}

// A gallery share and a web page share list only under ?files=1, so every
// folder link and breadcrumb on their listing keeps that flag.
func TestListingFolderLinksKeepFilesFlag(t *testing.T) {
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "site", map[string]string{
		"index.html":    "<p>hi</p>",
		"assets/a.css":  "p{}",
		"assets/x/b.js": "1",
	})
	rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"entry":"index.html"}`)
	if rec.Code != 200 {
		t.Fatalf("set entry: %d %s", rec.Code, rec.Body)
	}
	body := doReq(t, h, "GET", "/share/"+id+"?files=1", "", "").Body.String()
	if !strings.Contains(body, `href="/share/`+id+`?dir=assets&amp;files=1"`) {
		t.Errorf("folder link lost files=1: %s", body)
	}
	body = doReq(t, h, "GET", "/share/"+id+"?dir=assets&files=1", "", "").Body.String()
	if !strings.Contains(body, `href="/share/`+id+`?files=1">site</a>`) {
		t.Errorf("root crumb lost files=1: %s", body)
	}
	if !strings.Contains(body, `href="/share/`+id+`?dir=assets%2Fx&amp;files=1"`) {
		t.Errorf("nested folder link lost files=1 or its escaping: %s", body)
	}
	// Without the flag the site share redirects to its entry page.
	rec = doReq(t, h, "GET", "/share/"+id+"?dir=assets", "", "")
	if rec.Code != http.StatusFound {
		t.Errorf("a site share without files=1 should redirect to the site, got %d", rec.Code)
	}
}

func TestListingGalleryFolderLinksKeepFilesFlag(t *testing.T) {
	h := newTestAPI(t)
	id := newMediaShare(t, h, map[string]string{
		"root.jpg": "photo", "trip/day/beach.jpg": "photo",
	})
	for _, tc := range []struct {
		dir  string
		want []string
	}{
		{"", []string{`href="/share/` + id + `?dir=trip&amp;files=1"`}},
		{"trip", []string{`href="/share/` + id + `?dir=trip%2Fday&amp;files=1"`, `href="/share/` + id + `?files=1">Iceland</a>`}},
		{"trip/day", []string{`href="/share/` + id + `?dir=trip&amp;files=1">trip</a>`, `<span>day</span>`, `beach.jpg`}},
	} {
		rec := doReq(t, h, "GET", folderHref(id, tc.dir, true), "", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("folder %q: status %d", tc.dir, rec.Code)
		}
		body := rec.Body.String()
		for _, want := range tc.want {
			if !strings.Contains(body, want) {
				t.Errorf("folder %q: missing %q", tc.dir, want)
			}
		}
		if strings.Contains(body, "<script") {
			t.Errorf("folder %q rendered gallery JavaScript", tc.dir)
		}
	}
}

// An unnamed share is titled by how many files it holds, in the same words on
// the listing as on its card.
func TestAnUnnamedListingIsTitledByItsFileCount(t *testing.T) {
	h := newTestAPI(t)
	id := createShareBody(t, h, `{"listing":true}`)
	uploadGetSlug(t, h, id, "only.pdf", "x")
	body := doReq(t, h, "GET", "/share/"+id, "", "").Body.String()
	if !strings.Contains(body, "<title>1 file") || strings.Contains(body, "1 files") {
		t.Fatalf("the listing of one unnamed file is not titled \"1 file\":\n%s", body)
	}
}
