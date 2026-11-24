package api

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"hyperdrop/server/internal/linked"
	"hyperdrop/server/internal/metadb"
)

func moveReq(t *testing.T, h http.Handler, id, token, from, to string) (int, string) {
	t.Helper()
	rec := doReq(t, h, "POST", "/api/shares/"+id+"/move", token,
		`{"from":"`+from+`","to":"`+to+`"}`)
	return rec.Code, rec.Body.String()
}

// A move keeps every link: the slug survives, /download answers with the
// same bytes, and the listing shows the new path only.
func TestMoveFileKeepsItsLink(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "docs")
	slug := uploadGetSlug(t, h, id, "a.txt", "aaa")
	uploadGetSlug(t, h, id, "docs/b.txt", "bbb")

	code, body := moveReq(t, h, id, testToken, "a.txt", "docs/a.txt")
	if code != http.StatusOK {
		t.Fatalf("move = %d %s", code, body)
	}
	if !strings.Contains(body, `"docs/a.txt"`) || strings.Contains(body, `"a.txt"`) {
		t.Errorf("listing after the move: %s", body)
	}
	if !strings.Contains(body, slug) {
		t.Errorf("slug did not survive the move: %s", body)
	}
	rec := doReq(t, h, "GET", "/download/"+id+"/"+slug, "", "")
	if rec.Code != http.StatusOK || rec.Body.String() != "aaa" {
		t.Errorf("link after the move = %d %q", rec.Code, rec.Body.String())
	}
}

// A folder moves as one: its entries re-root, and the entry page follows,
// so the share link keeps opening the page at its new place.
func TestMoveFolderCarriesTheEntryPage(t *testing.T) {
	h, b := newTestAPIBackend(t)
	id := createShare(t, h, "site")
	uploadGetSlug(t, h, id, "site/index.html", "<html></html>")
	uploadGetSlug(t, h, id, "site/style.css", "body{}")
	if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"entry":"site/index.html"}`); rec.Code != 200 {
		t.Fatalf("set entry = %d %s", rec.Code, rec.Body)
	}
	if code, body := moveReq(t, h, id, testToken, "site", "www/site"); code != 200 {
		t.Fatalf("move = %d %s", code, body)
	}
	d, err := b.DB.Share(id)
	if err != nil {
		t.Fatal(err)
	}
	if d.Entry != "www/site/index.html" {
		t.Errorf("entry = %q, want www/site/index.html", d.Entry)
	}
	rec := doReq(t, h, "GET", "/share/"+id, "", "")
	if rec.Code != http.StatusFound && rec.Code != http.StatusSeeOther && rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("share link = %d, want a redirect to the page", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "www/site/index.html") {
		t.Errorf("share link redirects to %q", loc)
	}
}

// A folder holding nothing but folder RECORDS has no directory of its own,
// so the move is rows alone and must still answer 200.
func TestMoveAFolderThatOnlyExistsAsARecord(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "docs")
	if code, body := mkdirReq(t, h, id, testToken, "empty"); code != 200 {
		t.Fatalf("create folder = %d %s", code, body)
	}
	code, body := moveReq(t, h, id, testToken, "empty", "moved")
	if code != 200 {
		t.Fatalf("move = %d %s", code, body)
	}
	if !strings.Contains(body, `"folders":["moved"]`) {
		t.Errorf("folders after the move: %s", body)
	}
}

func TestMoveFileRefusals(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	alice := seedUser(t, um, "alice")
	bob := seedUser(t, um, "bob")
	id := createShareAs(t, h, alice, `{"name":"docs","files":[{"path":"later.bin","size":3}]}`)
	for _, rel := range []string{"a.txt", "docs/a.txt", "docs/sub/c.txt"} {
		if rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/"+rel, alice, "x"); rec.Code != 201 {
			t.Fatalf("upload %s = %d", rel, rec.Code)
		}
	}
	for _, tc := range []struct {
		name, token, from, to string
		code                  int
		want                  string
	}{
		{"someone else's share", bob, "a.txt", "docs/x.txt", 404, "not-found"},
		{"unknown file", alice, "nope.txt", "docs/nope.txt", 404, "not-found"},
		{"into itself", alice, "docs", "docs/sub", 400, "into-itself"},
		{"onto an existing file", alice, "a.txt", "docs/a.txt", 400, "path-taken"},
		{"onto an existing folder", alice, "docs/sub", "docs", 400, "path-taken"},
		{"still uploading", alice, "later.bin", "docs/later.bin", 409, "share-incomplete"},
		{"unclean path", alice, "a.txt", "../a.txt", 400, "clean relative"},
		{"empty destination", alice, "a.txt", "", 400, "clean relative"},
	} {
		code, body := moveReq(t, h, id, tc.token, tc.from, tc.to)
		if code != tc.code || !strings.Contains(body, tc.want) {
			t.Errorf("%s: %d %s, want %d %s", tc.name, code, body, tc.code, tc.want)
		}
	}
	// Bad JSON is a 400 too.
	if rec := doReq(t, h, "POST", "/api/shares/"+id+"/move", alice, "{"); rec.Code != 400 {
		t.Errorf("bad json = %d", rec.Code)
	}
}

// The wire rule: a decomposed spelling names the same stored file.
func TestMoveFileNormalizesBothPaths(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "docs")
	slug := uploadGetSlug(t, h, id, "café.txt", "c")
	uploadGetSlug(t, h, id, "docs/keep.txt", "k")
	code, body := moveReq(t, h, id, testToken, "café.txt", "docs/café.txt")
	if code != 200 || !strings.Contains(body, "docs/café.txt") || !strings.Contains(body, slug) {
		t.Fatalf("move = %d %s", code, body)
	}
}

// Linked entries are the source's: they do not move, nothing moves onto
// them, and a destination the source names is refused like an upload.
func TestMoveFileRespectsTheSource(t *testing.T) {
	h, _, _ := linkedTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"sources":["photo/2024"],"files":[{"path":"notes.txt","size":5},{"path":"docs/more.txt","size":1}],"name":"mix"}`)
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		ID string `json:"id"`
	}
	unmarshal(t, rec, &out)
	for rel, body := range map[string]string{"notes.txt": "hello", "docs/more.txt": "m"} {
		if rec := doReq(t, h, "PUT", "/api/shares/"+out.ID+"/files/"+rel, testToken, body); rec.Code/100 != 2 {
			t.Fatalf("put %s: %d %s", rel, rec.Code, rec.Body)
		}
	}
	for _, tc := range []struct {
		name, from, to string
		code           int
		want           string
	}{
		{"a linked file", "a.jpg", "docs/a.jpg", 409, "share-linked"},
		{"onto a linked file", "notes.txt", "a.jpg", 400, "path-taken"},
		{"a folder holding the linked files", "docs", "photo", 200, ""},
	} {
		code, body := moveReq(t, h, out.ID, testToken, tc.from, tc.to)
		if code != tc.code || !strings.Contains(body, tc.want) {
			t.Errorf("%s: %d %s, want %d %s", tc.name, code, body, tc.code, tc.want)
		}
	}
	// An upload moves beside the linked entries and keeps its slug.
	code, body := moveReq(t, h, out.ID, testToken, "notes.txt", "photo/notes.txt")
	if code != 200 || !strings.Contains(body, `"photo/notes.txt"`) {
		t.Fatalf("move beside the source: %d %s", code, body)
	}
}

// A gallery of a server folder tiles the folder's own entries, whose slugs
// live in slugs.json rather than the share's file rows: the thumbnail route must
// recognise them, or the app's backfill of tiles answers 404 for every one.
func TestThumbAcceptsALinkedEntry(t *testing.T) {
	vol := seedLinkedVolume(t)
	roots, err := linked.NewRoots(nil, []string{vol}, nil)
	if err != nil {
		t.Fatal(err)
	}
	b := testBackendWithRoots(t, roots)
	h := New(b, "2.0.0", testDomain(t), nil)
	d, err := b.DB.CreateShare(metadb.CreateOptions{Name: "trip", Owner: metadb.DefaultAdminName,
		Folder: true, Sources: []string{"photo/2024"}})
	if err != nil {
		t.Fatal(err)
	}
	slugs, err := b.DB.AssignSlugs(d.ID, []string{"a.jpg"})
	if err != nil {
		t.Fatal(err)
	}
	slug := slugs["a.jpg"]
	rec := doReq(t, h, "PUT", "/api/shares/"+d.ID+"/thumbs/"+slug, testToken, string(aJPEG(t, 32, 24)))
	if rec.Code != 204 {
		t.Fatalf("put thumb for a linked entry = %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "GET", "/thumb/"+d.ID+"/"+slug, "", ""); rec.Code != 200 {
		t.Fatalf("get thumb = %d", rec.Code)
	}
}

// The rows move first, so a rename that fails must put them back: a share
// whose bytes stayed where they were goes on listing them there, and the
// link the caller already sent keeps serving.
func TestAFailedRenameReturnsTheRowsToTheOldPath(t *testing.T) {
	h, b := newTestAPIBackend(t)
	id := createShare(t, h, "docs")
	slug := uploadGetSlug(t, h, id, "a.txt", "aaa")
	dir, err := b.FS.ShareDir(id)
	if err != nil {
		t.Fatal(err)
	}
	// A directory standing where the file would land, with nothing in the
	// rows to say so: the rename refuses, which is what this asks of it.
	planted := filepath.Join(dir, "files", "docs", "a.txt")
	if err := os.MkdirAll(filepath.Join(planted, "inside"), 0o755); err != nil {
		t.Fatal(err)
	}
	code, body := moveReq(t, h, id, testToken, "a.txt", "docs/a.txt")
	if code != http.StatusInternalServerError {
		t.Fatalf("move onto a planted directory = %d %s, want 500", code, body)
	}
	if !regexp.MustCompile(`^\{"error":"internal error \(ref [0-9a-f]{8}\)"\}\s*$`).MatchString(body) {
		t.Fatalf("the 500 = %s, want the reference alone", body)
	}
	d, err := b.DB.Share(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Files) != 1 || d.Files[0].Path != "a.txt" || d.Files[0].Slug != slug {
		t.Fatalf("rows after the refused move: %+v", d.Files)
	}
	rec := doReq(t, h, "GET", "/download/"+id+"/"+slug, "", "")
	if rec.Code != http.StatusOK || rec.Body.String() != "aaa" {
		t.Fatalf("link after the refused move = %d %q", rec.Code, rec.Body.String())
	}
}
