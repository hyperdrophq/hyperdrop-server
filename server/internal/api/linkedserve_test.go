package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hyperdrop/server/internal/linked"
	"hyperdrop/server/internal/metadb"
)

// seedLinkedVolume writes the fixture volume every linked-share test reads:
// photo/2024/{a.jpg,b.jpg} and public-share/index.html.
func seedLinkedVolume(t *testing.T) string {
	t.Helper()
	vol := t.TempDir()
	mk := func(p, body string) {
		os.MkdirAll(filepath.Dir(filepath.Join(vol, p)), 0o755)
		os.WriteFile(filepath.Join(vol, p), []byte(body), 0o644)
	}
	mk("photo/2024/a.jpg", "AAAA")
	mk("photo/2024/b.jpg", "BB")
	mk("public-share/index.html", "<h1>hi</h1>")
	return vol
}

// linkedTestAPI is a handler with the fixture volume scanned in as its
// server roots.
func linkedTestAPI(t *testing.T) (http.Handler, Backend, string) {
	t.Helper()
	vol := seedLinkedVolume(t)
	roots, err := linked.NewRoots(nil, []string{vol}, nil)
	if err != nil {
		t.Fatal(err)
	}
	b := testBackendWithRoots(t, roots)
	return New(b, "2.0.0", testDomain(t), nil), b, vol
}

// linkedTestAPIUsers is linkedTestAPI plus the database, for a test that
// seeds accounts beyond the admin against the source allowlist.
func linkedTestAPIUsers(t *testing.T) (http.Handler, *metadb.DB) {
	t.Helper()
	h, b, _ := linkedTestAPI(t)
	return h, b.DB
}

// linkedShare is one share serving one source folder, owned by the admin every
// test signs in as, and answers its id.
func linkedShare(t *testing.T, b Backend, source string) string {
	t.Helper()
	d, err := b.DB.CreateShare(metadb.CreateOptions{Name: "trip", Owner: metadb.DefaultAdminName,
		Folder: true, Sources: []string{source}})
	if err != nil {
		t.Fatal(err)
	}
	return d.ID
}

func TestLinkedListingIsLive(t *testing.T) {
	h, b, vol := linkedTestAPI(t)
	id := linkedShare(t, b, "photo/2024")
	os.WriteFile(filepath.Join(vol, "photo", "2024", "c.jpg"), []byte("C"), 0o644)
	rec := doReq(t, h, "GET", "/share/"+id, "", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "c.jpg") {
		t.Fatalf("listing: %d, has c.jpg=%v", rec.Code, strings.Contains(rec.Body.String(), "c.jpg"))
	}
}

func TestLinkedShareWhoseFolderIsGoneRendersTheUnavailablePage(t *testing.T) {
	h, b, vol := linkedTestAPI(t)
	id := linkedShare(t, b, "photo/2024")
	slug := linkedEntry(t, h, id, "a.jpg").Slug
	os.RemoveAll(filepath.Join(vol, "photo"))
	for _, p := range []string{"/share/" + id, "/download/" + id + "/" + slug, "/zip/" + id} {
		rec := doReq(t, h, "GET", p, "", "")
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "not available on this server") {
			t.Errorf("%s: %d %q", p, rec.Code, rec.Body.String()[:min(80, rec.Body.Len())])
		}
	}
}

// The owner's own bearer fetch of a share whose folder is gone gets an
// ERROR, never the unavailable page: `hyperdrop fetch` saves what it is
// handed, so an HTML page answered with 200 would land on disk as the file.
func TestLinkedBearerDownloadOfAGoneFolderIs404(t *testing.T) {
	h, b, vol := linkedTestAPI(t)
	id := linkedShare(t, b, "photo/2024")
	slug := linkedEntry(t, h, id, "a.jpg").Slug
	os.RemoveAll(filepath.Join(vol, "photo"))
	rec := doReq(t, h, "GET", "/download/"+id+"/"+slug, testToken, "")
	if rec.Code != 404 || !strings.Contains(rec.Body.String(), "source-missing") {
		t.Fatalf("bearer download: %d %q", rec.Code, rec.Body.String())
	}
	rec = doReq(t, h, "GET", "/download/"+id+"/"+slug, "", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "not available on this server") {
		t.Fatalf("anonymous download: %d %q", rec.Code, rec.Body.String())
	}
}

// A linked share serves its source folder live on every public byte route:
// /view and /download open one entry through the source's own root, and
// /zip streams the whole walk through it. The share's own directory holds
// nothing for any of them, so this is the whole of what makes a linked share
// readable.
func TestALinkedEntryServesThroughItsSourceRoot(t *testing.T) {
	h, b, vol := linkedTestAPI(t)
	id := linkedShare(t, b, "photo/2024")
	a := linkedEntry(t, h, id, "a.jpg")
	rec := doReq(t, h, "GET", "/download/"+id+"/"+a.Slug, "", "")
	if rec.Code != 200 || rec.Body.String() != "AAAA" {
		t.Fatalf("download: %d %q", rec.Code, rec.Body.String())
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "a.jpg") {
		t.Fatalf("disposition = %q", cd)
	}
	if rec := doReq(t, h, "GET", "/view/"+id+"/"+a.Slug, "", ""); rec.Code != 200 {
		t.Fatalf("view: %d", rec.Code)
	}
	// The bytes are read live, never copied: rewriting the file on the
	// server changes what the same link serves.
	if err := os.WriteFile(filepath.Join(vol, "photo", "2024", "a.jpg"), []byte("AAAAAAAA"), 0o644); err != nil {
		t.Fatal(err)
	}
	if rec := doReq(t, h, "GET", "/download/"+id+"/"+a.Slug, "", ""); rec.Body.String() != "AAAAAAAA" {
		t.Fatal("served stale bytes: the share must read the file live")
	}
	rec = doReq(t, h, "GET", "/zip/"+id, "", "")
	if rec.Code != 200 || rec.Header().Get("Content-Length") != "" {
		t.Fatalf("zip: %d, Content-Length %q (a linked zip streams chunked)",
			rec.Code, rec.Header().Get("Content-Length"))
	}
	for _, name := range []string{"a.jpg", "b.jpg"} {
		if !strings.Contains(rec.Body.String(), name) {
			t.Errorf("zip lacks %s", name)
		}
	}
}

// linkedEntry reads one of a linked share's entries back through the owner's
// own share route, which is where a linked entry's slug is minted. It asserts
// the entry really is linked, so a test built on it cannot pass against an
// upload of the same name.
func linkedEntry(t *testing.T, h http.Handler, id, rel string) struct {
	Path   string `json:"path"`
	Slug   string `json:"slug"`
	Linked bool   `json:"linked"`
} {
	t.Helper()
	var d struct {
		Files []struct {
			Path   string `json:"path"`
			Slug   string `json:"slug"`
			Linked bool   `json:"linked"`
		} `json:"files"`
	}
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+id, testToken, ""), &d)
	for _, f := range d.Files {
		if f.Path == rel {
			if !f.Linked {
				t.Fatalf("%s is not a linked entry: %+v", rel, f)
			}
			return f
		}
	}
	t.Fatalf("share %s holds no %s: %+v", id, rel, d.Files)
	panic("unreachable")
}

// A gallery fires one tile request per picture, and composing a linked share
// costs a source walk plus a slug-assigning write, so the tile route must
// not resolve the share through the walk. Proven from the outside: with the
// source folder GONE, every route that walks it renders the unavailable
// page, and the tile still comes back as itself.
func TestALinkedSharesTileIsServedWithoutWalkingTheSource(t *testing.T) {
	h, b, vol := linkedTestAPI(t)
	d, err := b.DB.CreateShare(metadb.CreateOptions{Name: "trip", Owner: metadb.DefaultAdminName,
		Folder: true, Media: true, Sources: []string{"photo/2024"}})
	if err != nil {
		t.Fatal(err)
	}
	slug := linkedEntry(t, h, d.ID, "a.jpg").Slug
	tile := aJPEG(t, 24, 18)
	if rec := doReq(t, h, "PUT", "/api/shares/"+d.ID+"/thumbs/"+slug, testToken,
		string(tile)); rec.Code != 204 {
		t.Fatalf("put tile = %d %s", rec.Code, rec.Body)
	}
	if err := os.RemoveAll(filepath.Join(vol, "photo")); err != nil {
		t.Fatal(err)
	}
	// The source really is gone, so the assertion below cannot pass by
	// accident: the listing, which does walk it, says so.
	if rec := doReq(t, h, "GET", "/share/"+d.ID, "", ""); !strings.Contains(rec.Body.String(),
		"not available on this server") {
		t.Fatalf("listing still resolves the source: %d", rec.Code)
	}
	rec := doReq(t, h, "GET", "/thumb/"+d.ID+"/"+slug, "", "")
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "image/jpeg" {
		t.Fatalf("tile = %d %q, want the picture", rec.Code, rec.Header().Get("Content-Type"))
	}
	if rec.Body.String() != string(tile) {
		t.Fatalf("tile body is %d bytes, want the %d stored", rec.Body.Len(), len(tile))
	}
}
