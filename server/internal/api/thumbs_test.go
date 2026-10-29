package api

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"image"
	"image/color"
	"image/jpeg"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/metadb"
)

// aJPEG returns a real, decodable JPEG of the given size. The thumbnail route
// refuses anything image/jpeg.DecodeConfig will not read, so tests cannot
// stand in a string.
func aJPEG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	img.Set(0, 0, color.RGBA{R: 200, G: 40, B: 90, A: 255})
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, nil); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// mediaShareWithFile creates a media share holding one committed file and
// returns the share id and the file's slug.
func mediaShareWithFile(t *testing.T, h http.Handler, name, body string) (string, string) {
	t.Helper()
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"Trip","media":true}`)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	var created struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)
	rec = doReq(t, h, "PUT", "/api/shares/"+created.ID+"/files/"+name, testToken, body)
	if rec.Code != 201 && rec.Code != 200 {
		t.Fatalf("upload = %d %s", rec.Code, rec.Body)
	}
	var up struct {
		Slug string `json:"slug"`
	}
	json.Unmarshal(rec.Body.Bytes(), &up)
	if up.Slug == "" {
		rec = doReq(t, h, "GET", "/api/shares/"+created.ID, testToken, "")
		var sh struct {
			Files []struct {
				Slug string `json:"slug"`
			} `json:"files"`
		}
		json.Unmarshal(rec.Body.Bytes(), &sh)
		up.Slug = sh.Files[0].Slug
	}
	return created.ID, up.Slug
}

func TestThumbRoundTripsOverHTTP(t *testing.T) {
	h := newTestAPI(t)
	id, slug := mediaShareWithFile(t, h, "a.jpg", "pretend-photo")
	want := aJPEG(t, 64, 48)
	rec := doReq(t, h, "PUT", "/api/shares/"+id+"/thumbs/"+slug, testToken, string(want))
	if rec.Code != 204 {
		t.Fatalf("put = %d %s", rec.Code, rec.Body)
	}
	rec = doReq(t, h, "GET", "/thumb/"+id+"/"+slug, "", "")
	if rec.Code != 200 {
		t.Fatalf("get = %d %s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "image/jpeg" {
		t.Fatalf("Content-Type = %q", ct)
	}
	if !bytes.Equal(rec.Body.Bytes(), want) {
		t.Fatal("body differs from what was stored")
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("thumbnail served without nosniff")
	}
}

func TestThumbRefusesWhatIsNotAJPEG(t *testing.T) {
	h := newTestAPI(t)
	id, slug := mediaShareWithFile(t, h, "a.jpg", "pretend-photo")
	for _, body := range []string{
		"<html><script>alert(1)</script>",
		"\x89PNG\r\n\x1a\n and then some",
		"",
	} {
		rec := doReq(t, h, "PUT", "/api/shares/"+id+"/thumbs/"+slug, testToken, body)
		if rec.Code != 400 {
			t.Errorf("put %q = %d, want 400", body[:min(len(body), 12)], rec.Code)
		}
	}
}

func TestThumbRefusesAnOversizeBody(t *testing.T) {
	h := newTestAPI(t)
	id, slug := mediaShareWithFile(t, h, "a.jpg", "pretend-photo")
	big := string(aJPEG(t, 64, 48)) + strings.Repeat("x", thumbMaxBytes)
	rec := doReq(t, h, "PUT", "/api/shares/"+id+"/thumbs/"+slug, testToken, big)
	if rec.Code != 413 {
		t.Fatalf("put = %d, want 413", rec.Code)
	}
}

func TestThumbRefusesASlugTheShareDoesNotHold(t *testing.T) {
	h := newTestAPI(t)
	id, _ := mediaShareWithFile(t, h, "a.jpg", "pretend-photo")
	other := "0192b3c4-5678-4abc-8def-0123456789ab"
	rec := doReq(t, h, "PUT", "/api/shares/"+id+"/thumbs/"+other, testToken, string(aJPEG(t, 8, 8)))
	if rec.Code != 404 {
		t.Fatalf("put = %d, want 404", rec.Code)
	}
	if rec := doReq(t, h, "GET", "/thumb/"+id+"/"+other, "", ""); rec.Code != 404 {
		t.Fatalf("get = %d, want 404", rec.Code)
	}
}

func TestThumbNeedsTheOwner(t *testing.T) {
	h := newTestAPI(t)
	id, slug := mediaShareWithFile(t, h, "a.jpg", "pretend-photo")
	rec := doReq(t, h, "PUT", "/api/shares/"+id+"/thumbs/"+slug, "", string(aJPEG(t, 8, 8)))
	if rec.Code != 401 {
		t.Fatalf("anonymous put = %d, want 401", rec.Code)
	}
}

// A protected share's thumbnails are behind its password, exactly as its
// files are: the grid is a view of the content.
func TestThumbOnAProtectedShareNeedsTheCookie(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"name":"Trip","media":true,"password":"letmein"}`)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	var created struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)
	rec = doReq(t, h, "PUT", "/api/shares/"+created.ID+"/files/a.jpg", testToken, "photo")
	var up struct {
		Slug string `json:"slug"`
	}
	json.Unmarshal(rec.Body.Bytes(), &up)
	doReq(t, h, "PUT", "/api/shares/"+created.ID+"/thumbs/"+up.Slug, testToken, string(aJPEG(t, 8, 8)))

	// No cookie: the password form, never the bytes.
	rec = doReq(t, h, "GET", "/thumb/"+created.ID+"/"+up.Slug, "", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "password-protected") {
		t.Fatalf("uncookied thumb = %d, body starts %q", rec.Code, rec.Body.String()[:min(rec.Body.Len(), 60)])
	}
	// With the password, the picture.
	rec = doReq(t, h, "GET", "/thumb/"+created.ID+"/"+up.Slug+"?pw=letmein", "", "")
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "image/jpeg" {
		t.Fatalf("unlocked thumb = %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "private, no-cache" {
		t.Fatalf("protected thumb Cache-Control = %q, want private, no-cache", cc)
	}
}

func TestGalleryMetadataRoute(t *testing.T) {
	h := newTestAPI(t)
	id, slug := mediaShareWithFile(t, h, "a.jpg", "pretend-photo")
	body := `{"items":[` +
		`{"slug":"` + slug + `","w":4032,"h":3024,"durationMs":0,"takenAt":"2026-08-01T10:00:00Z"},` +
		`{"slug":"0192b3c4-5678-4abc-8def-0123456789ab","w":1,"h":1}]}`
	rec := doReq(t, h, "PUT", "/api/shares/"+id+"/gallery", testToken, body)
	if rec.Code != 200 {
		t.Fatalf("put = %d %s", rec.Code, rec.Body)
	}
	// The item naming a slug this share does not hold is dropped, and the
	// response says how many were kept.
	var res struct {
		Items   int `json:"items"`
		Dropped int `json:"dropped"`
	}
	json.Unmarshal(rec.Body.Bytes(), &res)
	if res.Items != 1 || res.Dropped != 1 {
		t.Fatalf("response = %+v, want 1 kept and 1 dropped: %s", res, rec.Body)
	}
}

func TestGalleryMetadataNeedsTheOwner(t *testing.T) {
	h := newTestAPI(t)
	id, _ := mediaShareWithFile(t, h, "a.jpg", "pretend-photo")
	if rec := doReq(t, h, "PUT", "/api/shares/"+id+"/gallery", "", `{"items":[]}`); rec.Code != 401 {
		t.Fatalf("anonymous = %d, want 401", rec.Code)
	}
}

func TestGalleryMetadataRefusesAnOversizeBody(t *testing.T) {
	h := newTestAPI(t)
	id, _ := mediaShareWithFile(t, h, "a.jpg", "pretend-photo")
	body := `{"items":[` + strings.Repeat(`{"slug":"0192b3c4-5678-4abc-8def-0123456789ab"},`, 200000)
	rec := doReq(t, h, "PUT", "/api/shares/"+id+"/gallery", testToken, body+`{}]}`)
	if rec.Code != 413 {
		t.Fatalf("put = %d, want 413", rec.Code)
	}
}

// thumbTar builds a tar of name to bytes for the batched thumbnail route.
// Its own builder rather than batch_test's tarOf: the entries here are raw
// bytes and may repeat a name, which a map cannot express.
func thumbTar(t *testing.T, entries [][2]any) string {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		name, data := e[0].(string), e[1].([]byte)
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		tw.Write(data)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestThumbBatchStoresEveryTileInOneRequest(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"Trip","media":true}`)
	var created struct {
		ID string `json:"id"`
	}
	unmarshal(t, rec, &created)
	slugs := make([]string, 3)
	for i, name := range []string{"a.jpg", "b.jpg", "c.jpg"} {
		slugs[i] = uploadGetSlug(t, h, created.ID, name, "photo "+name)
	}
	tiles := aJPEG(t, 24, 18)
	body := thumbTar(t, [][2]any{
		{slugs[0] + ".jpg", tiles},
		{slugs[1] + ".jpg", tiles},
		// A slug this share does not hold, an unparseable name, and something
		// that is not a JPEG are all SKIPPED, never fatal: losing every good
		// tile because of one bad entry would be the wrong trade.
		{"0192b3c4-5678-4abc-8def-0123456789ab.jpg", tiles},
		{"not-a-slug.jpg", tiles},
		{slugs[2] + ".jpg", []byte("<html>nope</html>")},
	})
	rec = doReq(t, h, "POST", "/api/shares/"+created.ID+"/thumbs", testToken, body)
	if rec.Code != 200 {
		t.Fatalf("batch = %d %s", rec.Code, rec.Body)
	}
	var res struct {
		Stored  int      `json:"stored"`
		Skipped []string `json:"skipped"`
	}
	unmarshal(t, rec, &res)
	if res.Stored != 2 || len(res.Skipped) != 3 {
		t.Fatalf("result = %+v", res)
	}
	for _, slug := range slugs[:2] {
		got := doReq(t, h, "GET", "/thumb/"+created.ID+"/"+slug, "", "")
		if got.Code != 200 || !bytes.Equal(got.Body.Bytes(), tiles) {
			t.Errorf("thumb %s = %d, %d bytes", slug, got.Code, got.Body.Len())
		}
	}
	// The one whose body was not a JPEG stored nothing.
	if got := doReq(t, h, "GET", "/thumb/"+created.ID+"/"+slugs[2], "", ""); got.Code != 404 {
		t.Errorf("the refused tile is served: %d", got.Code)
	}
}

func TestThumbBatchNeedsTheOwner(t *testing.T) {
	h := newTestAPI(t)
	id, _ := mediaShareWithFile(t, h, "a.jpg", "photo")
	if rec := doReq(t, h, "POST", "/api/shares/"+id+"/thumbs", "", ""); rec.Code != 401 {
		t.Fatalf("anonymous = %d, want 401", rec.Code)
	}
}

func TestThumbBatchRefusesTooManyEntries(t *testing.T) {
	h := newTestAPI(t)
	id, slug := mediaShareWithFile(t, h, "a.jpg", "photo")
	tile := aJPEG(t, 8, 8)
	entries := make([][2]any, 0, sidecarBatchMaxFiles+1)
	for i := 0; i <= sidecarBatchMaxFiles; i++ {
		entries = append(entries, [2]any{slug + ".jpg", tile})
	}
	rec := doReq(t, h, "POST", "/api/shares/"+id+"/thumbs", testToken, thumbTar(t, entries))
	if rec.Code != 413 {
		t.Fatalf("batch = %d, want 413", rec.Code)
	}
}

// The gallery page runs on the APP origin and loads every tile from the FILE
// origin, so a protected gallery's thumbnails reach the browser only if an
// image-shaped request honours the access cookie. That is `openDests`' whole
// purpose, and this pins it for the thumbnail route the way embedread_test
// pins it for /view.
func TestAProtectedThumbLoadsAsAnImageAndNotAsAScriptRead(t *testing.T) {
	h := withDomain(t, "share.example.com")
	rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"name":"Trip","media":true,"password":"pw123"}`)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	var cr struct{ ID string }
	unmarshal(t, rec, &cr)
	slug := uploadGetSlug(t, h, cr.ID, "a.jpg", "photo bytes")
	jpg := aJPEG(t, 40, 30)
	if rec := doReq(t, h, "PUT", "/api/shares/"+cr.ID+"/thumbs/"+slug, testToken, string(jpg)); rec.Code != 204 {
		t.Fatalf("put thumb = %d %s", rec.Code, rec.Body)
	}
	cookies := unlockCookies(t, h, cr.ID, "pw123")
	path := "/thumb/" + cr.ID + "/" + slug

	// The grid's own request: a person looking at the page.
	got := httptest.NewRecorder()
	h.ServeHTTP(got, fileReq(path, "image", "no-cors", cookies))
	if got.Code != 200 || !bytes.Equal(got.Body.Bytes(), jpg) {
		t.Fatalf("image request = %d, %d bytes", got.Code, got.Body.Len())
	}

	// An uploaded page reading the same URL through script gets nothing, for
	// the reason /view refuses it: uploads share one origin.
	for _, dest := range []string{"iframe", "script", "style", "worker"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, fileReq(path, dest, "no-cors", cookies))
		if bytes.Equal(rec.Body.Bytes(), jpg) {
			t.Errorf("Sec-Fetch-Dest=%s was handed the protected tile", dest)
		}
	}
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, fileReq(path, "empty", "cors", cookies))
	if bytes.Equal(rec2.Body.Bytes(), jpg) {
		t.Error("a scripted fetch() was handed the protected tile")
	}
}

// The owner's share view says which files already have a tile, so the client
// that derives tiles plans only the files still wanting one instead of
// reading a whole NAS gallery back on every launch.
func TestTheOwnerViewSaysWhichFilesHaveATile(t *testing.T) {
	h := newTestAPI(t)
	id, slug := mediaShareWithFile(t, h, "a.jpg", "pretend-photo")
	rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/b.jpg", testToken, "another")
	if rec.Code != 201 && rec.Code != 200 {
		t.Fatalf("upload = %d %s", rec.Code, rec.Body)
	}
	flags := func() map[string]bool {
		rec := doReq(t, h, "GET", "/api/shares/"+id, testToken, "")
		if rec.Code != 200 {
			t.Fatalf("get = %d %s", rec.Code, rec.Body)
		}
		var sh struct {
			Files []struct {
				Path     string `json:"path"`
				HasThumb bool   `json:"hasThumb"`
			} `json:"files"`
		}
		json.Unmarshal(rec.Body.Bytes(), &sh)
		out := map[string]bool{}
		for _, f := range sh.Files {
			out[f.Path] = f.HasThumb
		}
		return out
	}
	if got := flags(); got["a.jpg"] || got["b.jpg"] {
		t.Fatalf("before any tile: %v", got)
	}
	rec = doReq(t, h, "PUT", "/api/shares/"+id+"/thumbs/"+slug, testToken, string(aJPEG(t, 8, 8)))
	if rec.Code != 204 {
		t.Fatalf("put thumb = %d %s", rec.Code, rec.Body)
	}
	if got := flags(); !got["a.jpg"] || got["b.jpg"] {
		t.Fatalf("after tiling a.jpg: %v", got)
	}
	// The flag is omitted, never written false: the row stays as small as
	// it was for every file without a tile.
	rec = doReq(t, h, "GET", "/api/shares/"+id, testToken, "")
	if strings.Contains(rec.Body.String(), `"hasThumb":false`) {
		t.Fatal("a file without a tile carries hasThumb:false")
	}
}

// A stored file's bytes never change under their slug, so any tile is
// current; a linked file is overwritten in place on the NAS, so a tile older
// than the file's modification time is stale and the file wants a new one.
func TestALinkedTileOlderThanItsFileIsNotCurrent(t *testing.T) {
	tileAt := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	older := tileAt.Add(-time.Hour)
	newer := tileAt.Add(time.Hour)
	tiles := map[string]time.Time{"s": tileAt}
	cases := []struct {
		name string
		f    fileView
		want bool
	}{
		{"no tile", fileView{File: metadb.File{Slug: "x"}}, false},
		{"stored, any age", fileView{File: metadb.File{Slug: "s", CommittedAt: &newer}}, true},
		{"linked, file older than tile", fileView{File: metadb.File{Slug: "s", CommittedAt: &older}, Linked: true}, true},
		{"linked, file rewritten after the tile", fileView{File: metadb.File{Slug: "s", CommittedAt: &newer}, Linked: true}, false},
		{"linked, no date", fileView{File: metadb.File{Slug: "s"}, Linked: true}, true},
	}
	for _, c := range cases {
		if got := thumbCurrent(c.f, tiles); got != c.want {
			t.Errorf("%s: thumbCurrent = %v, want %v", c.name, got, c.want)
		}
	}
}

// The owner's own bearer reads a tile of a protected gallery, the read a
// phone needs to draw the row of a gallery another device made. The public
// /thumb stays behind the password.
func TestTheOwnerReadsAProtectedGallerysTile(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"Trip","media":true,"password":"letmein"}`)
	var created struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)
	rec = doReq(t, h, "PUT", "/api/shares/"+created.ID+"/files/a.jpg", testToken, "photo")
	var up struct {
		Slug string `json:"slug"`
	}
	json.Unmarshal(rec.Body.Bytes(), &up)
	want := aJPEG(t, 8, 8)
	doReq(t, h, "PUT", "/api/shares/"+created.ID+"/thumbs/"+up.Slug, testToken, string(want))

	rec = doReq(t, h, "GET", "/api/shares/"+created.ID+"/thumbs/"+up.Slug, testToken, "")
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "image/jpeg" || !bytes.Equal(rec.Body.Bytes(), want) {
		t.Fatalf("owner read = %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "private") {
		t.Fatalf("Cache-Control = %q", cc)
	}
	if rec := doReq(t, h, "GET", "/api/shares/"+created.ID+"/thumbs/"+up.Slug, "", ""); rec.Code != 401 {
		t.Fatalf("anonymous = %d", rec.Code)
	}
}

func TestAnotherAccountCannotReadTheTile(t *testing.T) {
	h, b := newTestAPIBackend(t)
	bob := seedUser(t, b.DB, "bob")
	id, slug := mediaShareWithFile(t, h, "a.jpg", "photo")
	want := aJPEG(t, 8, 8)
	if rec := doReq(t, h, "PUT", "/api/shares/"+id+"/thumbs/"+slug, testToken, string(want)); rec.Code/100 != 2 {
		t.Fatalf("storing the tile = %d %s", rec.Code, rec.Body)
	}
	// The positive first: the tile is there and the owner reads it, so the
	// refusals below are the route refusing, not a tile or route missing.
	if rec := doReq(t, h, "GET", "/api/shares/"+id+"/thumbs/"+slug, testToken, ""); rec.Code != 200 || !bytes.Equal(rec.Body.Bytes(), want) {
		t.Fatalf("owner read = %d", rec.Code)
	}
	if rec := doReq(t, h, "GET", "/api/shares/"+id+"/thumbs/"+slug, bob, ""); rec.Code != 404 || errCode(t, rec.Body.String()) != "not-found" {
		t.Fatalf("another account = %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "GET", "/api/shares/"+id+"/thumbs/"+slug, "", ""); rec.Code != 401 {
		t.Fatalf("anonymous = %d", rec.Code)
	}
}

func TestAMissingTileIsNotFound(t *testing.T) {
	h := newTestAPI(t)
	id, slug := mediaShareWithFile(t, h, "a.jpg", "photo")
	if rec := doReq(t, h, "GET", "/api/shares/"+id+"/thumbs/"+slug, testToken, ""); rec.Code != 404 || errCode(t, rec.Body.String()) != "not-found" {
		t.Fatalf("no tile = %d %s", rec.Code, rec.Body)
	}
}

// paddedJPEG is a decodable JPEG followed by filler up to n bytes; the decoder
// reads only the image's header.
func paddedJPEG(t *testing.T, n int) []byte {
	t.Helper()
	pic := aJPEG(t, 8, 8)
	return append(pic, make([]byte, n-len(pic))...)
}

func TestAThumbnailLargerThanItsSmallFileIsRefused(t *testing.T) {
	h := newTestAPI(t)
	id, slug := mediaShareWithFile(t, h, "a.jpg", "x")
	rec := doReq(t, h, "PUT", "/api/shares/"+id+"/thumbs/"+slug, testToken, string(paddedJPEG(t, 100<<10)))
	if rec.Code != 413 || errCode(t, rec.Body.String()) != "thumb-too-large" {
		t.Fatalf("100 KiB tile for a 1-byte file = %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "PUT", "/api/shares/"+id+"/thumbs/"+slug, testToken, string(paddedJPEG(t, 60<<10))); rec.Code != 204 {
		t.Fatalf("60 KiB tile = %d %s", rec.Code, rec.Body)
	}
}

func TestAThumbnailUpToItsFilesSizeIsAccepted(t *testing.T) {
	h := newTestAPI(t)
	id, slug := mediaShareWithFile(t, h, "a.jpg", strings.Repeat("x", 300<<10))
	rec := doReq(t, h, "PUT", "/api/shares/"+id+"/thumbs/"+slug, testToken, string(paddedJPEG(t, 300<<10)))
	if rec.Code != 204 {
		t.Fatalf("300 KiB tile for a 300 KiB file = %d %s", rec.Code, rec.Body)
	}
}

func TestAThumbnailBatchSkipsAnOversizedTile(t *testing.T) {
	h := newTestAPI(t)
	id, _ := mediaShareWithFile(t, h, "a.jpg", "x")
	small := uploadGetSlug(t, h, id, "b.jpg", "y")
	big := uploadGetSlug(t, h, id, "c.jpg", "z")
	body := thumbTar(t, [][2]any{
		{small + ".jpg", paddedJPEG(t, 10<<10)},
		{big + ".jpg", paddedJPEG(t, 100<<10)},
	})
	rec := doReq(t, h, "POST", "/api/shares/"+id+"/thumbs", testToken, body)
	var res struct {
		Stored  int      `json:"stored"`
		Skipped []string `json:"skipped"`
	}
	unmarshal(t, rec, &res)
	if rec.Code != 200 || res.Stored != 1 || len(res.Skipped) != 1 || res.Skipped[0] != big+".jpg" {
		t.Fatalf("batch = %d %+v", rec.Code, res)
	}
	if got := doReq(t, h, "GET", "/thumb/"+id+"/"+big, "", ""); got.Code != 404 {
		t.Fatalf("the oversized tile was stored: %d", got.Code)
	}
}

func TestAThumbnailIsRefusedOnAFullDisk(t *testing.T) {
	b := testBackend(t)
	h := New(b, "test", testDomain(t), nil)
	id, slug := mediaShareWithFile(t, h, "a.jpg", "x")
	diskOf(b, gib/2) // below the flat 1 GiB reserve
	rec := doReq(t, h, "PUT", "/api/shares/"+id+"/thumbs/"+slug, testToken, string(aJPEG(t, 8, 8)))
	if rec.Code != 507 {
		t.Fatalf("tile on a full disk = %d %s", rec.Code, rec.Body)
	}
	if got := doReq(t, h, "GET", "/thumb/"+id+"/"+slug, "", ""); got.Code != 404 {
		t.Fatalf("a tile landed on a full disk: %d", got.Code)
	}
}
