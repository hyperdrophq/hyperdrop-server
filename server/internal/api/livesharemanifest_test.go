package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// liveShareManifestBody is a stream create request of n files with the paths a
// project folder really has: node_modules trees put most entries five
// folders deep under names this long, and the mime and mtime every stream
// entry carries come on top, so the body outgrows a stored share's early-links
// manifest cap long before its entry count does.
func liveShareManifestBody(t *testing.T, n int) string {
	t.Helper()
	type spec struct {
		Path  string `json:"path"`
		Size  int64  `json:"size"`
		Mime  string `json:"mime"`
		MTime string `json:"mtime"`
	}
	specs := make([]spec, n)
	for i := range specs {
		specs[i] = spec{
			Path: fmt.Sprintf("node_modules/@scope%03d/package-%04d/dist/esm/module-%06d.js", i%100, i%1000, i),
			Size: int64(i), Mime: "text/javascript", MTime: "2026-09-14T10:00:00.123456789+07:00",
		}
	}
	body, err := json.Marshal(map[string]any{"name": "nearby-app", "folder": true, "files": specs})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// A live share IS its manifest: every file the relay serves is described in
// the create request, with nothing sent later, so the bounds a stored share
// puts on its OPTIONAL early-links manifest would refuse any ordinary
// project folder. The folder that found this held 42,885 files.
func TestAStreamManifestOutgrowsTheStoredShareCaps(t *testing.T) {
	h := newTestAPI(t)
	n := 4 * maxManifestFiles
	body := liveShareManifestBody(t, n)
	if len(body) <= createBodyLimit {
		t.Fatalf("fixture is only %d bytes, inside the stored cap of %d", len(body), createBodyLimit)
	}
	rec := doReq(t, h, "POST", "/api/live-share", testToken, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create of %d files → %d, want 201: %.300s", n, rec.Code, rec.Body)
	}
	var sh liveShareOut
	unmarshal(t, rec, &sh)
	if len(sh.Files) != n {
		t.Fatalf("echoed %d entries, want %d", len(sh.Files), n)
	}
	page := doReq(t, h, "GET", "/share/"+sh.ID, "", "")
	if page.Code != http.StatusOK {
		t.Fatalf("listing → %d", page.Code)
	}
	html := page.Body.String()
	if strings.Count(html, `class="folder"`) != 1 || strings.Count(html, `class="row"`) != 0 {
		t.Fatal("the root should render only the node_modules folder")
	}
	if len(html) > 64<<10 || strings.Contains(html, "<script") {
		t.Fatalf("root listing should be bounded and script-free, got %d bytes", len(html))
	}
	leaf := "node_modules/@scope000/package-0000/dist/esm"
	page = doReq(t, h, "GET", folderHref(sh.ID, leaf, false), "", "")
	if page.Code != http.StatusOK {
		t.Fatalf("leaf listing: %d", page.Code)
	}
	if rows := strings.Count(page.Body.String(), `class="row"`); rows != (n+999)/1000 {
		t.Fatalf("leaf listing rendered %d rows, want %d", rows, (n+999)/1000)
	}

	// The relay can be handed a second tree of the same size.
	add := strings.Replace(liveShareManifestBody(t, 2*maxManifestFiles), `"files":`, `"addFiles":`, 1)
	add = strings.Replace(add, `,"folder":true`, "", 1) // a create-only key
	add = strings.Replace(add, "node_modules/", "vendor/", -1)
	rec = doReq(t, h, "PATCH", "/api/live-share/"+sh.ID, testToken, add)
	if rec.Code != http.StatusOK {
		t.Fatalf("addFiles of %d → %d, want 200: %.300s", 2*maxManifestFiles, rec.Code, rec.Body)
	}
}

// The stream ceiling is its own number, refused as a manifest problem with
// the number in the message, on create and on addFiles alike.
func TestALiveShareManifestPastItsOwnCapIsRefusedClearly(t *testing.T) {
	h := newTestAPI(t)
	body := liveShareManifestBody(t, liveShareManifestMaxFiles+1)
	rec := doReq(t, h, "POST", "/api/live-share", testToken, body)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413: %.300s", rec.Code, rec.Body)
	}
	var e struct{ Code, Error string }
	unmarshal(t, rec, &e)
	if e.Code != "manifest-too-big" || !strings.Contains(e.Error, fmt.Sprint(liveShareManifestMaxFiles)) {
		t.Fatalf("got %q / %q, want manifest-too-big naming %d", e.Code, e.Error, liveShareManifestMaxFiles)
	}

	sh := createLiveShare(t, h, testToken, liveShareCreateBodyOne)
	add := strings.Replace(body, `"files":`, `"addFiles":`, 1)
	add = strings.Replace(add, `,"folder":true`, "", 1) // a create-only key
	rec = doReq(t, h, "PATCH", "/api/live-share/"+sh.ID, testToken, add)
	unmarshal(t, rec, &e)
	if rec.Code != http.StatusRequestEntityTooLarge || e.Code != "manifest-too-big" {
		t.Fatalf("addFiles past the cap → %d %q, want 413 manifest-too-big", rec.Code, e.Code)
	}

	// A body past the byte bound is refused as a size, naming the bound,
	// rather than as a JSON syntax error.
	huge := `{"name":"x","files":[],"pad":"` + strings.Repeat("p", liveShareBodyLimit) + `"}`
	rec = doReq(t, h, "POST", "/api/live-share", testToken, huge)
	unmarshal(t, rec, &e)
	if rec.Code != http.StatusRequestEntityTooLarge || e.Code != "body-too-large" ||
		!strings.Contains(e.Error, fmt.Sprint(liveShareManifestMaxFiles)) {
		t.Fatalf("oversized body → %d %q %q, want 413 body-too-large naming the cap", rec.Code, e.Code, e.Error)
	}
}
