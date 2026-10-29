package api

import (
	"net/http"
	"strings"
	"testing"

	"hyperdrop/server/internal/liveshare"
	"hyperdrop/server/internal/shareid"
)

type liveShareKeyedOut struct {
	ID    string `json:"id"`
	Files []struct {
		Path    string `json:"path"`
		Slug    string `json:"slug"`
		FileKey string `json:"fileKey"`
	} `json:"files"`
}

const liveShareKeysBody = `{"name":"demo","files":[` +
	`{"path":"a.txt","size":5,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"},` +
	`{"path":"b.txt","size":6,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"}` +
	`]}`

func TestLiveShareAnswerCarriesFileKeys(t *testing.T) {
	h := newTestLiveShareHandler(t)
	mux := h.routes()

	rec := doReq(t, mux, "POST", "/api/live-share", testToken, liveShareKeysBody)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var created liveShareKeyedOut
	unmarshal(t, rec, &created)
	if len(created.Files) != 2 {
		t.Fatalf("files: %+v", created.Files)
	}
	for _, f := range created.Files {
		if !shareid.ValidFileKey(f.FileKey) {
			t.Fatalf("create: %s has fileKey %q", f.Path, f.FileKey)
		}
		reg, slug, ok := h.liveShareReg.ByFileKey(f.FileKey)
		if !ok || reg.ID != created.ID || slug != f.Slug {
			t.Fatalf("registry does not resolve %s: %v %q", f.Path, ok, slug)
		}
	}

	// Add files: the known file keeps its key, the new one has its own.
	rec = doReq(t, mux, "PATCH", "/api/live-share/"+created.ID, testToken,
		`{"addFiles":[{"path":"c.txt","size":1,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"}],"zipSize":99}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch: %d %s", rec.Code, rec.Body)
	}
	var patched liveShareKeyedOut
	unmarshal(t, rec, &patched)
	if len(patched.Files) != 3 || patched.Files[0].FileKey != created.Files[0].FileKey ||
		!shareid.ValidFileKey(patched.Files[2].FileKey) {
		t.Fatalf("patch answer: %+v", patched.Files)
	}

	// Resume answers the same keys.
	rec = doReq(t, mux, "POST", "/api/live-share", testToken,
		`{"resume":"`+created.ID+`","name":"demo","files":[`+
			`{"path":"a.txt","size":5,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"},`+
			`{"path":"b.txt","size":6,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"},`+
			`{"path":"c.txt","size":1,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"}],"zipSize":99}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("resume: %d %s", rec.Code, rec.Body)
	}
	var resumed liveShareKeyedOut
	unmarshal(t, rec, &resumed)
	for i := range patched.Files {
		if resumed.Files[i].FileKey != patched.Files[i].FileKey {
			t.Fatalf("resume changed key %d: %q -> %q", i, patched.Files[i].FileKey, resumed.Files[i].FileKey)
		}
	}

	// A public page never carries a key.
	page := doReq(t, mux, "GET", "/share/"+created.ID, "", "")
	for _, f := range patched.Files {
		if strings.Contains(page.Body.String(), f.FileKey) {
			t.Fatalf("the public share page carries the key of %s", f.Path)
		}
	}
	if strings.Contains(page.Body.String(), "fileKey") {
		t.Fatal("the public share page names a fileKey field")
	}

	// A manifest listed out of order: every key the answer pairs with a file
	// is the key the registry resolves to that file's own slug.
	rec = doReq(t, mux, "POST", "/api/live-share", testToken, `{"name":"mixed","files":[`+
		`{"path":"z.txt","size":1,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"},`+
		`{"path":"a/b.txt","size":2,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"},`+
		`{"path":"m.txt","size":3,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"}]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create mixed: %d %s", rec.Code, rec.Body)
	}
	var mixed liveShareKeyedOut
	unmarshal(t, rec, &mixed)
	if len(mixed.Files) != 3 {
		t.Fatalf("mixed files: %+v", mixed.Files)
	}
	for _, f := range mixed.Files {
		reg, slug, ok := h.liveShareReg.ByFileKey(f.FileKey)
		if !ok || reg.ID != mixed.ID || slug != f.Slug {
			t.Fatalf("%s carries a key the registry pairs with %q", f.Path, slug)
		}
	}

	// liveShareAnswer pairs by slug, not by position.
	so := liveShareAnswer(liveshare.Record{ID: mixed.ID, Name: "mixed", Files: []liveshare.File{
		{Path: "z.txt", Slug: "slug-z", Key: "key-z"},
		{Path: "a/b.txt", Slug: "slug-b", Key: "key-b"},
		{Path: "m.txt", Slug: "slug-m", Key: "key-m"},
	}})
	want := map[string]string{"slug-z": "key-z", "slug-b": "key-b", "slug-m": "key-m"}
	if len(so.Files) != 3 {
		t.Fatalf("answer files: %+v", so.Files)
	}
	for _, f := range so.Files {
		if f.FileKey != want[f.Slug] {
			t.Fatalf("%s (%s) carries %q, want %q", f.Path, f.Slug, f.FileKey, want[f.Slug])
		}
	}
}
