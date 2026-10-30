package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"hyperdrop/server/internal/housekeep"
	"hyperdrop/server/internal/metadb"
)

// A file link follows a publish: a replace keeps the file's slug, so the
// link serves the new bytes under their own entity tag; a delete ends the
// link at once, and the next housekeeping pass prunes its key.
func TestAFileLinkFollowsAPublish(t *testing.T) {
	h, b := publishAPI(t)
	id := createShare(t, h, "site")
	slug := uploadGetSlug(t, h, id, "a.txt", "old a")
	uploadGetSlug(t, h, id, "keep.txt", "kept")
	key := mintFileKey(t, h, testToken, id, slug)
	get := func(path string) *httptest.ResponseRecorder {
		return req(t, h, "GET", "files.share.example.com", path)
	}
	if rec := get("/f/" + key); rec.Code != 200 || rec.Body.String() != "old a" || rec.Header().Get("ETag") != `"`+sha("old a")+`"` {
		t.Fatalf("before the publish: %d %q ETag %s", rec.Code, rec.Body, rec.Header().Get("ETag"))
	}

	pid := openPublish(t, h, testToken, id)
	stageFile(t, h, id, pid, "a.txt", "the new a")
	if rec := commitPublish(t, h, id, pid, `{"files":["a.txt"]}`); rec.Code != 200 {
		t.Fatalf("replace: %d %s", rec.Code, rec.Body)
	}
	if got := readListed(t, h, id).slugs()["a.txt"]; got != slug {
		t.Fatalf("the replace moved a.txt's slug from %s to %s", slug, got)
	}
	for _, path := range []string{"/f/" + key, "/f/" + key + "/download"} {
		rec := get(path)
		if rec.Code != 200 || rec.Body.String() != "the new a" || rec.Header().Get("ETag") != `"`+sha("the new a")+`"` {
			t.Fatalf("%s after the replace: %d %q ETag %s", path, rec.Code, rec.Body, rec.Header().Get("ETag"))
		}
	}

	pid = openPublish(t, h, testToken, id)
	if rec := commitPublish(t, h, id, pid, `{"delete":["a.txt"]}`); rec.Code != 200 {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	for _, path := range []string{"/f/" + key, "/f/" + key + "/download"} {
		if rec := get(path); rec.Code != http.StatusNotFound {
			t.Fatalf("%s after the delete: %d %q", path, rec.Code, rec.Body)
		}
	}
	if _, _, err := b.DB.ResolveFileKey(key); err != nil {
		t.Fatalf("the key went before housekeeping: %v", err)
	}
	pass := housekeep.Pass{DB: b.DB, FS: b.FS}
	if res := pass.Run(); res.FileLinksErr != nil || res.FileLinks != 1 {
		t.Fatalf("housekeeping pruned %d file links (%v), want 1", res.FileLinks, res.FileLinksErr)
	}
	if _, _, err := b.DB.ResolveFileKey(key); !errors.Is(err, metadb.ErrNotFound) {
		t.Fatalf("the key outlived housekeeping: %v", err)
	}
	if rec := get("/f/" + key); rec.Code != http.StatusNotFound {
		t.Fatalf("a pruned key answered %d", rec.Code)
	}
}
