package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hyperdrop/server/internal/logfile"
)

func TestAdminLogAnswersTheTailToAnAdminOnly(t *testing.T) {
	dir := t.TempDir()
	b := testBackendAt(t, dir)
	h := newHandler(b, "2.0.0", testDomain(t), nil, Deployment{DataDir: dir}).routes()
	os.MkdirAll(filepath.Join(dir, "logs"), 0o755)
	os.WriteFile(filepath.Join(dir, "logs", logfile.Name), []byte("one\ntwo\nthree\n"), 0o644)

	rec := doReq(t, h, "GET", "/api/admin/log?tail=2", testToken, "")
	if rec.Code != 200 || rec.Body.String() != "two\nthree\n" {
		t.Fatalf("%d %q", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content type %q", ct)
	}

	rec = doReq(t, h, "GET", "/api/admin/log?tail=1&skip=1", testToken, "")
	if rec.Code != 200 || rec.Body.String() != "two\n" {
		t.Fatalf("skip: %d %q", rec.Code, rec.Body.String())
	}
	user := seedUser(t, b.DB, "bob")
	if rec := doReq(t, h, "GET", "/api/admin/log", user, ""); rec.Code != 403 {
		t.Fatalf("a user got %d", rec.Code)
	}
	if rec := doReq(t, h, "GET", "/api/admin/log?tail=x", testToken, ""); rec.Code != 400 {
		t.Fatalf("a bad tail got %d", rec.Code)
	}
}

func TestAdminLogWithNoLogDirectoryIsEmpty(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "GET", "/api/admin/log", testToken, "")
	if rec.Code != 200 || rec.Body.Len() != 0 {
		t.Fatalf("%d %q", rec.Code, rec.Body.String())
	}
}
