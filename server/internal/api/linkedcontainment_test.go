package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hyperdrop/server/internal/linked"
	"hyperdrop/server/internal/metadb"
)

func TestLinkedGrantAndSelectedSourceContainSymlinks(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	for rel, body := range map[string]string{"allowed/real.txt": "PUBLIC", "allowed/sub/own.txt": "OWN", "denied/secret.txt": "PRIVATE"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, rel)), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	roots, err := linked.NewRoots([]string{dir}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	b := testBackendWithRoots(t, roots)
	h := New(b, "test", testDomain(t), nil)
	bob := seedUser(t, b.DB, "bob")
	grants := []string{"data/allowed"}
	if _, err := b.DB.UpdateUser("bob", metadb.Settings{SourceRoots: &grants}); err != nil {
		t.Fatal(err)
	}
	// Mint a slug before replacing its formerly ordinary entry with an escaping link.
	if err := os.WriteFile(filepath.Join(dir, "allowed", "escape.txt"), []byte("BEFORE"), 0600); err != nil {
		t.Fatal(err)
	}
	created := doReq(t, h, "POST", "/api/shares", bob, `{"source":"data/allowed"}`)
	var share struct {
		ID    string
		Files []struct {
			Path string
			Slug string
		}
	}
	unmarshal(t, created, &share)
	if created.Code != 201 {
		t.Fatalf("create %d %s", created.Code, created.Body)
	}
	var slug string
	for _, f := range share.Files {
		if f.Path == "escape.txt" {
			slug = f.Slug
		}
	}
	if slug == "" {
		t.Fatal("no escape fixture slug")
	}
	if err := os.Remove(filepath.Join(dir, "allowed", "escape.txt")); err != nil {
		t.Fatal(err)
	}
	for rel, target := range map[string]string{"allowed/escape.txt": "../denied/secret.txt", "allowed/link": "../denied", "allowed/alias.txt": "real.txt", "allowed/sub/alias.txt": "../real.txt", "grantlink": "denied"} {
		if err := os.Symlink(target, filepath.Join(dir, rel)); err != nil {
			t.Fatal(err)
		}
	}
	if rec := doReq(t, h, "GET", "/api/sources/file?path=data/denied/secret.txt", bob, ""); rec.Code != 403 {
		t.Errorf("direct denied preview: %d %s", rec.Code, rec.Body)
	}
	for _, rel := range []string{"data/allowed/escape.txt", "data/allowed/link/secret.txt"} {
		rec := doReq(t, h, "GET", "/api/sources/file?path="+rel, bob, "")
		if rec.Code != 404 {
			t.Errorf("escaped preview %s: %d %s", rel, rec.Code, rec.Body)
		}
	}
	for _, rel := range []string{"data/allowed/alias.txt", "data/allowed/sub/alias.txt"} {
		rec := doReq(t, h, "GET", "/api/sources/file?path="+rel, bob, "")
		if rec.Code != 200 || rec.Body.String() != "PUBLIC" {
			t.Errorf("in-grant preview %s: %d %s", rel, rec.Code, rec.Body)
		}
	}
	rec := doReq(t, h, "GET", "/download/"+share.ID+"/"+slug, "", "")
	if rec.Code != 404 {
		t.Errorf("anonymous escaped download: %d %s", rec.Code, rec.Body)
	}
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+share.ID, bob, ""), &share)
	aliases := 0
	for _, file := range share.Files {
		if file.Path == "alias.txt" || file.Path == "sub/alias.txt" {
			aliases++
			rec := doReq(t, h, "GET", "/download/"+share.ID+"/"+file.Slug, "", "")
			if rec.Code != 200 || rec.Body.String() != "PUBLIC" {
				t.Errorf("public in-source link %s: %d %s", file.Path, rec.Code, rec.Body)
			}
		}
	}
	if aliases != 2 {
		t.Errorf("listed %d in-source aliases, want 2", aliases)
	}
	rec = doReq(t, h, "GET", "/api/sources/browse?path=data/allowed", bob, "")
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "alias.txt") || strings.Contains(rec.Body.String(), "escape.txt") {
		t.Errorf("picker offered symlink file: %d %s", rec.Code, rec.Body)
	}
	for _, source := range []string{"data/allowed/link", "data/allowed/alias.txt"} {
		rec := doReq(t, h, "POST", "/api/shares", bob, `{"source":"`+source+`"}`)
		if rec.Code != 404 {
			t.Errorf("symlink source %s: %d %s", source, rec.Code, rec.Body)
		}
	}
	grants = []string{"data/allowed/sub", "data/allowed"}
	if _, err := b.DB.UpdateUser("bob", metadb.Settings{SourceRoots: &grants}); err != nil {
		t.Fatal(err)
	}
	rec = doReq(t, h, "GET", "/api/sources/file?path=data/allowed/sub/alias.txt", bob, "")
	if rec.Code != 200 || rec.Body.String() != "PUBLIC" {
		t.Errorf("overlapping grant narrowed preview: %d %s", rec.Code, rec.Body)
	}
	grants = []string{"data/grantlink"}
	if _, err := b.DB.UpdateUser("bob", metadb.Settings{SourceRoots: &grants}); err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{"/api/sources/browse?path=data/grantlink", "/api/sources/file?path=data/grantlink/secret.txt"} {
		rec := doReq(t, h, "GET", route, bob, "")
		if rec.Code != 404 {
			t.Errorf("symlink grant %s: %d %s", route, rec.Code, rec.Body)
		}
	}
}

func TestExactFileGrantCannotBecomeASiblingAlias(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"allowed.txt": "PUBLIC", "secret.txt": "PRIVATE"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	roots, err := linked.NewRoots([]string{dir}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	b := testBackendWithRoots(t, roots)
	h := New(b, "test", testDomain(t), nil)
	bob := seedUser(t, b.DB, "bob")
	grants := []string{"data/allowed.txt"}
	if _, err := b.DB.UpdateUser("bob", metadb.Settings{SourceRoots: &grants}); err != nil {
		t.Fatal(err)
	}
	rec := doReq(t, h, "GET", "/api/sources/file?path=data/allowed.txt", bob, "")
	if rec.Code != 200 || rec.Body.String() != "PUBLIC" {
		t.Fatalf("regular file grant: %d %s", rec.Code, rec.Body)
	}
	rec = doReq(t, h, "POST", "/api/shares", bob, `{"source":"data/allowed.txt"}`)
	var share struct {
		ID    string
		Files []struct{ Slug string }
	}
	unmarshal(t, rec, &share)
	if rec.Code != 201 || len(share.Files) != 1 {
		t.Fatalf("file source: %d %s", rec.Code, rec.Body)
	}
	if err := os.Remove(filepath.Join(dir, "allowed.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("secret.txt", filepath.Join(dir, "allowed.txt")); err != nil {
		t.Fatal(err)
	}
	rec = doReq(t, h, "GET", "/api/sources/file?path=data/allowed.txt", bob, "")
	if rec.Code != 404 {
		t.Errorf("file grant alias preview: %d %s", rec.Code, rec.Body)
	}
	rec = doReq(t, h, "GET", "/download/"+share.ID+"/"+share.Files[0].Slug, "", "")
	if strings.Contains(rec.Body.String(), "PRIVATE") {
		t.Errorf("file source alias served secret: %d %s", rec.Code, rec.Body)
	}
	rec = doReq(t, h, "GET", "/api/shares/"+share.ID, bob, "")
	if !strings.Contains(rec.Body.String(), `"sourceMissing":true`) {
		t.Errorf("replacement source not unavailable: %d %s", rec.Code, rec.Body)
	}
}
