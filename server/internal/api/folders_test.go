package api

import (
	"net/http"
	"strings"
	"testing"
)

func mkdirReq(t *testing.T, h http.Handler, id, token, rel string) (int, string) {
	t.Helper()
	rec := doReq(t, h, "POST", "/api/shares/"+id+"/folders", token, `{"path":"`+rel+`"}`)
	return rec.Code, rec.Body.String()
}

func rmdirReq(t *testing.T, h http.Handler, id, token, rel string) (int, string) {
	t.Helper()
	rec := doReq(t, h, "DELETE", "/api/shares/"+id+"/folders/"+rel, token, "")
	return rec.Code, rec.Body.String()
}

// A created folder appears in the share view, in every read of the share,
// and a delete takes it out again.
func TestCreateAndDeleteFolder(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "docs")
	uploadGetSlug(t, h, id, "a.txt", "aaa")
	code, body := mkdirReq(t, h, id, testToken, "drafts")
	if code != http.StatusOK || !strings.Contains(body, `"folders":["drafts"]`) {
		t.Fatalf("create = %d %s", code, body)
	}
	rec := doReq(t, h, "GET", "/api/shares/"+id, testToken, "")
	if !strings.Contains(rec.Body.String(), `"folders":["drafts"]`) {
		t.Errorf("share read lacks the folder: %s", rec.Body.String())
	}
	rec = doReq(t, h, "GET", "/api/shares", testToken, "")
	if !strings.Contains(rec.Body.String(), `"folders":["drafts"]`) {
		t.Errorf("listing row lacks the folder: %s", rec.Body.String())
	}
	code, body = rmdirReq(t, h, id, testToken, "drafts")
	if code != http.StatusOK || strings.Contains(body, `"folders"`) {
		t.Fatalf("delete = %d %s", code, body)
	}
}

func TestFolderRouteRefusals(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	alice := seedUser(t, um, "alice")
	bob := seedUser(t, um, "bob")
	id := createShareAs(t, h, alice, `{"name":"docs","files":[]}`)
	for _, rel := range []string{"a.txt", "docs/b.txt"} {
		if rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/"+rel, alice, "x"); rec.Code != 201 {
			t.Fatalf("upload %s = %d", rel, rec.Code)
		}
	}
	if code, body := mkdirReq(t, h, id, alice, "drafts"); code != 200 {
		t.Fatalf("create = %d %s", code, body)
	}
	for _, tc := range []struct {
		name, token, rel string
		code             int
		want             string
	}{
		{"someone else's share", bob, "x", 404, "not-found"},
		{"a file's path", alice, "a.txt", 400, "path-taken"},
		{"beneath a file", alice, "a.txt/x", 400, "path-taken"},
		{"a folder files imply", alice, "docs", 400, "path-taken"},
		{"an existing record", alice, "drafts", 400, "path-taken"},
		{"unclean", alice, "../x", 400, "clean relative"},
		{"empty", alice, "", 400, "clean relative"},
	} {
		code, body := mkdirReq(t, h, id, tc.token, tc.rel)
		if code != tc.code || !strings.Contains(body, tc.want) {
			t.Errorf("create %s: %d %s, want %d %s", tc.name, code, body, tc.code, tc.want)
		}
	}
	for _, tc := range []struct {
		name, token, rel string
		code             int
		want             string
	}{
		{"someone else's share", bob, "drafts", 404, "not-found"},
		{"a folder holding a file", alice, "docs", 409, "not-empty"},
		{"no record", alice, "never", 404, "not-found"},
	} {
		code, body := rmdirReq(t, h, id, tc.token, tc.rel)
		if code != tc.code || !strings.Contains(body, tc.want) {
			t.Errorf("delete %s: %d %s, want %d %s", tc.name, code, body, tc.code, tc.want)
		}
	}
	if rec := doReq(t, h, "POST", "/api/shares/"+id+"/folders", alice, "{"); rec.Code != 400 {
		t.Errorf("bad json = %d", rec.Code)
	}
}

// An inbox holds no folders.
func TestInboxRefusesFolders(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"inbox","receive":true}`)
	if rec.Code != 201 {
		t.Fatalf("create inbox = %d %s", rec.Code, rec.Body)
	}
	var out struct {
		ID string `json:"id"`
	}
	unmarshal(t, rec, &out)
	if code, body := mkdirReq(t, h, out.ID, testToken, "x"); code != 409 || !strings.Contains(body, "receive") {
		t.Errorf("create on an inbox = %d %s", code, body)
	}
}

// The wire rule: a decomposed spelling creates the NFC folder.
func TestCreateFolderNormalizesThePath(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "docs")
	uploadGetSlug(t, h, id, "a.txt", "a")
	code, body := mkdirReq(t, h, id, testToken, "café")
	if code != 200 || !strings.Contains(body, `"folders":["café"]`) {
		t.Fatalf("create = %d %s", code, body)
	}
	if code, _ := rmdirReq(t, h, id, testToken, "cafe%CC%81"); code != 200 {
		t.Errorf("delete by the decomposed spelling = %d", code)
	}
}

// A name the share's source already lists is the source's.
func TestCreateFolderRespectsTheSource(t *testing.T) {
	h, _, _ := linkedTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"sources":["photo/2024"],"files":[],"name":"mix"}`)
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		ID string `json:"id"`
	}
	unmarshal(t, rec, &out)
	if code, body := mkdirReq(t, h, out.ID, testToken, "a.jpg"); code != 400 || !strings.Contains(body, "path-taken") {
		t.Errorf("a name the source lists = %d %s", code, body)
	}
	if code, body := mkdirReq(t, h, out.ID, testToken, "drafts"); code != 200 {
		t.Errorf("a free name beside a source = %d %s", code, body)
	}
}
