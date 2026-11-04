package api

import (
	"net/http"
	"strings"
	"testing"
)

func TestDeleteFileRemovesEntryAndKillsItsLink(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "docs")
	slugA := uploadGetSlug(t, h, id, "a.txt", "aaa")
	slugB := uploadGetSlug(t, h, id, "b.txt", "bbb")

	rec := doReq(t, h, "DELETE", "/api/shares/"+id+"/files/a.txt", testToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("delete file = %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "a.txt") {
		t.Errorf("updated share still lists the removed file: %s", rec.Body)
	}
	// The removed file's slug is dead; the survivor keeps serving.
	if rec := doReq(t, h, "GET", "/download/"+id+"/"+slugA, "", ""); rec.Code != http.StatusNotFound {
		t.Errorf("removed file's link = %d, want 404", rec.Code)
	}
	if rec := doReq(t, h, "GET", "/download/"+id+"/"+slugB, "", ""); rec.Code != http.StatusOK {
		t.Errorf("surviving file's link = %d, want 200", rec.Code)
	}
}

// The same content in another share must survive one share's file delete: each
// share holds its own copy, and a delete reaches only the share it names.
func TestDeleteFileKeepsContentSharedWithAnotherShare(t *testing.T) {
	h := newTestAPI(t)
	one := createShare(t, h, "one")
	two := createShare(t, h, "two")
	uploadGetSlug(t, h, one, "same.txt", "shared bytes")
	slugTwo := uploadGetSlug(t, h, two, "same.txt", "shared bytes")

	if rec := doReq(t, h, "DELETE", "/api/shares/"+one+"/files/same.txt", testToken, ""); rec.Code != http.StatusOK {
		t.Fatalf("delete = %d", rec.Code)
	}
	rec := doReq(t, h, "GET", "/download/"+two+"/"+slugTwo, "", "")
	if rec.Code != http.StatusOK || rec.Body.String() != "shared bytes" {
		t.Fatalf("other share's copy = %d %q", rec.Code, rec.Body.String())
	}
}

// Removing the entry the share's link opened drops the link back to the
// file listing rather than pointing at a page that does not exist.
func TestDeleteFileClearsADanglingEntry(t *testing.T) {
	h, b := newTestAPIBackend(t)
	id := createShare(t, h, "site")
	uploadGetSlug(t, h, id, "index.html", "<html></html>")
	uploadGetSlug(t, h, id, "other.txt", "x")
	rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"entry":"index.html"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("set entry = %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "DELETE", "/api/shares/"+id+"/files/index.html", testToken, ""); rec.Code != http.StatusOK {
		t.Fatalf("delete = %d", rec.Code)
	}
	d, err := b.DB.Share(id)
	if err != nil {
		t.Fatal(err)
	}
	if d.Entry != "" {
		t.Errorf("entry = %q after its file was removed, want empty", d.Entry)
	}
}

func TestDeleteFileRefusals(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	alice := seedUser(t, um, "alice")
	bob := seedUser(t, um, "bob")
	id := createShareAs(t, h, alice, `{"name":"docs"}`)
	if rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/a.txt", alice, "aaa"); rec.Code != 201 {
		t.Fatalf("upload = %d", rec.Code)
	}
	// Another account: plain 404, indistinguishable from no share.
	if rec := doReq(t, h, "DELETE", "/api/shares/"+id+"/files/a.txt", bob, ""); rec.Code != http.StatusNotFound {
		t.Errorf("other account = %d", rec.Code)
	}
	if rec := doReq(t, h, "DELETE", "/api/shares/"+id+"/files/a.txt", "", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous = %d", rec.Code)
	}
	// An unknown path refuses without touching the share.
	if rec := doReq(t, h, "DELETE", "/api/shares/"+id+"/files/nope.txt", alice, ""); rec.Code != http.StatusNotFound {
		t.Errorf("unknown path = %d", rec.Code)
	}
	// ServeMux hands a wildcard its percent-DECODED value, so a route that
	// believes it holds a clean relpath can be reached with a dot segment
	// in it; the refusal comes before the rows are touched.
	if rec := doReq(t, h, "DELETE", "/api/shares/"+id+"/files/%2e%2e/a.txt", alice, ""); rec.Code != http.StatusBadRequest {
		t.Errorf("unclean path = %d, want 400", rec.Code)
	}
	rec := doReq(t, h, "GET", "/api/shares/"+id, alice, "")
	if !strings.Contains(rec.Body.String(), "a.txt") {
		t.Errorf("share lost its file to a refused delete: %s", rec.Body)
	}
}
