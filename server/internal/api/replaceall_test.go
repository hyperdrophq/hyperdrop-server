package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestReplaceAllCollapsesShareToNewFile(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "batch")
	uploadGetSlug(t, h, id, "a.txt", "aaa")
	uploadGetSlug(t, h, id, "b.txt", "bbb")

	rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/fresh.png?replaceAll=1", testToken, "img-bytes")
	if rec.Code != 201 {
		t.Fatalf("replaceAll upload = %d %s", rec.Code, rec.Body)
	}

	get := doReq(t, h, "GET", "/api/shares/"+id, testToken, "")
	var sh struct {
		Files []struct {
			Path string `json:"path"`
			Slug string `json:"slug"`
		} `json:"files"`
	}
	unmarshal(t, get, &sh)
	if len(sh.Files) != 1 || sh.Files[0].Path != "fresh.png" {
		t.Fatalf("files = %+v, want just fresh.png", sh.Files)
	}
	// The collapsed share serves the new bytes publicly.
	dl := doReq(t, h, "GET", "/download/"+id+"/"+sh.Files[0].Slug, "", "")
	if dl.Code != 200 || dl.Body.String() != "img-bytes" {
		t.Fatalf("download = %d %q", dl.Code, dl.Body)
	}
}

func TestReplaceAllSingleFileKeepsLink(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "one")
	oldSlug := uploadGetSlug(t, h, id, "old.txt", "old bytes")

	rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/new.txt?replaceAll=1", testToken, "new bytes")
	if rec.Code != 201 {
		t.Fatalf("replaceAll upload = %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Slug string `json:"slug"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Slug != oldSlug {
		t.Fatalf("slug = %s, want inherited %s", out.Slug, oldSlug)
	}
	// The link that was already sent serves the NEW content.
	dl := doReq(t, h, "GET", "/download/"+id+"/"+oldSlug, "", "")
	if dl.Code != 200 || dl.Body.String() != "new bytes" {
		t.Fatalf("old link after replace = %d %q", dl.Code, dl.Body)
	}
	if cd := dl.Header().Get("Content-Disposition"); !strings.Contains(cd, "new.txt") {
		t.Fatalf("Content-Disposition = %q, want the new name", cd)
	}
}

func TestReplaceAllResumableUpload(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "one")
	oldSlug := uploadGetSlug(t, h, id, "old.txt", "old")

	// Two ranged chunks; replaceAll must apply on the committing PUT.
	put := "/api/shares/" + id + "/files/big.bin?replaceAll=1"
	c1 := doReqResume(t, h, put, "AAAA", "0", "8")
	if c1.Code != 202 {
		t.Fatalf("chunk1 = %d %s", c1.Code, c1.Body)
	}
	c2 := doReqResume(t, h, put, "BBBB", "4", "8")
	if c2.Code != 201 {
		t.Fatalf("chunk2 = %d %s", c2.Code, c2.Body)
	}
	var out struct {
		Slug string `json:"slug"`
	}
	json.Unmarshal(c2.Body.Bytes(), &out)
	if out.Slug != oldSlug {
		t.Fatalf("slug = %s, want inherited %s", out.Slug, oldSlug)
	}
	dl := doReq(t, h, "GET", "/download/"+id+"/"+oldSlug, "", "")
	if dl.Body.String() != "AAAABBBB" {
		t.Fatalf("content = %q", dl.Body)
	}
}

func TestReplaceAllRejectsCombinedWithReplaces(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "x")
	uploadGetSlug(t, h, id, "a.txt", "a")

	rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/b.txt?replaceAll=1&replaces=a.txt", testToken, "b")
	if rec.Code != 400 {
		t.Fatalf("replaceAll+replaces = %d, want 400", rec.Code)
	}
}
