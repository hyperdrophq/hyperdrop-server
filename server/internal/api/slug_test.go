package api

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func uploadGetSlug(t *testing.T, h http.Handler, id, path, content string) string {
	t.Helper()
	rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/"+path, testToken, content)
	if rec.Code != 201 {
		t.Fatalf("upload %s: %d %s", path, rec.Code, rec.Body)
	}
	var out struct {
		Slug string `json:"slug"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	return out.Slug
}

func TestUploadReturnsUUIDSlug(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "s")
	slug := uploadGetSlug(t, h, id, "secret-report.pdf", "pdfbytes")
	if !uuidRe.MatchString(slug) {
		t.Fatalf("slug = %q, want uuidv4", slug)
	}
}

func TestSlugStableAcrossOverwrite(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "s")
	first := uploadGetSlug(t, h, id, "a.txt", "one")
	second := uploadGetSlug(t, h, id, "a.txt", "twotwo")
	if first != second {
		t.Fatalf("slug changed on overwrite: %q → %q", first, second)
	}
	other := uploadGetSlug(t, h, id, "b.txt", "x")
	if other == first {
		t.Fatalf("distinct files share a slug")
	}
}

func TestServeBySlugRestoresOriginalName(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "s")
	slug := uploadGetSlug(t, h, id, "dir/secret%20report.pdf", "%PDF fake")

	rec := doReq(t, h, "GET", "/view/"+id+"/"+slug, "", "")
	if rec.Code != 200 || rec.Body.String() != "%PDF fake" {
		t.Fatalf("view by slug = %d %q", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/pdf" {
		t.Errorf("Content-Type = %q (must come from the ORIGINAL extension)", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "secret report.pdf") {
		t.Errorf("Content-Disposition = %q, want original filename", cd)
	}

	rec = doReq(t, h, "GET", "/download/"+id+"/"+slug, "", "")
	if cd := rec.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment") ||
		!strings.Contains(cd, "secret report.pdf") {
		t.Errorf("download disposition = %q", cd)
	}
}

func TestListingAndRedirectUseSlugs(t *testing.T) {
	h := newTestAPI(t)
	// Single file: /share/{id} redirects to the slug URL, not the name.
	id := createShare(t, h, "one")
	slug := uploadGetSlug(t, h, id, "private-name.txt", "x")
	rec := doReq(t, h, "GET", "/share/"+id, "", "")
	if rec.Code != 302 {
		t.Fatalf("single-file /share = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/view/"+id+"/"+slug {
		t.Errorf("redirect = %q, want slug URL", loc)
	}

	// Folder: listing hrefs use slugs; display text keeps the original names.
	fid := createShare(t, h, "folder")
	s1 := uploadGetSlug(t, h, fid, "aaa.txt", "1")
	uploadGetSlug(t, h, fid, "bbb.txt", "2")
	rec = doReq(t, h, "GET", "/share/"+fid, "", "")
	body := rec.Body.String()
	if !strings.Contains(body, "/view/"+fid+"/"+s1) {
		t.Errorf("listing lacks slug href: %s", body)
	}
	if strings.Contains(body, "/view/"+fid+"/aaa.txt") {
		t.Errorf("listing leaks name-based href: %s", body)
	}
	if !strings.Contains(body, "aaa.txt") || !strings.Contains(body, "bbb.txt") {
		t.Errorf("listing must still display original names: %s", body)
	}
}

func TestFilenameURLsAreNotRoutable(t *testing.T) {
	// Backward compatibility deliberately broken (user call, 2026-07-13):
	// public URLs are slug-only; the original name never routes.
	h := newTestAPI(t)
	id := createShare(t, h, "legacy")
	uploadGetSlug(t, h, id, "old.txt", "legacy content")
	rec := doReq(t, h, "GET", "/view/"+id+"/old.txt", "", "")
	if rec.Code != 404 {
		t.Fatalf("filename link = %d, want 404", rec.Code)
	}
}
