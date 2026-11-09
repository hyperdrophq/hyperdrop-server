package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"hyperdrop/server/internal/metadb"
)

// newTestAPIWithUsers is newTestAPI, but hands back the database so a
// test can mint a second (non-admin) user's token.
func newTestAPIWithUsers(t *testing.T) (http.Handler, *metadb.DB) {
	t.Helper()
	b := testBackend(t)
	return New(b, "2.0.0", testDomain(t), nil), b.DB
}

func protectedShareWithFile(t *testing.T, h http.Handler) (id, slug string) {
	t.Helper()
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"p","password":"hunter2"}`)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	var cr struct{ ID string }
	json.Unmarshal(rec.Body.Bytes(), &cr)
	return cr.ID, uploadGetSlug(t, h, cr.ID, "a.txt", "data")
}

// A protected share's /download serves the bytes to its owner's bearer token: the
// authenticated client (the Finder mount, `hyperdrop fetch`) reading its own
// content without a cookie or a stored plaintext password.
func TestDownloadHonorsOwnerBearer(t *testing.T) {
	h := newTestAPI(t)
	id, slug := protectedShareWithFile(t, h)

	got := doReq(t, h, "GET", "/download/"+id+"/"+slug, testToken, "")
	if got.Code != 200 || got.Body.String() != "data" {
		t.Fatalf("owner bearer: code=%d body=%q", got.Code, got.Body)
	}
	if !strings.Contains(got.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("no attachment disposition: %q", got.Header().Get("Content-Disposition"))
	}
}

// /view never honors Bearer: the inline route stays exactly as public as it was.
func TestViewIgnoresBearer(t *testing.T) {
	h := newTestAPI(t)
	id, slug := protectedShareWithFile(t, h)

	got := doReq(t, h, "GET", "/view/"+id+"/"+slug, testToken, "")
	if got.Code == 200 && got.Body.String() == "data" {
		t.Fatal("/view served protected bytes to a bearer token")
	}
}

// A stranger's valid token unlocks nothing.
func TestDownloadRejectsForeignBearer(t *testing.T) {
	h, um := newTestAPIWithUsers(t)
	guestToken := seedUser(t, um, "guest")
	id, slug := protectedShareWithFile(t, h)

	got := doReq(t, h, "GET", "/download/"+id+"/"+slug, guestToken, "")
	if got.Code == 200 && got.Body.String() == "data" {
		t.Fatal("served protected bytes to a non-owner token")
	}
}

// An invalid token degrades to the anonymous path (password form), never a 500.
func TestDownloadGarbageBearerFallsBack(t *testing.T) {
	h := newTestAPI(t)
	id, slug := protectedShareWithFile(t, h)

	got := doReq(t, h, "GET", "/download/"+id+"/"+slug, "hd_u_garbage", "")
	if got.Code == 200 && got.Body.String() == "data" {
		t.Fatal("served protected bytes to a garbage token")
	}
	if got.Code >= 500 {
		t.Fatalf("garbage token = %d, want the anonymous path", got.Code)
	}
}
