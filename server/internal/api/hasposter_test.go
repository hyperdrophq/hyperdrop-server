package api

import (
	"net/http"
	"strings"
	"testing"
)

// The app's list needs to know which shares have a thumbnail without probing
// one URL per row, so every listed entry reports hasPoster.
func TestListReportsHasPoster(t *testing.T) {
	h := newTestAPI(t)
	withPoster := createShare(t, h, "shot")
	without := createShare(t, h, "plain")
	if code := putPoster(t, h, withPoster, posterJPEG(t, "jpeg")); code != http.StatusNoContent {
		t.Fatalf("PUT poster = %d", code)
	}
	var listing struct {
		Shares []struct {
			ID        string `json:"id"`
			HasPoster bool   `json:"hasPoster"`
		} `json:"shares"`
	}
	rec := doReq(t, h, "GET", "/api/shares", testToken, "")
	unmarshal(t, rec, &listing)
	got := map[string]bool{}
	for _, s := range listing.Shares {
		got[s.ID] = s.HasPoster
	}
	if !got[withPoster] || got[without] {
		t.Fatalf("hasPoster flags = %v", got)
	}

	var one struct {
		HasPoster bool `json:"hasPoster"`
	}
	rec = doReq(t, h, "GET", "/api/shares/"+withPoster, testToken, "")
	unmarshal(t, rec, &one)
	if !one.HasPoster {
		t.Error("GET /api/shares/{id} did not report hasPoster")
	}
}

// The owner's own app fetches thumbnails over this authenticated route. A
// password on the share does not withhold the image here: the caller has
// proven ownership, unlike the anonymous unfurler bots the public card route
// refuses.
func TestOwnerPosterRouteServesProtectedShares(t *testing.T) {
	h := newTestAPI(t)
	id := createShareWithPassword(t, h, "secret", "hunter2")
	if code := putPoster(t, h, id, posterJPEG(t, "frame")); code != http.StatusNoContent {
		t.Fatalf("PUT poster = %d", code)
	}
	rec := doReq(t, h, "GET", "/api/shares/"+id+"/poster", testToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("owner GET = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "image/jpeg" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "private, max-age=3600" {
		t.Errorf("Cache-Control = %q", cc)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("poster served without nosniff")
	}
	if !strings.Contains(rec.Body.String(), "frame") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestOwnerPosterRouteRefusals(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	alice := seedUser(t, um, "alice")
	bob := seedUser(t, um, "bob")
	id := createShareAs(t, h, alice, `{"name":"shot"}`)
	if rec := doReq(t, h, "PUT", "/api/shares/"+id+"/poster", alice, posterJPEG(t, "x")); rec.Code != http.StatusNoContent {
		t.Fatalf("PUT poster = %d", rec.Code)
	}
	// Another account gets a plain 404, indistinguishable from no share.
	if rec := doReq(t, h, "GET", "/api/shares/"+id+"/poster", bob, ""); rec.Code != http.StatusNotFound {
		t.Errorf("other account's GET = %d", rec.Code)
	}
	if rec := doReq(t, h, "GET", "/api/shares/"+id+"/poster", "", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous GET = %d", rec.Code)
	}
	// The owner of a share with no sidecar: 404 too.
	bare := createShareAs(t, h, alice, `{"name":"bare"}`)
	if rec := doReq(t, h, "GET", "/api/shares/"+bare+"/poster", alice, ""); rec.Code != http.StatusNotFound {
		t.Errorf("no-sidecar GET = %d", rec.Code)
	}
}
