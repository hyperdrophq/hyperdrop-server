package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func putPoster(t *testing.T, h http.Handler, id, body string) int {
	t.Helper()
	return doReq(t, h, "PUT", "/api/shares/"+id+"/poster", testToken, body).Code
}

// posterJPEG is a decodable JPEG carrying marker in a comment segment, so a
// test can tell which poster a response holds.
func posterJPEG(t *testing.T, marker string) string {
	t.Helper()
	pic := aJPEG(t, 8, 6)
	com := append([]byte{0xFF, 0xFE, 0, byte(2 + len(marker))}, marker...)
	return string(pic[:2]) + string(com) + string(pic[2:])
}

// The poster is served to strangers as image/jpeg on every host, the app
// origin included, so only bytes that decode as a JPEG are stored.
func TestAPosterMustBeAJPEG(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "clip")
	for _, body := range []string{"\xff\xd8 not really", "<svg onload=alert(1)>", "GIF89a"} {
		rec := doReq(t, h, "PUT", "/api/shares/"+id+"/poster", testToken, body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("PUT %q = %d, want 400", body, rec.Code)
		}
	}
	if rec := doReq(t, h, "GET", "/api/shares/"+id+"/poster", testToken, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("a refused poster was stored: GET = %d", rec.Code)
	}
	if rec := doReq(t, h, "PUT", "/api/shares/"+id+"/poster", testToken, ""); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("empty PUT = %d, want 413", rec.Code)
	}
}

func TestPosterUploadAndServe(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "clip")
	uploadGetSlug(t, h, id, "clip.mp4", "not really video")

	if code := putPoster(t, h, id, posterJPEG(t, "jpeg")); code != http.StatusNoContent {
		t.Fatalf("PUT poster = %d", code)
	}
	rec := doReq(t, h, "GET", "/card/"+id+"/poster.jpg", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET poster = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "image/jpeg" {
		t.Errorf("Content-Type = %q", ct)
	}
	if rec.Header().Get("X-Robots-Tag") == "" {
		t.Error("a poster must not be indexable")
	}
	if body := rec.Body.String(); !strings.Contains(body, "jpeg") {
		t.Errorf("body = %q", body)
	}
}

// THE security case. og:image is fetched by anonymous bots with no cookies, so
// the route cannot be gated by the password; it must refuse outright. Chat
// providers cache what they fetch, so one leak outlives deleting the share.
func TestAProtectedSharesPosterIs404(t *testing.T) {
	h := newTestAPI(t)
	id := createShareWithPassword(t, h, "secret", "hunter2")
	if code := putPoster(t, h, id, posterJPEG(t, "frame")); code != http.StatusNoContent {
		t.Fatalf("PUT poster = %d", code)
	}
	rec := doReq(t, h, "GET", "/card/"+id+"/poster.jpg", "", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("protected poster served with %d, a frame leaked", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "frame") {
		t.Fatal("protected poster bytes reached the response")
	}
}

// The card for a locked share points at the STATIC tile, whose URL carries no
// share id, so nothing about the share is disclosed by the URL either.
func TestAProtectedVideoCardUsesTheStaticTile(t *testing.T) {
	h := newTestAPI(t)
	id := createShareWithPassword(t, h, "secret", "hunter2")
	uploadGetSlug(t, h, id, "clip.mp4", "video bytes")
	rec := doReqWithHeader(t, h, "GET", "/share/"+id, "User-Agent", "Twitterbot/1.0")
	body := rec.Body.String()
	if !strings.Contains(body, "/card-video.png") {
		t.Errorf("protected video card image, want the static tile:\n%s", body)
	}
	if strings.Contains(body, "/card/"+id+"/poster.jpg") {
		t.Error("protected card pointed at a real frame")
	}
}

func TestAnOpenVideoCardPointsAtThePoster(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "clip")
	uploadGetSlug(t, h, id, "clip.mp4", "video bytes")
	putPoster(t, h, id, posterJPEG(t, "frame"))
	rec := doReqWithHeader(t, h, "GET", "/share/"+id, "User-Agent", "Twitterbot/1.0")
	if !strings.Contains(rec.Body.String(), "/card/"+id+"/poster.jpg") {
		t.Errorf("open video card did not use its poster:\n%s", rec.Body.String())
	}
}

// Without a poster an open video still says it is a video.
func TestAnOpenVideoWithoutPosterUsesTheTile(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "clip")
	uploadGetSlug(t, h, id, "clip.mp4", "video bytes")
	rec := doReqWithHeader(t, h, "GET", "/share/"+id, "User-Agent", "Twitterbot/1.0")
	if !strings.Contains(rec.Body.String(), "/card-video.png") {
		t.Errorf("open video without a poster did not use the tile")
	}
}

func TestPosterRouteRefusesUnknownAndUnauthorised(t *testing.T) {
	h := newTestAPI(t)
	if rec := doReq(t, h, "GET", "/card/nosuchshare/poster.jpg", "", ""); rec.Code != http.StatusNotFound {
		t.Errorf("unknown share = %d", rec.Code)
	}
	id := createShare(t, h, "clip")
	if rec := doReq(t, h, "PUT", "/api/shares/"+id+"/poster", "", "x"); rec.Code == http.StatusNoContent {
		t.Error("PUT poster accepted without a token")
	}
}

func TestTheStaticVideoTileIsServed(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "GET", "/card-video.png", "", "")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("og-video.png = %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	if rec.Body.Len() < 1000 {
		t.Errorf("tile suspiciously small: %d bytes", rec.Body.Len())
	}
}

// A poster set on a one-file share names that file, so deleting the file
// takes the frame off the public card: the card route answers 404 and the
// share's card falls back to the play tile. A second file added later does
// not change which file the poster came from.
func TestDeletingThePostersFileWithholdsThePoster(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "clip")
	uploadGetSlug(t, h, id, "clip.mp4", "video bytes")
	if code := putPoster(t, h, id, posterJPEG(t, "frame")); code != http.StatusNoContent {
		t.Fatalf("PUT poster = %d", code)
	}
	uploadGetSlug(t, h, id, "other.mp4", "more video bytes")
	if rec := doReq(t, h, "GET", "/card/"+id+"/poster.jpg", "", ""); rec.Code != http.StatusOK {
		t.Fatalf("poster with its file present = %d, want 200", rec.Code)
	}
	if rec := doReq(t, h, "DELETE", "/api/shares/"+id+"/files/clip.mp4", testToken, ""); rec.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "GET", "/card/"+id+"/poster.jpg", "", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("poster after its file was deleted = %d, want 404", rec.Code)
	}
	body := doReqWithHeader(t, h, "GET", "/share/"+id, "User-Agent", "Twitterbot/1.0").Body.String()
	if strings.Contains(body, "/card/"+id+"/poster.jpg") || !strings.Contains(body, "/card-video.png") {
		t.Errorf("card after the poster's file was deleted, want the play tile:\n%s", body)
	}
	// The owner's own thumbnail is not a public card and stays.
	if rec := doReq(t, h, "GET", "/api/shares/"+id+"/poster", testToken, ""); rec.Code != http.StatusOK {
		t.Errorf("owner poster = %d, want 200", rec.Code)
	}
}

// A poster set while the share holds several files names none of them, so
// deleting one of those files leaves it on the card.
func TestAPosterOfSeveralFilesNamesNone(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "clips")
	uploadGetSlug(t, h, id, "a.mp4", "video a")
	uploadGetSlug(t, h, id, "b.mp4", "video b")
	if code := putPoster(t, h, id, posterJPEG(t, "frame")); code != http.StatusNoContent {
		t.Fatalf("PUT poster = %d", code)
	}
	if rec := doReq(t, h, "DELETE", "/api/shares/"+id+"/files/a.mp4", testToken, ""); rec.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "GET", "/card/"+id+"/poster.jpg", "", ""); rec.Code != http.StatusOK {
		t.Fatalf("poster = %d, want 200", rec.Code)
	}
}

// A protected Receive Inbox's password form, which is what an unfurler sees,
// carries the brand card whatever the inbox has received, and names the
// inbox's upload page rather than a /share/ address that answers 404.
func TestAProtectedInboxCardRevealsNothingItReceived(t *testing.T) {
	h := newTestAPI(t)
	id := createInbox(t, h, `{"name":"tapes","receive":true}`)
	if rec := doReq(t, h, "PUT", "/receive/"+id+"/files/clip.mp4", "", "video bytes"); rec.Code != http.StatusCreated {
		t.Fatalf("inbox upload = %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"password":"hunter2"}`); rec.Code != http.StatusOK {
		t.Fatalf("set password = %d %s", rec.Code, rec.Body)
	}
	form := doReqUA(t, h, "/receive/"+id, telegramUA)
	wrong := httptest.NewRequest("POST", "/unlock/"+id, strings.NewReader("password=nope"))
	wrong.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wrong.Header.Set("User-Agent", telegramUA)
	retry := httptest.NewRecorder()
	h.ServeHTTP(retry, wrong)
	for name, rec := range map[string]*httptest.ResponseRecorder{"the form": form, "a wrong password": retry} {
		body := rec.Body.String()
		if got := metaContent(body, "og:image"); !strings.HasSuffix(got, "/card.png") {
			t.Errorf("%s: og:image = %q, want the brand card", name, got)
		}
		if got := metaContent(body, "og:url"); !strings.HasSuffix(got, "/receive/"+id) {
			t.Errorf("%s: og:url = %q, want the inbox's upload page", name, got)
		}
		for _, leak := range []string{"card-video", "clip.mp4", "tapes"} {
			if strings.Contains(body, leak) {
				t.Errorf("%s: the card leaks %q", name, leak)
			}
		}
	}
}

func TestDeletePosterClearsTheCard(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "clip")
	uploadGetSlug(t, h, id, "clip.mp4", "not really video")
	if code := putPoster(t, h, id, posterJPEG(t, "jpeg")); code != http.StatusNoContent {
		t.Fatalf("PUT poster = %d", code)
	}
	if rec := doReq(t, h, "DELETE", "/api/shares/"+id+"/poster", testToken, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE poster = %d %s", rec.Code, rec.Body)
	}
	rec := doReq(t, h, "GET", "/api/shares/"+id+"/poster", testToken, "")
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), `"not-found"`) {
		t.Fatalf("GET poster = %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "GET", "/card/"+id+"/poster.jpg", "", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("card poster = %d", rec.Code)
	}
	page := doReqUA(t, h, "/share/"+id, telegramUA)
	if got := metaContent(page.Body.String(), "og:image"); strings.Contains(got, "poster.jpg") {
		t.Fatalf("og:image = %q still the poster", got)
	}
}

func TestDeletePosterIsIdempotentAndOwnerScoped(t *testing.T) {
	h, um := newTestAPIWithUsers(t)
	other := seedUser(t, um, "guest")
	id := createShare(t, h, "clip")
	for i := 0; i < 2; i++ {
		if rec := doReq(t, h, "DELETE", "/api/shares/"+id+"/poster", testToken, ""); rec.Code != http.StatusNoContent {
			t.Fatalf("DELETE without a poster = %d", rec.Code)
		}
	}
	if code := putPoster(t, h, id, posterJPEG(t, "jpeg")); code != http.StatusNoContent {
		t.Fatalf("PUT poster = %d", code)
	}
	if rec := doReq(t, h, "DELETE", "/api/shares/"+id+"/poster", other, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("foreign DELETE = %d, want 404", rec.Code)
	}
	if rec := doReq(t, h, "GET", "/api/shares/"+id+"/poster", testToken, ""); rec.Code != http.StatusOK {
		t.Fatalf("the foreign DELETE removed the poster: %d", rec.Code)
	}
}
