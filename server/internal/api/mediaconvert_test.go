package api

import (
	"net/http"
	"strings"
	"testing"
)

// Turning a share into a gallery and back is ONE question with one answer,
// but the two directions are not symmetrical, and that asymmetry is the whole
// rule: a file listing renders anything, so leaving a gallery is always safe,
// while entering one publishes a grid of tiles that have to be playable.

func createShareBody(t *testing.T, h http.Handler, body string) string {
	t.Helper()
	rec := doReq(t, h, "POST", "/api/shares", testToken, body)
	if rec.Code != 201 {
		t.Fatalf("create: status %d body %s", rec.Code, rec.Body)
	}
	var out struct {
		ID string `json:"id"`
	}
	unmarshal(t, rec, &out)
	return out.ID
}

func readShare(t *testing.T, h http.Handler, id string) (media bool, entry string) {
	t.Helper()
	rec := doReq(t, h, "GET", "/api/shares/"+id, testToken, "")
	if rec.Code != 200 {
		t.Fatalf("read %s: status %d", id, rec.Code)
	}
	var out struct {
		Media bool   `json:"media"`
		Entry string `json:"entry"`
	}
	unmarshal(t, rec, &out)
	return out.Media, out.Entry
}

func TestAGalleryCanAlwaysBecomeAListing(t *testing.T) {
	h := newTestAPI(t)
	id := createShareBody(t, h, `{"name":"Holiday","media":true}`)
	// Content a browser cannot play. Leaving is still allowed: a listing
	// renders anything, which is exactly why this direction has no gate.
	uploadFile(t, h, testToken, id, "clip.mov", "not really a movie")
	rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"media":false}`)
	if rec.Code != 200 {
		t.Fatalf("leaving a gallery: status %d body %s", rec.Code, rec.Body)
	}
	if media, _ := readShare(t, h, id); media {
		t.Fatal("share is still a gallery after media:false")
	}
}

func TestAShareOfPlayableFilesCanBecomeAGallery(t *testing.T) {
	h := newTestAPI(t)
	id := createShareBody(t, h, `{"name":"Screenshots"}`)
	uploadFile(t, h, testToken, id, "a.png", "\x89PNG\r\n\x1a\n pretend")
	uploadFile(t, h, testToken, id, "b.jpg", "\xff\xd8\xff pretend")
	rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"media":true}`)
	if rec.Code != 200 {
		t.Fatalf("becoming a gallery: status %d body %s", rec.Code, rec.Body)
	}
	if media, _ := readShare(t, h, id); !media {
		t.Fatal("share is not a gallery after media:true")
	}
}

// A file that would be TILED has to be playable. A file that lands in the
// gallery's own file list does not, exactly as at creation.
func TestANonMediaFileDoesNotBlockAGallery(t *testing.T) {
	h := newTestAPI(t)
	id := createShareBody(t, h, `{"name":"Trip"}`)
	uploadFile(t, h, testToken, id, "a.png", "\x89PNG\r\n\x1a\n pretend")
	uploadFile(t, h, testToken, id, "notes.pdf", "%PDF-1.4 pretend")
	rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"media":true}`)
	if rec.Code != 200 {
		t.Fatalf("a PDF beside the photos blocked the gallery: %d %s", rec.Code, rec.Body)
	}
}

func TestAShareOfUnplayableMediaIsRefusedAGallery(t *testing.T) {
	h := newTestAPI(t)
	id := createShareBody(t, h, `{"name":"Camera roll"}`)
	uploadFile(t, h, testToken, id, "a.png", "\x89PNG\r\n\x1a\n pretend")
	uploadFile(t, h, testToken, id, "clip.mov", "pretend movie")
	rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"media":true}`)
	if rec.Code != 400 {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body)
	}
	if code := errCode(t, rec.Body.String()); code != "not-gallery-playable" {
		t.Fatalf("code = %q, want not-gallery-playable: %s", code, rec.Body)
	}
	if media, _ := readShare(t, h, id); media {
		t.Fatal("a refused conversion still flipped the share")
	}
}

// A pending entry has no sniffed MIME, so nothing can be said about it yet.
// Refusing is the honest answer; guessing from the extension would let a
// share turn into a gallery on a promise.
func TestAShareStillUploadingIsRefusedAGallery(t *testing.T) {
	h := newTestAPI(t)
	id := createShareBody(t, h,
		`{"name":"Uploading","files":[{"path":"a.png","size":10},{"path":"b.png","size":10}]}`)
	rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"media":true}`)
	if rec.Code != 400 {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body)
	}
	if code := errCode(t, rec.Body.String()); code != "share-incomplete" {
		t.Fatalf("code = %q, want share-incomplete: %s", code, rec.Body)
	}
}

func TestAnEmptyShareIsRefusedAGallery(t *testing.T) {
	h := newTestAPI(t)
	id := createShareBody(t, h, `{"name":"Nothing"}`)
	rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"media":true}`)
	if rec.Code != 400 {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body)
	}
}

// The gallery IS the landing page, so the two settings answer the same
// question. The check is on the RESULTING state, not on what is stored, so
// one request can move a web page straight to a gallery.
func TestAWebPageBecomesAGalleryInOneRequest(t *testing.T) {
	h := newTestAPI(t)
	id := createShareBody(t, h, `{"name":"Site","entry":"index.html"}`)
	uploadFile(t, h, testToken, id, "index.html", "<h1>hi</h1>")
	uploadFile(t, h, testToken, id, "a.png", "\x89PNG\r\n\x1a\n pretend")
	rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"media":true,"entry":""}`)
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body)
	}
	media, entry := readShare(t, h, id)
	if !media || entry != "" {
		t.Fatalf("media = %v entry = %q, want true and empty", media, entry)
	}
}

func TestAGalleryStillRefusesAnEntryPage(t *testing.T) {
	h := newTestAPI(t)
	id := createShareBody(t, h, `{"name":"Holiday","media":true}`)
	uploadFile(t, h, testToken, id, "index.html", "<h1>hi</h1>")
	rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"entry":"index.html"}`)
	if rec.Code != 400 {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body)
	}
}

// An inbox's content is never served publicly, so it has no page to
// render and nothing to choose between.
//
// The link HOLDS a playable picture on purpose. Probing an empty one proves
// nothing: it is refused for having no pictures, whatever the inbox rule
// says, which is how the gap this pins stayed invisible.
func TestAnInboxIsRefusedAGallery(t *testing.T) {
	h := newTestAPI(t)
	id := createShareBody(t, h, `{"name":"Send me","receive":true}`)
	uploadFile(t, h, testToken, id, "a.png", "\x89PNG\r\n\x1a\n pretend")
	rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"media":true}`)
	if rec.Code != 400 {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body)
	}
	sh := doReq(t, h, "GET", "/api/shares/"+id, testToken, "")
	if strings.Contains(sh.Body.String(), `"media":true`) {
		t.Fatalf("the inbox became a gallery: %s", sh.Body)
	}
}

// media alone is a change; it must not read as "nothing to change".
func TestMediaAloneIsAChange(t *testing.T) {
	h := newTestAPI(t)
	id := createShareBody(t, h, `{"name":"Holiday","media":true}`)
	rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"media":false}`)
	if rec.Code == 400 {
		t.Fatalf("media:false read as nothing to change: %s", rec.Body)
	}
}
