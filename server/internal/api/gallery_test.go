package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// galleryItemsOf pulls the inlined item list back out of a rendered page, so
// tests assert on the data the browser gets rather than on markup.
func galleryItemsOf(t *testing.T, body string) []map[string]any {
	t.Helper()
	const open = `<script type="application/json" id="data"`
	i := strings.Index(body, open)
	if i < 0 {
		t.Fatalf("page carries no item block:\n%s", body[:min(len(body), 400)])
	}
	rest := body[i:]
	j := strings.Index(rest, ">")
	k := strings.Index(rest, "</script>")
	if j < 0 || k < 0 {
		t.Fatal("item block is not closed")
	}
	var items []map[string]any
	if err := json.Unmarshal([]byte(rest[j+1:k]), &items); err != nil {
		t.Fatalf("item block is not JSON: %v\n%s", err, rest[j+1:k])
	}
	return items
}

// newMediaShare creates a media share holding the named files, each with the
// given body, and returns the share id.
func newMediaShare(t *testing.T, h http.Handler, files map[string]string) string {
	t.Helper()
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"Iceland","media":true}`)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	var created struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)
	for name, body := range files {
		if rec := doReq(t, h, "PUT", "/api/shares/"+created.ID+"/files/"+name, testToken, body); rec.Code != 201 {
			t.Fatalf("upload %s = %d %s", name, rec.Code, rec.Body)
		}
	}
	return created.ID
}

func TestAMediaShareOpensAsAGallery(t *testing.T) {
	h := newTestAPI(t)
	id := newMediaShare(t, h, map[string]string{
		"beach.jpg": "photo-bytes", "clip.mp4": "video-bytes", "notes.pdf": "doc-bytes",
	})
	rec := doReq(t, h, "GET", "/share/"+id, "", "")
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `id="lb"`) || !strings.Contains(body, `id="groups"`) {
		t.Fatal("page is not the gallery")
	}
	if !strings.Contains(body, "Iceland") {
		t.Error("gallery does not carry the share name")
	}
	items := galleryItemsOf(t, body)
	if len(items) != 3 {
		t.Fatalf("items = %d, want 3", len(items))
	}
	kinds := map[string]string{}
	for _, it := range items {
		kinds[it["n"].(string)] = it["k"].(string)
	}
	if kinds["beach.jpg"] != "photo" || kinds["clip.mp4"] != "video" || kinds["notes.pdf"] != "file" {
		t.Fatalf("kinds = %v", kinds)
	}
}

func TestAnOrdinaryShareStillOpensAsAListing(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "Docs")
	doReq(t, h, "PUT", "/api/shares/"+id+"/files/a.jpg", testToken, "x")
	doReq(t, h, "PUT", "/api/shares/"+id+"/files/b.jpg", testToken, "y")
	rec := doReq(t, h, "GET", "/share/"+id, "", "")
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), `id="lb"`) {
		t.Fatal("an ordinary share rendered the gallery")
	}
}

func TestTheGalleryHasAWayBackToTheFileList(t *testing.T) {
	h := newTestAPI(t)
	id := newMediaShare(t, h, map[string]string{"a.jpg": "x", "b.jpg": "y"})
	rec := doReq(t, h, "GET", "/share/"+id, "", "")
	if !strings.Contains(rec.Body.String(), "/share/"+id+"?files=1") {
		t.Fatal("the gallery offers no way to the file list")
	}
	rec = doReq(t, h, "GET", "/share/"+id+"?files=1", "", "")
	if rec.Code != 200 {
		t.Fatalf("?files=1 status = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), `id="lb"`) {
		t.Fatal("?files=1 still rendered the gallery")
	}
}

func TestTheFileListHasAWayBackToTheGallery(t *testing.T) {
	h := newTestAPI(t)
	id := newMediaShare(t, h, map[string]string{"a.jpg": "x", "b.jpg": "y"})
	rec := doReq(t, h, "GET", "/share/"+id+"?files=1", "", "")
	if rec.Code != 200 {
		t.Fatalf("?files=1 status = %d", rec.Code)
	}
	body := rec.Body.String()
	// A FOOTER LINK, worded and placed as the gallery's own "View as a file
	// list" is: the two pages point at each other, so the two affordances
	// must read as the same control.
	if !strings.Contains(body, "View as a gallery") || !strings.Contains(body, `href="/share/`+id+`"`) {
		t.Fatal("the file list offers no way back to the gallery")
	}
	if strings.Contains(body, "Open gallery") {
		t.Fatal("the way back is the footer link, not a button")
	}

	// An ordinary share's listing has no gallery to point at.
	plain := createShare(t, h, "Docs")
	doReq(t, h, "PUT", "/api/shares/"+plain+"/files/a.pdf", testToken, "x")
	doReq(t, h, "PUT", "/api/shares/"+plain+"/files/b.pdf", testToken, "y")
	if body := doReq(t, h, "GET", "/share/"+plain, "", "").Body.String(); strings.Contains(body, "View as a gallery") {
		t.Fatal("an ordinary listing offers a gallery")
	}
}

// A gallery of one photo is still a gallery: the owner chose the kind, and
// the single-file redirect would hand over the raw image instead.
func TestASingleFileMediaShareDoesNotRedirect(t *testing.T) {
	h := newTestAPI(t)
	id := newMediaShare(t, h, map[string]string{"only.jpg": "x"})
	rec := doReq(t, h, "GET", "/share/"+id, "", "")
	if rec.Code != 200 {
		t.Fatalf("status = %d (Location %q), want 200", rec.Code, rec.Header().Get("Location"))
	}
	if !strings.Contains(rec.Body.String(), `id="lb"`) {
		t.Fatal("page is not the gallery")
	}
}

func TestTheGalleryCarriesThumbnailsAndMetadata(t *testing.T) {
	h := newTestAPI(t)
	id := newMediaShare(t, h, map[string]string{"a.jpg": "x", "b.jpg": "y"})
	rec := doReq(t, h, "GET", "/api/shares/"+id, testToken, "")
	var sh struct {
		Files []struct {
			Path string `json:"path"`
			Slug string `json:"slug"`
		} `json:"files"`
	}
	json.Unmarshal(rec.Body.Bytes(), &sh)
	slugs := map[string]string{}
	for _, f := range sh.Files {
		slugs[f.Path] = f.Slug
	}
	// One file gets a thumbnail and metadata; the other gets neither.
	doReq(t, h, "PUT", "/api/shares/"+id+"/thumbs/"+slugs["a.jpg"], testToken, string(aJPEG(t, 32, 24)))
	doReq(t, h, "PUT", "/api/shares/"+id+"/gallery", testToken,
		`{"items":[{"slug":"`+slugs["a.jpg"]+`","w":4032,"h":3024,"takenAt":"2026-08-01T10:00:00Z"}]}`)

	items := galleryItemsOf(t, doReq(t, h, "GET", "/share/"+id, "", "").Body.String())
	byName := map[string]map[string]any{}
	for _, it := range items {
		byName[it["n"].(string)] = it
	}
	a, b := byName["a.jpg"], byName["b.jpg"]
	if a["t"] != "/thumb/"+id+"/"+slugs["a.jpg"] {
		t.Errorf("a.jpg thumb = %v", a["t"])
	}
	if a["w"] != float64(4032) || a["h"] != float64(3024) {
		t.Errorf("a.jpg size = %v x %v", a["w"], a["h"])
	}
	if a["ta"] != "2026-08-01T10:00:00Z" {
		t.Errorf("a.jpg takenAt = %v", a["ta"])
	}
	if _, has := b["t"]; has {
		t.Errorf("b.jpg claims a thumbnail it does not have: %v", b)
	}
	if _, has := b["w"]; has {
		t.Errorf("b.jpg claims dimensions it does not have: %v", b)
	}
}

// Both the page and the bytes it points at must be reachable from a bare
// domain-less dev server, and from a real one the picture URLs must name the
// file origin so the grid does not take a redirect per tile.
func TestGalleryURLsFollowTheOriginSplit(t *testing.T) {
	h := newTestAPI(t)
	id := newMediaShare(t, h, map[string]string{"a.jpg": "x", "b.jpg": "y"})
	items := galleryItemsOf(t, doReq(t, h, "GET", "/share/"+id, "", "").Body.String())
	for _, it := range items {
		if v := it["v"].(string); !strings.HasPrefix(v, "/view/") {
			t.Fatalf("with no domain the view URL should stay root-relative, got %q", v)
		}
	}

	hd := withDomain(t, "share.example.com")
	id2 := newMediaShare(t, hd, map[string]string{"a.jpg": "x", "b.jpg": "y"})
	items = galleryItemsOf(t, req(t, hd, "GET", "share.example.com", "/share/"+id2).Body.String())
	for _, it := range items {
		if v := it["v"].(string); !strings.HasPrefix(v, "https://files.share.example.com/view/") {
			t.Fatalf("view URL = %q, want the file origin", v)
		}
		if d := it["d"].(string); !strings.HasPrefix(d, "https://files.share.example.com/download/") {
			t.Fatalf("download URL = %q, want the file origin", d)
		}
	}
}

func TestAProtectedGalleryShowsThePasswordForm(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"name":"Trip","media":true,"password":"letmein"}`)
	var created struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)
	doReq(t, h, "PUT", "/api/shares/"+created.ID+"/files/a.jpg", testToken, "x")
	rec = doReq(t, h, "GET", "/share/"+created.ID, "", "")
	if strings.Contains(rec.Body.String(), `id="lb"`) {
		t.Fatal("a protected gallery rendered without the password")
	}
	if !strings.Contains(rec.Body.String(), "password-protected") {
		t.Fatalf("not the password form: %s", rec.Body.String()[:min(rec.Body.Len(), 200)])
	}
	rec = doReq(t, h, "GET", "/share/"+created.ID+"?pw=letmein", "", "")
	if !strings.Contains(rec.Body.String(), `id="lb"`) {
		t.Fatal("the unlocked gallery did not render")
	}
}

// An unfurler is answered before anything else on this route, gallery or not.
func TestAGalleryStillUnfurls(t *testing.T) {
	h := newTestAPI(t)
	id := newMediaShare(t, h, map[string]string{"a.jpg": "x", "b.jpg": "y"})
	rec := doReqWithHeader(t, h, "GET", "/share/"+id, "User-Agent", "Twitterbot/1.0")
	body := rec.Body.String()
	if strings.Contains(body, `id="lb"`) {
		t.Fatal("an unfurler got the gallery instead of the card")
	}
	if !strings.Contains(body, "og:title") {
		t.Fatalf("no card: %s", body[:min(len(body), 200)])
	}
}

// A pending file has no bytes yet, so the page must poll rather than tile a
// broken picture.
// A gallery whose pictures are still uploading is the waiting page, not a
// grid of placeholders: the gallery renders only once every tile has bytes.
func TestAGalleryWithPendingFilesWaits(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"name":"Trip","media":true,"files":[{"path":"a.jpg","size":10},{"path":"b.jpg","size":10}]}`)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	var created struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)
	body := doReq(t, h, "GET", "/share/"+created.ID, "", "").Body.String()
	if !strings.Contains(body, "the share will open right here") ||
		!strings.Contains(body, `fetch("/share/" + shareID + "/status"`) {
		t.Fatalf("a gallery with pending files did not wait: %s", body)
	}
	if strings.Contains(body, `id="data"`) {
		t.Fatalf("a gallery with pending files rendered its grid: %s", body)
	}
}

// An HTML file that rides along in a gallery opens by PATH, exactly as it
// does in the ordinary listing, so its relative references resolve.
func TestAnHTMLFileInAGalleryOpensBySitePath(t *testing.T) {
	h := newTestAPI(t)
	id := newMediaShare(t, h, map[string]string{
		"a.jpg": "photo", "page.html": "<html>hello</html>",
	})
	items := galleryItemsOf(t, doReq(t, h, "GET", "/share/"+id, "", "").Body.String())
	for _, it := range items {
		v := it["v"].(string)
		switch it["n"].(string) {
		case "page.html":
			if !strings.HasPrefix(v, "/site/"+id+"/") {
				t.Errorf("page.html view = %q, want a /site path", v)
			}
			if it["k"] != "file" {
				t.Errorf("page.html kind = %v, want file", it["k"])
			}
		case "a.jpg":
			if !strings.HasPrefix(v, "/view/"+id+"/") {
				t.Errorf("a.jpg view = %q, want a /view slug", v)
			}
		}
	}
}

// The slideshow toggle wears a STOP square while it runs: a pressed-looking
// play triangle does not say "this is a slideshow you can stop".
func TestTheSlideshowButtonCarriesBothIcons(t *testing.T) {
	h := newTestAPI(t)
	id := newMediaShare(t, h, map[string]string{"a.jpg": "x"})
	body := doReq(t, h, "GET", "/share/"+id, "", "").Body.String()
	for _, want := range []string{
		`class="go"`,   // the play triangle, shown while stopped
		`class="halt"`, // the stop square, shown while running
		`#lbplay[aria-pressed="true"] .go{display:none}`,
		`#lbplay[aria-pressed="true"] .halt{display:inline}`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("gallery page misses %q", want)
		}
	}
}

// The lightbox's top bar carries a filmstrip of the items either side of the
// one on screen, and the current one is ringed. The blank slots are what keep
// it in the centre of the strip at every index.
func TestTheViewerCarriesAFilmstrip(t *testing.T) {
	h := newTestAPI(t)
	id := newMediaShare(t, h, map[string]string{"a.jpg": "x", "b.jpg": "y", "c.jpg": "z"})
	body := doReq(t, h, "GET", "/share/"+id, "", "").Body.String()
	for _, want := range []string{
		`<div class="strip" id="lbstrip">`,
		`.lb .th.on{opacity:1;outline-color:#fff}`,
		`.lb .th.gap{visibility:hidden}`,
		`gap.className = "th gap";`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("gallery page misses %q", want)
		}
	}
}

// A tile whose thumbnail has not been derived yet falls back to the file
// itself, which works for a photo and cannot work for a clip: an MP4 is not
// an <img>. Pointing one at it costs a few MB off the server per tile
// scrolled past before the decoder gives up, and then draws the generic
// document glyph the error handler keeps for genuinely broken pictures. A
// clip with no tile is drawn as a clip instead, and fetches nothing. The
// filmstrip already follows this rule (`it.t || (it.k === "photo" ...)`),
// so the grid is the odd one out.
func TestAnUntiledClipIsDrawnAsAClipRatherThanFetched(t *testing.T) {
	h := newTestAPI(t)
	id := newMediaShare(t, h, map[string]string{"a.mp4": "x"})
	body := doReq(t, h, "GET", "/share/"+id, "", "").Body.String()
	for _, want := range []string{
		"var FILM_SVG = ",
		`var src = it.t || (it.k === "photo" ? it.v : "");`,
		`'<div class="glyph">' + FILM_SVG + '</div>'`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("gallery page misses %q", want)
		}
	}
	if strings.Contains(body, "esc(it.t || it.v)") {
		t.Fatal("the grid still points an img at whatever the file is")
	}
}

// An item is sized before its bytes arrive, and a clip's box is the FITTED
// one: a replaced element handed both a width and a height clamps each
// against its own maximum, which would fill the stage and letterbox the
// picture inside it.
func TestTheViewerSizesAnItemBeforeItLoads(t *testing.T) {
	h := newTestAPI(t)
	id := newMediaShare(t, h, map[string]string{"a.mp4": "x"})
	body := doReq(t, h, "GET", "/share/"+id, "", "").Body.String()
	for _, want := range []string{
		`var k = Math.min(sw / w, sh / h, 1);`,
		`el.addEventListener("loadedmetadata", function(){`,
		// The neighbours are held as elements, and only the neighbours.
		`preload(i + 1, "auto");`,
		`preload(i - 1, "metadata");`,
		`keepOnly(i);`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("gallery page misses %q", want)
		}
	}
}

// Chrome's media controls live in a shadow tree the page cannot see into: a
// key pressed while they hold focus never reaches the document, so Left and
// Right would scrub the clip instead of moving through the share. Focus is
// handed back to the dialog as soon as a click parks it there.
func TestTheViewerKeepsTheArrowsItsOwn(t *testing.T) {
	h := newTestAPI(t)
	id := newMediaShare(t, h, map[string]string{"a.mp4": "x", "b.mp4": "y"})
	body := doReq(t, h, "GET", "/share/"+id, "", "").Body.String()
	for _, want := range []string{
		`stage.addEventListener("focusin", function(ev){`,
		`if (tag === "VIDEO" || tag === "AUDIO") lb.focus();`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("gallery page misses %q", want)
		}
	}
}

// A direct link to one item (/share/{id}#slug) is the gallery's own history
// entry: the ✕ must land the reader on the grid, so it drops the item from
// the address rather than pressing Back, which would leave the page. An
// entry the gallery pushed itself keeps Back, which is one press either way.
func TestClosingADeepLinkedItemReturnsToTheGrid(t *testing.T) {
	h := newTestAPI(t)
	id := newMediaShare(t, h, map[string]string{"a.jpg": "x", "b.jpg": "y"})
	body := doReq(t, h, "GET", "/share/"+id, "", "").Body.String()
	for _, want := range []string{
		// The pushed entry is marked as the gallery's own,
		`history.pushState({lb: 1, own: 1}`,
		// walking between items preserves that mark,
		`history.replaceState({lb: 1, own: ownEntry()}`,
		// and the close chooses by it.
		`if (history.state.own) history.back();`,
		`else history.replaceState({}, "", location.pathname + location.search);`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("the gallery page is missing %q", want)
		}
	}
	if strings.Contains(body, `if (!fromPop && history.state && history.state.lb) history.back();`) {
		t.Fatal("the close still goes Back unconditionally, which leaves a deep-linked page")
	}
}
