package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/linked"
	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/shareid"
)

// unescapedJS reads a rendered page with html/template's JS string escape of
// "/" undone, so a test can look for an address the page's script holds.
func unescapedJS(body string) string { return strings.ReplaceAll(body, `\/`, "/") }

// pendingSlugs answers the slug of every file a share declares, by path.
func pendingSlugs(t *testing.T, h http.Handler, id string) map[string]string {
	t.Helper()
	var sh struct {
		Files []struct {
			Path string `json:"path"`
			Slug string `json:"slug"`
		} `json:"files"`
	}
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+id, testToken, ""), &sh)
	out := map[string]string{}
	for _, f := range sh.Files {
		out[f.Path] = f.Slug
	}
	return out
}

func TestWaitingPagePollsTheURLItIsGiven(t *testing.T) {
	h := newTestAPI(t)
	id := createShareBody(t, h, `{"name":"Zebra","files":[{"path":"a/deep/clip.pdf","size":100}]}`)
	slug := pendingSlugs(t, h, id)["a/deep/clip.pdf"]

	share := doReq(t, h, "GET", "/view/"+id+"/"+slug, "", "").Body.String()
	if !strings.Contains(share, `fetch("/share/" + shareID + "/status"`) ||
		!strings.Contains(share, `const shareID = "`+id+`"`) {
		t.Fatalf("the share's waiting page does not poll /share/{id}/status: %s", share)
	}

	key := mintFileKey(t, h, testToken, id, slug)
	for _, tc := range []struct{ path, words string }{
		{"/f/" + key, "the file will appear right here"},
		{"/f/" + key + "/download", "your download will start automatically"},
	} {
		rec := doReq(t, h, "GET", tc.path, "", "")
		body := rec.Body.String()
		if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
			t.Fatalf("GET %s = %d %q", tc.path, rec.Code, rec.Header().Get("Content-Type"))
		}
		if !strings.Contains(unescapedJS(body), `const statusURL = "/f/`+key+`/status"`) {
			t.Errorf("GET %s does not poll its own status: %s", tc.path, body)
		}
		if !strings.Contains(body, `const shareID = ""`) || !strings.Contains(body, `const slug = ""`) {
			t.Errorf("GET %s carries a share id or a slug: %s", tc.path, body)
		}
		if !strings.Contains(body, "<title>clip.pdf — HyperDrop</title>") || !strings.Contains(body, "<h1>clip.pdf</h1>") {
			t.Errorf("GET %s is not titled by the base name: %s", tc.path, body)
		}
		if !strings.Contains(body, tc.words) || !strings.Contains(body, "so the file isn") {
			t.Errorf("GET %s lacks the one-file sentences: %s", tc.path, body)
		}
		namesNothing(t, "waiting "+tc.path, rec, id, slug, "Zebra", "a/deep")
	}
}

func TestFileLinkStatusShape(t *testing.T) {
	h := newTestAPI(t)
	id := createShareBody(t, h, `{"name":"Zebra","files":[{"path":"a/x.bin","size":4},{"path":"b.bin","size":3}]}`)
	slugs := pendingSlugs(t, h, id)
	key := mintFileKey(t, h, testToken, id, slugs["a/x.bin"])

	shape := func(what string) map[string]json.RawMessage {
		t.Helper()
		rec := doReq(t, h, "GET", "/f/"+key+"/status", "", "")
		if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: %d %q", what, rec.Code, rec.Header().Get("Cache-Control"))
		}
		namesNothing(t, what, rec, id, slugs["a/x.bin"], slugs["b.bin"], "a/x.bin", "b.bin", "Zebra")
		var top map[string]json.RawMessage
		unmarshal(t, rec, &top)
		if keysOf(top) != "complete,file" {
			t.Fatalf("%s: top-level fields %s, want complete,file: %s", what, keysOf(top), rec.Body)
		}
		var file map[string]json.RawMessage
		if err := json.Unmarshal(top["file"], &file); err != nil {
			t.Fatal(err)
		}
		if got := keysOf(file); got != "bytes,complete,size" {
			t.Fatalf("%s: file fields %s, want bytes,complete,size: %s", what, got, rec.Body)
		}
		return file
	}
	file := shape("pending")
	if string(file["complete"]) != "false" || string(file["size"]) != "4" {
		t.Errorf("pending file = %v", file)
	}
	uploadGetSlug(t, h, id, "a/x.bin", "abcd")
	file = shape("complete")
	if string(file["complete"]) != "true" || string(file["bytes"]) != "4" {
		t.Errorf("committed file = %v", file)
	}

	lh, _, _ := linkedTestAPI(t)
	_, _, rkey := publicProbeRevokedShare(t, lh, func(string, string, string) {})
	rec := doReq(t, lh, "GET", "/f/"+rkey+"/status", "", "")
	if rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != `{"unavailable":true}` {
		t.Fatalf("revoked source status = %d %s", rec.Code, rec.Body)
	}
}

// keysOf is a JSON object's field names, sorted and comma-joined.
func keysOf(m map[string]json.RawMessage) string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return strings.Join(ks, ",")
}

func TestFileLinkCards(t *testing.T) {
	h := newTestAPI(t)
	id, slugs := shareWithFiles(t, h, "Zebra", map[string]string{
		"a/deep/clip.mp4": mp4Fixture(23, 1920, 1200, 4096),
		"doc.pdf":         "pdf",
	})
	// A poster on the share: a file link's card never shows it.
	if rec := doReq(t, h, "PUT", "/api/shares/"+id+"/poster", testToken, string(aJPEG(t, 8, 6))); rec.Code != 204 {
		t.Fatalf("poster = %d %s", rec.Code, rec.Body)
	}
	clip := mintFileKey(t, h, testToken, id, slugs["a/deep/clip.mp4"])
	doc := mintFileKey(t, h, testToken, id, slugs["doc.pdf"])
	base := "https://203.0.113.7"

	body := doReqUA(t, h, "/f/"+clip, telegramUA).Body.String()
	for prop, want := range map[string]string{
		"og:title":            "clip.mp4",
		"og:url":              base + "/f/" + clip,
		"og:image":            base + "/card-video.png",
		"og:video":            base + "/f/" + clip + "?ogmedia=1",
		"og:video:type":       "video/mp4",
		"og:video:width":      "1920",
		"og:description":      "MP4 · 0:23 · " + humanSize(int64(len(mp4Fixture(23, 1920, 1200, 4096)))) + " · " + cardFooter,
		"og:type":             "video.other",
		"twitter:image":       base + "/card-video.png",
		"og:video:secure_url": base + "/f/" + clip + "?ogmedia=1",
	} {
		if got := metaContent(body, prop); got != want {
			t.Errorf("video card %s = %q, want %q", prop, got, want)
		}
	}
	if strings.Contains(body, "/card/") || strings.Contains(body, id) || strings.Contains(body, "a/deep") {
		t.Errorf("the video card names the share or its poster: %s", body)
	}
	media := doReqUA(t, h, "/f/"+clip+"?ogmedia=1", telegramUA)
	if media.Header().Get("Content-Type") != "video/mp4" || media.Body.Len() != len(mp4Fixture(23, 1920, 1200, 4096)) {
		t.Errorf("the card's own video fetch = %q, %d bytes", media.Header().Get("Content-Type"), media.Body.Len())
	}
	if dl := doReqUA(t, h, "/f/"+clip+"/download", telegramUA).Body.String(); metaContent(dl, "og:url") != base+"/f/"+clip {
		t.Errorf("the download's card is not at the link's address: %s", dl)
	}

	body = doReqUA(t, h, "/f/"+doc, telegramUA).Body.String()
	for prop, want := range map[string]string{
		"og:title":       "doc.pdf",
		"og:url":         base + "/f/" + doc,
		"og:image":       base + "/card.png",
		"og:description": "PDF · " + humanSize(3) + " · " + cardFooter,
		"og:video":       "",
	} {
		if got := metaContent(body, prop); got != want {
			t.Errorf("document card %s = %q, want %q", prop, got, want)
		}
	}

	pid := createShareBody(t, h, `{"name":"Zebra","password":"hunter2"}`)
	pclip := uploadGetSlug(t, h, pid, "a/deep/clip.mp4", mp4Fixture(23, 1920, 1200, 4096))
	pdoc := uploadGetSlug(t, h, pid, "doc.pdf", "pdf")
	for _, tc := range []struct{ slug, image string }{
		{pclip, "/card-video.png"},
		{pdoc, "/card.png"},
	} {
		key := mintFileKey(t, h, testToken, pid, tc.slug)
		for _, ua := range []string{telegramUA, chromeUA} {
			body := doReqUA(t, h, "/f/"+key, ua).Body.String()
			for prop, want := range map[string]string{
				"og:title":       "Password-protected",
				"og:description": cardFooter,
				"og:url":         base + "/f/" + key,
				"og:image":       base + tc.image,
				"og:video":       "",
			} {
				if got := metaContent(body, prop); got != want {
					t.Errorf("protected card (%s) %s = %q, want %q", ua, prop, got, want)
				}
			}
			if strings.Contains(body, "clip.mp4") || strings.Contains(body, "doc.pdf") || strings.Contains(body, pid) {
				t.Errorf("the protected card names the file or the share: %s", body)
			}
		}
	}

	lh := newTestLiveShareHandler(t)
	mux := lh.routes()
	var live liveShareKeyedOut
	unmarshal(t, doReq(t, mux, "POST", "/api/live-share", testToken, `{"name":"Zebra","files":[`+
		`{"path":"clip.mp4","size":1000,"mime":"video/mp4","mtime":"2026-08-06T10:00:00Z"}]}`), &live)
	for _, p := range []string{"/f/" + live.Files[0].FileKey, "/f/" + live.Files[0].FileKey + "?ogmedia=1"} {
		rec := doReqUA(t, mux, p, telegramUA)
		body := rec.Body.String()
		if !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") || strings.Contains(body, "og:video") {
			t.Errorf("a live share's card %s offers its video: %s", p, body)
		}
		if got := metaContent(body, "og:image"); got != base+"/card-video.png" {
			t.Errorf("a live video's card image = %q", got)
		}
		if got := metaContent(body, "og:url"); got != base+"/f/"+live.Files[0].FileKey {
			t.Errorf("a live card's url = %q", got)
		}
	}
}

func TestFileLinkOnALinkedEntry(t *testing.T) {
	h, b, _ := linkedTestAPI(t)
	id := linkedShare(t, b, "photo/2024")
	a := linkedEntry(t, h, id, "a.jpg")
	key := mintFileKey(t, h, testToken, id, a.Slug)
	if rec := doReq(t, h, "GET", "/f/"+key+"/download", "", ""); rec.Code != 200 || rec.Body.String() != "AAAA" {
		t.Fatalf("before the hide = %d %q", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"linked":{"photo/2024":{"hide":["a.jpg"]}}}`); rec.Code != 200 {
		t.Fatalf("hide = %d %s", rec.Code, rec.Body)
	}
	for _, p := range []string{"/f/" + key, "/f/" + key + "/download", "/f/" + key + "/status"} {
		if rec := doReq(t, h, "GET", p, "", ""); rec.Code != 404 {
			t.Errorf("hidden %s = %d, want 404", p, rec.Code)
		}
	}
	if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"linked":{"photo/2024":{"show":["a.jpg"]}}}`); rec.Code != 200 {
		t.Fatalf("show = %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "GET", "/f/"+key+"/download", "", ""); rec.Code != 200 || rec.Body.String() != "AAAA" {
		t.Fatalf("shown again = %d %q", rec.Code, rec.Body)
	}

	bob := grantedUser(t, h, "bob", "photo/2024")
	var made revokedView
	unmarshal(t, doReq(t, h, "POST", "/api/shares", bob, `{"source":"photo/2024","name":"ZebraTrip"}`), &made)
	rkey := mintFileKey(t, h, bob, made.ID, slugOf(t, made, "a.jpg"))
	if rec := doReq(t, h, "PATCH", "/api/users/bob", testToken, `{"sourceRoots":[],"confirmRevoke":true}`); rec.Code != 200 {
		t.Fatalf("revoke = %d %s", rec.Code, rec.Body)
	}
	for _, p := range []string{"/f/" + rkey, "/f/" + rkey + "/download"} {
		rec := doReq(t, h, "GET", p, "", "")
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "This file is unavailable") {
			t.Fatalf("revoked %s = %d %s", p, rec.Code, rec.Body)
		}
		namesNothing(t, "revoked "+p, rec, "ZebraTrip", made.ID, "AAAA")
	}
}

// TestAFileLinkNeverNamesItsShare drives every answer a file link gives (the
// list of spec §10) on a share whose id and name are distinctive, holding
// the file in a folder beside other files, and asserts that no header and no
// body names the share, the folder, another file or another file's slug.
func TestAFileLinkNeverNamesItsShare(t *testing.T) {
	const (
		name     = "ZanzibarLedger7731"
		source   = "OkapiSourceFolder"
		report   = "a/secret-folder/report.pdf"
		pending  = "a/secret-folder/pending.mp4"
		password = "hunter2"
	)
	contents := map[string]string{report: "%PDF report", "page.html": "<p>page</p>", "other.txt": "sibling"}
	manifest := `"files":[{"path":"` + report + `","size":11},{"path":"page.html","size":11},` +
		`{"path":"other.txt","size":7},{"path":"` + pending + `","size":100}]`

	vol := t.TempDir()
	for p, body := range contents {
		full := filepath.Join(vol, source, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	roots, err := linked.NewRoots(nil, []string{vol}, nil)
	if err != nil {
		t.Fatal(err)
	}
	b := testBackendWithRoots(t, roots)
	h := New(b, "2.0.0", testDomain(t), nil)

	type fixture struct {
		id    string
		slugs map[string]string
		keys  map[string]string
	}
	stored := func(extra string) fixture {
		id := createShareBody(t, h, `{"name":"`+name+`"`+extra+`,`+manifest+`}`)
		for p, body := range contents {
			uploadGetSlug(t, h, id, p, body)
		}
		fx := fixture{id: id, slugs: pendingSlugs(t, h, id), keys: map[string]string{}}
		for p, slug := range fx.slugs {
			fx.keys[p] = mintFileKey(t, h, testToken, id, slug)
		}
		return fx
	}
	open := stored("")
	locked := stored(`,"password":"` + password + `"`)
	d, err := b.DB.CreateShare(metadb.CreateOptions{Name: name, Owner: metadb.DefaultAdminName,
		Folder: true, Sources: []string{source}})
	if err != nil {
		t.Fatal(err)
	}
	ln := fixture{id: d.ID, slugs: map[string]string{}, keys: map[string]string{}}
	for p := range contents {
		ln.slugs[p] = linkedEntry(t, h, d.ID, p).Slug
		ln.keys[p] = mintFileKey(t, h, testToken, d.ID, ln.slugs[p])
	}

	// words is everything a file link to report.pdf must never carry.
	words := func(fx fixture) []string {
		w := []string{fx.id, name, source, "secret-folder", "other.txt", "pending.mp4", "page.html"}
		for _, slug := range fx.slugs {
			w = append(w, slug)
		}
		return w
	}
	// pageWords is the same for a link to page.html, whose own name it shows.
	pageWords := func(fx fixture) []string {
		var w []string
		for _, s := range words(fx) {
			if s != "page.html" {
				w = append(w, s)
			}
		}
		return append(w, "report.pdf")
	}
	check := func(what string, rec *httptest.ResponseRecorder, wantCode int, ws []string) {
		t.Helper()
		if rec.Code != wantCode {
			t.Errorf("%s = %d, want %d: %s", what, rec.Code, wantCode, rec.Body)
		}
		namesNothing(t, what, rec, ws...)
	}
	nav := map[string]string{"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}
	bot := map[string]string{"User-Agent": telegramUA}

	// View, Download and HEAD of a stored and a linked file, and an HTML file.
	for _, fx := range []fixture{open, ln} {
		k := fx.keys[report]
		for _, m := range []string{"GET", "HEAD"} {
			check(m+" view", fileLinkReq(t, h, m, "/f/"+k, nil), 200, words(fx))
			check(m+" download", fileLinkReq(t, h, m, "/f/"+k+"/download", nil), 200, words(fx))
		}
		p := fx.keys["page.html"]
		check("html view", fileLinkReq(t, h, "GET", "/f/"+p, nil), 200, pageWords(fx))
		check("html download", fileLinkReq(t, h, "GET", "/f/"+p+"/download", nil), 200, pageWords(fx))
		check("card", fileLinkReq(t, h, "GET", "/f/"+k, bot), 200, words(fx))
		check("status", fileLinkReq(t, h, "GET", "/f/"+k+"/status", nil), 200, words(fx))
	}

	// The waiting page and its poll.
	pk := open.keys[pending]
	pendingWords := append(words(open), "report.pdf")
	for i, s := range pendingWords {
		if s == "pending.mp4" {
			pendingWords = append(pendingWords[:i:i], pendingWords[i+1:]...)
			break
		}
	}
	check("waiting view", fileLinkReq(t, h, "GET", "/f/"+pk, nil), 200, pendingWords)
	check("waiting download", fileLinkReq(t, h, "GET", "/f/"+pk+"/download", nil), 200, pendingWords)
	check("waiting card", fileLinkReq(t, h, "GET", "/f/"+pk, bot), 200, pendingWords)
	check("waiting poll", fileLinkReq(t, h, "GET", "/f/"+pk+"/status", nil), 200, pendingWords)

	// The password form, its card, a wrong guess, ?pw='s redirect, a right
	// guess, and what the cookie then opens.
	lk := locked.keys[report]
	lw := words(locked)
	check("form", fileLinkReq(t, h, "GET", "/f/"+lk, nil), 200, lw)
	check("form download", fileLinkReq(t, h, "GET", "/f/"+lk+"/download", nil), 200, lw)
	check("protected card", fileLinkReq(t, h, "GET", "/f/"+lk, bot), 200, lw)
	check("poll without the cookie", fileLinkReq(t, h, "GET", "/f/"+lk+"/status", nil), 401, lw)
	check("wrong guess", fileLinkUnlock(t, h, lk, "nope", "/f/"+lk), 401, lw)
	pw := fileLinkReq(t, h, "GET", "/f/"+lk+"/download?pw="+password, nav)
	check("?pw= redirect", pw, 303, lw)
	right := fileLinkUnlock(t, h, lk, password, "/f/"+lk+"/download")
	check("right guess", right, 303, lw)
	c := cookieNamed(right, "hdf_"+lk)
	if c == nil {
		t.Fatal("the right guess set no cookie")
	}
	check("unlocked view", fileLinkReq(t, h, "GET", "/f/"+lk, nil, c), 200, lw)
	lpk := locked.keys[pending]
	pc := cookieNamed(fileLinkUnlock(t, h, lpk, password, ""), "hdf_"+lpk)
	if pc == nil {
		t.Fatal("unlocking the pending file set no cookie")
	}
	lockedPending := append(words(locked), "report.pdf")
	for i, s := range lockedPending {
		if s == "pending.mp4" {
			lockedPending = append(lockedPending[:i:i], lockedPending[i+1:]...)
			break
		}
	}
	check("unlocked waiting", fileLinkReq(t, h, "GET", "/f/"+lpk, nil, pc), 200, lockedPending)
	check("unlocked poll", fileLinkReq(t, h, "GET", "/f/"+lpk+"/status", nil, pc), 200, lockedPending)

	// The 404s: a key of the wrong shape, one that names nothing, and one
	// the owner stopped.
	stopped := open.keys["other.txt"]
	if rec := doReq(t, h, "DELETE", "/api/shares/"+open.id+"/file-links/"+open.slugs["other.txt"], testToken, ""); rec.Code/100 != 2 {
		t.Fatalf("stop = %d %s", rec.Code, rec.Body)
	}
	for _, k := range []string{"short", shareid.NewFileKey(), stopped, open.id} {
		for _, p := range []string{"/f/" + k, "/f/" + k + "/download", "/f/" + k + "/status"} {
			check("404 "+p, fileLinkReq(t, h, "GET", p, nil), 404, words(open))
		}
		check("404 unlock", fileLinkUnlock(t, h, k, password, ""), 404, words(open))
	}

	// The cross-site embed refusal.
	yes := true
	if _, err := b.DB.UpdateUser(metadb.DefaultAdminName, metadb.Settings{NoEmbed: &yes}); err != nil {
		t.Fatal(err)
	}
	embed := map[string]string{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Dest": "image"}
	check("embed refusal", fileLinkReq(t, h, "GET", "/f/"+open.keys[report], embed), 403, words(open))

	// The lockout.
	wrong := url.Values{"password": {"nope"}}.Encode()
	var rec *httptest.ResponseRecorder
	for i := 0; i < pwFailLimit; i++ {
		rec = doReqFormFrom(t, h, "/f/"+lk+"/unlock", wrong, "203.0.113.50:1")
	}
	check("lockout", rec, 429, lw)

	// The unavailable page and its poll: the linked copy's folder is gone.
	if err := os.RemoveAll(filepath.Join(vol, source)); err != nil {
		t.Fatal(err)
	}
	lnk := ln.keys[report]
	for _, p := range []string{"/f/" + lnk, "/f/" + lnk + "/download"} {
		rec := fileLinkReq(t, h, "GET", p, nil)
		check("unavailable "+p, rec, 200, words(ln))
		if !strings.Contains(rec.Body.String(), "This file is unavailable") {
			t.Errorf("unavailable %s: %s", p, rec.Body)
		}
	}
	check("unavailable poll", fileLinkReq(t, h, "GET", "/f/"+lnk+"/status", nil), 200, words(ln))
	check("unavailable unlock", fileLinkUnlock(t, h, lnk, password, ""), 200, words(ln))

	// A live file: View, Download and HEAD while the sharer is online, its
	// card, then the offline answer.
	liveBody := `{"name":"` + name + `","files":[` +
		`{"path":"` + report + `","size":5,"mime":"application/pdf","mtime":"2026-08-06T10:00:00Z"},` +
		`{"path":"other.txt","size":7,"mime":"text/plain","mtime":"2026-08-06T10:00:00Z"}]}`
	lh := newTestLiveShareHandler(t)
	lmux := lh.routes()
	var live liveShareKeyedOut
	unmarshal(t, doReq(t, lmux, "POST", "/api/live-share", testToken, liveBody), &live)
	serveLiveShareBody(t, lh, live.ID, metadb.DefaultAdminName, "hello")
	liveWords := []string{live.ID, name, "secret-folder", "other.txt"}
	var liveKey string
	for _, f := range live.Files {
		liveWords = append(liveWords, f.Slug)
		if f.Path == report {
			liveKey = f.FileKey
		}
	}
	for _, m := range []string{"GET", "HEAD"} {
		for _, p := range []string{"/f/" + liveKey, "/f/" + liveKey + "/download"} {
			check("live "+m+" "+p, liveFileLinkReq(t, lmux, m, p), 200, liveWords)
		}
	}
	check("live card", fileLinkReq(t, lmux, "GET", "/f/"+liveKey, bot), 200, liveWords)

	now := time.Now()
	off := newTestHandlerLiveShare(t, liveshareConfigAt(&now))
	offMux := off.routes()
	unmarshal(t, doReq(t, offMux, "POST", "/api/live-share", testToken, liveBody), &live)
	now = now.Add(15 * time.Second)
	offWords := []string{live.ID, name, "secret-folder", "other.txt"}
	for _, f := range live.Files {
		offWords = append(offWords, f.Slug)
		if f.Path == report {
			liveKey = f.FileKey
		}
	}
	check("live offline", fileLinkReq(t, offMux, "GET", "/f/"+liveKey, nil), http.StatusServiceUnavailable, offWords)
}

// liveFileLinkReq is doLiveShareGet for any method: the request may wait on
// the sharer's rendezvous, so it times out rather than hanging the suite.
func liveFileLinkReq(t *testing.T, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("%s %s did not answer within 10 s", method, path)
	}
	return rec
}
