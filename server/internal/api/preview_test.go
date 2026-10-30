package api

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"image"
	_ "image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/metadb"
)

// telegramUA is a real Telegram link-preview User-Agent.
const telegramUA = "TelegramBot (like TwitterBot)"

// chromeUA is an ordinary browser: the traffic that must NEVER see a card.
const chromeUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 " +
	"(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

func doReqUA(t *testing.T, h http.Handler, path, ua string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("User-Agent", ua)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// metaContent pulls the content of an og/twitter meta tag out of rendered
// HTML. Empty when the tag is absent.
func metaContent(body, property string) string {
	for _, attr := range []string{`property="` + property + `"`, `name="` + property + `"`} {
		i := strings.Index(body, attr)
		if i < 0 {
			continue
		}
		rest := body[i+len(attr):]
		j := strings.Index(rest, `content="`)
		if j < 0 {
			continue
		}
		rest = rest[j+len(`content="`):]
		if k := strings.Index(rest, `"`); k >= 0 {
			return rest[:k]
		}
	}
	return ""
}

func TestIsUnfurler(t *testing.T) {
	bots := []string{
		"TelegramBot (like TwitterBot)",
		"Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)",
		"Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
		"Slackbot 1.0 (+https://api.slack.com/robots)",
		"facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
		"Twitterbot/1.0",
		"WhatsApp/2.19.81 A",
		"LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com)",
		"SkypeUriPreview Preview/0.5",
		"Iframely/1.3.1 (+http://iframely.com/docs/about)",
		"redditbot/1.0",
		"Mozilla/5.0 (compatible; Bluesky Cardyb/1.1)",
		"http.rb/5.1.1 (Mastodon/4.2.1; +https://mastodon.social/)",
		"vkShare; +http://vk.com/dev/Share",
		"Mozilla/5.0 (compatible; Pinterestbot/1.0; +http://www.pinterest.com/bot.html)",
		"Pinterest/0.2 (+http://www.pinterest.com/bot.html)",
	}
	for _, ua := range bots {
		if !isUnfurler(ua) {
			t.Errorf("isUnfurler(%q) = false, want true", ua)
		}
	}

	humans := []string{
		"",
		chromeUA,
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 " +
			"(KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
		"curl/8.6.0",
		"Wget/1.21.4",
		"Go-http-client/2.0",
		"hyperdrop/1.0.0",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 " +
			"(KHTML, like Gecko) Mobile/15E148 [Pinterest/iOS]",
		"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) " +
			"Chrome/126.0 Mobile Safari/537.36 [Pinterest/Android]",
	}
	for _, ua := range humans {
		if isUnfurler(ua) {
			t.Errorf("isUnfurler(%q) = true, want false", ua)
		}
	}
}

// A browser asking for a file gets the file. This is the regression that
// matters most: bot detection must never intercept human traffic.
func TestBrowserGetsBytesNotCard(t *testing.T) {
	h := newTestAPI(t)
	id, slugs := shareWithFiles(t, h, "pics", map[string]string{"a.png": "\x89PNG fake"})
	rec := doReqUA(t, h, "/view/"+id+"/"+slugs["a.png"], chromeUA)
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "image/png" {
		t.Errorf("Content-Type = %q, want image/png", ct)
	}
	if rec.Body.String() != "\x89PNG fake" {
		t.Errorf("body = %q, want the file bytes", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "og:title") {
		t.Error("browser response contains og tags")
	}
}

func TestSingleFileCard(t *testing.T) {
	h := newTestAPI(t)
	id, slugs := shareWithFiles(t, h, "report",
		map[string]string{"severance-agreement.pdf": strings.Repeat("x", 2048)})
	rec := doReqUA(t, h, "/view/"+id+"/"+slugs["severance-agreement.pdf"], telegramUA)
	if rec.Code != 200 {
		t.Fatalf("status = %d body %s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", ct)
	}
	body := rec.Body.String()
	if got := metaContent(body, "og:title"); got != "severance-agreement.pdf" {
		t.Errorf("og:title = %q, want the filename", got)
	}
	desc := metaContent(body, "og:description")
	for _, want := range []string{"PDF", "2.0 KB", "Shared via HyperDrop"} {
		if !strings.Contains(desc, want) {
			t.Errorf("og:description = %q, want it to contain %q", desc, want)
		}
	}
	if got := metaContent(body, "og:image"); got != "https://203.0.113.7/card.png" {
		t.Errorf("og:image = %q", got)
	}
	if got := metaContent(body, "og:url"); got != "https://203.0.113.7/view/"+id+"/"+slugs["severance-agreement.pdf"] {
		t.Errorf("og:url = %q", got)
	}
	if got := metaContent(body, "twitter:card"); got != "summary" {
		t.Errorf("twitter:card = %q, want summary", got)
	}
	// The card must not leak the file's bytes.
	if strings.Contains(body, strings.Repeat("x", 100)) {
		t.Error("card contains file content")
	}
}

func TestDownloadLinkCardServesNoBytes(t *testing.T) {
	h := newTestAPI(t)
	big := strings.Repeat("A", 5000)
	id, slugs := shareWithFiles(t, h, "dl", map[string]string{"movie.mp4": big})
	rec := doReqUA(t, h, "/download/"+id+"/"+slugs["movie.mp4"], telegramUA)
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), big) {
		t.Error("/download card streamed the file to a bot")
	}
	if got := metaContent(rec.Body.String(), "og:title"); got != "movie.mp4" {
		t.Errorf("og:title = %q", got)
	}
	if cd := rec.Header().Get("Content-Disposition"); cd != "" {
		t.Errorf("Content-Disposition = %q, want none on a card", cd)
	}
}

func TestFolderCard(t *testing.T) {
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "vacation-photos", map[string]string{
		"a.jpg": strings.Repeat("x", 1024),
		"b.jpg": strings.Repeat("y", 1024),
		"c.jpg": strings.Repeat("z", 1024),
	})
	// The listing page carries the tags for everyone, bot or not.
	rec := doReqUA(t, h, "/share/"+id, telegramUA)
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if got := metaContent(body, "og:title"); got != "vacation-photos" {
		t.Errorf("og:title = %q, want the share name", got)
	}
	desc := metaContent(body, "og:description")
	for _, want := range []string{"3 files", "3.0 KB", "Shared via HyperDrop"} {
		if !strings.Contains(desc, want) {
			t.Errorf("og:description = %q, want it to contain %q", desc, want)
		}
	}
	if got := metaContent(body, "og:url"); got != "https://203.0.113.7/share/"+id {
		t.Errorf("og:url = %q", got)
	}
}

// An unnamed multi-file share falls back to a file count, never to a blank
// title or the share ID.
func TestFolderCardUnnamedFallsBackToCount(t *testing.T) {
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "", map[string]string{"a.txt": "1", "b.txt": "2"})
	rec := doReqUA(t, h, "/share/"+id, telegramUA)
	if got := metaContent(rec.Body.String(), "og:title"); got != "2 files" {
		t.Errorf("og:title = %q, want %q", got, "2 files")
	}
}

// A zip link handed to a bot returns the card, not a generated archive.
func TestZipCardGeneratesNoArchive(t *testing.T) {
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "bundle", map[string]string{
		"a.txt": strings.Repeat("a", 4096), "b.txt": strings.Repeat("b", 4096)})
	rec := doReqUA(t, h, "/zip/"+id, telegramUA)
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html (a card, not a zip)", ct)
	}
	if bytes.HasPrefix(rec.Body.Bytes(), []byte("PK")) {
		t.Error("bot got a real zip stream")
	}
	if got := metaContent(rec.Body.String(), "og:title"); got != "bundle" {
		t.Errorf("og:title = %q", got)
	}
}

// A password-protected share reveals nothing beyond "it is protected": the
// share name and filenames must appear nowhere in the response.
func TestProtectedShareCardHidesName(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"name":"secret-merger-docs","password":"hunter2"}`)
	if rec.Code != 201 {
		t.Fatalf("create status = %d body %s", rec.Code, rec.Body)
	}
	var created struct {
		ID string `json:"id"`
	}
	unmarshal(t, rec, &created)
	slug := uploadGetSlug(t, h, created.ID, "acquisition-terms.pdf", "confidential")

	for _, path := range []string{"/share/" + created.ID, "/view/" + created.ID + "/" + slug, "/zip/" + created.ID} {
		w := doReqUA(t, h, path, telegramUA)
		body := w.Body.String()
		if got := metaContent(body, "og:title"); got != "Password-protected" {
			t.Errorf("%s: og:title = %q, want %q", path, got, "Password-protected")
		}
		for _, leak := range []string{"secret-merger-docs", "acquisition-terms.pdf", "confidential"} {
			if strings.Contains(body, leak) {
				t.Errorf("%s: response leaks %q", path, leak)
			}
		}
	}
}

// Early links get pasted before the upload finishes. The card shows the
// final size and never a progress figure, because preview caches freeze whatever
// they see first, so "uploading… 40%" would be permanent.
func TestPendingFileCardShowsFinalSizeNotProgress(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"name":"docs","files":[{"path":"report.pdf","size":2048}]}`)
	if rec.Code != 201 {
		t.Fatalf("create status = %d body %s", rec.Code, rec.Body)
	}
	var resp shareResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	w := doReqUA(t, h, "/view/"+resp.ID+"/"+resp.Files[0].Slug, telegramUA)
	if w.Code != 200 {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	if got := metaContent(body, "og:title"); got != "report.pdf" {
		t.Errorf("og:title = %q", got)
	}
	desc := metaContent(body, "og:description")
	if !strings.Contains(desc, "2.0 KB") {
		t.Errorf("og:description = %q, want the final size", desc)
	}
	// Nothing a cache would freeze wrongly: no progress, no "uploading".
	for _, transient := range []string{"uploading", "%", "waiting", "pending"} {
		if strings.Contains(strings.ToLower(desc), transient) {
			t.Errorf("og:description %q contains transient state %q", desc, transient)
		}
	}
	if strings.Contains(strings.ToLower(body), "uploading") {
		t.Error("card page contains upload progress")
	}
}

func TestExpiredShareHasNoCard(t *testing.T) {
	h, b := newTestAPIBackend(t)
	past := time.Now().Add(-time.Hour).UTC()
	d, err := b.DB.CreateShare(metadb.CreateOptions{Name: "gone", Owner: metadb.DefaultAdminName,
		ExpiresAt: &past})
	if err != nil {
		t.Fatal(err)
	}
	commitFile(t, b, d.ID, "a.txt", "bye")
	got, err := b.DB.Share(d.ID)
	if err != nil {
		t.Fatal(err)
	}
	sh := got
	slug := got.Files[0].Slug

	for _, path := range []string{"/share/" + sh.ID, "/view/" + sh.ID + "/" + slug, "/zip/" + sh.ID} {
		w := doReqUA(t, h, path, telegramUA)
		if w.Code != 404 {
			t.Errorf("%s: status = %d, want 404", path, w.Code)
		}
		if strings.Contains(w.Body.String(), "og:title") {
			t.Errorf("%s: expired share still emits a card", path)
		}
	}
}

// og:url comes from the server's own identity, never from the request Host,
// which is attacker-controlled.
func TestCardURLIgnoresSpoofedHost(t *testing.T) {
	h := newTestAPI(t)
	id, slugs := shareWithFiles(t, h, "x", map[string]string{"a.txt": "hi"})
	req := httptest.NewRequest("GET", "/view/"+id+"/"+slugs["a.txt"], nil)
	req.Header.Set("User-Agent", telegramUA)
	req.Host = "evil.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body := rec.Body.String()
	if strings.Contains(body, "evil.example.com") {
		t.Error("card reflects the Host header")
	}
	if got := metaContent(body, "og:url"); !strings.HasPrefix(got, "https://203.0.113.7/") {
		t.Errorf("og:url = %q, want the configured IP", got)
	}
}

func TestOGImageIsAPNG(t *testing.T) {
	h := newTestAPI(t)
	rec := doReqUA(t, h, "/card.png", telegramUA)
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "image/png" {
		t.Errorf("Content-Type = %q", ct)
	}
	cfg, format, err := image.DecodeConfig(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if format != "png" {
		t.Errorf("format = %q", format)
	}
	if cfg.Width != 1200 || cfg.Height != 630 {
		t.Errorf("size = %dx%d, want 1200x630", cfg.Width, cfg.Height)
	}
}

func TestPublicRoutesAreNoIndex(t *testing.T) {
	h := newTestAPI(t)
	id, slugs := shareWithFiles(t, h, "s", map[string]string{"a.txt": "hi", "b.txt": "yo"})
	for _, path := range []string{"/view/" + id + "/" + slugs["a.txt"], "/download/" + id + "/" + slugs["a.txt"], "/zip/" + id} {
		rec := doReqUA(t, h, path, chromeUA)
		if got := rec.Header().Get("X-Robots-Tag"); got != "noindex" {
			t.Errorf("%s: X-Robots-Tag = %q, want noindex", path, got)
		}
	}
	// HTML pages carry the meta tag too.
	rec := doReqUA(t, h, "/share/"+id, chromeUA)
	if !strings.Contains(rec.Body.String(), `name="robots" content="noindex"`) {
		t.Error("listing page has no robots noindex meta")
	}
}

// --- playable video cards ---------------------------------------------------

// mp4Fixture builds a minimal but structurally valid MP4 header: ftyp, then
// moov{mvhd, trak{tkhd}}, then an mdat of filler. Enough for the metadata
// walk, which reads header integers and decodes nothing.
func mp4Fixture(durationSec, width, height, fillerBytes int) string {
	box := func(name string, payload []byte) []byte {
		out := make([]byte, 8, 8+len(payload))
		binary.BigEndian.PutUint32(out[0:4], uint32(8+len(payload)))
		copy(out[4:8], name)
		return append(out, payload...)
	}
	// mvhd v0: version+flags, ctime, mtime, timescale, duration, then the
	// rate/volume/matrix/predefined tail the spec fixes at 80 bytes.
	mvhd := make([]byte, 100)
	mvhd[0] = 0                                                       // version 0
	binary.BigEndian.PutUint32(mvhd[12:16], 1000)                     // timescale
	binary.BigEndian.PutUint32(mvhd[16:20], uint32(durationSec*1000)) // duration
	// tkhd v0: 84-byte body with 16.16 fixed-point width/height at the end.
	tkhd := make([]byte, 84)
	tkhd[0] = 0
	binary.BigEndian.PutUint32(tkhd[76:80], uint32(width)<<16)
	binary.BigEndian.PutUint32(tkhd[80:84], uint32(height)<<16)

	var out []byte
	out = append(out, box("ftyp", []byte("isomiso2avc1mp41"))...)
	moov := append(box("mvhd", mvhd), box("trak", box("tkhd", tkhd))...)
	out = append(out, box("moov", moov)...)
	out = append(out, box("mdat", bytes.Repeat([]byte("v"), fillerBytes))...)
	return string(out)
}

func TestVideoCardIsPlayable(t *testing.T) {
	h := newTestAPI(t)
	id, slugs := shareWithFiles(t, h, "demo",
		map[string]string{"screencast.mp4": mp4Fixture(23, 1920, 1200, 4096)})
	body := doReqUA(t, h, "/view/"+id+"/"+slugs["screencast.mp4"], telegramUA).Body.String()

	if got := metaContent(body, "og:type"); got != "video.other" {
		t.Errorf("og:type = %q, want video.other (else chat apps show a still tile)", got)
	}
	wantVideo := "https://203.0.113.7/view/" + id + "/" + slugs["screencast.mp4"] + "?ogmedia=1"
	if got := metaContent(body, "og:video"); got != wantVideo {
		t.Errorf("og:video = %q, want %q", got, wantVideo)
	}
	if got := metaContent(body, "og:video:secure_url"); got != wantVideo {
		t.Errorf("og:video:secure_url = %q", got)
	}
	if got := metaContent(body, "og:video:type"); got != "video/mp4" {
		t.Errorf("og:video:type = %q", got)
	}
	if got := metaContent(body, "og:video:width"); got != "1920" {
		t.Errorf("og:video:width = %q, want 1920 from the mp4 header", got)
	}
	if got := metaContent(body, "og:video:height"); got != "1200" {
		t.Errorf("og:video:height = %q", got)
	}
	// The duration comes from the header too, and reads like a player.
	if desc := metaContent(body, "og:description"); !strings.Contains(desc, "0:23") {
		t.Errorf("og:description = %q, want the 0:23 duration", desc)
	}
	// Still metadata only: the card itself carries no frame of the file.
	if strings.Contains(body, strings.Repeat("v", 100)) {
		t.Error("card contains file content")
	}
}

// The card points og:video at its OWN url, which the chat app fetches with the
// same bot User-Agent, so without the escape hatch we would answer our own
// preview with HTML and nothing would ever play.
func TestOGMediaFetchGetsBytesNotCard(t *testing.T) {
	h := newTestAPI(t)
	content := mp4Fixture(5, 640, 480, 2048)
	id, slugs := shareWithFiles(t, h, "demo", map[string]string{"clip.mp4": content})
	rec := doReqUA(t, h, "/view/"+id+"/"+slugs["clip.mp4"]+"?ogmedia=1", telegramUA)
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "video/mp4" {
		t.Errorf("Content-Type = %q, want video/mp4", ct)
	}
	if rec.Body.Len() != len(content) {
		t.Errorf("body = %d bytes, want the whole file (%d)", rec.Body.Len(), len(content))
	}
	// The plain bot fetch of the same URL still gets the card.
	plain := doReqUA(t, h, "/view/"+id+"/"+slugs["clip.mp4"], telegramUA)
	if ct := plain.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("without ogmedia: Content-Type = %q, want the card", ct)
	}
}

// Only MP4 is advertised as playable: a raw .mov (what Finder hands over) would
// be downloaded by the chat app and then fail to play.
func TestNonMP4GetsNoPlayableCard(t *testing.T) {
	h := newTestAPI(t)
	id, slugs := shareWithFiles(t, h, "raw",
		map[string]string{"recording.mov": mp4Fixture(10, 1280, 720, 1024)})
	body := doReqUA(t, h, "/view/"+id+"/"+slugs["recording.mov"], telegramUA).Body.String()
	if got := metaContent(body, "og:video"); got != "" {
		t.Errorf("og:video = %q, want none for a .mov", got)
	}
	if got := metaContent(body, "og:type"); got != "website" {
		t.Errorf("og:type = %q, want website", got)
	}
}

func TestProtectedVideoRevealsNothing(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"demo","password":"s3cret"}`)
	if rec.Code != 201 {
		t.Fatalf("create status = %d body %s", rec.Code, rec.Body)
	}
	var created struct {
		ID string `json:"id"`
	}
	unmarshal(t, rec, &created)
	id := created.ID
	slug := uploadGetSlug(t, h, id, "screencast.mp4", mp4Fixture(23, 1920, 1200, 4096))
	body := doReqUA(t, h, "/view/"+id+"/"+slug, telegramUA).Body.String()
	if got := metaContent(body, "og:video"); got != "" {
		t.Errorf("og:video = %q: a protected share must reveal no content", got)
	}
	if got := metaContent(body, "og:title"); got != "Password-protected" {
		t.Errorf("og:title = %q", got)
	}
}

// The gates that are cheaper to test directly than by staging the file.
func TestVideoCardFieldsGates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clip.mp4")
	if err := os.WriteFile(path, []byte(mp4Fixture(9, 800, 600, 256)), 0o600); err != nil {
		t.Fatal(err)
	}
	open := func() (*os.File, error) { return os.Open(path) }
	// A file that cannot be opened is a playable card without its header facts.
	missing := func() (*os.File, error) { return os.Open(path + ".missing") }
	if _, info, got := videoCardFields(fileView{File: metadb.File{Path: "clip.mp4", Mime: "video/mp4", Size: 1 << 20}}, missing); !got || info != (mp4Info{}) {
		t.Errorf("unopenable mp4: ok=%v info=%+v", got, info)
	}
	ok := fileView{File: metadb.File{Path: "clip.mp4", Mime: "video/mp4", Size: 1 << 20}}
	if _, info, got := videoCardFields(ok, open); !got || info.Width != 800 || info.Duration != 9 {
		t.Errorf("committed small mp4: ok=%v info=%+v", got, info)
	}
	// A pending (early-link) file's /view serves a waiting page; a preview cache
	// would freeze "broken" forever.
	pending := ok
	pending.Pending = true
	if _, _, got := videoCardFields(pending, open); got {
		t.Error("pending file must not be advertised as playable")
	}
	// Past the cap the chat app gives up anyway, and fetching it would cost a
	// full transfer of the file for nothing.
	big := ok
	big.Size = ogVideoMaxBytes + 1
	if _, _, got := videoCardFields(big, open); got {
		t.Error("oversized video must not be advertised as playable")
	}
	// Parameterised mime ("video/mp4; codecs=…") still counts.
	param := ok
	param.Mime = "video/mp4; codecs=avc1.640028"
	if _, _, got := videoCardFields(param, open); !got {
		t.Error("mime with parameters must still count as mp4")
	}
	// A media type is case-insensitive.
	upper := ok
	upper.Mime = "Video/MP4"
	if _, _, got := videoCardFields(upper, open); !got {
		t.Error("an upper-case video/mp4 must still count as mp4")
	}
}

func TestReadMP4InfoSurvivesGarbage(t *testing.T) {
	cases := map[string]string{
		"empty.mp4":     "",
		"short.mp4":     "abc",
		"lying.mp4":     string([]byte{0xff, 0xff, 0xff, 0xff}) + "moov" + strings.Repeat("\x00", 40),
		"notavideo.mp4": strings.Repeat("garbage", 100),
	}
	for name, content := range cases {
		// Must not panic, must not hang, must report nothing.
		if info := readMP4Info(strings.NewReader(content)); info != (mp4Info{}) {
			t.Errorf("%s: info = %+v, want zero", name, info)
		}
	}
}

func TestHumanDuration(t *testing.T) {
	for _, c := range []struct {
		in   int
		want string
	}{{0, "0:00"}, {5, "0:05"}, {23, "0:23"}, {247, "4:07"}, {3731, "1:02:11"}, {-3, "0:00"}} {
		if got := humanDuration(c.in); got != c.want {
			t.Errorf("humanDuration(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}
