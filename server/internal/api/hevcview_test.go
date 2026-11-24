package api

import (
	"bytes"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// doReqRange asks for one window of a route, the way a player does.
func doReqRange(t *testing.T, h http.Handler, path, rng string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("Range", rng)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func hevcBox(typ string, parts ...[]byte) []byte {
	var body []byte
	for _, p := range parts {
		body = append(body, p...)
	}
	out := make([]byte, 8, 8+len(body))
	binary.BigEndian.PutUint32(out, uint32(8+len(body)))
	copy(out[4:], typ)
	return append(out, body...)
}

// hevcMovie is a file whose video track carries `entryType`, with the four
// letters also sitting in the picture data where they are not a tag.
func hevcMovie(entryType string) []byte {
	stsd := hevcBox("stsd", []byte{0, 0, 0, 0, 0, 0, 0, 1},
		hevcBox(entryType, bytes.Repeat([]byte{0x11}, 20)))
	moov := hevcBox("moov",
		hevcBox("trak", hevcBox("mdia", hevcBox("minf", hevcBox("stbl", stsd)))))
	mdat := hevcBox("mdat", []byte("....hev1....picture bytes...."))
	return append(append(hevcBox("ftyp", []byte("isommp41avc1")), moov...), mdat...)
}

func hevcTagAt(file []byte) int {
	// The sample entry's type, which is the one inside stsd rather than the
	// copy planted in the picture data.
	return bytes.Index(file, []byte("stsd")) + 4 + 8 + 4
}

// A browser refuses `hev1` exactly as Apple's decoders do, so the route that
// exists to SHOW the file hands it the name every decoder accepts. The route
// that exists to SAVE it hands over the owner's file, byte for byte.
func TestViewServesAnHEV1MovieAsHVC1AndDownloadDoesNot(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "camera")
	file := hevcMovie("hev1")
	slug := uploadGetSlug(t, h, id, "clip.mp4", string(file))

	view := doReq(t, h, "GET", "/view/"+id+"/"+slug, "", "")
	if view.Code != http.StatusOK {
		t.Fatalf("view status = %d", view.Code)
	}
	got := view.Body.Bytes()
	if len(got) != len(file) {
		t.Fatalf("view length = %d, want %d: a rewrite must not resize the file", len(got), len(file))
	}
	at := hevcTagAt(file)
	if string(got[at:at+4]) != "hvc1" {
		t.Fatalf("view sample entry = %q, want hvc1", got[at:at+4])
	}
	mdat := bytes.Index(file, []byte("mdat"))
	if !bytes.Equal(got[mdat:], file[mdat:]) {
		t.Fatal("view changed the picture data; only the sample entry's type may be rewritten")
	}

	down := doReq(t, h, "GET", "/download/"+id+"/"+slug, "", "")
	if down.Code != http.StatusOK {
		t.Fatalf("download status = %d", down.Code)
	}
	if !bytes.Equal(down.Body.Bytes(), file) {
		t.Fatal("download did not serve the stored file byte for byte")
	}
}

// The two routes now answer different bytes, so they must never validate
// against each other's cached copy.
func TestViewAndDownloadOfARetaggedMovieCarryDifferentETags(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "camera")
	slug := uploadGetSlug(t, h, id, "clip.mp4", string(hevcMovie("hev1")))

	view := doReq(t, h, "GET", "/view/"+id+"/"+slug, "", "")
	down := doReq(t, h, "GET", "/download/"+id+"/"+slug, "", "")
	vt, dt := view.Header().Get("ETag"), down.Header().Get("ETag")
	if vt == "" || dt == "" {
		t.Fatalf("missing ETag: view %q download %q", vt, dt)
	}
	if vt == dt {
		t.Fatalf("both routes answered ETag %q while serving different bytes", vt)
	}
}

// A player asks for windows, and the tag lands wherever it lands inside one.
func TestARangeOfAViewedMovieIsRewrittenAtTheRightOffset(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "camera")
	file := hevcMovie("hev1")
	slug := uploadGetSlug(t, h, id, "clip.mp4", string(file))
	at := hevcTagAt(file)

	rec := doReqRange(t, h, "/view/"+id+"/"+slug,
		"bytes="+strconv.Itoa(at+1)+"-"+strconv.Itoa(at+2))
	if rec.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206", rec.Code)
	}
	if rec.Body.String() != "vc" {
		t.Fatalf("window = %q, want the middle of hvc1", rec.Body.String())
	}
}

// Nothing to rewrite means nothing is touched: a movie that already plays
// must reach the viewer exactly as it was stored.
func TestViewServesAnHVC1MovieUnchanged(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "camera")
	file := hevcMovie("hvc1")
	slug := uploadGetSlug(t, h, id, "clip.mp4", string(file))

	view := doReq(t, h, "GET", "/view/"+id+"/"+slug, "", "")
	if !bytes.Equal(view.Body.Bytes(), file) {
		t.Fatal("an already-playable movie was changed on its way to the viewer")
	}
	down := doReq(t, h, "GET", "/download/"+id+"/"+slug, "", "")
	if view.Header().Get("ETag") != down.Header().Get("ETag") {
		t.Fatal("nothing was rewritten, so both routes serve one representation")
	}
}

// Anything may be named .mp4. A file that is not one is served as it is,
// rather than having four bytes rewritten somewhere in the middle of it.
func TestAFileThatIsNotAMovieIsServedUnchanged(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "camera")
	body := "hev1 hev1 hev1 not a movie at all"
	slug := uploadGetSlug(t, h, id, "notes.mp4", body)
	view := doReq(t, h, "GET", "/view/"+id+"/"+slug, "", "")
	if view.Body.String() != body {
		t.Fatalf("body = %q, want it untouched", view.Body.String())
	}
}

// gatedMovie is a movie reader whose scan starts by counting itself and then
// waits for the gate, so a test can hold the first scan open while others
// arrive.
type gatedMovie struct {
	*bytes.Reader
	scans *atomic.Int32
	gate  chan struct{}
	began bool
}

func (g *gatedMovie) Seek(off int64, whence int) (int64, error) {
	if !g.began {
		g.began = true
		g.scans.Add(1)
		<-g.gate
	}
	return g.Reader.Seek(off, whence)
}

// A player opens a movie with several Range requests at once. They all miss
// the cache together, and one scan answers them all rather than one each.
func TestConcurrentFirstViewsOfAMovieScanItOnce(t *testing.T) {
	_, hd := newTestAPIParts(t)
	file := hevcMovie("hev1")
	var scans atomic.Int32
	gate := make(chan struct{})
	var wg sync.WaitGroup
	results := make([][]int64, 8)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rs := &gatedMovie{Reader: bytes.NewReader(file), scans: &scans, gate: gate}
			results[i] = hd.hevcOffsets(shareView{}, "", "same-content", nil, rs)
		}()
	}
	deadline := time.Now().Add(5 * time.Second)
	for scans.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	close(gate)
	wg.Wait()
	if n := scans.Load(); n != 1 {
		t.Fatalf("%d scans of one movie, want 1", n)
	}
	for i, offs := range results {
		if len(offs) != 1 || offs[0] != int64(hevcTagAt(file)) {
			t.Fatalf("request %d got offsets %v, want [%d]", i, offs, hevcTagAt(file))
		}
	}
}

// panickingMovie is a file whose every read panics.
type panickingMovie struct{}

func (panickingMovie) Read([]byte) (int, error)       { panic("read") }
func (panickingMovie) Seek(int64, int) (int64, error) { panic("seek") }

// A scan that panics still releases the file's key: the next viewer scans it
// again rather than waiting forever on the scan that never finished.
func TestAScanThatPanicsReleasesItsWaiters(t *testing.T) {
	_, hd := newTestAPIParts(t)
	func() {
		defer func() { _ = recover() }()
		hd.hevcOffsets(shareView{}, "", "same-content", nil, panickingMovie{})
	}()
	file := hevcMovie("hev1")
	got := make(chan []int64, 1)
	go func() { got <- hd.hevcOffsets(shareView{}, "", "same-content", nil, bytes.NewReader(file)) }()
	select {
	case offs := <-got:
		if len(offs) != 1 || offs[0] != int64(hevcTagAt(file)) {
			t.Fatalf("offsets after the panicked scan = %v, want [%d]", offs, hevcTagAt(file))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the next viewer waited on the scan that panicked")
	}
}
