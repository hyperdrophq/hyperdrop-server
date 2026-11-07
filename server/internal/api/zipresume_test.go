package api

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

var zipResumeFiles = map[string]string{
	"a.txt":     "alpha",
	"sub/b.txt": strings.Repeat("bravo ", 2000),
	"sub/c.txt": "charlie",
	"z.txt":     strings.Repeat("zulu ", 3000),
}

func zipFrom(t *testing.T, h http.Handler, path string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	return doReqHeaders(t, h, http.MethodGet, path, hdr)
}

// zipExtracts reads body as an archive and compares every file, CRCs checked.
func zipExtracts(t *testing.T, body []byte, want map[string]string) {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("not an archive: %v", err)
	}
	if len(zr.File) != len(want) {
		t.Fatalf("%d entries, want %d", len(zr.File), len(want))
	}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("%s: %v", f.Name, err)
		}
		if string(got) != want[f.Name] {
			t.Fatalf("%s: wrong bytes", f.Name)
		}
	}
}

func TestAZipIsTheSameBytesEachTime(t *testing.T) {
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "bundle", zipResumeFiles)
	first := zipFrom(t, h, "/zip/"+id, nil)
	time.Sleep(1100 * time.Millisecond) // past the archive's one-second clock
	second := zipFrom(t, h, "/zip/"+id, nil)
	if first.Code != 200 || second.Code != 200 {
		t.Fatalf("codes %d, %d", first.Code, second.Code)
	}
	if !bytes.Equal(first.Body.Bytes(), second.Body.Bytes()) {
		t.Fatal("two requests got different bytes")
	}
	if first.Header().Get("Accept-Ranges") != "bytes" {
		t.Errorf("Accept-Ranges %q", first.Header().Get("Accept-Ranges"))
	}
	etag := first.Header().Get("ETag")
	if !strings.HasPrefix(etag, `"`) || etag != second.Header().Get("ETag") {
		t.Errorf("ETags %q, %q: want one strong validator", etag, second.Header().Get("ETag"))
	}
	if first.Header().Get("Content-Length") != strconv.Itoa(first.Body.Len()) {
		t.Errorf("Content-Length %q, body %d", first.Header().Get("Content-Length"), first.Body.Len())
	}
	zipExtracts(t, first.Body.Bytes(), zipResumeFiles)
}

// An entry carries the time it was uploaded, not the time of the download.
func TestAZipEntryCarriesItsCommitTime(t *testing.T) {
	h, b := newTestAPIBackend(t)
	id, _ := shareWithFiles(t, h, "bundle", map[string]string{"a.txt": "alpha"})
	f, err := b.DB.File(id, "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	body := zipFrom(t, h, "/zip/"+id, nil).Body.Bytes()
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := zr.File[0].Modified.Unix(), f.CommittedAt.Unix(); got != want {
		t.Fatalf("entry time %d, committed %d", got, want)
	}
}

func TestAZipResumesFromWhereItStopped(t *testing.T) {
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "bundle", zipResumeFiles)
	whole := zipFrom(t, h, "/zip/"+id, nil)
	etag := whole.Header().Get("ETag")
	body := whole.Body.Bytes()
	for _, cut := range []int{0, 1, 30, 100, 5000, len(body) / 2, len(body) - 30, len(body) - 1} {
		rec := zipFrom(t, h, "/zip/"+id, map[string]string{"Range": fmt.Sprintf("bytes=%d-", cut), "If-Range": etag})
		if rec.Code != http.StatusPartialContent {
			t.Fatalf("from %d: code %d", cut, rec.Code)
		}
		if got, want := rec.Header().Get("Content-Range"), fmt.Sprintf("bytes %d-%d/%d", cut, len(body)-1, len(body)); got != want {
			t.Fatalf("Content-Range %q, want %q", got, want)
		}
		if got, want := rec.Header().Get("Content-Length"), strconv.Itoa(len(body)-cut); got != want {
			t.Fatalf("Content-Length %q, want %q", got, want)
		}
		if rec.Header().Get("ETag") != etag {
			t.Fatalf("ETag changed: %q", rec.Header().Get("ETag"))
		}
		if !bytes.Equal(rec.Body.Bytes(), body[cut:]) {
			t.Fatalf("from %d: wrong bytes", cut)
		}
		zipExtracts(t, append(append([]byte{}, body[:cut]...), rec.Body.Bytes()...), zipResumeFiles)
	}
}

// The forms curl and download managers send, and the ones a server may ignore.
func TestAZipAnswersEachRangeForm(t *testing.T) {
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "bundle", zipResumeFiles)
	whole := zipFrom(t, h, "/zip/"+id, nil)
	body := whole.Body.Bytes()
	total := len(body)
	for _, c := range []struct {
		rng  string
		code int
		want []byte
	}{
		{"bytes=0-9", 206, body[:10]},
		{"bytes=100-199", 206, body[100:200]},
		{"bytes=-22", 206, body[total-22:]},
		{fmt.Sprintf("bytes=%d-999999999", total-5), 206, body[total-5:]},
		{"bytes=0-0,5-9", 200, body},
		{"bytes=abc", 200, body},
		{"items=0-5", 200, body},
		{"bytes=9-5", 200, body},
	} {
		rec := zipFrom(t, h, "/zip/"+id, map[string]string{"Range": c.rng})
		if rec.Code != c.code || !bytes.Equal(rec.Body.Bytes(), c.want) {
			t.Errorf("%s: code %d, %d bytes", c.rng, rec.Code, rec.Body.Len())
		}
	}
	rec := zipFrom(t, h, "/zip/"+id, map[string]string{"Range": fmt.Sprintf("bytes=%d-", total)})
	if rec.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("past the end: code %d", rec.Code)
	}
	if got, want := rec.Header().Get("Content-Range"), fmt.Sprintf("bytes */%d", total); got != want {
		t.Fatalf("Content-Range %q, want %q", got, want)
	}
}

// A resume after the share changed must not stitch two archives together.
func TestAZipResumeAfterAChangeStartsOver(t *testing.T) {
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "bundle", map[string]string{"a.txt": "alpha", "b.txt": "bravo"})
	before := zipFrom(t, h, "/zip/"+id, nil).Header().Get("ETag")
	replaceFile(t, h, id, "a.txt", "ALPHA") // the same length, other bytes
	rec := zipFrom(t, h, "/zip/"+id, map[string]string{"Range": "bytes=10-", "If-Range": before})
	if rec.Code != 200 {
		t.Fatalf("code %d, want the whole archive", rec.Code)
	}
	if rec.Header().Get("ETag") == before {
		t.Fatal("other bytes under the same validator")
	}
	zipExtracts(t, rec.Body.Bytes(), map[string]string{"a.txt": "ALPHA", "b.txt": "bravo"})
}

// Chrome's validator is the ETag; a date cannot prove the archive is the same one.
func TestADateIsNotAZipValidator(t *testing.T) {
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "bundle", zipResumeFiles)
	rec := zipFrom(t, h, "/zip/"+id, map[string]string{"Range": "bytes=10-", "If-Range": time.Now().UTC().Format(http.TimeFormat)})
	if rec.Code != 200 {
		t.Fatalf("code %d", rec.Code)
	}
}

// One folder and the whole share are different archives.
func TestAFolderZipResumesOnItsOwnValidator(t *testing.T) {
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "bundle", zipResumeFiles)
	whole := zipFrom(t, h, "/zip/"+id, nil).Header().Get("ETag")
	folder := zipFrom(t, h, "/zip/"+id+"?dir=sub", nil)
	if folder.Header().Get("ETag") == whole {
		t.Fatal("a folder shares the whole archive's validator")
	}
	body := folder.Body.Bytes()
	want := map[string]string{"b.txt": zipResumeFiles["sub/b.txt"], "c.txt": "charlie"}
	zipExtracts(t, body, want)
	rec := zipFrom(t, h, "/zip/"+id+"?dir=sub", map[string]string{"Range": "bytes=50-", "If-Range": folder.Header().Get("ETag")})
	if rec.Code != 206 || !bytes.Equal(rec.Body.Bytes(), body[50:]) {
		t.Fatalf("code %d, %d bytes", rec.Code, rec.Body.Len())
	}
}

func TestAZipRemembersTheCRCsItMeasured(t *testing.T) {
	h, b := newTestAPIBackend(t)
	id, _ := shareWithFiles(t, h, "bundle", zipResumeFiles)
	zipFrom(t, h, "/zip/"+id, nil)
	for p := range zipResumeFiles {
		f, err := b.DB.File(id, p)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := f.CRC32(); !ok {
			t.Errorf("%s: no CRC kept", p)
		}
	}
}

// replaceFile uploads over a path in a session of its own: the same bytes count from
// one session is that session's retry, which changes nothing.
func replaceFile(t *testing.T, h http.Handler, id, path, content string) {
	t.Helper()
	rec := doReqSession(t, h, "/api/shares/"+id+"/files/"+path, content, "0", strconv.Itoa(len(content)), "replacing")
	if rec.Code != 201 {
		t.Fatalf("replace %s: %d %s", path, rec.Code, rec.Body)
	}
}

// serveUntilAborted runs a request that must end by dropping its connection.
func serveUntilAborted(t *testing.T, h http.Handler, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	defer func() {
		if got := recover(); got != http.ErrAbortHandler {
			t.Fatalf("recovered %v, want the connection dropped", got)
		}
	}()
	h.ServeHTTP(w, r)
}

// failingResponse takes left bytes and then fails, a client gone part way.
type failingResponse struct {
	*httptest.ResponseRecorder
	left int
}

func (f *failingResponse) Write(p []byte) (int, error) {
	if len(p) > f.left {
		f.left = 0
		return 0, errors.New("client gone")
	}
	f.left -= len(p)
	return f.ResponseRecorder.Write(p)
}

// A download cut off is exactly when the next request needs what the stream measured.
func TestAZipCutOffKeepsTheCRCsItFinished(t *testing.T) {
	h, b := newTestAPIBackend(t)
	id, _ := shareWithFiles(t, h, "bundle", zipResumeFiles)
	rec := &failingResponse{ResponseRecorder: httptest.NewRecorder(), left: 20000}
	serveUntilAborted(t, h, rec, httptest.NewRequest(http.MethodGet, "/zip/"+id, nil))
	f, err := b.DB.File(id, "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.CRC32(); !ok {
		t.Fatal("the first file finished before the cut, and its CRC was lost")
	}
	if z, _ := b.DB.File(id, "z.txt"); func() bool { _, ok := z.CRC32(); return ok }() {
		t.Fatal("a file never sent has a CRC")
	}
}

// With every CRC kept, a resume reads only the bytes it sends: the earlier files need
// not even exist any more, the rows being the truth about them.
func TestAResumeDoesNotRereadWhatWasSent(t *testing.T) {
	h, b := newTestAPIBackend(t)
	id, _ := shareWithFiles(t, h, "bundle", zipResumeFiles)
	whole := zipFrom(t, h, "/zip/"+id, nil)
	p, err := b.FS.FilePath(id, "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	cut := whole.Body.Len() - 100
	rec := zipFrom(t, h, "/zip/"+id, map[string]string{"Range": fmt.Sprintf("bytes=%d-", cut), "If-Range": whole.Header().Get("ETag")})
	if rec.Code != 206 || !bytes.Equal(rec.Body.Bytes(), whole.Body.Bytes()[cut:]) {
		t.Fatalf("code %d, %d bytes", rec.Code, rec.Body.Len())
	}
}

// A resume nothing has measured for, say after a crash lost what its stream measured,
// reads what it must and still answers the right bytes.
func TestAResumeWithNoCRCsMeasuresThem(t *testing.T) {
	h := newTestAPI(t)
	for _, cut := range []int{-100, -1, 5, 8000} {
		id, _ := shareWithFiles(t, h, "bundle", zipResumeFiles)
		from := fmt.Sprintf("bytes=%d-", cut)
		if cut < 0 {
			from = fmt.Sprintf("bytes=%d", cut)
		}
		rec := zipFrom(t, h, "/zip/"+id, map[string]string{"Range": from})
		if rec.Code != 206 {
			t.Fatalf("%s: code %d", from, rec.Code)
		}
		whole := zipFrom(t, h, "/zip/"+id, nil).Body.Bytes()
		if !bytes.HasSuffix(whole, rec.Body.Bytes()) {
			t.Fatalf("%s: wrong bytes", from)
		}
	}
}

// Bytes changed under a stream that has already answered: the CRC it holds is the old
// bytes', so the stream stops rather than hand over an archive that fails to extract.
func TestAFileReplacedWhileAZipRunsEndsTheStream(t *testing.T) {
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "bundle", map[string]string{
		"a.txt": strings.Repeat("a", 2*zipStallChunk), "b.txt": "bravo",
	})
	zipFrom(t, h, "/zip/"+id, nil) // every CRC measured
	rec := &gatedRecorder{ResponseRecorder: httptest.NewRecorder(), started: make(chan struct{}), gate: make(chan struct{})}
	panicked := make(chan any, 1)
	go func() {
		defer func() { panicked <- recover() }()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/zip/"+id, nil))
	}()
	<-rec.started
	replaceFile(t, h, id, "b.txt", "BRAVO")
	close(rec.gate)
	if got := <-panicked; got != http.ErrAbortHandler {
		t.Fatalf("recovered %v, want the connection dropped", got)
	}
	if strings.Contains(rec.Body.String(), "BRAVO") {
		t.Fatal("the replaced bytes went out under the old CRC")
	}
}

// Download managers ask first, and a HEAD has no bytes to read.
func TestAZipAnswersHeadWithoutReading(t *testing.T) {
	h, b := newTestAPIBackend(t)
	id, _ := shareWithFiles(t, h, "bundle", zipResumeFiles)
	rec := doReqHeaders(t, h, http.MethodHead, "/zip/"+id, nil)
	if rec.Code != 200 || rec.Body.Len() != 0 {
		t.Fatalf("code %d, %d bytes", rec.Code, rec.Body.Len())
	}
	if f, _ := b.DB.File(id, "a.txt"); func() bool { _, ok := f.CRC32(); return ok }() {
		t.Error("a HEAD read a file")
	}
	whole := zipFrom(t, h, "/zip/"+id, nil)
	if got := rec.Header().Get("Content-Length"); got != strconv.Itoa(whole.Body.Len()) {
		t.Errorf("Content-Length %q", got)
	}
	if rec.Header().Get("Accept-Ranges") != "bytes" || rec.Header().Get("ETag") != whole.Header().Get("ETag") {
		t.Errorf("headers %v", rec.Header())
	}
}

// A linked share walks a live folder: no row holds a CRC, and the next walk may find
// other files, so it promises nothing a resume could rely on.
func TestALinkedZipOffersNoResume(t *testing.T) {
	h, b, _ := linkedTestAPI(t)
	id := linkedShare(t, b, "photo/2024")
	rec := zipFrom(t, h, "/zip/"+id, map[string]string{"Range": "bytes=5-"})
	if rec.Code != 200 {
		t.Fatalf("code %d", rec.Code)
	}
	if rec.Header().Get("Accept-Ranges") != "" || rec.Header().Get("ETag") != "" {
		t.Errorf("headers %v", rec.Header())
	}
	if _, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len())); err != nil {
		t.Fatal(err)
	}
}

// A browser takes a 200 to its Range for the whole new file and saves what it reads, so
// a resume must never be answered with a page in that status: the visitor would hold a
// page named bundle.zip and no error.
func TestAResumeOfAShareStillUploadingIsNotAPage(t *testing.T) {
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "bundle", zipResumeFiles)
	etag := zipFrom(t, h, "/zip/"+id, nil).Header().Get("ETag")
	if rec := doReqSession(t, h, "/api/shares/"+id+"/files/late.txt", "half", "0", "8", "replacing"); rec.Code >= 300 {
		t.Fatalf("partial upload: %d %s", rec.Code, rec.Body)
	}
	rec := zipFrom(t, h, "/zip/"+id, map[string]string{"Range": "bytes=100-", "If-Range": etag})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("code %d, type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("no Retry-After")
	}
	// A person opening the link still gets the page that waits with them.
	if page := zipFrom(t, h, "/zip/"+id, nil); page.Code != 200 || !strings.Contains(page.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("a fresh request: %d %q", page.Code, page.Header().Get("Content-Type"))
	}
}

// The access cookie can lapse between a download's cut and its resume, for a zip and
// for a single file alike.
func TestAResumeWithoutAccessIsNotAnsweredWithTheForm(t *testing.T) {
	h := newTestAPI(t)
	id, slug := protectedShareWithFile(t, h)
	for _, path := range []string{"/zip/" + id, "/download/" + id + "/" + slug} {
		rec := zipFrom(t, h, path, map[string]string{"Range": "bytes=100-", "If-Range": `"whatever"`})
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: code %d", path, rec.Code)
		}
		if page := zipFrom(t, h, path, nil); page.Code != 200 {
			t.Errorf("%s: a person opening it: %d", path, page.Code)
		}
	}
}

// So too on a file link, and on the file origin, where a person's visit is bounced to
// the other origin: a redirect would end at the form all the same.
func TestAResumeIsNeverBouncedToAForm(t *testing.T) {
	_, h := splitHandler(t)
	id, slug := hopShare(t, h, "s3cret")
	rec := fileLinkReq(t, h, "GET", "https://"+hopFile+"/download/"+id+"/"+slug, map[string]string{
		"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document", "Range": "bytes=100-"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code %d, Location %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestAFileLinkResumeWithoutAccessIsNotAnsweredWithTheForm(t *testing.T) {
	h := newTestAPI(t)
	_, _, key := protectedFileLink(t, h)
	rec := fileLinkReq(t, h, "GET", "/f/"+key, map[string]string{"Range": "bytes=100-"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code %d", rec.Code)
	}
}

// A single file a new upload has put back to pending is the same case as a zip.
func TestAResumeOfAFileStillUploadingIsNotAPage(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"early","files":[{"path":"a.bin","size":8}]}`)
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var made struct {
		ID    string
		Files []struct{ Slug string }
	}
	unmarshal(t, rec, &made)
	got := zipFrom(t, h, "/download/"+made.ID+"/"+made.Files[0].Slug, map[string]string{"Range": "bytes=2-"})
	if got.Code != http.StatusServiceUnavailable {
		t.Fatalf("code %d", got.Code)
	}
}
