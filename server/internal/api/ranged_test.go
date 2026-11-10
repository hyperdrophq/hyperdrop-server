package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/klauspost/compress/zstd"

	"hyperdrop/server/internal/metadb"
)

func rangedBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*13 + i/97)
	}
	return b
}

func hexSum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// putRange sends one Upload-Range PUT as the admin. extra adds headers.
func putRange(t *testing.T, h http.Handler, token, id, rel, session string, start, end, total int, body []byte, extra ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("PUT", "/api/shares/"+id+"/files/"+rel, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Upload-Session", session)
	req.Header.Set("Upload-Total", strconv.Itoa(total))
	req.Header.Set("Upload-Range", fmt.Sprintf("%d-%d", start, end))
	for i := 0; i+1 < len(extra); i += 2 {
		req.Header.Set(extra[i], extra[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

type uploadDone struct {
	Path, Slug, SHA256 string
	Size               int64
}

type uploadStatusOut struct {
	Offset   int64      `json:"offset"`
	Complete bool       `json:"complete"`
	Total    int64      `json:"total"`
	Missing  [][2]int64 `json:"missing"`
	SHA256   string     `json:"sha256"`
	Session  string     `json:"session"`
}

func statusOf(t *testing.T, h http.Handler, id, rel, session string) uploadStatusOut {
	t.Helper()
	rec := doReq(t, h, "GET", "/api/shares/"+id+"/uploads/"+rel+"?session="+session, testToken, "")
	if rec.Code != 200 {
		t.Fatalf("status = %d %s", rec.Code, rec.Body)
	}
	var st uploadStatusOut
	unmarshal(t, rec, &st)
	return st
}

func TestRangedChunksInAnyOrderCommitOnce(t *testing.T) {
	h, b := newTestAPIBackend(t)
	id := createShare(t, h, "big")
	data := rangedBytes(3000)
	for _, rg := range [][2]int{{2000, 3000}, {0, 1000}} {
		rec := putRange(t, h, testToken, id, "big.bin", "sess-1", rg[0], rg[1], 3000, data[rg[0]:rg[1]])
		if rec.Code != 202 {
			t.Fatalf("chunk %v = %d %s", rg, rec.Code, rec.Body)
		}
	}
	st := statusOf(t, h, id, "big.bin", "sess-1")
	if st.Complete || st.Offset != 1000 || st.Total != 3000 || len(st.Missing) != 1 || st.Missing[0] != [2]int64{1000, 2000} {
		t.Fatalf("status mid-upload = %+v", st)
	}
	rec := putRange(t, h, testToken, id, "big.bin", "sess-1", 1000, 2000, 3000, data[1000:2000])
	if rec.Code != 201 {
		t.Fatalf("last chunk = %d %s", rec.Code, rec.Body)
	}
	var done uploadDone
	unmarshal(t, rec, &done)
	if done.Size != 3000 || done.SHA256 != hexSum(data) || done.Slug == "" {
		t.Fatalf("commit answer %+v", done)
	}
	fh, _, err := b.FS.Open(id, "big.bin")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(fh)
	fh.Close()
	if !bytes.Equal(got, data) {
		t.Fatal("stored bytes differ")
	}
	if st := statusOf(t, h, id, "big.bin", "sess-1"); !st.Complete || st.SHA256 != hexSum(data) || st.Session != "sess-1" {
		t.Fatalf("status after commit = %+v", st)
	}
}

func TestRangedParallelChunksCommitExactlyOnce(t *testing.T) {
	h, b := newTestAPIBackend(t)
	id := createShare(t, h, "par")
	const chunk, chunks = 2048, 16
	data := rangedBytes(chunk * chunks)
	codes := make(chan int, chunks)
	var wg sync.WaitGroup
	for i := range chunks {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s, e := i*chunk, (i+1)*chunk
			codes <- putRange(t, h, testToken, id, "p.bin", "sess-p", s, e, len(data), data[s:e]).Code
		}(i)
	}
	wg.Wait()
	close(codes)
	count := map[int]int{}
	for c := range codes {
		count[c]++
	}
	if count[201] != 1 || count[202] != chunks-1 {
		t.Fatalf("answers %v, want one 201 and %d 202s", count, chunks-1)
	}
	f, err := b.DB.File(id, "p.bin")
	if err != nil || f.Pending || f.SHA256 != hexSum(data) {
		t.Fatalf("row %+v %v", f, err)
	}
}

func TestRangedRetryOfACommittedChunkAnswersTheCommit(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "retry")
	data := rangedBytes(100)
	if rec := putRange(t, h, testToken, id, "r.bin", "sess-r", 0, 100, 100, data); rec.Code != 201 {
		t.Fatalf("first = %d %s", rec.Code, rec.Body)
	}
	rec := putRange(t, h, testToken, id, "r.bin", "sess-r", 0, 50, 100, data[:50])
	if rec.Code != 201 {
		t.Fatalf("retried chunk = %d %s, want the commit's 201", rec.Code, rec.Body)
	}
	if st := statusOf(t, h, id, "r.bin", "sess-r"); !st.Complete {
		t.Fatalf("a retried chunk restarted the upload: %+v", st)
	}
}

func TestRangedBadRangesAre400(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "bad")
	cases := []struct{ rg, total string }{
		{"5-3", "10"}, {"0-11", "10"}, {"x-1", "10"}, {"-1-2", "10"}, {"3", "10"}, {"4-4", "10"},
		{"0-0", "10"}, {"+1-5", "10"}, {"1-+5", "10"}, {"0--1", "10"},
		{"0-99999999999999999999", "10"}, {"99999999999999999999-1", "10"},
		{"0-9223372036854775807", "10"},
		{"0-1", "0"}, {"1-1", "0"}, {"+0-0", "0"},
	}
	for _, c := range cases {
		req := httptest.NewRequest("PUT", "/api/shares/"+id+"/files/b.bin", strings.NewReader("hello"))
		req.Header.Set("Authorization", "Bearer "+testToken)
		req.Header.Set("Upload-Session", "sess-b")
		req.Header.Set("Upload-Total", c.total)
		req.Header.Set("Upload-Range", c.rg)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 400 || !strings.Contains(rec.Body.String(), `Upload-Range \"`+c.rg) {
			t.Errorf("Upload-Range %q of %s = %d %s, want a 400 naming the range", c.rg, c.total, rec.Code, rec.Body)
		}
	}
}

func TestRangedBodyLongerThanItsRangeIs400(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "long")
	if rec := putRange(t, h, testToken, id, "l.bin", "sess-l", 0, 4, 10, []byte("hello")); rec.Code != 400 {
		t.Fatalf("= %d %s, want 400", rec.Code, rec.Body)
	}
	if st := statusOf(t, h, id, "l.bin", "sess-l"); st.Offset != 0 {
		t.Fatalf("a refused body was recorded: %+v", st)
	}
}

func TestRangedZstdChunkCountsDecodedBytes(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "zstd")
	data := bytes.Repeat([]byte("compressible "), 400)
	enc, _ := zstd.NewWriter(nil)
	body := enc.EncodeAll(data, nil)
	rec := putRange(t, h, testToken, id, "z.txt", "sess-z", 0, len(data), len(data), body, "Content-Encoding", "zstd")
	if rec.Code != 201 {
		t.Fatalf("= %d %s", rec.Code, rec.Body)
	}
	var done uploadDone
	unmarshal(t, rec, &done)
	if done.Size != int64(len(data)) || done.SHA256 != hexSum(data) {
		t.Fatalf("%+v", done)
	}
}

func TestRangedEmptyFile(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "empty")
	rec := putRange(t, h, testToken, id, "e.txt", "sess-e", 0, 0, 0, nil)
	if rec.Code != 201 {
		t.Fatalf("= %d %s", rec.Code, rec.Body)
	}
}

func TestRangedQuotaIsRefusedBeforeAByteLands(t *testing.T) {
	b := testBackend(t)
	h := New(b, "test", testDomain(t), nil)
	token := seedUser(t, b.DB, "bob")
	quota := int64(10)
	if _, err := b.DB.UpdateUser("bob", metadb.Settings{QuotaBytes: &quota}); err != nil {
		t.Fatal(err)
	}
	rec := doReq(t, h, "POST", "/api/shares", token, `{"name":"q"}`)
	var created struct{ ID string }
	unmarshal(t, rec, &created)
	data := rangedBytes(20)
	got := putRange(t, h, token, created.ID, "q.bin", "sess-q", 0, 10, 20, data[:10])
	if got.Code != 507 || !strings.Contains(got.Body.String(), `"code":"quota"`) {
		t.Fatalf("= %d %s, want 507 quota", got.Code, got.Body)
	}
	if n, _ := b.FS.PartSize(created.ID, "q.bin"); n != 0 {
		t.Fatalf("%d bytes staged past the quota", n)
	}
}

// A replace whose file is already committed by its own session (sessions are
// derived from the file, so an unchanged file re-sent is exactly that) still
// collapses the share: the commit is answered, and the replace runs.
func TestARangedReplaceAllOfAnUnchangedFileStillCollapses(t *testing.T) {
	h, b := newTestAPIBackend(t)
	id := createShare(t, h, "collapse")
	data := rangedBytes(100)
	if rec := putRange(t, h, testToken, id, "keep.bin", "sess-u", 0, 100, 100, data); rec.Code != 201 {
		t.Fatalf("first = %d %s", rec.Code, rec.Body)
	}
	commitFile(t, b, id, "other.txt", "other")
	rec := putRange(t, h, testToken, id, "keep.bin?replaceAll=1", "sess-u", 0, 100, 100, data)
	if rec.Code != 201 {
		t.Fatalf("replaceAll = %d %s", rec.Code, rec.Body)
	}
	if _, err := b.DB.File(id, "other.txt"); !errors.Is(err, metadb.ErrNotFound) {
		t.Fatalf("other.txt survived the replaceAll: %v", err)
	}
}

func TestARangedReplacesOfAnUnchangedFileTakesTheSlugOnce(t *testing.T) {
	h, b := newTestAPIBackend(t)
	id := createShare(t, h, "donate")
	commitFile(t, b, id, "old.bin", "old")
	old, err := b.DB.File(id, "old.bin")
	if err != nil {
		t.Fatal(err)
	}
	data := rangedBytes(100)
	if rec := putRange(t, h, testToken, id, "new.bin", "sess-v", 0, 100, 100, data); rec.Code != 201 {
		t.Fatalf("first = %d %s", rec.Code, rec.Body)
	}
	for i := range 2 {
		rec := putRange(t, h, testToken, id, "new.bin?replaces=old.bin", "sess-v", 0, 100, 100, data)
		if rec.Code != 201 {
			t.Fatalf("replace %d = %d %s", i, rec.Code, rec.Body)
		}
		var done uploadDone
		unmarshal(t, rec, &done)
		if done.Slug != old.Slug {
			t.Fatalf("replace %d answered slug %q, want the donated %q", i, done.Slug, old.Slug)
		}
	}
	if _, err := b.DB.File(id, "old.bin"); !errors.Is(err, metadb.ErrNotFound) {
		t.Fatalf("old.bin survived the replace: %v", err)
	}
}

// A session re-sending a file it already committed (a replace resumed after
// a failed attempt) reads its staged bytes, not the earlier commit, until the
// new commit lands.
func TestStatusAnswersTheSessionsStagedPartBeforeItsCommit(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "restage")
	data := rangedBytes(200)
	if rec := putRange(t, h, testToken, id, "r.bin", "sess-s", 0, 100, 100, data[:100]); rec.Code != 201 {
		t.Fatalf("ranged commit = %d %s", rec.Code, rec.Body)
	}
	if rec := putRange(t, h, testToken, id, "r.bin", "sess-s", 100, 200, 200, data[100:]); rec.Code != 202 {
		t.Fatalf("ranged restage = %d %s", rec.Code, rec.Body)
	}
	if st := statusOf(t, h, id, "r.bin", "sess-s"); st.Complete || st.Total != 200 || len(st.Missing) != 1 || st.Missing[0] != [2]int64{0, 100} {
		t.Fatalf("ranged status = %+v, want the staged part", st)
	}
}

// A chunk arriving while its session's commit is between the rename and the
// row never stages a fresh part: it is refused, and the commit answers.
func TestALateChunkCannotRestageAnUploadBeingCommitted(t *testing.T) {
	b := testBackend(t)
	hd := newHandler(b, "2.0.0", testDomain(t), nil, Deployment{})
	h := hd.routes()
	id := createShare(t, h, "late")
	data := rangedBytes(100)
	end := hd.committing.begin(id, "l.bin", "sess-late")
	if rec := putRange(t, h, testToken, id, "l.bin", "sess-late", 0, 50, 100, data[:50]); rec.Code != 409 {
		t.Fatalf("chunk during the commit = %d %s, want 409", rec.Code, rec.Body)
	}
	if _, ok := b.FS.PartRanges(id, "l.bin", "sess-late"); ok {
		t.Fatal("a chunk during the commit staged a part")
	}
	end()
	if rec := putRange(t, h, testToken, id, "l.bin", "sess-late", 0, 50, 100, data[:50]); rec.Code != 202 {
		t.Fatalf("chunk after the commit window = %d %s", rec.Code, rec.Body)
	}
}
