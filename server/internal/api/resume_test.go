package api

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/sharefs"
)

// doReqResume sends body as one Upload-Range chunk starting at start, of an
// upload of total bytes, under the session test-session.
func doReqResume(t *testing.T, h http.Handler, path, body, start, total string) *httptest.ResponseRecorder {
	t.Helper()
	return doReqResumeAs(t, h, path, testToken, body, start, total)
}

// doReqResumeAs is doReqResume for a caller other than the admin.
func doReqResumeAs(t *testing.T, h http.Handler, path, token, body, start, total string) *httptest.ResponseRecorder {
	t.Helper()
	from, err := strconv.Atoi(start)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("PUT", path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Upload-Session", "test-session")
	req.Header.Set("Upload-Range", fmt.Sprintf("%d-%d", from, from+len(body)))
	req.Header.Set("Upload-Total", total)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestResumableUploadPartialThenCommit(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "big")
	put := "/api/shares/" + id + "/files/big.bin"

	// First chunk short of total → 202 with what is still missing.
	rec := doReqResume(t, h, put, "hello ", "0", "11")
	if rec.Code != 202 {
		t.Fatalf("partial status = %d, want 202; body %s", rec.Code, rec.Body)
	}
	var partial struct {
		Missing [][2]int64 `json:"missing"`
	}
	json.Unmarshal(rec.Body.Bytes(), &partial)
	if len(partial.Missing) != 1 || partial.Missing[0] != [2]int64{6, 11} {
		t.Fatalf("missing = %v, want [[6 11]]", partial.Missing)
	}

	// Status while pending.
	rec = doReq(t, h, "GET", "/api/shares/"+id+"/uploads/big.bin?session=test-session", testToken, "")
	if rec.Code != 200 {
		t.Fatalf("status status = %d; body %s", rec.Code, rec.Body)
	}
	var st struct {
		Offset   int64  `json:"offset"`
		Complete bool   `json:"complete"`
		Slug     string `json:"slug"`
	}
	json.Unmarshal(rec.Body.Bytes(), &st)
	if st.Offset != 6 || st.Complete {
		t.Fatalf("pending status = %+v, want offset 6 complete false", st)
	}

	// Remainder → 201 with the usual upload response.
	rec = doReqResume(t, h, put, "world", "6", "11")
	if rec.Code != 201 {
		t.Fatalf("final status = %d, want 201; body %s", rec.Code, rec.Body)
	}
	var done struct {
		Path string `json:"path"`
		Size int64  `json:"size"`
		Slug string `json:"slug"`
	}
	json.Unmarshal(rec.Body.Bytes(), &done)
	if done.Path != "big.bin" || done.Size != 11 || done.Slug == "" {
		t.Fatalf("final body = %+v", done)
	}

	// Status after commit reports complete with size + slug.
	rec = doReq(t, h, "GET", "/api/shares/"+id+"/uploads/big.bin?session=test-session", testToken, "")
	json.Unmarshal(rec.Body.Bytes(), &st)
	if !st.Complete || st.Offset != 11 || st.Slug != done.Slug {
		t.Fatalf("complete status = %+v, want offset 11 complete true slug %s", st, done.Slug)
	}
}

func TestZeroByteUploadUsesTheSameRequiredProtocol(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "empty")
	rec := doReqResume(t, h, "/api/shares/"+id+"/files/empty.txt", "", "0", "0")
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body)
	}
}

func TestUploadStatusUnknownShare404(t *testing.T) {
	h := newTestAPI(t)
	if rec := doReq(t, h, "GET", "/api/shares/zzzzzzzzzz/uploads/a.bin?session=test-session", testToken, ""); rec.Code != 404 {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestUploadStatusNoPending(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "x")
	rec := doReq(t, h, "GET", "/api/shares/"+id+"/uploads/never.bin?session=test-session", testToken, "")
	if rec.Code != 200 {
		t.Fatalf("status = %d; body %s", rec.Code, rec.Body)
	}
	var st struct {
		Offset   int64 `json:"offset"`
		Complete bool  `json:"complete"`
	}
	json.Unmarshal(rec.Body.Bytes(), &st)
	if st.Offset != 0 || st.Complete {
		t.Errorf("status = %+v, want offset 0 complete false", st)
	}
}

func TestUploadStatusRequiresAuth(t *testing.T) {
	h := newTestAPI(t)
	if rec := doReq(t, h, "GET", "/api/shares/x/uploads/a.bin", "", ""); rec.Code != 401 {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestUploadRequiresRangeTotalAndSession(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "x")
	put := "/api/shares/" + id + "/files/a.bin"
	for _, tc := range []struct {
		name    string
		headers map[string]string
	}{
		{"no headers", nil},
		{"no session", map[string]string{"Upload-Range": "0-5", "Upload-Total": "5"}},
		{"no range", map[string]string{"Upload-Session": "test-session", "Upload-Total": "5"}},
		{"no total", map[string]string{"Upload-Session": "test-session", "Upload-Range": "0-5"}},
	} {
		req := httptest.NewRequest("PUT", put, strings.NewReader("fresh"))
		req.Header.Set("Authorization", "Bearer "+testToken)
		for k, v := range tc.headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 400 {
			t.Errorf("%s: status = %d, want 400; body %s", tc.name, rec.Code, rec.Body)
		}
	}
}

// A row the database refuses takes its bytes with it: nothing is left in
// files/ for a path no entry names, and nothing is left staged either. The
// anonymous inbox PUT is where this matters most, because it skips the
// advisory admission check (it has no user row to read) and the commit is
// the only gate the owner's quota has.
func TestACommitRefusedByTheRowTakesItsBytesWithIt(t *testing.T) {
	h, b := newTestAPIBackend(t)
	quota := int64(5)
	if _, err := b.DB.UpdateUser(metadb.DefaultAdminName, metadb.Settings{QuotaBytes: &quota}); err != nil {
		t.Fatal(err)
	}
	id := createShare(t, h, "tight")
	rec := doReqResume(t, h, "/api/shares/"+id+"/files/big.bin", strings.Repeat("x", 10), "0", "10")
	if rec.Code != 507 || errCode(t, rec.Body.String()) != "quota" {
		t.Fatalf("over quota = %d %s, want 507 quota", rec.Code, rec.Body)
	}
	if _, err := b.FS.Stat(id, "big.bin"); !errors.Is(err, sharefs.ErrNotFound) {
		t.Fatalf("bytes for a refused commit = %v, want ErrNotFound", err)
	}

	inbox := createInbox(t, h, `{"name":"inbox","receive":true}`)
	rec = doReq(t, h, "PUT", "/receive/"+inbox+"/files/big.bin", "", strings.Repeat("x", 10))
	if rec.Code != 507 || errCode(t, rec.Body.String()) != "quota" {
		t.Fatalf("inbox over quota = %d %s, want 507 quota", rec.Code, rec.Body)
	}
	if _, err := b.FS.Stat(inbox, "big.bin"); !errors.Is(err, sharefs.ErrNotFound) {
		t.Fatalf("inbox bytes for a refused commit = %v, want ErrNotFound", err)
	}
	d, err := b.DB.Share(inbox)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Files) != 0 {
		t.Fatalf("a refused inbox upload left rows behind: %+v", d.Files)
	}
	if n, err := b.FS.PartSize(inbox, "big.bin"); err != nil || n != 0 {
		t.Fatalf("staged part after a refused commit = %d (%v), want 0", n, err)
	}
}

// A resumed upload keeps what landed and commits the whole file: the part
// survives between the two requests, status reports it, and the committed
// hash covers both halves.
func TestAResumedUploadKeepsItsPart(t *testing.T) {
	h, b := newTestAPIBackend(t)
	id := createShare(t, h, "resumed")
	put := "/api/shares/" + id + "/files/six.bin"
	if rec := doReqResume(t, h, put, "abc", "0", "6"); rec.Code != 202 {
		t.Fatalf("first chunk = %d %s, want 202", rec.Code, rec.Body)
	}
	if n, err := b.FS.PartSize(id, "six.bin"); err != nil || n != 3 {
		t.Fatalf("staged part = %d (%v), want 3", n, err)
	}
	rec := doReq(t, h, "GET", "/api/shares/"+id+"/uploads/six.bin?session=test-session", testToken, "")
	var st struct {
		Offset   int64 `json:"offset"`
		Complete bool  `json:"complete"`
	}
	unmarshal(t, rec, &st)
	if st.Offset != 3 || st.Complete {
		t.Fatalf("status between chunks = %+v, want offset 3 complete false", st)
	}
	rec = doReqResume(t, h, put, "def", "3", "6")
	if rec.Code != 201 {
		t.Fatalf("second chunk = %d %s, want 201", rec.Code, rec.Body)
	}
	var done struct {
		Size   int64  `json:"size"`
		SHA256 string `json:"sha256"`
	}
	unmarshal(t, rec, &done)
	want := fmt.Sprintf("%x", sha256.Sum256([]byte("abcdef")))
	if done.Size != 6 || done.SHA256 != want {
		t.Fatalf("committed = %+v, want size 6 sha %s", done, want)
	}
}

// sharePaths is every path GET /api/shares/{id} lists.
func sharePaths(t *testing.T, h http.Handler, token, id string) []string {
	t.Helper()
	rec := doReq(t, h, "GET", "/api/shares/"+id, token, "")
	if rec.Code != 200 {
		t.Fatalf("get share = %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Files []struct {
			Path string `json:"path"`
		} `json:"files"`
	}
	unmarshal(t, rec, &out)
	paths := make([]string, 0, len(out.Files))
	for _, f := range out.Files {
		paths = append(paths, f.Path)
	}
	return paths
}

// An overwrite the row refuses leaves the previous version served as it
// was: the file layer keeps the old bytes linked beside the new ones until
// the row decides, and puts them back when it refuses. Lower the quota while
// the final chunk is read, after its admission check, to exercise
// commit-time enforcement.
func TestARefusedOverwriteKeepsThePreviousVersion(t *testing.T) {
	h, db, b := newMultiUserAPI(t)
	alice := seedUser(t, db, "alice")
	id := createShareAs(t, h, alice, `{"name":"alices"}`)
	if rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/a.txt", alice, "abc"); rec.Code != 201 {
		t.Fatalf("seed upload = %d %s", rec.Code, rec.Body)
	}
	put := "/api/shares/" + id + "/files/a.txt"
	if rec := doReqResumeAs(t, h, put, alice, strings.Repeat("x", 5), "0", "10"); rec.Code != 202 {
		t.Fatalf("partial overwrite = %d %s", rec.Code, rec.Body)
	}
	body := &beforeReadUploadBody{Reader: strings.NewReader("xxxxx"), before: func() {
		quota := int64(5)
		if _, err := db.UpdateUser("alice", metadb.Settings{QuotaBytes: &quota}); err != nil {
			t.Fatal(err)
		}
	}}
	req := httptest.NewRequest("PUT", put, body)
	req.Header.Set("Authorization", "Bearer "+alice)
	req.Header.Set("Upload-Session", "test-session")
	req.Header.Set("Upload-Range", "5-10")
	req.Header.Set("Upload-Total", "10")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 507 || errCode(t, rec.Body.String()) != "quota" {
		t.Fatalf("overwrite past the owner's quota = %d %s, want 507 quota", rec.Code, rec.Body)
	}
	if paths := sharePaths(t, h, alice, id); len(paths) != 1 || paths[0] != "a.txt" {
		t.Errorf("share lists %v, want the previous a.txt", paths)
	}
	f, err := b.DB.File(id, "a.txt")
	if err != nil || f.Size != 3 {
		t.Fatalf("row after the refusal = %+v, %v, want the previous 3 bytes", f, err)
	}
	fh, _, err := b.FS.Open(id, "a.txt")
	if err != nil {
		t.Fatalf("bytes after the refusal: %v", err)
	}
	defer fh.Close()
	if data, _ := io.ReadAll(fh); string(data) != "abc" {
		t.Fatalf("a.txt holds %q after the refusal, want the previous abc", data)
	}
}

// The common way to that refusal involves no admin: an overwrite admitted
// against the usage of its moment is refused at commit because another
// upload of the same account committed meanwhile. The path keeps its
// previous version.
func TestAnOverwriteRefusedByAParallelUploadKeepsThePreviousVersion(t *testing.T) {
	h, db, b := newMultiUserAPI(t)
	quota := int64(100)
	if _, err := db.CreateUser("guest", "guest-pw", metadb.RoleUser, metadb.Settings{QuotaBytes: &quota}); err != nil {
		t.Fatal(err)
	}
	tok, err := db.MintToken("guest", "t")
	if err != nil {
		t.Fatal(err)
	}
	id := createShareAs(t, h, tok, `{"name":"s"}`)
	if rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/a.txt", tok, strings.Repeat("A", 40)); rec.Code != 201 {
		t.Fatalf("seed = %d %s", rec.Code, rec.Body)
	}
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	done := make(chan *httptest.ResponseRecorder)
	go func() {
		req := httptest.NewRequest("PUT", "/api/shares/"+id+"/files/a.txt",
			&inboxHeldBody{Reader: strings.NewReader(strings.Repeat("B", 60)), entered: entered, release: release})
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Upload-Range", "0-60")
		req.Header.Set("Upload-Total", "60")
		req.Header.Set("Upload-Session", "sess-overwrite")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		done <- rec
	}()
	<-entered // admitted against 40 used: 40 - 40 + 60 <= 100
	if rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/b.txt", tok, strings.Repeat("C", 50)); rec.Code != 201 {
		t.Fatalf("parallel upload = %d %s", rec.Code, rec.Body)
	}
	close(release)
	if rec := <-done; rec.Code != 507 {
		t.Fatalf("overwrite = %d %s, want 507 at commit (90 - 40 + 60 > 100)", rec.Code, rec.Body)
	}
	f, err := b.DB.File(id, "a.txt")
	if err != nil || f.Size != 40 {
		t.Fatalf("a.txt row = %+v, %v, want the previous 40 bytes", f, err)
	}
	fh, _, err := b.FS.Open(id, "a.txt")
	if err != nil {
		t.Fatalf("a.txt bytes: %v", err)
	}
	defer fh.Close()
	if data, _ := io.ReadAll(fh); string(data) != strings.Repeat("A", 40) {
		t.Fatalf("a.txt holds %q", data)
	}
}

// beforeReadUploadBody changes server state after header admission but before
// the bytes arrive, exercising commit-time revalidation without a timing race.
type beforeReadUploadBody struct {
	io.Reader
	before func()
}

func (b *beforeReadUploadBody) Read(p []byte) (int, error) {
	if b.before != nil {
		before := b.before
		b.before = nil
		before()
	}
	return b.Reader.Read(p)
}
