package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"hyperdrop/server/internal/metadb"
)

// stageAs stages content at rel into publish pid with token, whole.
func stageAs(t *testing.T, h http.Handler, token, id, pid, rel, content string) *httpResult {
	t.Helper()
	rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/"+rel+"?publish="+pid, token, content)
	return &httpResult{code: rec.Code, body: rec.Body.String()}
}

type httpResult struct {
	code int
	body string
}

// Staged bytes count against the owner's quota beside the committed ones,
// across every publish the owner holds open, for a ranged upload and a
// batch alike: what the publishes hold until they commit is on the disk.
// A ranged upload's later chunks are not charged twice, and an abort gives
// the bytes back.
func TestStagedBytesCountAgainstTheQuota(t *testing.T) {
	h, b := publishAPI(t)
	token := seedUser(t, b.DB, "bob")
	quota := int64(100)
	if _, err := b.DB.UpdateUser("bob", metadb.Settings{QuotaBytes: &quota}); err != nil {
		t.Fatal(err)
	}
	var made struct{ ID string }
	unmarshal(t, doReq(t, h, "POST", "/api/shares", token, `{"name":"one"}`), &made)
	one := made.ID
	unmarshal(t, doReq(t, h, "POST", "/api/shares", token, `{"name":"two"}`), &made)
	two := made.ID
	if rec := doReq(t, h, "PUT", "/api/shares/"+one+"/files/held.txt", token, strings.Repeat("h", 30)); rec.Code != 201 {
		t.Fatalf("the committed file: %d %s", rec.Code, rec.Body)
	}

	p1 := openPublish(t, h, token, one)
	data := []byte(strings.Repeat("s", 50))
	for _, rg := range [][2]int{{0, 20}, {20, 50}} {
		req := stageChunkAs(t, h, token, one, p1, "big.bin", data, rg[0], rg[1], "quota-session")
		if req.Code != http.StatusAccepted && req.Code != http.StatusCreated {
			t.Fatalf("chunk %v of 50 staged bytes beside 30 committed: %d %s", rg, req.Code, req.Body)
		}
	}
	p2 := openPublish(t, h, token, two)
	if r := stageAs(t, h, token, two, p2, "more.txt", strings.Repeat("m", 30)); r.code != http.StatusInsufficientStorage || !strings.Contains(r.body, `"quota"`) {
		t.Fatalf("30 more bytes over 30 committed and 50 staged in another publish: %d %s", r.code, r.body)
	}
	body := tarOf(t, map[string]string{"t.txt": strings.Repeat("t", 30)}, []string{"t.txt"})
	if rec := doReq(t, h, "POST", "/api/shares/"+two+"/batch?publish="+p2, token, string(body)); !strings.Contains(rec.Body.String(), `"quota"`) {
		t.Fatalf("a staged batch over the quota: %d %s", rec.Code, rec.Body)
	}
	if r := stageAs(t, h, token, two, p2, "small.txt", strings.Repeat("m", 20)); r.code != http.StatusCreated {
		t.Fatalf("20 bytes that fit: %d %s", r.code, r.body)
	}
	if rec := doReq(t, h, "DELETE", "/api/shares/"+one+"/publishes/"+p1, token, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("abort: %d %s", rec.Code, rec.Body)
	}
	if r := stageAs(t, h, token, two, p2, "more.txt", strings.Repeat("m", 30)); r.code != http.StatusCreated {
		t.Fatalf("30 bytes once the other publish is aborted: %d %s", r.code, r.body)
	}
}

// A plain upload's room counts the owner's staged bytes too, a ranged PUT
// and a batch alike: what an open publish holds is on the disk until it
// commits or goes.
func TestAPlainUploadCountsStagedBytes(t *testing.T) {
	h, b := publishAPI(t)
	token := seedUser(t, b.DB, "bob")
	quota := int64(100)
	if _, err := b.DB.UpdateUser("bob", metadb.Settings{QuotaBytes: &quota}); err != nil {
		t.Fatal(err)
	}
	var made struct{ ID string }
	unmarshal(t, doReq(t, h, "POST", "/api/shares", token, `{"name":"one"}`), &made)
	one := made.ID
	unmarshal(t, doReq(t, h, "POST", "/api/shares", token, `{"name":"two"}`), &made)
	two := made.ID
	pid := openPublish(t, h, token, one)
	if r := stageAs(t, h, token, one, pid, "staged.bin", strings.Repeat("s", 70)); r.code != http.StatusCreated {
		t.Fatalf("70 staged bytes: %d %s", r.code, r.body)
	}

	if rec := doReq(t, h, "PUT", "/api/shares/"+two+"/files/plain.txt", token, strings.Repeat("p", 40)); rec.Code != http.StatusInsufficientStorage || !strings.Contains(rec.Body.String(), `"quota"`) {
		t.Fatalf("a plain 40 bytes beside 70 staged: %d %s", rec.Code, rec.Body)
	}
	body := tarOf(t, map[string]string{"t.txt": strings.Repeat("t", 40)}, []string{"t.txt"})
	if rec := doReq(t, h, "POST", "/api/shares/"+two+"/batch", token, string(body)); !strings.Contains(rec.Body.String(), `"quota"`) {
		t.Fatalf("a plain batch of 40 bytes beside 70 staged: %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "PUT", "/api/shares/"+two+"/files/fits.txt", token, strings.Repeat("p", 30)); rec.Code != http.StatusCreated {
		t.Fatalf("a plain 30 bytes that fit beside 70 staged: %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "DELETE", "/api/shares/"+one+"/publishes/"+pid, token, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("abort: %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "PUT", "/api/shares/"+two+"/files/plain.txt", token, strings.Repeat("p", 40)); rec.Code != http.StatusCreated {
		t.Fatalf("a plain 40 bytes once the publish is aborted: %d %s", rec.Code, rec.Body)
	}
}

// stageChunkAs is stageChunk with another account's token.
func stageChunkAs(t *testing.T, h http.Handler, token, id, pid, rel string, data []byte, start, end int, session string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("PUT", "/api/shares/"+id+"/files/"+rel+"?publish="+pid, strings.NewReader(string(data[start:end])))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Upload-Range", fmt.Sprintf("%d-%d", start, end))
	req.Header.Set("Upload-Total", strconv.Itoa(len(data)))
	req.Header.Set("Upload-Session", session)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// A publish stages at most its file cap of distinct paths: the next new
// path is refused 409 publish-limit before any byte, while a path already
// staged can be sent again.
func TestAPublishStagesAtMostItsFileCap(t *testing.T) {
	h, b := publishAPI(t)
	b.FS.StageMaxFiles = 2
	id := createShare(t, h, "s")
	pid := openPublish(t, h, testToken, id)
	stageFile(t, h, id, pid, "a.txt", "a")
	stageFile(t, h, id, pid, "b.txt", "b")
	rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/c.txt?publish="+pid, testToken, "c")
	if rec.Code != http.StatusConflict || errCode(t, rec.Body.String()) != "publish-limit" {
		t.Fatalf("a third path into a publish capped at two: %d %s", rec.Code, rec.Body)
	}
	body := tarOf(t, map[string]string{"d.txt": "d"}, []string{"d.txt"})
	if rec := doReq(t, h, "POST", "/api/shares/"+id+"/batch?publish="+pid, testToken, string(body)); !strings.Contains(rec.Body.String(), `"publish-limit"`) {
		t.Fatalf("a batch entry past the cap: %d %s", rec.Code, rec.Body)
	}
	stageFile(t, h, id, pid, "a.txt", "a again")
	if rec := commitPublish(t, h, id, pid, `{"files":["a.txt","b.txt"]}`); rec.Code != 200 {
		t.Fatalf("commit: %d %s", rec.Code, rec.Body)
	}
}
