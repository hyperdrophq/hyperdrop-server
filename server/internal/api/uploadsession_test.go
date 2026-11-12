package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// doReqSession sends body as one Upload-Range chunk starting at start, of an
// upload of total bytes, under session.
func doReqSession(t *testing.T, h http.Handler, path, body, start, total, session string) *httptest.ResponseRecorder {
	t.Helper()
	from, err := strconv.Atoi(start)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("PUT", path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Upload-Range", fmt.Sprintf("%d-%d", from, from+len(body)))
	req.Header.Set("Upload-Total", total)
	if session != "" {
		req.Header.Set("Upload-Session", session)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// A chunk under another session never lands beside a foreign partial: it
// takes the path over whole, and the first session's resume point is 0.
func TestAForeignSessionsChunkTakesThePathOverWhole(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "x")
	put := "/api/shares/" + id + "/files/a.bin"
	if rec := doReqSession(t, h, put, "1234", "0", "10", "sess-a"); rec.Code != 202 {
		t.Fatalf("setup status = %d; body %s", rec.Code, rec.Body)
	}
	rec := doReqSession(t, h, put, "5678", "4", "10", "sess-b")
	if rec.Code != 202 {
		t.Fatalf("status = %d, want 202; body %s", rec.Code, rec.Body)
	}
	var body struct {
		Missing [][2]int64 `json:"missing"`
	}
	json.Unmarshal(rec.Body.Bytes(), &body)
	if len(body.Missing) != 2 || body.Missing[0] != [2]int64{0, 4} {
		t.Errorf("missing = %v, want sess-a's bytes missing again", body.Missing)
	}
	var st struct {
		Offset   int64 `json:"offset"`
		Complete bool  `json:"complete"`
	}
	rec = doReq(t, h, "GET", "/api/shares/"+id+"/uploads/a.bin?session=sess-a", testToken, "")
	json.Unmarshal(rec.Body.Bytes(), &st)
	if st.Offset != 0 || st.Complete {
		t.Errorf("sess-a status = %+v, want offset 0", st)
	}
}

func TestUploadStatusAnswersPerSession(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "x")
	put := "/api/shares/" + id + "/files/a.bin"
	if rec := doReqSession(t, h, put, "1234", "0", "10", "sess-a"); rec.Code != 202 {
		t.Fatalf("setup status = %d; body %s", rec.Code, rec.Body)
	}
	var st struct {
		Offset   int64 `json:"offset"`
		Complete bool  `json:"complete"`
	}
	// The owner sees its partial.
	rec := doReq(t, h, "GET", "/api/shares/"+id+"/uploads/a.bin?session=sess-a", testToken, "")
	json.Unmarshal(rec.Body.Bytes(), &st)
	if st.Offset != 4 || st.Complete {
		t.Fatalf("own status = %+v, want offset 4", st)
	}
	// Anyone else is told to start from scratch: a foreign partial is not
	// their resume state.
	rec = doReq(t, h, "GET", "/api/shares/"+id+"/uploads/a.bin?session=sess-b", testToken, "")
	json.Unmarshal(rec.Body.Bytes(), &st)
	if st.Offset != 0 || st.Complete {
		t.Errorf("foreign status = %+v, want offset 0", st)
	}
}

func TestUploadStatusEchoesTheCommitSession(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "x")
	put := "/api/shares/" + id + "/files/a.bin"
	if rec := doReqSession(t, h, put, "full body!", "0", "10", "sess-a"); rec.Code != 201 {
		t.Fatalf("commit status = %d; body %s", rec.Code, rec.Body)
	}
	var st struct {
		Offset   int64  `json:"offset"`
		Complete bool   `json:"complete"`
		Session  string `json:"session"`
	}
	rec := doReq(t, h, "GET", "/api/shares/"+id+"/uploads/a.bin?session=sess-b", testToken, "")
	json.Unmarshal(rec.Body.Bytes(), &st)
	if !st.Complete || st.Session != "sess-a" {
		t.Errorf("status = %+v, want complete with session sess-a (so sess-b knows the commit is not its own)", st)
	}
}

func TestUploadSessionHeaderValidation(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "x")
	put := "/api/shares/" + id + "/files/a.bin"
	for _, bad := range []string{
		"",
		strings.Repeat("x", 65),
		"spaces are not ok",
		"newline\nnope",
	} {
		if rec := doReqSession(t, h, put, "x", "0", "10", bad); rec.Code != 400 {
			t.Errorf("session %q: status = %d, want 400 (body %s)", bad, rec.Code, rec.Body)
		}
	}
}

func TestListingsDoNotExposeUploadSessions(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "x")
	put := "/api/shares/" + id + "/files/a.bin"
	if rec := doReqSession(t, h, put, "full body!", "0", "10", "sess-a"); rec.Code != 201 {
		t.Fatalf("commit status = %d; body %s", rec.Code, rec.Body)
	}
	for _, path := range []string{"/api/shares", "/api/shares/" + id} {
		rec := doReq(t, h, "GET", path, testToken, "")
		if rec.Code != 200 {
			t.Fatalf("%s status = %d", path, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "sess-a") || strings.Contains(rec.Body.String(), "uploadSession") {
			t.Errorf("%s leaks the upload session: %s", path, rec.Body)
		}
	}
}

// A share 404 carries a machine code: to the device that just uploaded into
// it (or has an edit sheet open on it), "share not found" almost always means
// "deleted or expired while you weren't looking, possibly from another
// device", and the client can only word that if the refusal is typed.
func TestShareNotFoundCarriesACode(t *testing.T) {
	h := newTestAPI(t)
	for _, req := range [][2]string{
		{"GET", "/api/shares/zzzzzzzzzz"},
		{"DELETE", "/api/shares/zzzzzzzzzz"},
		{"PATCH", "/api/shares/zzzzzzzzzz"},
	} {
		rec := doReq(t, h, req[0], req[1], testToken, "{}")
		if rec.Code != 404 {
			t.Fatalf("%s %s = %d, want 404", req[0], req[1], rec.Code)
		}
		if !strings.Contains(rec.Body.String(), `"code":"not-found"`) {
			t.Errorf("%s %s body = %s, want code not-found", req[0], req[1], rec.Body)
		}
	}
	// The upload PUT too: that is the delete-mid-upload path.
	rec := doReqResume(t, h, "/api/shares/zzzzzzzzzz/files/a.bin", "x", "0", "1")
	if rec.Code != 404 || !strings.Contains(rec.Body.String(), `"code":"not-found"`) {
		t.Errorf("PUT = %d %s, want 404 with code not-found", rec.Code, rec.Body)
	}
}
