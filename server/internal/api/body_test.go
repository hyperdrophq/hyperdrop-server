package api

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// A body past a route's cap is refused whole, never read up to the cap and
// decoded as if that prefix were the request.
func TestABodyPastItsCapIsRefusedNotTruncated(t *testing.T) {
	h := newTestAPI(t)
	pad := strings.Repeat(" ", 70<<10)
	for _, tc := range []struct{ method, path, token, body string }{
		{"POST", "/api/auth/login", "", loginBody("admin", testAdminPassword, "")},
		{"POST", "/api/me/totp", testToken, `{"currentPassword":"` + testAdminPassword + `"}`},
		{"PATCH", "/api/users/admin", testToken, `{"noEmbed":true}`},
	} {
		if rec := doReq(t, h, tc.method, tc.path, tc.token, tc.body); rec.Code >= 400 {
			t.Fatalf("%s %s within the cap = %d %s", tc.method, tc.path, rec.Code, rec.Body)
		}
		if rec := doReq(t, h, tc.method, tc.path, tc.token, tc.body+pad); rec.Code != http.StatusBadRequest {
			t.Errorf("%s %s past the cap = %d %s, want 400", tc.method, tc.path, rec.Code, rec.Body)
		}
	}
}

// The enrollment routes take an empty body as an empty request.
func TestAnOptionalBodyMayBeEmpty(t *testing.T) {
	h := newTestAPI(t)
	if rec := doReq(t, h, "POST", "/api/me/totp/confirm", testToken, ""); rec.Code == http.StatusBadRequest {
		t.Fatalf("empty confirm body = %d %s, want it read as no code", rec.Code, rec.Body)
	}
}

// failingBody hands out data, then answers err in place of the end: a
// connection that ends early, or the body deadline cutting it.
type failingBody struct {
	data []byte
	err  error
}

func (b *failingBody) Read(p []byte) (int, error) {
	if len(b.data) == 0 {
		return 0, b.err
	}
	n := copy(p, b.data)
	b.data = b.data[n:]
	return n, nil
}

// putRangeBody is putRange over any body.
func putRangeBody(h http.Handler, id, rel string, total int, body io.Reader, extra ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("PUT", "/api/shares/"+id+"/files/"+rel, body)
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Upload-Session", "sess-body")
	req.Header.Set("Upload-Total", strconv.Itoa(total))
	req.Header.Set("Upload-Range", fmt.Sprintf("0-%d", total))
	for i := 0; i+1 < len(extra); i += 2 {
		req.Header.Set(extra[i], extra[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// An upload body that fails on the client's side is answered with a code,
// never an uncoded 500: a zstd stream that arrived whole and does not decode
// is 400 bad-body, and a body that stopped arriving, cut by the stall
// deadline or by the connection ending, is 408 body-incomplete.
func TestAFailedUploadBodyIsACodedRefusal(t *testing.T) {
	data := bytes.Repeat([]byte("compressible "), 4000)
	enc, _ := zstd.NewWriter(nil)
	frame := enc.EncodeAll(data, nil)
	for _, tc := range []struct {
		name   string
		body   io.Reader
		zstd   bool
		status int
		code   string
	}{
		{"a truncated zstd stream", bytes.NewReader(frame[:len(frame)/2]), true, http.StatusBadRequest, "bad-body"},
		{"a corrupt zstd stream", bytes.NewReader(append([]byte("not zstd at all"), frame...)), true, http.StatusBadRequest, "bad-body"},
		{"a stalled zstd body", &failingBody{frame[:len(frame)/2], ErrBodyStalled}, true, http.StatusRequestTimeout, "body-incomplete"},
		{"a stalled body", &failingBody{data[:100], ErrBodyStalled}, false, http.StatusRequestTimeout, "body-incomplete"},
		{"a body cut short", &failingBody{data[:100], io.ErrUnexpectedEOF}, false, http.StatusRequestTimeout, "body-incomplete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestAPI(t)
			id := createShare(t, h, "body")
			var extra []string
			if tc.zstd {
				extra = []string{"Content-Encoding", "zstd"}
			}
			rec := putRangeBody(h, id, "f.txt", len(data), tc.body, extra...)
			if rec.Code != tc.status || errCode(t, rec.Body.String()) != tc.code {
				t.Fatalf("= %d %s, want %d %s", rec.Code, rec.Body, tc.status, tc.code)
			}
		})
	}
}

// A batch whose body stalls, or whose tar stream breaks inside an entry,
// answers the same codes, with what committed before it.
func TestABrokenBatchBodyIsACodedRefusal(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, name := range []string{"a.txt", "b.txt"} {
		content := bytes.Repeat([]byte(name), 2000)
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write(content)
	}
	tw.Close()
	stream := buf.Bytes()
	cut := len(stream) - 3000 // inside b.txt
	for _, tc := range []struct {
		name   string
		body   io.Reader
		status int
		code   string
	}{
		{"a tar that ends inside an entry", bytes.NewReader(stream[:cut]), http.StatusBadRequest, "bad-body"},
		{"a stalled body", &failingBody{stream[:cut], ErrBodyStalled}, http.StatusRequestTimeout, "body-incomplete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestAPI(t)
			id := createShare(t, h, "batch")
			req := httptest.NewRequest("POST", "/api/shares/"+id+"/batch", tc.body)
			req.Header.Set("Authorization", "Bearer "+testToken)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			var out struct {
				Committed int    `json:"committed"`
				Code      string `json:"code"`
			}
			unmarshal(t, rec, &out)
			if rec.Code != tc.status || out.Code != tc.code || out.Committed != 1 {
				t.Fatalf("= %d %s, want %d %s with a.txt committed", rec.Code, rec.Body, tc.status, tc.code)
			}
		})
	}
}

// An anonymous inbox upload whose body stops arriving is 408 body-incomplete.
func TestAnInboxUploadThatStopsIsBodyIncomplete(t *testing.T) {
	h := newTestAPI(t)
	id := createInbox(t, h, `{"name":"in","receive":true}`)
	req := httptest.NewRequest("PUT", "/receive/"+id+"/files/f.txt", &failingBody{[]byte("part"), io.ErrUnexpectedEOF})
	req.ContentLength = 100
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestTimeout || errCode(t, rec.Body.String()) != "body-incomplete" {
		t.Fatalf("= %d %s, want 408 body-incomplete", rec.Code, rec.Body)
	}
}
