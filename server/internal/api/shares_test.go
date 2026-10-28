package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

const testToken = "test-token-123"

func newTestAPI(t *testing.T) http.Handler {
	t.Helper()
	upd, _ := testDDNS(t)
	return New(testBackend(t), "2.0.0", testDomain(t), upd)
}

// newTestAPIBackend is newTestAPI plus the backend it serves from, for a
// test that seeds rows or bytes directly instead of through the API.
func newTestAPIBackend(t *testing.T) (http.Handler, Backend) {
	t.Helper()
	b := testBackend(t)
	return New(b, "2.0.0", testDomain(t), nil), b
}

func doReq(t *testing.T, h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if method == http.MethodPut && strings.HasPrefix(path, "/api/shares/") && strings.Contains(path, "/files/") {
		req.Header.Set("Upload-Range", "0-"+strconv.Itoa(len(body)))
		req.Header.Set("Upload-Total", strconv.Itoa(len(body)))
		req.Header.Set("Upload-Session", "test-session")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func createShare(t *testing.T, h http.Handler, name string) string {
	t.Helper()
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"`+name+`"}`)
	if rec.Code != 201 {
		t.Fatalf("create status = %d body %s", rec.Code, rec.Body)
	}
	var resp struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	return resp.ID
}

func TestAuthRequired(t *testing.T) {
	h := newTestAPI(t)
	for _, tc := range []struct{ method, path string }{
		{"POST", "/api/shares"},
		{"GET", "/api/shares"},
		{"PUT", "/api/shares/x/files/a.txt"},
		{"DELETE", "/api/shares/x"},
	} {
		if rec := doReq(t, h, tc.method, tc.path, "", ""); rec.Code != 401 {
			t.Errorf("%s %s no token: status = %d, want 401", tc.method, tc.path, rec.Code)
		}
		if rec := doReq(t, h, tc.method, tc.path, "wrong", ""); rec.Code != 401 {
			t.Errorf("%s %s wrong token: status = %d, want 401", tc.method, tc.path, rec.Code)
		}
	}
	// health stays open
	if rec := doReq(t, h, "GET", "/api/health", "", ""); rec.Code != 200 {
		t.Errorf("health: status = %d, want 200", rec.Code)
	}
}

func TestCreateShare(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"photos"}`)
	if rec.Code != 201 {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body)
	}
	var resp struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		CreatedAt string `json:"createdAt"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if len(resp.ID) != 10 || resp.Name != "photos" || resp.CreatedAt == "" {
		t.Errorf("resp = %+v", resp)
	}
}

func TestCreateShareEmptyBodyDefaultsName(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, "")
	if rec.Code != 201 {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body)
	}
	var resp struct {
		Name string `json:"name"`
	}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Name != "" {
		t.Errorf("name = %q, want empty", resp.Name)
	}
}

func TestUploadFile(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "docs")
	rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/docs/a.txt", testToken, "hello")
	if rec.Code != 201 {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body)
	}
	var resp struct {
		Path string `json:"path"`
		Size int64  `json:"size"`
	}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Path != "docs/a.txt" || resp.Size != 5 {
		t.Errorf("resp = %+v, want {docs/a.txt 5}", resp)
	}
}

func TestUploadToUnknownShare404(t *testing.T) {
	h := newTestAPI(t)
	if rec := doReq(t, h, "PUT", "/api/shares/zzzzzzzzzz/files/a.txt", testToken, "x"); rec.Code != 404 {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestUploadTraversal400(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "bad")
	if rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/%2e%2e/evil.txt", testToken, "x"); rec.Code != 400 {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestListShares(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "listed")
	doReq(t, h, "PUT", "/api/shares/"+id+"/files/a.bin", testToken, "12345678")
	rec := doReq(t, h, "GET", "/api/shares", testToken, "")
	if rec.Code != 200 {
		t.Fatalf("status = %d; body %s", rec.Code, rec.Body)
	}
	var resp struct {
		Shares []struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			TotalSize int64  `json:"totalSize"`
			Files     []struct {
				Path string `json:"path"`
				Size int64  `json:"size"`
			} `json:"files"`
		} `json:"shares"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if len(resp.Shares) != 1 || resp.Shares[0].ID != id || resp.Shares[0].TotalSize != 8 ||
		len(resp.Shares[0].Files) != 1 || resp.Shares[0].Files[0].Path != "a.bin" {
		t.Errorf("resp = %+v", resp)
	}
}

func TestDeleteShare(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "gone")
	if rec := doReq(t, h, "DELETE", "/api/shares/"+id, testToken, ""); rec.Code != 204 {
		t.Fatalf("delete status = %d, want 204", rec.Code)
	}
	if rec := doReq(t, h, "DELETE", "/api/shares/"+id, testToken, ""); rec.Code != 404 {
		t.Errorf("second delete status = %d, want 404", rec.Code)
	}
}

// The Finder mount's Date Modified rides the listing, so the API must carry
// the row's commit time out to clients.
func TestShareListingCarriesCommittedAt(t *testing.T) {
	h, _ := newTestAPIBackend(t)
	id := createShare(t, h, "docs")
	if rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/a.txt", testToken, "hi"); rec.Code != 201 {
		t.Fatalf("upload status = %d body %s", rec.Code, rec.Body)
	}

	rec := doReq(t, h, "GET", "/api/shares", testToken, "")
	var out struct {
		Shares []struct {
			ModifiedAt *time.Time `json:"modifiedAt"`
			Files      []struct {
				Path        string     `json:"path"`
				CommittedAt *time.Time `json:"committedAt"`
				AddedAt     *time.Time `json:"addedAt"`
			} `json:"files"`
		} `json:"shares"`
	}
	unmarshal(t, rec, &out)
	if len(out.Shares) != 1 || len(out.Shares[0].Files) != 1 {
		t.Fatalf("listing = %+v", out)
	}
	got := out.Shares[0].Files[0].CommittedAt
	if got == nil {
		t.Fatal("committedAt missing from the listing")
	}
	if time.Since(*got) > time.Minute {
		t.Errorf("committedAt = %v, want ~now", got)
	}
	if added := out.Shares[0].Files[0].AddedAt; added == nil || !added.Equal(*got) {
		t.Fatal("listing lost first upload date")
	}
	if modified := out.Shares[0].ModifiedAt; modified == nil || modified.Before(*got) || modified.Sub(*got) >= time.Second {
		t.Fatal("listing lost share modification date")
	}
}

// A pending manifest entry has committed nothing, so the field must be
// absent rather than a zero date.
func TestPendingFileHasNoCommittedAtInListing(t *testing.T) {
	h, _ := newTestAPIBackend(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"name":"docs","files":[{"path":"later.txt","size":3}]}`)
	if rec.Code != 201 {
		t.Fatalf("create status = %d body %s", rec.Code, rec.Body)
	}
	rec = doReq(t, h, "GET", "/api/shares", testToken, "")
	if strings.Contains(rec.Body.String(), "committedAt") {
		t.Errorf("pending entry reported a committedAt: %s", rec.Body)
	}
}
