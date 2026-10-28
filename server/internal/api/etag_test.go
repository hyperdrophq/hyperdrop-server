package api

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServeFileETagFromContentHash(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "etag")
	body := "etag body bytes"
	sum := sha256.Sum256([]byte(body))
	want := `"` + hex.EncodeToString(sum[:]) + `"`
	slug := uploadGetSlug(t, h, id, "a.txt", body)

	for _, route := range []string{"/view/", "/download/"} {
		rec := doReq(t, h, "GET", route+id+"/"+slug, "", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: status %d", route, rec.Code)
		}
		if got := rec.Header().Get("ETag"); got != want {
			t.Errorf("GET %s ETag = %q, want %q", route, got, want)
		}
	}

	// A matching If-None-Match revalidates without re-sending the bytes.
	req := httptest.NewRequest("GET", "/download/"+id+"/"+slug, nil)
	req.Header.Set("If-None-Match", want)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotModified {
		t.Fatalf("If-None-Match status = %d, want 304", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("304 carried a body: %q", rec.Body)
	}
}
