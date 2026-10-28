package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestHealthNoAuth(t *testing.T) {
	b := testBackend(t)
	h := New(b, "2.0.0", testDomain(t), nil)
	req := httptest.NewRequest("GET", "/api/health", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body struct {
		Status   string `json:"status"`
		Version  string `json:"version"`
		ServerID string `json:"serverID"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if body.Status != "ok" || body.Version != "2.0.0" {
		t.Fatalf("body = %+v, want status ok version 2.0.0", body)
	}
	if body.ServerID == "" || body.ServerID != b.FS.ServerID() {
		t.Fatalf("serverID = %q, want %q", body.ServerID, b.FS.ServerID())
	}
}
