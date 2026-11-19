package api

import (
	"encoding/json"
	"testing"
)

func TestMediaShareRoundTrips(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"Holiday","media":true}`)
	if rec.Code != 201 {
		t.Fatalf("create status = %d body %s", rec.Code, rec.Body)
	}
	var created struct {
		ID    string `json:"id"`
		Media bool   `json:"media"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if !created.Media {
		t.Fatalf("create response media = false, want true: %s", rec.Body)
	}
	// And it survives a read back, so the flag is persisted rather than
	// echoed.
	rec = doReq(t, h, "GET", "/api/shares/"+created.ID, testToken, "")
	if rec.Code != 200 {
		t.Fatalf("get status = %d", rec.Code)
	}
	var read struct {
		Media bool `json:"media"`
	}
	json.Unmarshal(rec.Body.Bytes(), &read)
	if !read.Media {
		t.Fatalf("read back media = false, want true: %s", rec.Body)
	}
}

func TestOrdinaryShareIsNotMedia(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "Docs")
	rec := doReq(t, h, "GET", "/api/shares/"+id, testToken, "")
	if body := rec.Body.String(); jsonHasTrue(body, "media") {
		t.Fatalf("an ordinary share reports media: %s", body)
	}
}

// jsonHasTrue reports whether the response body sets key to true. The DTO
// omits the flag entirely when it is false, so absence is the pass.
func jsonHasTrue(body, key string) bool {
	var m map[string]any
	if json.Unmarshal([]byte(body), &m) != nil {
		return false
	}
	v, ok := m[key].(bool)
	return ok && v
}

func TestMediaAndInboxAreRefusedTogether(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"name":"Both","media":true,"receive":true}`)
	if rec.Code != 400 {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body)
	}
}

func TestMediaAndEntryAreRefusedTogether(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"name":"Both","media":true,"entry":"index.html"}`)
	if rec.Code != 400 {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body)
	}
}

func TestMediaCannotBeSetByEdit(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "Docs")
	rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"media":true}`)
	if rec.Code != 400 {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body)
	}
	// And not as a rider on an edit that would otherwise succeed.
	rec = doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"name":"Renamed","media":true}`)
	if rec.Code != 400 {
		t.Fatalf("rider status = %d, want 400: %s", rec.Code, rec.Body)
	}
}

func TestAMediaShareTakesNoEntryOnEdit(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"Trip","media":true}`)
	if rec.Code != 201 {
		t.Fatalf("create status = %d", rec.Code)
	}
	var created struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)
	rec = doReq(t, h, "PATCH", "/api/shares/"+created.ID, testToken, `{"entry":"a.html"}`)
	if rec.Code != 400 {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body)
	}
}
