package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

// A big folder's manifest is bigger than the create body cap: 765k files in
// /Applications serialize to ~96 MiB, and the handler reads at most 1 MiB.
func TestCreateShareHugeManifest(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	type spec struct {
		Path string `json:"path"`
		Size int64  `json:"size"`
	}
	specs := make([]spec, 40000) // ~1.5 MiB of JSON, past the 1 MiB cap
	for i := range specs {
		specs[i] = spec{Path: fmt.Sprintf("dir%05d/file%05d.bin", i, i), Size: int64(i)}
	}
	body, _ := json.Marshal(map[string]any{"name": "big", "files": specs})
	t.Logf("manifest body: %d bytes", len(body))
	rec := doReq(t, h, "POST", "/api/shares", testToken, string(body))
	t.Logf("→ %d %s", rec.Code, rec.Body.String())
	if rec.Code == http.StatusCreated {
		t.Log("accepted (no cap problem)")
	}
}
