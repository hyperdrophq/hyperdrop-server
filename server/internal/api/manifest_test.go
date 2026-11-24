package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func manifestBody(t *testing.T, n int) string {
	t.Helper()
	type spec struct {
		Path string `json:"path"`
		Size int64  `json:"size"`
	}
	specs := make([]spec, n)
	for i := range specs {
		specs[i] = spec{Path: fmt.Sprintf("d%05d/f%05d.bin", i, i), Size: int64(i)}
	}
	body, err := json.Marshal(map[string]any{"name": "big", "files": specs})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// A manifest past the entry limit is refused AS a manifest problem: silent
// truncation by a LimitReader, reported as "invalid JSON", is the error that
// points nowhere, and a 765k-file folder share is what walks into it.
func TestCreateShareRejectsOversizedManifestClearly(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)

	// Past the entry cap but inside the body cap → manifest-too-big.
	rec := doReq(t, h, "POST", "/api/shares", testToken, manifestBody(t, maxManifestFiles+1))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over the entry cap → %d, want 413: %s", rec.Code, rec.Body)
	}
	var e struct{ Error, Code string }
	unmarshal(t, rec, &e)
	if e.Code != "manifest-too-big" {
		t.Fatalf("code = %q, want manifest-too-big (%s)", e.Code, rec.Body)
	}
	if !strings.Contains(e.Error, fmt.Sprint(maxManifestFiles)) {
		t.Fatalf("error should state the limit: %q", e.Error)
	}

	// Past the BODY cap → a size error, never a JSON syntax error.
	huge := manifestBody(t, 200000)
	if len(huge) <= createBodyLimit {
		t.Fatalf("fixture is only %d bytes, expected past the %d limit", len(huge), createBodyLimit)
	}
	rec = doReq(t, h, "POST", "/api/shares", testToken, huge)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over the body cap → %d, want 413: %s", rec.Code, rec.Body)
	}
	unmarshal(t, rec, &e)
	if e.Code != "body-too-large" {
		t.Fatalf("code = %q, want body-too-large (%s)", e.Code, rec.Body)
	}
	if strings.Contains(strings.ToLower(e.Error), "json") {
		t.Fatalf("a too-big body must not read as a JSON error: %q", e.Error)
	}
}

// A manifest at the limit still works: the cap is a guard rail, not a wall in
// front of ordinary folder shares.
func TestCreateShareAcceptsManifestAtTheLimit(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, manifestBody(t, maxManifestFiles))
	if rec.Code != http.StatusCreated {
		t.Fatalf("manifest of %d → %d: %.300s", maxManifestFiles, rec.Code, rec.Body)
	}
	var out struct {
		ID    string `json:"id"`
		Files []struct {
			Path    string `json:"path"`
			Slug    string `json:"slug"`
			Pending bool   `json:"pending"`
		} `json:"files"`
	}
	unmarshal(t, rec, &out)
	if len(out.Files) != maxManifestFiles {
		t.Fatalf("echoed %d entries, want %d", len(out.Files), maxManifestFiles)
	}
	if out.Files[0].Slug == "" {
		t.Fatal("manifest entries must come back with pre-minted slugs")
	}
}
