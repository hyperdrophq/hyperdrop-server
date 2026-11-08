package api

import (
	"encoding/json"
	"testing"
)

// shareRespFile mirrors fileOut for test assertions.
type shareRespFile struct {
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	Slug     string `json:"slug"`
	SHA256   string `json:"sha256"`
	Viewable bool   `json:"viewable"`
	Pending  bool   `json:"pending"`
}

type shareResp struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	TotalSize int64           `json:"totalSize"`
	Files     []shareRespFile `json:"files"`
}

func TestCreateShareWithManifest(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"name":"docs","files":[{"path":"report.pdf","size":1234},{"path":"img/p.jpg","size":9}]}`)
	if rec.Code != 201 {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body)
	}
	var resp shareResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if len(resp.Files) != 2 {
		t.Fatalf("files = %+v, want 2 entries", resp.Files)
	}
	if resp.TotalSize != 1243 {
		t.Errorf("totalSize = %d, want 1243", resp.TotalSize)
	}
	for _, f := range resp.Files {
		if !f.Pending {
			t.Errorf("file %+v: pending = false, want true", f)
		}
		if len(f.Slug) != 36 {
			t.Errorf("file %+v: slug len = %d, want 36", f, len(f.Slug))
		}
		if f.SHA256 != "" {
			t.Errorf("file %+v: sha256 = %q, want empty", f, f.SHA256)
		}
		if !f.Viewable {
			t.Errorf("file %+v: viewable = false, want true", f)
		}
	}
}

func TestCreateShareManifestBadPath(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"files":[{"path":"../x","size":1}]}`)
	if rec.Code != 400 {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body)
	}
	rec = doReq(t, h, "GET", "/api/shares", testToken, "")
	var resp struct {
		Shares []json.RawMessage `json:"shares"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if len(resp.Shares) != 0 {
		t.Errorf("shares = %d, want 0 (bad manifest must not create a share)", len(resp.Shares))
	}
}

func TestUploadCommitsPendingEntry(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"name":"docs","files":[{"path":"a.txt","size":5}]}`)
	if rec.Code != 201 {
		t.Fatalf("create status = %d, want 201; body %s", rec.Code, rec.Body)
	}
	var created shareResp
	unmarshal(t, rec, &created)
	if len(created.Files) != 1 {
		t.Fatalf("created files = %+v, want 1 entry", created.Files)
	}
	manifestSlug := created.Files[0].Slug

	rec = doReq(t, h, "PUT", "/api/shares/"+created.ID+"/files/a.txt", testToken, "hello")
	if rec.Code != 201 {
		t.Fatalf("upload status = %d, want 201; body %s", rec.Code, rec.Body)
	}
	var uploadResp struct {
		Slug string `json:"slug"`
	}
	unmarshal(t, rec, &uploadResp)
	if uploadResp.Slug != manifestSlug {
		t.Errorf("upload slug = %q, want manifest slug %q", uploadResp.Slug, manifestSlug)
	}

	rec = doReq(t, h, "GET", "/api/shares/"+created.ID, testToken, "")
	var got shareResp
	unmarshal(t, rec, &got)
	if len(got.Files) != 1 {
		t.Fatalf("files = %+v, want 1 entry", got.Files)
	}
	f := got.Files[0]
	if f.Pending {
		t.Errorf("file %+v: pending = true, want false/omitted after commit", f)
	}
	if f.SHA256 == "" {
		t.Errorf("file %+v: sha256 empty, want set after commit", f)
	}
	if f.Size != 5 {
		t.Errorf("file %+v: size = %d, want 5 (real uploaded size)", f, f.Size)
	}
}

func TestUploadOutsideManifestStillWorks(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"name":"docs","files":[{"path":"a.txt","size":5}]}`)
	if rec.Code != 201 {
		t.Fatalf("create status = %d, want 201; body %s", rec.Code, rec.Body)
	}
	var created shareResp
	unmarshal(t, rec, &created)
	aSlug := created.Files[0].Slug

	rec = doReq(t, h, "PUT", "/api/shares/"+created.ID+"/files/b.txt", testToken, "goodbye!")
	if rec.Code != 201 {
		t.Fatalf("upload status = %d, want 201; body %s", rec.Code, rec.Body)
	}
	var uploadResp struct {
		Slug string `json:"slug"`
	}
	unmarshal(t, rec, &uploadResp)
	if uploadResp.Slug == "" || uploadResp.Slug == aSlug {
		t.Errorf("upload slug = %q, want a fresh non-empty slug distinct from %q", uploadResp.Slug, aSlug)
	}

	rec = doReq(t, h, "GET", "/api/shares/"+created.ID, testToken, "")
	var got shareResp
	unmarshal(t, rec, &got)
	if len(got.Files) != 2 {
		t.Fatalf("files = %+v, want 2 entries", got.Files)
	}
	var foundA, foundB bool
	for _, f := range got.Files {
		switch f.Path {
		case "a.txt":
			foundA = true
			if !f.Pending {
				t.Errorf("a.txt: pending = false, want true (still not uploaded)")
			}
		case "b.txt":
			foundB = true
			if f.Pending {
				t.Errorf("b.txt: pending = true, want false")
			}
		}
	}
	if !foundA || !foundB {
		t.Errorf("files = %+v, want both a.txt and b.txt", got.Files)
	}
}
