package api

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"hyperdrop/server/internal/metadb"
)

func tarOf(t *testing.T, files map[string]string, order []string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if order == nil {
		for name := range files {
			order = append(order, name)
		}
	}
	for _, name := range order {
		body := files[name]
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func postBatch(t *testing.T, h http.Handler, id, token string, body []byte, encoding string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/shares/"+id+"/batch", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-tar")
	if encoding != "" {
		req.Header.Set("Content-Encoding", encoding)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// The batch commits every entry exactly as individual PUTs would: hashed,
// slugged, viewable-resolved, and readable on the public routes afterwards.
func TestBatchCommitsAllEntries(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"bundle","folder":true}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create → %d", rec.Code)
	}
	var created struct{ ID string }
	unmarshal(t, rec, &created)

	files := map[string]string{
		"a/one.txt":   "alpha",
		"a/two.txt":   "beta",
		"b/three.bin": strings.Repeat("z", 100),
	}
	order := []string{"a/one.txt", "a/two.txt", "b/three.bin"}
	rec = postBatch(t, h, created.ID, testToken, tarOf(t, files, order), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("batch → %d: %s", rec.Code, rec.Body)
	}
	var out struct {
		Committed int `json:"committed"`
		Files     []struct {
			Path     string `json:"path"`
			Size     int64  `json:"size"`
			Slug     string `json:"slug"`
			SHA256   string `json:"sha256"`
			Viewable bool   `json:"viewable"`
		} `json:"files"`
	}
	unmarshal(t, rec, &out)
	if out.Committed != 3 || len(out.Files) != 3 {
		t.Fatalf("committed %d / %d files, want 3", out.Committed, len(out.Files))
	}
	for i, f := range out.Files {
		if f.Path != order[i] {
			t.Errorf("file %d = %q, want %q (order must match the stream)", i, f.Path, order[i])
		}
		if f.Slug == "" || f.SHA256 == "" {
			t.Errorf("%s got no slug/hash: %+v", f.Path, f)
		}
		if int(f.Size) != len(files[f.Path]) {
			t.Errorf("%s size = %d, want %d", f.Path, f.Size, len(files[f.Path]))
		}
	}
	// Each file appears in its folder, and the bytes serve publicly.
	for name := range files {
		page := doReq(t, h, "GET", folderHref(created.ID, path.Dir(name), false), "", "")
		if page.Code != http.StatusOK {
			t.Fatalf("folder listing: %d", page.Code)
		}
		if !strings.Contains(page.Body.String(), pathBase(name)) {
			t.Errorf("listing is missing %s", name)
		}
	}
	dl := doReq(t, h, "GET", "/download/"+created.ID+"/"+out.Files[0].Slug, "", "")
	if dl.Code != http.StatusOK || dl.Body.String() != files["a/one.txt"] {
		t.Fatalf("download → %d %q", dl.Code, dl.Body.String())
	}
}

// zstd on the wire: the batch decodes while receiving, like the single-file PUT.
func TestBatchAcceptsZstd(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"z"}`)
	var created struct{ ID string }
	unmarshal(t, rec, &created)

	raw := tarOf(t, map[string]string{"c.txt": strings.Repeat("compressible ", 200)}, []string{"c.txt"})
	var zbuf bytes.Buffer
	zw, err := zstd.NewWriter(&zbuf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if zbuf.Len() >= len(raw) {
		t.Fatalf("fixture did not compress (%d → %d)", len(raw), zbuf.Len())
	}
	rec = postBatch(t, h, created.ID, testToken, zbuf.Bytes(), "zstd")
	if rec.Code != http.StatusOK {
		t.Fatalf("zstd batch → %d: %s", rec.Code, rec.Body)
	}
	var out struct{ Committed int }
	unmarshal(t, rec, &out)
	if out.Committed != 1 {
		t.Fatalf("committed %d, want 1", out.Committed)
	}
	// Stored size is the ORIGINAL length, not the compressed one.
	sh := doReq(t, h, "GET", "/api/shares/"+created.ID, testToken, "")
	if !strings.Contains(sh.Body.String(), fmt.Sprint(len(strings.Repeat("compressible ", 200)))) {
		t.Errorf("stored size is not the original: %s", sh.Body)
	}
}

// Quotas apply per file INSIDE a batch, and the response names what committed
// before the refusal so a client doesn't resend it.
func TestBatchStopsAtQuotaAndReportsCommitted(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	aliceTok := seedUser(t, um, "alice")
	quota := int64(120)
	if _, err := um.UpdateUser("alice", metadb.Settings{QuotaBytes: &quota}); err != nil {
		t.Fatal(err)
	}
	rec := doReq(t, h, "POST", "/api/shares", aliceTok, `{"name":"tight"}`)
	var created struct{ ID string }
	unmarshal(t, rec, &created)

	body := tarOf(t, map[string]string{
		"one.bin":   strings.Repeat("1", 50),
		"two.bin":   strings.Repeat("2", 50),
		"three.bin": strings.Repeat("3", 50), // pushes past the 120-byte quota
	}, []string{"one.bin", "two.bin", "three.bin"})
	rec = postBatch(t, h, created.ID, aliceTok, body, "")
	if rec.Code != http.StatusInsufficientStorage {
		t.Fatalf("over quota → %d, want 507: %s", rec.Code, rec.Body)
	}
	var out struct {
		Committed int    `json:"committed"`
		Error     string `json:"error"`
		Code      string `json:"code"`
		Files     []struct {
			Path string `json:"path"`
		} `json:"files"`
	}
	unmarshal(t, rec, &out)
	// The CODE is what clients branch on, never the prose. A batch route that
	// answers with prose alone makes a quota stop here indistinguishable from
	// any other failure while the single-file route reports it properly.
	if out.Code != "quota" {
		t.Errorf("code = %q, want \"quota\": same as the single-file route", out.Code)
	}
	if out.Committed != 2 || len(out.Files) != 2 {
		t.Fatalf("want the 2 files that fit reported as committed, got %d: %s", out.Committed, rec.Body)
	}
	if !strings.Contains(out.Error, "three.bin") || !strings.Contains(out.Error, "quota") {
		t.Errorf("error should name the file and the reason: %q", out.Error)
	}
}

// A batch is owner-scoped like every other share route: another user's share ID
// is a 404, not an upload.
func TestBatchIsOwnerScoped(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	aliceTok := seedUser(t, um, "alice")
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"admins"}`)
	var created struct{ ID string }
	unmarshal(t, rec, &created)

	rec = postBatch(t, h, created.ID, aliceTok, tarOf(t, map[string]string{"x.txt": "hi"}, []string{"x.txt"}), "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-owner batch → %d, want 404", rec.Code)
	}
}

// Junk in the stream is refused, and a directory entry is simply skipped
// (paths already carry the structure).
func TestBatchRejectsNonRegularAndSkipsDirs(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"odd"}`)
	var created struct{ ID string }
	unmarshal(t, rec, &created)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "dir/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "dir/f.txt", Typeflag: tar.TypeReg, Size: 2, Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	tw.Write([]byte("ok"))
	if err := tw.WriteHeader(&tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd", Mode: 0o777}); err != nil {
		t.Fatal(err)
	}
	tw.Close()

	rec = postBatch(t, h, created.ID, testToken, buf.Bytes(), "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("symlink entry → %d, want 400: %s", rec.Code, rec.Body)
	}
	var out struct {
		Committed int    `json:"committed"`
		Error     string `json:"error"`
	}
	unmarshal(t, rec, &out)
	// The regular file before it committed; the directory was skipped silently.
	if out.Committed != 1 {
		t.Errorf("committed %d, want the 1 regular file: %s", out.Committed, rec.Body)
	}
}

// Escaping paths are refused by the server's own validation, exactly as for a PUT.
func TestBatchRefusesEscapingPaths(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"evil"}`)
	var created struct{ ID string }
	unmarshal(t, rec, &created)

	for _, bad := range []string{"../outside.txt", "/abs.txt", "a/../../b.txt"} {
		rec := postBatch(t, h, created.ID, testToken,
			tarOf(t, map[string]string{bad: "x"}, []string{bad}), "")
		if rec.Code == http.StatusOK {
			t.Errorf("path %q was accepted", bad)
		}
	}
	sh := doReq(t, h, "GET", "/api/shares/"+created.ID, testToken, "")
	var out struct {
		Files []json.RawMessage `json:"files"`
	}
	unmarshal(t, sh, &out)
	if len(out.Files) != 0 {
		t.Fatalf("share gained %d files from rejected paths", len(out.Files))
	}
}

func pathBase(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// A stream that dies inside an entry leaves no row for that entry: the
// files before it stay committed, and the one whose bytes never arrived is
// not left waiting for bytes nobody will send.
func TestABatchEntryThatNeverLandsLeavesNoRow(t *testing.T) {
	h, b := newTestAPIBackend(t)
	id := createShare(t, h, "cut")
	full := tarOf(t, map[string]string{
		"one.txt": "ok",
		"cut.bin": strings.Repeat("x", 4096),
	}, []string{"one.txt", "cut.bin"})
	rec := postBatch(t, h, id, testToken, full[:len(full)-2048], "")
	if rec.Code == http.StatusOK {
		t.Fatalf("a truncated batch = 200 %s, want a failure", rec.Body)
	}
	var out struct {
		Committed int `json:"committed"`
	}
	unmarshal(t, rec, &out)
	if out.Committed != 1 {
		t.Fatalf("committed = %d, want the one entry that landed whole", out.Committed)
	}
	d, err := b.DB.Share(id)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range d.Files {
		if f.Path == "cut.bin" {
			t.Fatalf("the share still holds %+v for an entry that never arrived", f)
		}
	}
	if len(d.Files) != 1 || d.Files[0].Path != "one.txt" {
		t.Fatalf("files = %+v, want one.txt alone", d.Files)
	}
}
