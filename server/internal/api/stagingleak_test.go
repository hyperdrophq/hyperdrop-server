package api

import (
	"archive/tar"
	"bytes"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// partsLeft lists what a share's parts/ directory still holds.
func partsLeft(t *testing.T, b Backend, id string) []string {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join(b.FS.DataDir(), "shares", id, "parts"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// A name no filesystem can store is refused before its body is staged, on
// the anonymous route and on every authenticated upload form, so nothing
// lands outside the link's caps, the owner's quota and the sweeps.
func TestOverLongNameIsRefusedBeforeAnyByteIsStaged(t *testing.T) {
	b := testBackend(t)
	h := New(b, "test", testDomain(t), nil)
	long := strings.Repeat("a", 300)

	inbox := createInbox(t, h, `{"name":"inbox","receive":true,"maxBytes":10}`)
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("PUT", "/receive/"+inbox+"/files/"+long[i:], strings.NewReader("12345678"))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 400 {
			t.Fatalf("inbox upload %d = %d %s", i, rec.Code, rec.Body)
		}
	}
	if left := partsLeft(t, b, inbox); len(left) != 0 {
		t.Fatalf("inbox staging left behind: %v", left)
	}

	share := createShare(t, h, "s")
	if rec := doReq(t, h, "PUT", "/api/shares/"+share+"/files/dir/"+long, testToken, "body"); rec.Code != 400 {
		t.Fatalf("whole-body upload = %d %s", rec.Code, rec.Body)
	}
	if rec := putRange(t, h, testToken, share, long, "test-session", 0, 4, 4, []byte("body")); rec.Code != 400 {
		t.Fatalf("ranged upload = %d %s", rec.Code, rec.Body)
	}
	if rec := postBatch(t, h, share, testToken, tarOf(t, map[string]string{long: "body"}, nil), ""); rec.Code != 400 {
		t.Fatalf("batch = %d %s", rec.Code, rec.Body)
	}
	if left := partsLeft(t, b, share); len(left) != 0 {
		t.Fatalf("share staging left behind: %v", left)
	}
}

// A batch entry whose path the stored tree refuses (a file where its folder
// would go) takes its staged part with it: a one-shot body is no resume
// state, and a part without a row is invisible to quota and the sweep.
func TestBatchEntryThePathRefusesLeavesNoPart(t *testing.T) {
	b := testBackend(t)
	h := New(b, "test", testDomain(t), nil)
	share := createShare(t, h, "s")
	uploadFile(t, h, testToken, share, "a", "file")
	rec := postBatch(t, h, share, testToken, tarOf(t, map[string]string{"a/b": "under a file"}, nil), "")
	if rec.Code != 400 {
		t.Fatalf("batch = %d %s", rec.Code, rec.Body)
	}
	if left := partsLeft(t, b, share); len(left) != 0 {
		t.Fatalf("staging left behind: %v", left)
	}
}

// A missing FILE is named as one: a ?replaces= naming nothing the share
// holds says which file, never "share not found" about a share that is
// there.
func TestAMissingFileIsNotReportedAsAMissingShare(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "s")
	rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/new.txt?replaces=missing.txt", testToken, "x")
	if rec.Code != 400 || strings.Contains(rec.Body.String(), "share not found") || !strings.Contains(rec.Body.String(), "missing.txt") {
		t.Fatalf("replaces of a missing file = %d %s", rec.Code, rec.Body)
	}
}

// Directory entries commit nothing and carry no bytes, but they are entries:
// an endless run of them ends at batchMaxEntries instead of holding the
// connection for as long as the sender likes.
func TestABatchOfEndlessDirectoryEntriesEnds(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "s")
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for i := 0; i <= batchMaxEntries; i++ {
		if err := tw.WriteHeader(&tar.Header{Name: fmt.Sprintf("d%d/", i), Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	if rec := postBatch(t, h, id, testToken, buf.Bytes(), ""); rec.Code != 413 {
		t.Fatalf("batch of directory entries = %d %s", rec.Code, rec.Body)
	}
}
