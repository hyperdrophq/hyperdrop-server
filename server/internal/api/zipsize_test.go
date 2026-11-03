package api

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/metadb"
)

// The predictor must agree byte-for-byte with the writer zipShare actually
// uses: same headers, store mode, streaming data descriptors.
func TestZipTotalSizeMatchesRealWriter(t *testing.T) {
	cases := [][]struct {
		name string
		body string
	}{
		{{"a.txt", "alpha"}},
		{{"a.txt", ""}}, // empty file still carries a descriptor
		{{"a.txt", "alpha"}, {"sub/dir/b.bin", strings.Repeat("x", 70_000)}, {"empty", ""}},
		{{"файл.txt", "utf-8 name"}, {"b c.md", "spaces"}},
	}
	now := time.Now()
	for i, files := range cases {
		var entries []fileView
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		for _, f := range files {
			entries = append(entries, fileView{File: metadb.File{Path: f.name, Size: int64(len(f.body))}})
			dst, err := zw.CreateHeader(&zip.FileHeader{Name: f.name, Method: zip.Store, Modified: now})
			if err != nil {
				t.Fatal(err)
			}
			dst.Write([]byte(f.body))
		}
		zw.Close()

		got, ok := zipTotalSize(entries, now)
		if !ok {
			t.Fatalf("case %d: predictor bailed", i)
		}
		if got != int64(buf.Len()) {
			t.Fatalf("case %d: predicted %d, real zip is %d bytes", i, got, buf.Len())
		}
	}
}

func TestZipTotalSizeBailsOnZip64(t *testing.T) {
	now := time.Now()
	if _, ok := zipTotalSize([]fileView{{File: metadb.File{Path: "huge.bin", Size: 5 << 30}}}, now); ok {
		t.Fatal("a 4 GiB or larger file needs zip64 records: predictor must bail")
	}
	// Files individually fine, total over the 4 GiB offset boundary.
	many := []fileView{
		{File: metadb.File{Path: "a.bin", Size: 3 << 30}},
		{File: metadb.File{Path: "b.bin", Size: 2 << 30}},
	}
	if _, ok := zipTotalSize(many, now); ok {
		t.Fatal("a 4 GiB or larger archive needs zip64 records: predictor must bail")
	}
}

func TestZipDownloadSendsContentLength(t *testing.T) {
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "bundle", map[string]string{
		"a.txt":     "alpha",
		"sub/b.txt": "bravo",
	})
	rec := doReq(t, h, "GET", "/zip/"+id, "", "")
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	cl := rec.Header().Get("Content-Length")
	if cl == "" {
		t.Fatal("no Content-Length on zip download")
	}
	n, err := strconv.Atoi(cl)
	if err != nil || n != rec.Body.Len() {
		t.Fatalf("Content-Length = %q, body is %d bytes", cl, rec.Body.Len())
	}
}

// The concurrency cap: a request that can't get a slot before its client
// goes away streams nothing (no partial zip bytes, no held slot).
func TestZipStreamCapRespectsCancel(t *testing.T) {
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "bundle", map[string]string{"a.txt": "alpha"})

	// Fill every global slot, each from a DIFFERENT owner so the per-owner
	// sub-cap isn't what blocks this request.
	for i := 0; i < cap(zipSem.global); i++ {
		if !zipSem.acquire(context.Background(), fmt.Sprintf("hog-%d", i)) {
			t.Fatal("could not fill the zip slots")
		}
	}
	defer func() {
		for i := 0; i < cap(zipSem.global); i++ {
			zipSem.release(fmt.Sprintf("hog-%d", i))
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // client already gone
	req := httptest.NewRequest("GET", "/zip/"+id, nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Body.Len() != 0 {
		t.Fatalf("blocked zip wrote %d bytes, want none", rec.Body.Len())
	}
}
