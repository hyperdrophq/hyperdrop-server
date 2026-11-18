package api

import (
	"archive/zip"
	"bytes"
	"io"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func TestZipDownload(t *testing.T) {
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "bundle", map[string]string{
		"a.txt":        "alpha",
		"sub/b.txt":    "bravo",
		"sub/c%20d.md": "charlie delta",
	})
	rec := doReq(t, h, "GET", "/zip/"+id, "", "")
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/zip" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "bundle.zip") {
		t.Errorf("Content-Disposition = %q, want bundle.zip", cd)
	}

	zr, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatalf("zip.NewReader: %v", err)
	}
	want := map[string]string{"a.txt": "alpha", "sub/b.txt": "bravo", "sub/c d.md": "charlie delta"}
	if len(zr.File) != len(want) {
		t.Fatalf("zip has %d entries, want %d", len(zr.File), len(want))
	}
	for _, f := range zr.File {
		wantContent, ok := want[f.Name]
		if !ok {
			t.Errorf("unexpected entry %q", f.Name)
			continue
		}
		if f.Method != zip.Store {
			t.Errorf("entry %q method = %d, want Store", f.Name, f.Method)
		}
		rc, _ := f.Open()
		data, _ := io.ReadAll(rc)
		rc.Close()
		if string(data) != wantContent {
			t.Errorf("entry %q = %q, want %q", f.Name, data, wantContent)
		}
	}
}

func TestZipUnknownShare404(t *testing.T) {
	h := newTestAPI(t)
	if rec := doReq(t, h, "GET", "/zip/zzzzzzzzzz", "", ""); rec.Code != 404 {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestZipUnnamedShareUsesID(t *testing.T) {
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "", map[string]string{"a.txt": "x", "b.txt": "y"})
	rec := doReq(t, h, "GET", "/zip/"+id, "", "")
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, id+".zip") {
		t.Errorf("Content-Disposition = %q, want %s.zip", cd, id)
	}
}

// A folder of a share downloads on its own, holding what is IN it at the
// archive's root: the relation the whole-share zip has to the share, whose name
// is not a folder inside it either.
func TestZipOneFolderOfAShare(t *testing.T) {
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "bundle", map[string]string{
		"a.txt":          "alpha",
		"sub/b.txt":      "bravo",
		"sub/deep/c.txt": "charlie",
		"other/d.txt":    "delta",
	})
	rec := doReq(t, h, "GET", "/zip/"+id+"?dir=sub", "", "")
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "sub.zip") {
		t.Errorf("Content-Disposition = %q, want sub.zip", cd)
	}
	zr, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatalf("zip.NewReader: %v", err)
	}
	want := map[string]string{"b.txt": "bravo", "deep/c.txt": "charlie"}
	if len(zr.File) != len(want) {
		t.Fatalf("zip has %d entries, want %d", len(zr.File), len(want))
	}
	for _, f := range zr.File {
		wantContent, ok := want[f.Name]
		if !ok {
			t.Errorf("unexpected entry %q", f.Name)
			continue
		}
		rc, _ := f.Open()
		data, _ := io.ReadAll(rc)
		rc.Close()
		if string(data) != wantContent {
			t.Errorf("entry %q = %q, want %q", f.Name, data, wantContent)
		}
	}
}

// A folder zip declares its own length, not the whole share's: the figure is
// what a recipient's progress bar counts against.
func TestZipOneFolderDeclaresItsOwnLength(t *testing.T) {
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "bundle", map[string]string{
		"sub/b.txt": "bravo",
		"big.txt":   strings.Repeat("x", 4096),
	})
	rec := doReq(t, h, "GET", "/zip/"+id+"?dir=sub", "", "")
	if got := rec.Header().Get("Content-Length"); got == "" {
		t.Fatal("no Content-Length on a folder zip")
	} else if got != strconv.Itoa(rec.Body.Len()) {
		t.Errorf("Content-Length = %s, body is %d bytes", got, rec.Body.Len())
	}
}

// A name that is not a clean relpath never reaches the manifest, and a folder
// holding nothing is not an empty archive: both are the 404 an unknown slug
// gets.
func TestZipRefusesADirThatNamesNoFolder(t *testing.T) {
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "bundle", map[string]string{"sub/b.txt": "bravo"})
	for _, dir := range []string{"nope", "../etc", "sub/..", ".", "/sub", "su"} {
		rec := doReq(t, h, "GET", "/zip/"+id+"?dir="+url.QueryEscape(dir), "", "")
		if rec.Code != 404 {
			t.Errorf("dir=%q: status = %d, want 404", dir, rec.Code)
		}
	}
}

// A file of the share is not a folder of it: the prefix match is on the
// separator, so "sub" never matches "subtitle.txt".
func TestZipFolderPrefixIsWholeSegments(t *testing.T) {
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "bundle", map[string]string{
		"sub/b.txt":    "bravo",
		"subtitle.txt": "not in sub",
	})
	rec := doReq(t, h, "GET", "/zip/"+id+"?dir=sub", "", "")
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	zr, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatalf("zip.NewReader: %v", err)
	}
	if len(zr.File) != 1 || zr.File[0].Name != "b.txt" {
		t.Fatalf("entries = %v, want [b.txt]", names(zr))
	}
}

func names(zr *zip.Reader) []string {
	out := make([]string, 0, len(zr.File))
	for _, f := range zr.File {
		out = append(out, f.Name)
	}
	return out
}
