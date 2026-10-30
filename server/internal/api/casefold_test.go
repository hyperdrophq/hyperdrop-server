package api

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hyperdrop/server/internal/metadb"
)

// An owner's straße.pdf and strasse.pdf are one row where the volume takes
// them for one file (APFS) and two where it keeps them apart, and every row
// serves its own upload's bytes either way.
func TestOnTheRealVolumeTheVolumeDecidesWhatAnUploadReplaces(t *testing.T) {
	dir := t.TempDir()
	b := testBackendAt(t, dir)
	h := New(b, "2.0.0", testDomain(t), nil)
	id := createShareBody(t, h, `{"name":"s"}`)
	uploadFile(t, h, testToken, id, "straße.pdf", "first")
	uploadFile(t, h, testToken, id, "strasse.pdf", "second!")
	p := filepath.Join(dir, "probe-straße")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := os.Stat(filepath.Join(dir, "probe-strasse"))
	os.Remove(p)
	merged := err == nil
	got := ownerPaths(t, h, id)
	if merged {
		if got != "straße.pdf" || storedBytes(t, b, id, "straße.pdf") != "second!" {
			t.Fatalf("a merging volume: paths %s", got)
		}
		return
	}
	if got != "strasse.pdf,straße.pdf" || storedBytes(t, b, id, "straße.pdf") != "first" ||
		storedBytes(t, b, id, "strasse.pdf") != "second!" {
		t.Fatalf("a volume keeping them apart: paths %s", got)
	}
}

// Two first uploads into an empty share whose folders differ only in case,
// A/x and a/y, are both spelled by the route before either commits, so each
// stages and lands under its own spelling. The volume puts a/y in the folder
// A/x made, and the store spells its row A/y: the row and the file agree,
// and both files serve.
func TestOnTheRealVolumeTwoFirstUploadsDifferingInCaseLandInOneFolder(t *testing.T) {
	dir := t.TempDir()
	if !volumeFolds(t, dir) {
		t.Skip("this volume is case-sensitive")
	}
	hd := newHandler(testBackendAt(t, dir), "2.0.0", testDomain(t), nil, Deployment{})
	h := hd.routes()
	id := createShareBody(t, h, `{"name":"s"}`)
	for rel, body := range map[string]string{"A/x": "ex", "a/y": "why"} {
		if _, err := hd.fs.Write(id, hd.spelled(id, rel, ""), strings.NewReader(body)); err != nil {
			t.Fatal(err)
		}
	}
	for rel, body := range map[string]string{"A/x": "ex", "a/y": "why"} {
		if _, err := hd.commitUpload(metadb.CommitInput{ShareID: id, Path: rel}, int64(len(body))); err != nil {
			t.Fatalf("commit %s: %v", rel, err)
		}
	}
	got := ownerPaths(t, h, id)
	if got != "A/x,A/y" && got != "a/x,a/y" {
		t.Fatalf("paths = %s, want one spelling of the folder", got)
	}
	b := Backend{DB: hd.db, FS: hd.fs}
	for _, p := range strings.Split(got, ",") {
		want := map[string]string{"x": "ex", "y": "why"}[p[2:]]
		if s := storedBytes(t, b, id, p); s != want {
			t.Errorf("%s holds %q, want %q", p, s, want)
		}
	}
}

// volumeFolds reports whether the filesystem under dir matches names
// case-insensitively, asked the way a person would: make a file, look for
// it under another case.
func volumeFolds(t *testing.T, dir string) bool {
	t.Helper()
	p := filepath.Join(dir, "fold-probe")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(p)
	_, err := os.Stat(filepath.Join(dir, "FOLD-PROBE"))
	return err == nil
}

// storedBytes reads one stored file of a share through the file layer.
func storedBytes(t *testing.T, b Backend, id, rel string) string {
	t.Helper()
	f, _, err := b.FS.Open(id, rel)
	if err != nil {
		t.Fatalf("open %s: %v", rel, err)
	}
	defer f.Close()
	body, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// ownerPaths answers the paths a share's owner sees, comma-joined.
func ownerPaths(t *testing.T, h http.Handler, id string) string {
	t.Helper()
	var share struct{ Files []struct{ Path string } }
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+id, testToken, ""), &share)
	var out []string
	for _, f := range share.Files {
		out = append(out, f.Path)
	}
	return strings.Join(out, ",")
}

// On a volume that folds case, report.pdf and Report.pdf are one file, so
// an inbox numbers the second the way it numbers an exact repeat, and both
// senders' bytes stay.
func TestOnTheRealVolumeAnInboxNeverLetsCaseReplaceAFile(t *testing.T) {
	dir := t.TempDir()
	if !volumeFolds(t, dir) {
		t.Skip("this volume is case-sensitive")
	}
	b := testBackendAt(t, dir)
	h := New(b, "2.0.0", testDomain(t), nil)
	id := createInbox(t, h, `{"name":"inbox","receive":true}`)
	if rec := doReq(t, h, "PUT", "/receive/"+id+"/files/report.pdf", "", "first"); rec.Code != 201 {
		t.Fatalf("first = %d %s", rec.Code, rec.Body)
	}
	rec := doReq(t, h, "PUT", "/receive/"+id+"/files/Report.pdf", "", "second")
	if rec.Code != 201 || !strings.Contains(rec.Body.String(), "Report 2.pdf") {
		t.Fatalf("second = %d %s", rec.Code, rec.Body)
	}
	if got := storedBytes(t, b, id, "report.pdf"); got != "first" {
		t.Errorf("report.pdf holds %q", got)
	}
	if got := storedBytes(t, b, id, "Report 2.pdf"); got != "second" {
		t.Errorf("Report 2.pdf holds %q", got)
	}
}

// foldingAPI is a handler whose file layer is told the volume folds case,
// so the folded decisions run on a case-sensitive volume too.
func foldingAPI(t *testing.T, folds bool) (http.Handler, Backend) {
	t.Helper()
	b := testBackend(t)
	b.FS.SetFoldsCase(folds)
	return New(b, "2.0.0", testDomain(t), nil), b
}

func TestAFoldingVolumeNumbersAnInboxNameThatDiffersOnlyInCase(t *testing.T) {
	h, b := foldingAPI(t, true)
	id := createInbox(t, h, `{"name":"inbox","receive":true}`)
	for _, up := range []struct{ name, body, want string }{
		{"report.pdf", "first", "report.pdf"},
		{"Report.pdf", "second", "Report 2.pdf"},
		{"REPORT.PDF", "third", "REPORT 3.PDF"},
		{"report 2.PDF", "fourth", "report 2 2.PDF"},
	} {
		rec := doReq(t, h, "PUT", "/receive/"+id+"/files/"+strings.ReplaceAll(up.name, " ", "%20"), "", up.body)
		if rec.Code != 201 || !strings.Contains(rec.Body.String(), `"name":"`+up.want+`"`) {
			t.Fatalf("%s = %d %s, want %s", up.name, rec.Code, rec.Body, up.want)
		}
		if got := storedBytes(t, b, id, up.want); got != up.body {
			t.Errorf("%s holds %q, want %q", up.want, got, up.body)
		}
	}
	if got := storedBytes(t, b, id, "report.pdf"); got != "first" {
		t.Errorf("report.pdf holds %q", got)
	}
}

func TestACaseSensitiveVolumeKeepsNamesThatDifferOnlyInCase(t *testing.T) {
	h, b := foldingAPI(t, false)
	if volumeFolds(t, b.FS.DataDir()) {
		t.Skip("this volume folds case")
	}
	id := createInbox(t, h, `{"name":"inbox","receive":true}`)
	for _, name := range []string{"report.pdf", "Report.pdf"} {
		rec := doReq(t, h, "PUT", "/receive/"+id+"/files/"+name, "", name)
		if rec.Code != 201 || !strings.Contains(rec.Body.String(), `"name":"`+name+`"`) {
			t.Fatalf("%s = %d %s", name, rec.Code, rec.Body)
		}
	}
	created := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"s","files":[{"path":"a.txt","size":1},{"path":"A.txt","size":1}]}`)
	if created.Code != 201 {
		t.Fatalf("a manifest of a.txt and A.txt = %d %s", created.Code, created.Body)
	}
	for _, name := range []string{"report.pdf", "Report.pdf"} {
		if got := storedBytes(t, b, id, name); got != name {
			t.Errorf("%s holds %q", name, got)
		}
	}
}

// An owner's upload whose name differs only in case from a file the share
// holds is an upload to that file, as an exact repeat is: one row, the new
// bytes, the old slug.
func TestAFoldingVolumeTakesAnOwnersUploadAsTheFileItFolds(t *testing.T) {
	h, b := foldingAPI(t, true)
	id := createShareBody(t, h, `{"name":"s"}`)
	uploadFile(t, h, testToken, id, "docs/report.pdf", "old")
	slug := func() string {
		var share struct{ Files []struct{ Path, Slug string } }
		unmarshal(t, doReq(t, h, "GET", "/api/shares/"+id, testToken, ""), &share)
		for _, f := range share.Files {
			if f.Path == "docs/report.pdf" {
				return f.Slug
			}
		}
		return ""
	}
	before := slug()
	uploadFile(t, h, testToken, id, "DOCS/Report.pdf", "newer")
	uploadFile(t, h, testToken, id, "Docs/other.txt", "other")
	if got := ownerPaths(t, h, id); got != "docs/other.txt,docs/report.pdf" {
		t.Fatalf("paths = %s", got)
	}
	if got := storedBytes(t, b, id, "docs/report.pdf"); got != "newer" {
		t.Errorf("docs/report.pdf holds %q", got)
	}
	if after := slug(); after == "" || after != before {
		t.Errorf("slug %q became %q", before, after)
	}
}

func TestAFoldingVolumeRefusesWhatWouldStandOnAFileByCase(t *testing.T) {
	h, _ := foldingAPI(t, true)
	if rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"s","files":[{"path":"a.txt","size":1},{"path":"A.txt","size":1}]}`); rec.Code != 400 {
		t.Errorf("a manifest of a.txt and A.txt = %d %s", rec.Code, rec.Body)
	}
	id := createShareBody(t, h, `{"name":"s"}`)
	uploadFile(t, h, testToken, id, "a.txt", "a")
	uploadFile(t, h, testToken, id, "b.txt", "b")
	uploadFile(t, h, testToken, id, "docs/x.txt", "x")
	if rec := doReq(t, h, "POST", "/api/shares/"+id+"/move", testToken, `{"from":"b.txt","to":"A.txt"}`); rec.Code != 400 && rec.Code != 409 {
		t.Errorf("move onto A.txt = %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "POST", "/api/shares/"+id+"/folders", testToken, `{"path":"DOCS"}`); rec.Code != 400 && rec.Code != 409 {
		t.Errorf("folder DOCS = %d %s", rec.Code, rec.Body)
	}
	// A case-only rename names nothing else, so it renames.
	if rec := doReq(t, h, "POST", "/api/shares/"+id+"/move", testToken, `{"from":"a.txt","to":"A.txt"}`); rec.Code != 200 {
		t.Errorf("move a.txt to A.txt = %d %s", rec.Code, rec.Body)
	}
	if got := ownerPaths(t, h, id); got != "A.txt,b.txt,docs/x.txt" {
		t.Errorf("paths = %s", got)
	}
}
