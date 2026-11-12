package api

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"hyperdrop/server/internal/domain"
	"hyperdrop/server/internal/housekeep"
)

// publishAPIParts is publishAPI with the handler behind it, for a test that
// sets one of its seams.
func publishAPIParts(t *testing.T) (http.Handler, *handler, Backend) {
	t.Helper()
	dom, err := domain.Load(filepath.Join(t.TempDir(), "domain"), "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	if err := dom.Adopt("share.example.com"); err != nil {
		t.Fatal(err)
	}
	b := testBackend(t)
	hd := newHandler(b, "2.0.0", dom, nil, Deployment{})
	return hd.routes(), hd, b
}

// A commit reads its staged records and writes its journal before it takes
// the share's swap lock: while that prepare step runs (held here by the
// seam, with the journal already written), a visitor's read of the share
// answers at once.
func TestACommitPreparesOutsideTheSwapLock(t *testing.T) {
	h, hd, b := publishAPIParts(t)
	id := createShare(t, h, "site")
	slug := uploadGetSlug(t, h, id, "page.txt", "served throughout")
	pid := openPublish(t, h, testToken, id)
	stageFile(t, h, id, pid, "a.txt", "staged a")

	prepared, release := make(chan struct{}), make(chan struct{})
	hd.publishPrepared = func(string, string) {
		close(prepared)
		<-release
	}
	done := make(chan int, 1)
	go func() { done <- commitPublish(t, h, id, pid, `{"files":["a.txt"]}`).Code }()
	<-prepared
	if j, held, err := b.FS.ReadJournal(id, pid); err != nil || !held || j.Rows != nil {
		close(release)
		t.Fatalf("the journal during the prepare step: %+v held %v, %v", j, held, err)
	}
	read := make(chan int, 1)
	go func() { read <- req(t, h, "GET", "files.share.example.com", "/view/"+id+"/"+slug).Code }()
	select {
	case code := <-read:
		if code != 200 {
			close(release)
			t.Fatalf("the read during the prepare step = %d", code)
		}
	case <-time.After(2 * time.Second):
		close(release)
		<-read
		t.Fatal("a visitor's read waited for a commit's prepare step")
	}
	close(release)
	if code := <-done; code != 200 {
		t.Fatalf("the commit = %d", code)
	}
	if got, _ := publishedBytes(t, b, id, "a.txt"); got != "staged a" {
		t.Fatalf("a.txt = %q", got)
	}
}

// Bytes no row names (a delete whose removal of the bytes failed) never
// stop a commit: a stray file where the commit needs a folder, and a stray
// folder where it renames a file, are cleared, inside the share, by the
// commit that needs the path.
func TestACommitClearsBytesNoRowNames(t *testing.T) {
	h, b := publishAPI(t)
	id := createShare(t, h, "site")
	uploadGetSlug(t, h, id, "keep.txt", "kept")
	dir, err := b.FS.ShareDir(id)
	if err != nil {
		t.Fatal(err)
	}
	files := filepath.Join(dir, "files")
	if err := os.WriteFile(filepath.Join(files, "docs"), []byte("stray file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(files, "x", "deep"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(files, "x", "deep", "junk"), []byte("stray"), 0o600); err != nil {
		t.Fatal(err)
	}
	pid := openPublish(t, h, testToken, id)
	stageFile(t, h, id, pid, "docs/index.html", "<p>docs</p>")
	stageFile(t, h, id, pid, "x", "a file at x")
	if rec := commitPublish(t, h, id, pid, `{"files":["docs/index.html","x"]}`); rec.Code != 200 {
		t.Fatalf("the commit over stray bytes: %d %s", rec.Code, rec.Body)
	}
	for rel, want := range map[string]string{"docs/index.html": "<p>docs</p>", "x": "a file at x", "keep.txt": "kept"} {
		if got, _ := publishedBytes(t, b, id, rel); got != want {
			t.Fatalf("%s = %q, want %q", rel, got, want)
		}
	}
	if b.FS.StageExists(id, pid) {
		t.Fatal("the publish is still open")
	}
}

// A rename that fails on a running server is finished by the next
// housekeeping pass, under the commit's locks, without a restart: the rows
// then name their bytes and the publish is closed.
func TestHousekeepingFinishesAFailedRename(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes into any directory")
	}
	h, b := publishAPI(t)
	id := createShare(t, h, "site")
	uploadGetSlug(t, h, id, "d/old.txt", "d")
	uploadGetSlug(t, h, id, "gone.txt", "bye")
	pid := openPublish(t, h, testToken, id)
	stageFile(t, h, id, pid, "d/c.txt", "staged c")
	dir, err := b.FS.ShareDir(id)
	if err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(dir, "files", "d")
	if err := os.Chmod(locked, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o700) })
	if rec := commitPublish(t, h, id, pid, `{"files":["d/c.txt"],"delete":["gone.txt"]}`); rec.Code != http.StatusInternalServerError {
		t.Fatalf("a commit whose rename fails: %d %s", rec.Code, rec.Body)
	}
	pass := &housekeep.Pass{DB: b.DB, FS: b.FS}
	if r := pass.Run(); r.PublishesFinished != 0 || r.PublishesErr == nil {
		t.Fatalf("a pass while the rename still fails: finished %d, %v", r.PublishesFinished, r.PublishesErr)
	}
	if _, held, _ := b.FS.ReadJournal(id, pid); !held {
		t.Fatal("the journal went while its rename still fails")
	}
	os.Chmod(locked, 0o700)
	if r := pass.Run(); r.PublishesFinished != 1 || r.PublishesErr != nil {
		t.Fatalf("the pass after the disk recovers: finished %d, %v", r.PublishesFinished, r.PublishesErr)
	}
	if b.FS.StageExists(id, pid) {
		t.Fatal("the publish is still open")
	}
	listed := readListed(t, h, id)
	for _, f := range listed.Files {
		got, ok := publishedBytes(t, b, id, f.Path)
		if !ok || sha(got) != f.SHA256 {
			t.Fatalf("row %s (sha256 %s) names %q (present %v)", f.Path, f.SHA256, got, ok)
		}
	}
	if _, ok := publishedBytes(t, b, id, "gone.txt"); ok {
		t.Fatal("the deleted file is still on disk")
	}
	if code, body := moveReq(t, h, id, testToken, "d", "e"); code != http.StatusOK {
		t.Fatalf("a move of the finished path: %d %s", code, body)
	}
}

// A delete removes its rows, then its bytes under the path's lock; a
// publish committing the same path in between keeps the bytes its row
// names: the delete leaves bytes a row names where they are.
func TestADeleteKeepsBytesAPublishCommittedMeanwhile(t *testing.T) {
	h, hd, b := publishAPIParts(t)
	id := createShare(t, h, "site")
	uploadGetSlug(t, h, id, "a.txt", "old a")
	uploadGetSlug(t, h, id, "keep.txt", "kept")
	pid := openPublish(t, h, testToken, id)
	stageFile(t, h, id, pid, "a.txt", "published a")
	hd.rowsRemoved = func(string, []string) {
		hd.rowsRemoved = nil
		if rec := commitPublish(t, h, id, pid, `{"files":["a.txt"]}`); rec.Code != 200 {
			t.Errorf("the commit between the delete's rows and bytes: %d %s", rec.Code, rec.Body)
		}
	}
	if rec := doReq(t, h, "DELETE", "/api/shares/"+id+"/files/a.txt", testToken, ""); rec.Code != 200 {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	listed := readListed(t, h, id)
	if len(listed.Files) != 2 {
		t.Fatalf("the share lists %d files, want 2", len(listed.Files))
	}
	for _, f := range listed.Files {
		got, ok := publishedBytes(t, b, id, f.Path)
		if !ok || sha(got) != f.SHA256 {
			t.Fatalf("row %s (sha256 %s) names %q (present %v)", f.Path, f.SHA256, got, ok)
		}
	}
}

// A row is never served over bytes of another size: a file whose bytes on
// disk are not the row's length (a rename that failed, leaving the file it
// was to replace) answers 404 on every read route rather than old bytes
// under the new row's hash and length.
func TestAFileWhoseBytesAreNotItsRowsSizeIsNotServed(t *testing.T) {
	h, b := publishAPI(t)
	id := createShare(t, h, "site")
	slug := uploadGetSlug(t, h, id, "page.txt", "the row's bytes")
	p, err := b.FS.FilePath(id, "page.txt")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("other bytes, of another length"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/view/" + id + "/" + slug, "/download/" + id + "/" + slug, "/site/" + id + "/page.txt"} {
		if rec := req(t, h, "GET", "files.share.example.com", path); rec.Code != http.StatusNotFound {
			t.Fatalf("%s = %d %q, want 404", path, rec.Code, rec.Body)
		}
	}
}

// A publish committing a file still being prepared (declared pending, its
// sender reporting an encode) drops the report, as a plain commit does:
// the file it names is committed.
func TestAPublishCommitDropsThePreparingReport(t *testing.T) {
	h, hd, _ := publishAPIParts(t)
	id, _ := declaredShare(t, h, 5)
	if code := report(t, h, testToken, id, "a.mp4", `{"fraction":0.5,"stage":"encoding"}`); code != 204 {
		t.Fatalf("report: %d", code)
	}
	pid := openPublish(t, h, testToken, id)
	stageFile(t, h, id, pid, "a.mp4", "hello")
	if rec := commitPublish(t, h, id, pid, `{"files":["a.mp4"]}`); rec.Code != 200 {
		t.Fatalf("commit: %d %s", rec.Code, rec.Body)
	}
	if _, ok := hd.prep.get(id, "a.mp4"); ok {
		t.Fatal("a committed file kept its preparing report")
	}
}
