package api

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/sharefs"
	"hyperdrop/server/internal/shareid"
)

// dupOut is the part of a share answer the duplicate tests read.
type dupOut struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	LinksOff bool   `json:"linksOff"`
	Files    []struct {
		Path    string `json:"path"`
		Slug    string `json:"slug"`
		Pending bool   `json:"pending"`
	} `json:"files"`
	Sources []string `json:"sources"`
}

// duplicateOf asks for a copy of id and answers the 201's share.
func duplicateOf(t *testing.T, h http.Handler, token, id, body string) dupOut {
	t.Helper()
	rec := doReq(t, h, "POST", "/api/shares/"+id+"/duplicate", token, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("duplicate %s = %d %s", id, rec.Code, rec.Body)
	}
	var out dupOut
	unmarshal(t, rec, &out)
	return out
}

// waitCopyDone waits until the copy id has finished (copying_from cleared)
// or is gone, and reports whether it still exists.
func waitCopyDone(t *testing.T, db *metadb.DB, id string) bool {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		d, err := db.ShareCapped(id, 1)
		if errors.Is(err, metadb.ErrNotFound) {
			return false
		}
		if err != nil {
			t.Fatal(err)
		}
		if d.CopyingFrom == "" {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("copy %s did not finish", id)
	return false
}

// copyJobsOf answers every job of the copy id still to do.
func copyJobsOf(t *testing.T, db *metadb.DB, id string) []metadb.CopyJob {
	t.Helper()
	jobs, err := db.CopyJobs(id, "", 1000)
	if err != nil {
		t.Fatal(err)
	}
	return jobs
}

// holdCopy holds the copy line inside its first file until the release it
// answers is called (once, or at the test's end): entered is closed once a
// copy is inside it.
func holdCopy(t *testing.T) (entered <-chan struct{}, release func()) {
	t.Helper()
	in, out := make(chan struct{}), make(chan struct{})
	var first, done sync.Once
	real := stageCopy
	stageCopy = func(f *sharefs.FS, srcID, srcRel, dstID, dstRel string) (int64, error) {
		first.Do(func() {
			close(in)
			<-out
		})
		return real(f, srcID, srcRel, dstID, dstRel)
	}
	release = func() { done.Do(func() { close(out) }) }
	t.Cleanup(func() {
		release()
		stageCopy = real
	})
	return in, release
}

// readStored answers the bytes share id stores at rel.
func readStored(t *testing.T, fs *sharefs.FS, id, rel string) string {
	t.Helper()
	f, _, err := fs.Open(id, rel)
	if err != nil {
		t.Fatalf("open %s/%s: %v", id, rel, err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// uploadedShare creates a share named name holding files (path -> content)
// through the API, every file committed.
func uploadedShare(t *testing.T, h http.Handler, token, name string, files map[string]string) string {
	t.Helper()
	rec := doReq(t, h, "POST", "/api/shares", token, `{"name":"`+name+`","folder":true}`)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	var out dupOut
	unmarshal(t, rec, &out)
	for rel, content := range files {
		uploadFile(t, h, token, out.ID, rel, content)
	}
	return out.ID
}

// A duplicate answers 201 with a new share holding the original's paths
// under new slugs, still pending, then fills them with the original's bytes
// and leaves the original as it was.
func TestDuplicateAnswersANewShareAndFillsIt(t *testing.T) {
	h, b := newTestAPIBackend(t)
	files := map[string]string{"a.txt": "alpha", "docs/b.txt": "bravo!"}
	src := uploadedShare(t, h, testToken, "trip", files)
	var before dupOut
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+src, testToken, ""), &before)

	d := duplicateOf(t, h, testToken, src, `{}`)
	if d.ID == src || !shareid.ValidID(d.ID) {
		t.Fatalf("the copy's id %q", d.ID)
	}
	if d.Name != "trip copy" {
		t.Fatalf("the copy's name %q", d.Name)
	}
	if len(d.Files) != 2 {
		t.Fatalf("the copy answered %d files", len(d.Files))
	}
	srcSlugs := map[string]string{}
	for _, f := range before.Files {
		srcSlugs[f.Path] = f.Slug
	}
	for _, f := range d.Files {
		if old, ok := srcSlugs[f.Path]; !ok || old == f.Slug {
			t.Fatalf("copy file %s slug %s, original's %q", f.Path, f.Slug, old)
		}
	}

	if !waitCopyDone(t, b.DB, d.ID) {
		t.Fatal("the copy was deleted")
	}
	var got dupOut
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+d.ID, testToken, ""), &got)
	if len(got.Files) != 2 {
		t.Fatalf("the finished copy holds %d files", len(got.Files))
	}
	for _, f := range got.Files {
		if f.Pending {
			t.Fatalf("%s still pending after the copy finished", f.Path)
		}
		if readStored(t, b.FS, d.ID, f.Path) != files[f.Path] {
			t.Fatalf("%s bytes differ", f.Path)
		}
	}
	var after dupOut
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+src, testToken, ""), &after)
	if after.Name != "trip" || len(after.Files) != 2 {
		t.Fatalf("the original changed: %+v", after)
	}
	for _, f := range after.Files {
		if f.Slug != srcSlugs[f.Path] || readStored(t, b.FS, src, f.Path) != files[f.Path] {
			t.Fatalf("the original's %s changed", f.Path)
		}
	}

	// A name and the links state the request gives win over the defaults.
	named := duplicateOf(t, h, testToken, src, `{"name":"second","linksOff":true}`)
	if named.Name != "second" || !named.LinksOff {
		t.Fatalf("named copy = %+v", named)
	}
	waitCopyDone(t, b.DB, named.ID)
	// An empty body is the defaults too.
	waitCopyDone(t, b.DB, duplicateOf(t, h, testToken, src, ``).ID)
}

// A password protected share's copy opens with the same password, and its
// readable copy is sealed for the copy's own id.
func TestDuplicateKeepsTheReadablePassword(t *testing.T) {
	h, b := newTestAPIBackend(t)
	src := uploadedShare(t, h, testToken, "secret", map[string]string{"a.txt": "x"})
	if rec := doReq(t, h, "PATCH", "/api/shares/"+src, testToken, `{"password":"hunter22-long"}`); rec.Code != 200 {
		t.Fatalf("set password = %d %s", rec.Code, rec.Body)
	}
	d := duplicateOf(t, h, testToken, src, `{}`)
	waitCopyDone(t, b.DB, d.ID)
	var out struct {
		Password string `json:"password"`
	}
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+d.ID, testToken, ""), &out)
	if out.Password != "hunter22-long" {
		t.Fatalf("the copy's readable password = %q", out.Password)
	}
}

// What cannot be duplicated is refused before anything is written: an inbox
// and a live share (409 duplicate-unsupported), a share still uploading or
// with a publish open (409 share-busy), another account's share (404), and
// a copy past the owner's quota (507 quota).
func TestDuplicateRefusals(t *testing.T) {
	h := newTestLiveShareHandler(t)
	mux := h.routes()
	db := h.db

	expect := func(what, id, token string, status int, code string) {
		t.Helper()
		rec := doReq(t, mux, "POST", "/api/shares/"+id+"/duplicate", token, `{}`)
		if rec.Code != status || (code != "" && errCode(t, rec.Body.String()) != code) {
			t.Fatalf("%s: %d %s, want %d %s", what, rec.Code, rec.Body, status, code)
		}
	}
	shares := func() int {
		page, err := db.List(metadb.ListQuery{Owner: metadb.DefaultAdminName})
		if err != nil {
			t.Fatal(err)
		}
		return page.Total
	}

	rec := doReq(t, mux, "POST", "/api/shares", testToken, `{"name":"in","receive":true}`)
	var inbox dupOut
	unmarshal(t, rec, &inbox)
	expect("an inbox", inbox.ID, testToken, 409, "duplicate-unsupported")

	rec = doReq(t, mux, "POST", "/api/live-share", testToken, liveShareKeysBody)
	var live dupOut
	unmarshal(t, rec, &live)
	expect("a live share", live.ID, testToken, 409, "duplicate-unsupported")

	rec = doReq(t, mux, "POST", "/api/shares", testToken, `{"name":"up","files":[{"path":"a.txt","size":3}]}`)
	var pending dupOut
	unmarshal(t, rec, &pending)
	expect("a share still uploading", pending.ID, testToken, 409, "share-busy")

	open := uploadedShare(t, mux, testToken, "pub", map[string]string{"a.txt": "abc"})
	openPublish(t, mux, testToken, open)
	expect("a share with a publish open", open, testToken, 409, "share-busy")

	mine := uploadedShare(t, mux, testToken, "mine", map[string]string{"a.txt": "0123456789"})
	bob := seedUser(t, db, "bob")
	expect("another account's share", mine, bob, 404, "")
	expect("no share", shareid.NewID(), testToken, 404, "")
	expect("a live share of another account", live.ID, bob, 404, "")

	quota := int64(15)
	if _, err := db.UpdateUser("bob", metadb.Settings{QuotaBytes: &quota}); err != nil {
		t.Fatal(err)
	}
	bobs := uploadedShare(t, mux, bob, "bobs", map[string]string{"a.txt": "0123456789"})
	expect("a copy past the quota", bobs, bob, 507, "quota")

	before := shares()
	expect("an inbox again", inbox.ID, testToken, 409, "duplicate-unsupported")
	if shares() != before {
		t.Fatal("a refused duplicate left a share behind")
	}
}

// A linked share's copy links the same server folders and copies no bytes.
func TestDuplicateOfALinkedShare(t *testing.T) {
	h, b, _ := linkedTestAPI(t)
	src := linkedShare(t, b, "photo/2024")
	d := duplicateOf(t, h, testToken, src, `{}`)
	if len(d.Sources) != 1 || d.Sources[0] != "photo/2024" {
		t.Fatalf("the copy's sources %v", d.Sources)
	}
	if !waitCopyDone(t, b.DB, d.ID) {
		t.Fatal("the copy was deleted")
	}
	got, err := b.DB.Share(d.ID)
	if err != nil || len(got.Files) != 0 {
		t.Fatalf("a linked copy stored files: %+v %v", got.Files, err)
	}
}

// Editing the copy (a rename, a file removed) leaves the original whole.
func TestEditingTheCopyLeavesTheOriginal(t *testing.T) {
	h, b := newTestAPIBackend(t)
	src := uploadedShare(t, h, testToken, "orig", map[string]string{"a.txt": "alpha", "b.txt": "bravo"})
	d := duplicateOf(t, h, testToken, src, `{}`)
	waitCopyDone(t, b.DB, d.ID)

	if rec := doReq(t, h, "PATCH", "/api/shares/"+d.ID, testToken, `{"name":"renamed"}`); rec.Code != 200 {
		t.Fatalf("rename the copy = %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "DELETE", "/api/shares/"+d.ID+"/files/a.txt", testToken, ""); rec.Code/100 != 2 {
		t.Fatalf("delete from the copy = %d %s", rec.Code, rec.Body)
	}
	var orig dupOut
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+src, testToken, ""), &orig)
	if orig.Name != "orig" || len(orig.Files) != 2 {
		t.Fatalf("the original changed: %+v", orig)
	}
	if readStored(t, b.FS, src, "a.txt") != "alpha" || readStored(t, b.FS, src, "b.txt") != "bravo" {
		t.Fatal("the original's bytes changed")
	}
}

// A copy that fails part way deletes the whole duplicate, its rows and its
// directory, and leaves the original alone.
func TestAFailedCopyDeletesTheDuplicate(t *testing.T) {
	h, b := newTestAPIBackend(t)
	src := uploadedShare(t, h, testToken, "orig", map[string]string{"a.txt": "alpha", "b.txt": "bravo"})
	calls := 0
	real := stageCopy
	stageCopy = func(f *sharefs.FS, srcID, srcRel, dstID, dstRel string) (int64, error) {
		if calls++; calls == 2 {
			return 0, errors.New("a read error")
		}
		return real(f, srcID, srcRel, dstID, dstRel)
	}
	t.Cleanup(func() { stageCopy = real })

	d := duplicateOf(t, h, testToken, src, `{}`)
	if waitCopyDone(t, b.DB, d.ID) {
		t.Fatal("the failed copy still exists")
	}
	if dir, err := b.FS.ShareDir(d.ID); err == nil {
		if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the failed copy's directory is left: %v", err)
		}
	}
	if readStored(t, b.FS, src, "a.txt") != "alpha" {
		t.Fatal("the original lost its bytes")
	}
}

// A duplicate a stopped process left copying is deleted by the boot pass,
// rows then directory; a finished one and the original stay.
func TestBootDeletesAnUnfinishedCopy(t *testing.T) {
	h, b := newTestAPIBackend(t)
	src := uploadedShare(t, h, testToken, "orig", map[string]string{"a.txt": "alpha"})
	d, err := b.DB.DuplicateShare(src, metadb.DuplicateOptions{NewID: shareid.NewID()})
	if err != nil {
		t.Fatal(err)
	}
	jobs := copyJobsOf(t, b.DB, d.ID)
	if _, err := b.FS.StageCopy(src, jobs[0].Rel, d.ID, jobs[0].Rel); err != nil {
		t.Fatal(err)
	}
	done := duplicateOf(t, h, testToken, src, `{}`)
	waitCopyDone(t, b.DB, done.ID)

	n, err := RemoveUnfinishedCopies(b.DB, b.FS)
	if err != nil || n != 1 {
		t.Fatalf("RemoveUnfinishedCopies = %d, %v", n, err)
	}
	if _, err := b.DB.Share(d.ID); !errors.Is(err, metadb.ErrNotFound) {
		t.Fatalf("the unfinished copy's rows: %v", err)
	}
	dir, _ := b.FS.ShareDir(d.ID)
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the unfinished copy's directory: %v", err)
	}
	for _, id := range []string{src, done.ID} {
		if _, err := b.DB.Share(id); err != nil {
			t.Fatalf("%s went with it: %v", id, err)
		}
	}
}

// A copy in progress is the waiting page on its public link, even once its
// files have all landed and only its tiles are still copying, and its status
// does not call it complete until the copy finishes.
func TestACopyingShareShowsTheWaitingPage(t *testing.T) {
	h, b := newTestAPIBackend(t)
	src := uploadedShare(t, h, testToken, "orig", map[string]string{"a.txt": "alpha", "b.txt": "bravo"})
	d, err := b.DB.DuplicateShare(src, metadb.DuplicateOptions{NewID: shareid.NewID()})
	if err != nil {
		t.Fatal(err)
	}
	jobs := copyJobsOf(t, b.DB, d.ID)
	waiting := func(when string) {
		t.Helper()
		body := doReq(t, h, "GET", "/share/"+d.ID, "", "").Body.String()
		if !strings.Contains(body, "the share will open right here") {
			t.Fatalf("%s: not the waiting page: %s", when, body)
		}
		var st struct {
			Complete bool `json:"complete"`
		}
		unmarshal(t, doReq(t, h, "GET", "/share/"+d.ID+"/status", "", ""), &st)
		if st.Complete {
			t.Fatalf("%s: status says complete", when)
		}
	}
	waiting("every file pending")
	view := doReq(t, h, "GET", "/view/"+d.ID+"/"+jobs[0].NewSlug, "", "")
	if !strings.Contains(view.Body.String(), waitingFileView) {
		t.Fatalf("a pending file of the copy: %d %s", view.Code, view.Body)
	}

	for _, j := range jobs {
		if _, err := b.FS.StageCopy(src, j.Rel, d.ID, j.Rel); err != nil {
			t.Fatal(err)
		}
		c, err := b.FS.Commit(d.ID, j.Rel, j.Size, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := b.DB.CommitFile(metadb.CommitInput{ShareID: d.ID, Path: j.Rel, Size: c.Size, SHA256: c.SHA256, Mime: c.Mime}); err != nil {
			t.Fatal(err)
		}
	}
	waiting("every file landed, the copy not finished")

	if err := b.DB.FinishCopy(d.ID); err != nil {
		t.Fatal(err)
	}
	body := doReq(t, h, "GET", "/share/"+d.ID, "", "").Body.String()
	if !strings.Contains(body, "a.txt") || !strings.Contains(body, "b.txt") {
		t.Fatalf("the finished copy did not list its files: %s", body)
	}
}

// A share answered while it is copying says so, even once every file has
// landed and only its tiles remain, and the finished copy omits the field,
// which is what a client waiting on the copy reads.
func TestACopyingShareAnswersCopying(t *testing.T) {
	h, b := newTestAPIBackend(t)
	src := uploadedShare(t, h, testToken, "orig", map[string]string{"a.txt": "alpha"})
	d, err := b.DB.DuplicateShare(src, metadb.DuplicateOptions{NewID: shareid.NewID()})
	if err != nil {
		t.Fatal(err)
	}
	jobs := copyJobsOf(t, b.DB, d.ID)
	copying := func() (bool, bool) {
		t.Helper()
		var out map[string]any
		unmarshal(t, doReq(t, h, "GET", "/api/shares/"+d.ID, testToken, ""), &out)
		v, present := out["copying"]
		return v == true, present
	}
	if on, _ := copying(); !on {
		t.Fatal("a share still copying did not answer copying:true")
	}
	for _, j := range jobs {
		if _, err := b.FS.StageCopy(src, j.Rel, d.ID, j.Rel); err != nil {
			t.Fatal(err)
		}
		c, err := b.FS.Commit(d.ID, j.Rel, j.Size, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := b.DB.CommitFile(metadb.CommitInput{ShareID: d.ID, Path: j.Rel, Size: c.Size, SHA256: c.SHA256, Mime: c.Mime}); err != nil {
			t.Fatal(err)
		}
	}
	if on, _ := copying(); !on {
		t.Fatal("every file landed but the copy is unfinished, and it did not answer copying:true")
	}
	if err := b.DB.FinishCopy(d.ID); err != nil {
		t.Fatal(err)
	}
	if _, present := copying(); present {
		t.Fatal("the finished copy still carries copying")
	}
	var orig map[string]any
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+src, testToken, ""), &orig)
	if _, present := orig["copying"]; present {
		t.Fatal("an ordinary share carries copying")
	}
}

// The copy line runs one duplicate per owner and two at once, and refuses a
// duplicate past its waiting bounds: 32 in all, and per owner.
func TestTheCopyLineIsBounded(t *testing.T) {
	var c copier
	release := make(chan struct{})
	var mu sync.Mutex
	running := map[string]int{}
	most, mostOwner := 0, 0
	run := func(ctx context.Context, task copyTask) {
		mu.Lock()
		running[task.owner]++
		total := 0
		for _, n := range running {
			total += n
		}
		most, mostOwner = max(most, total), max(mostOwner, running[task.owner])
		mu.Unlock()
		<-release
		mu.Lock()
		running[task.owner]--
		mu.Unlock()
	}
	submit := func(owner string) error {
		t.Helper()
		slot, err := c.reserve(owner, "src-"+owner, 1)
		if err != nil {
			return err
		}
		c.submit(slot, copyTask{owner: owner}, run)
		return nil
	}
	for i := range copyMaxWaitingPerOwner + 1 {
		if err := submit("alice"); err != nil {
			t.Fatalf("alice's copy %d: %v", i, err)
		}
	}
	if err := submit("alice"); !errors.Is(err, errCopyBusy) {
		t.Fatalf("alice past her bound: %v", err)
	}
	accounts := 0
	for accounts = 0; ; accounts++ {
		if err := submit(string(rune('b' + accounts))); err != nil {
			if !errors.Is(err, errCopyBusy) {
				t.Fatal(err)
			}
			break
		}
	}
	// alice's first runs, and one other account's; everything else waits.
	if waiting := copyMaxWaitingPerOwner + accounts - 1; waiting != copyMaxWaiting {
		t.Fatalf("%d waiting when refused, want %d", waiting, copyMaxWaiting)
	}
	close(release)
	c.stop(10 * time.Second)
	if most > copyMaxRunning || mostOwner > 1 {
		t.Fatalf("ran %d at once, %d for one owner", most, mostOwner)
	}
	if _, err := c.reserve("alice", "src", 1); !errors.Is(err, errCopyBusy) {
		t.Fatalf("a stopped line took a copy: %v", err)
	}
}

// A shutdown stops a copy between files and leaves it marked, for the boot
// pass to remove; it is not deleted on the way down.
func TestShutdownLeavesAnInterruptedCopyForBoot(t *testing.T) {
	hd := newTestLiveShareHandler(t)
	h := hd.routes()
	src := uploadedShare(t, h, testToken, "orig", map[string]string{"a.txt": "alpha", "b.txt": "bravo"})
	entered, release := make(chan struct{}), make(chan struct{})
	var first sync.Once
	real := stageCopy
	stageCopy = func(f *sharefs.FS, srcID, srcRel, dstID, dstRel string) (int64, error) {
		first.Do(func() {
			entered <- struct{}{}
			<-release
		})
		return real(f, srcID, srcRel, dstID, dstRel)
	}
	t.Cleanup(func() { stageCopy = real })

	d := duplicateOf(t, h, testToken, src, `{}`)
	<-entered
	stopped := make(chan struct{})
	go func() {
		hd.copies.stop(10 * time.Second)
		close(stopped)
	}()
	for !hd.copies.stopping() {
		time.Sleep(time.Millisecond)
	}
	close(release)
	<-stopped
	got, err := hd.db.ShareCapped(d.ID, 1)
	if err != nil || got.CopyingFrom != src {
		t.Fatalf("the interrupted copy: %+v %v", got, err)
	}
	if got.Committed != 1 {
		t.Fatalf("the copy went on past the shutdown: %d committed", got.Committed)
	}
}

// waitCopiesIdle waits until the copy line holds nothing for src: no copy
// of it running or waiting.
func waitCopiesIdle(t *testing.T, c *copier, src string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for c.reading(src) {
		if time.Now().After(deadline) {
			t.Fatalf("the copy line still reads %s", src)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// While a copy reads a share, every change to what the original holds is
// refused 409 copy-in-progress (the share's delete, alone and in a batch, a
// file's delete, a move, an upload or replace, a batch upload, a publish),
// and the same content edits of the copy itself, so the copy is the
// original as it was asked for. What does not touch the bytes (a rename)
// still applies to both. Once the copy is done, the original deletes.
func TestACopyInProgressFreezesTheOriginalsContent(t *testing.T) {
	hd := newTestLiveShareHandler(t)
	h := hd.routes()
	src := uploadedShare(t, h, testToken, "orig", map[string]string{"a.txt": "alpha", "b.txt": "bravo"})
	entered, release := holdCopy(t)
	d := duplicateOf(t, h, testToken, src, `{}`)
	<-entered

	refused := func(what string, rec *httptest.ResponseRecorder) {
		t.Helper()
		if rec.Code != http.StatusConflict || errCode(t, rec.Body.String()) != "copy-in-progress" {
			t.Fatalf("%s: %d %s, want 409 copy-in-progress", what, rec.Code, rec.Body)
		}
	}
	for _, id := range []string{src, d.ID} {
		who := map[string]string{src: "the original", d.ID: "the copy"}[id]
		refused(who+": a file's delete", doReq(t, h, "DELETE", "/api/shares/"+id+"/files/a.txt", testToken, ""))
		refused(who+": a move", doReq(t, h, "POST", "/api/shares/"+id+"/move", testToken, `{"from":"a.txt","to":"c.txt"}`))
		refused(who+": an upload", doReq(t, h, "PUT", "/api/shares/"+id+"/files/new.txt", testToken, "x"))
		refused(who+": a replace", doReq(t, h, "PUT", "/api/shares/"+id+"/files/a2.txt?replaces=a.txt", testToken, "x"))
		refused(who+": a batch upload", doReq(t, h, "POST", "/api/shares/"+id+"/batch", testToken, ""))
		refused(who+": a publish", doReq(t, h, "POST", "/api/shares/"+id+"/publishes", testToken, ""))
		if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"name":"renamed"}`); rec.Code != http.StatusOK {
			t.Fatalf("%s: a rename = %d %s", who, rec.Code, rec.Body)
		}
	}
	refused("the original's delete", doReq(t, h, "DELETE", "/api/shares/"+src, testToken, ""))
	rec := doReq(t, h, "POST", "/api/shares/delete", testToken, `{"ids":["`+src+`"]}`)
	var bulk struct {
		Deleted []string `json:"deleted"`
		Failed  []struct {
			ID   string `json:"id"`
			Code string `json:"code"`
		} `json:"failed"`
	}
	unmarshal(t, rec, &bulk)
	if len(bulk.Deleted) != 0 || len(bulk.Failed) != 1 || bulk.Failed[0].ID != src || bulk.Failed[0].Code != "copy-in-progress" {
		t.Fatalf("the bulk delete of the original: %d %s", rec.Code, rec.Body)
	}

	release()
	if !waitCopyDone(t, hd.db, d.ID) {
		t.Fatal("the copy was deleted")
	}
	waitCopiesIdle(t, &hd.copies, src)
	got, err := hd.db.Share(d.ID)
	if err != nil || got.Committed != 2 || got.FileCount != 2 {
		t.Fatalf("the finished copy: %+v %v", got, err)
	}
	if readStored(t, hd.fs, d.ID, "a.txt") != "alpha" || readStored(t, hd.fs, d.ID, "b.txt") != "bravo" {
		t.Fatal("the copy's bytes are not the original's")
	}
	if rec := doReq(t, h, "DELETE", "/api/shares/"+d.ID+"/files/a.txt", testToken, ""); rec.Code != http.StatusOK {
		t.Fatalf("the finished copy's file delete = %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "DELETE", "/api/shares/"+src, testToken, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("the original's delete once the copy is done = %d %s", rec.Code, rec.Body)
	}
}

// A copy waiting in the line for its owner's running one already holds its
// original: the original's delete is refused before the copy starts.
func TestAWaitingCopyHoldsItsOriginal(t *testing.T) {
	hd := newTestLiveShareHandler(t)
	h := hd.routes()
	first := uploadedShare(t, h, testToken, "one", map[string]string{"a.txt": "alpha"})
	second := uploadedShare(t, h, testToken, "two", map[string]string{"b.txt": "bravo"})
	entered, release := holdCopy(t)
	d1 := duplicateOf(t, h, testToken, first, `{}`)
	<-entered
	d2 := duplicateOf(t, h, testToken, second, `{}`)
	rec := doReq(t, h, "DELETE", "/api/shares/"+second, testToken, "")
	if rec.Code != http.StatusConflict || errCode(t, rec.Body.String()) != "copy-in-progress" {
		t.Fatalf("the waiting copy's original deleted: %d %s", rec.Code, rec.Body)
	}
	release()
	for _, id := range []string{d1.ID, d2.ID} {
		if !waitCopyDone(t, hd.db, id) {
			t.Fatalf("copy %s was deleted", id)
		}
	}
	waitCopiesIdle(t, &hd.copies, second)
	if rec := doReq(t, h, "DELETE", "/api/shares/"+second, testToken, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("the original's delete once its copy is done = %d %s", rec.Code, rec.Body)
	}
}

// The copy itself can be deleted while it is still being made: the share is
// gone at once, its worker drops the rest of the job without logging it as
// a failure, and nothing of it is left on disk.
func TestDeletingACopyInProgress(t *testing.T) {
	hd := newTestLiveShareHandler(t)
	h := hd.routes()
	src := uploadedShare(t, h, testToken, "orig", map[string]string{"a.txt": "alpha", "b.txt": "bravo"})
	var logged bytes.Buffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	entered, release := holdCopy(t)
	d := duplicateOf(t, h, testToken, src, `{}`)
	<-entered
	if rec := doReq(t, h, "DELETE", "/api/shares/"+d.ID, testToken, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("the copy's delete = %d %s", rec.Code, rec.Body)
	}
	release()
	waitCopiesIdle(t, &hd.copies, src)
	if _, err := hd.db.Share(d.ID); !errors.Is(err, metadb.ErrNotFound) {
		t.Fatalf("the deleted copy's rows: %v", err)
	}
	dir, err := hd.fs.ShareDir(d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the deleted copy's directory: %v", err)
	}
	if strings.Contains(logged.String(), d.ID) {
		t.Fatalf("the dropped copy was logged: %s", logged.String())
	}
	if readStored(t, hd.fs, src, "a.txt") != "alpha" {
		t.Fatal("the original lost its bytes")
	}
}

// A gallery's copy is a gallery of its own: its tile is served under the
// file's new slug, its card shows the poster, its page lists the new slugs
// with the gallery row's numbers, and the original's slugs name nothing in
// it. The worker reads its jobs a page at a time, here one, so the tiles and
// the poster land across pages.
func TestADuplicatedGalleryServesItsTilesAndPoster(t *testing.T) {
	old := copyJobsPage
	copyJobsPage = 1
	t.Cleanup(func() { copyJobsPage = old })
	h, b := newTestAPIBackend(t)
	src := newMediaShare(t, h, map[string]string{"a.jpg": "x"})
	if code := putPoster(t, h, src, posterJPEG(t, "the-poster")); code != http.StatusNoContent {
		t.Fatalf("PUT poster = %d", code)
	}
	if rec := doReq(t, h, "PUT", "/api/shares/"+src+"/files/b.jpg", testToken, "y"); rec.Code != http.StatusCreated {
		t.Fatalf("upload b.jpg = %d %s", rec.Code, rec.Body)
	}
	var orig dupOut
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+src, testToken, ""), &orig)
	oldSlug := map[string]string{}
	for _, f := range orig.Files {
		oldSlug[f.Path] = f.Slug
	}
	tile := string(aJPEG(t, 32, 24))
	if rec := doReq(t, h, "PUT", "/api/shares/"+src+"/thumbs/"+oldSlug["a.jpg"], testToken, tile); rec.Code/100 != 2 {
		t.Fatalf("PUT tile = %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "PUT", "/api/shares/"+src+"/gallery", testToken,
		`{"items":[{"slug":"`+oldSlug["a.jpg"]+`","w":4032,"h":3024}]}`); rec.Code/100 != 2 {
		t.Fatalf("PUT gallery = %d %s", rec.Code, rec.Body)
	}

	d := duplicateOf(t, h, testToken, src, `{}`)
	if !waitCopyDone(t, b.DB, d.ID) {
		t.Fatal("the copy was deleted")
	}
	var got dupOut
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+d.ID, testToken, ""), &got)
	newSlug := map[string]string{}
	for _, f := range got.Files {
		newSlug[f.Path] = f.Slug
	}
	if len(newSlug) != 2 || newSlug["a.jpg"] == "" || newSlug["a.jpg"] == oldSlug["a.jpg"] {
		t.Fatalf("the copy's files: %+v", got.Files)
	}

	rec := doReq(t, h, "GET", "/thumb/"+d.ID+"/"+newSlug["a.jpg"], "", "")
	if rec.Code != http.StatusOK || rec.Body.String() != tile {
		t.Fatalf("the copy's tile = %d (%d bytes)", rec.Code, rec.Body.Len())
	}
	rec = doReq(t, h, "GET", "/card/"+d.ID+"/poster.jpg", "", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "the-poster") {
		t.Fatalf("the copy's poster = %d", rec.Code)
	}
	if src, err := b.FS.PosterSource(d.ID); err != nil || src != newSlug["a.jpg"] {
		t.Fatalf("the copy's poster names %q (%v), want a.jpg's new slug %s", src, err, newSlug["a.jpg"])
	}

	items := galleryItemsOf(t, doReq(t, h, "GET", "/share/"+d.ID, "", "").Body.String())
	byName := map[string]map[string]any{}
	for _, it := range items {
		byName[it["n"].(string)] = it
	}
	a, bItem := byName["a.jpg"], byName["b.jpg"]
	if a == nil || bItem == nil {
		t.Fatalf("the copy's gallery lists %v", items)
	}
	if a["t"] != "/thumb/"+d.ID+"/"+newSlug["a.jpg"] || a["w"] != float64(4032) || a["h"] != float64(3024) {
		t.Fatalf("a.jpg in the copy's gallery: %v", a)
	}
	if v := a["v"].(string); !strings.Contains(v, newSlug["a.jpg"]) {
		t.Fatalf("a.jpg's view in the copy = %q", v)
	}
	if v := bItem["v"].(string); !strings.Contains(v, newSlug["b.jpg"]) {
		t.Fatalf("b.jpg's view in the copy = %q", v)
	}

	for path, slug := range oldSlug {
		for _, route := range []string{"/thumb/", "/view/"} {
			if rec := doReq(t, h, "GET", route+d.ID+"/"+slug, "", ""); rec.Code != http.StatusNotFound {
				t.Fatalf("the original's %s slug on the copy's %s = %d", path, route, rec.Code)
			}
		}
	}
	// The original still serves its own.
	if rec := doReq(t, h, "GET", "/thumb/"+src+"/"+oldSlug["a.jpg"], "", ""); rec.Code != http.StatusOK {
		t.Fatalf("the original's tile = %d", rec.Code)
	}
}
