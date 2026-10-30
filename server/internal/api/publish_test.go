package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"hyperdrop/server/internal/domain"
	"hyperdrop/server/internal/housekeep"
	"hyperdrop/server/internal/sharefs"
	"hyperdrop/server/internal/shareid"
)

// publishAPI is a handler on the domain share.example.com plus the backend
// it serves from, for the publish tests that look at the disk.
func publishAPI(t *testing.T) (http.Handler, Backend) {
	t.Helper()
	dom, err := domain.Load(filepath.Join(t.TempDir(), "domain"), "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	if err := dom.Adopt("share.example.com"); err != nil {
		t.Fatal(err)
	}
	b := testBackend(t)
	return New(b, "2.0.0", dom, nil), b
}

// openPublish opens a publish on share id and answers its id.
func openPublish(t *testing.T, h http.Handler, token, id string) string {
	t.Helper()
	rec := doReq(t, h, "POST", "/api/shares/"+id+"/publishes", token, `{}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("open publish: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Publish string `json:"publish"`
	}
	unmarshal(t, rec, &out)
	if !shareid.ValidPublishID(out.Publish) {
		t.Fatalf("open publish answered %q", out.Publish)
	}
	return out.Publish
}

// stageChunk sends data[start:end] of rel's upload into publish pid.
func stageChunk(t *testing.T, h http.Handler, id, pid, rel string, data []byte, start, end int, session string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("PUT", "/api/shares/"+id+"/files/"+rel+"?publish="+pid, strings.NewReader(string(data[start:end])))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Upload-Range", fmt.Sprintf("%d-%d", start, end))
	req.Header.Set("Upload-Total", strconv.Itoa(len(data)))
	req.Header.Set("Upload-Session", session)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// stagedAnswer is the 201 of a staged upload.
type stagedAnswer struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Staged bool   `json:"staged"`
}

// stageFile sends rel whole into publish pid and requires the staged 201.
func stageFile(t *testing.T, h http.Handler, id, pid, rel, content string) stagedAnswer {
	t.Helper()
	rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/"+rel+"?publish="+pid, testToken, content)
	if rec.Code != http.StatusCreated {
		t.Fatalf("stage %s: %d %s", rel, rec.Code, rec.Body)
	}
	var out stagedAnswer
	unmarshal(t, rec, &out)
	if !out.Staged || out.Path != rel || out.Size != int64(len(content)) || out.SHA256 != sha(content) {
		t.Fatalf("stage %s answered %s", rel, rec.Body)
	}
	return out
}

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// commitPublish commits publish pid with body.
func commitPublish(t *testing.T, h http.Handler, id, pid, body string) *httptest.ResponseRecorder {
	t.Helper()
	return doReq(t, h, "POST", "/api/shares/"+id+"/publishes/"+pid+"/commit", testToken, body)
}

// listedShare is what the owner's read of a share says about its files.
type listedShare struct {
	FileCount  int    `json:"fileCount"`
	TotalSize  int64  `json:"totalSize"`
	ModifiedAt string `json:"modifiedAt"`
	Files      []struct {
		Path    string `json:"path"`
		Slug    string `json:"slug"`
		SHA256  string `json:"sha256"`
		Pending bool   `json:"pending"`
	} `json:"files"`
}

func readListed(t *testing.T, h http.Handler, id string) listedShare {
	t.Helper()
	rec := doReq(t, h, "GET", "/api/shares/"+id, testToken, "")
	if rec.Code != 200 {
		t.Fatalf("read %s: %d %s", id, rec.Code, rec.Body)
	}
	var out listedShare
	unmarshal(t, rec, &out)
	return out
}

func (s listedShare) slugs() map[string]string {
	m := map[string]string{}
	for _, f := range s.Files {
		m[f.Path] = f.Slug
	}
	return m
}

// changesCursor answers the change feed's cursor now.
func changesCursor(t *testing.T, h http.Handler) string {
	t.Helper()
	rec := doReq(t, h, "GET", "/api/shares/changes", testToken, "")
	var out struct {
		Cursor string `json:"cursor"`
	}
	unmarshal(t, rec, &out)
	return out.Cursor
}

// changesSince answers how many shares changed after cursor.
func changesSince(t *testing.T, h http.Handler, cursor string) int {
	t.Helper()
	rec := doReq(t, h, "GET", "/api/shares/changes?since="+url.QueryEscape(cursor), testToken, "")
	if rec.Code != 200 {
		t.Fatalf("changes: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Changes []json.RawMessage `json:"changes"`
		Reset   bool              `json:"reset"`
	}
	unmarshal(t, rec, &out)
	if out.Reset {
		t.Fatal("the change feed reset")
	}
	return len(out.Changes)
}

// publishedBytes reads a stored file of share id off the disk, "" when absent.
func publishedBytes(t *testing.T, b Backend, id, rel string) (string, bool) {
	t.Helper()
	p, err := b.FS.FilePath(id, rel)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return "", false
	}
	return string(data), true
}

func stageDirOf(t *testing.T, b Backend, id, pid string) string {
	t.Helper()
	dir, err := b.FS.ShareDir(id)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "stage", pid)
}

// A staged upload declares no row: while a new picture uploads into a
// published site, the site keeps serving its page, and the listing, the
// file count and the change feed do not move.
func TestAStagedUploadIsInvisible(t *testing.T) {
	h, _ := publishAPI(t)
	id := siteShare(t, h, "index.html", "style.css")
	if rec := setEntry(t, h, id, "index.html"); rec.Code != 200 {
		t.Fatalf("entry: %d %s", rec.Code, rec.Body)
	}
	before := readListed(t, h, id)
	cursor := changesCursor(t, h)

	pid := openPublish(t, h, testToken, id)
	pic := []byte(strings.Repeat("P", 4096))
	if rec := stageChunk(t, h, id, pid, "pic.png", pic, 0, 1000, "pic-session"); rec.Code != http.StatusAccepted {
		t.Fatalf("first chunk: %d %s", rec.Code, rec.Body)
	}
	stageFile(t, h, id, pid, "new.css", "body{}")
	stageFile(t, h, id, pid, "style.css", "replaced")

	if rec := pageGet(t, h, "/share/"+id); rec.Code != http.StatusFound {
		t.Fatalf("/share during a staged upload = %d, want the page's redirect: %s", rec.Code, rec.Body)
	}
	for path, want := range map[string]string{"index.html": "body of index.html", "style.css": "body of style.css"} {
		rec := fileGet(t, h, "/site/"+id+"/"+path)
		if rec.Code != 200 || rec.Body.String() != want {
			t.Fatalf("/site/%s during a staged upload = %d %q, want %q", path, rec.Code, rec.Body, want)
		}
	}
	for _, path := range []string{"new.css", "pic.png"} {
		if rec := fileGet(t, h, "/site/"+id+"/"+path); rec.Code != http.StatusNotFound {
			t.Fatalf("/site/%s staged but not committed = %d", path, rec.Code)
		}
	}
	after := readListed(t, h, id)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("the share moved while uploads were staged:\nbefore %+v\nafter  %+v", before, after)
	}
	if n := changesSince(t, h, cursor); n != 0 {
		t.Fatalf("the change feed reports %d changes for staged uploads", n)
	}
}

// One commit makes every staged file live and deletes the named files in
// one step: one change, a replaced file keeping its slug, a new one minted,
// a deleted one gone with its bytes, and the publish closed.
func TestACommitMakesEverythingLiveAtOnce(t *testing.T) {
	h, b := publishAPI(t)
	id := createShare(t, h, "site")
	for rel, body := range map[string]string{"a.txt": "old a", "b.txt": "old b", "gone.txt": "bye"} {
		uploadGetSlug(t, h, id, rel, body)
	}
	before := readListed(t, h, id).slugs()
	pid := openPublish(t, h, testToken, id)
	stageFile(t, h, id, pid, "a.txt", "new a")
	stageFile(t, h, id, pid, "c/d.txt", "new d")
	stageFile(t, h, id, pid, "unnamed.txt", "dropped with the publish")
	if got, _ := publishedBytes(t, b, id, "a.txt"); got != "old a" {
		t.Fatalf("a.txt before the commit = %q", got)
	}
	cursor := changesCursor(t, h)
	if b.FS.OpenPublishes("admin") != 1 {
		t.Fatalf("open publishes = %d, want 1", b.FS.OpenPublishes("admin"))
	}

	rec := commitPublish(t, h, id, pid, `{"files":["a.txt","c/d.txt"],"delete":["gone.txt"],"base":{"a.txt":"`+sha("old a")+`","gone.txt":"`+sha("bye")+`"}}`)
	if rec.Code != 200 {
		t.Fatalf("commit: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		ID        string `json:"id"`
		FileCount int    `json:"fileCount"`
		Published struct {
			Files   int `json:"files"`
			Deleted int `json:"deleted"`
		} `json:"published"`
	}
	unmarshal(t, rec, &out)
	if out.ID != id || out.FileCount != 3 || out.Published.Files != 2 || out.Published.Deleted != 1 {
		t.Fatalf("commit answered %s", rec.Body)
	}

	after := readListed(t, h, id)
	slugs := after.slugs()
	if len(slugs) != 3 || slugs["a.txt"] != before["a.txt"] || slugs["b.txt"] != before["b.txt"] || slugs["c/d.txt"] == "" {
		t.Fatalf("files after the commit: %v (before %v)", slugs, before)
	}
	if _, ok := slugs["gone.txt"]; ok {
		t.Fatal("gone.txt is still listed")
	}
	for rel, want := range map[string]string{"a.txt": "new a", "b.txt": "old b", "c/d.txt": "new d"} {
		if got, ok := publishedBytes(t, b, id, rel); !ok || got != want {
			t.Fatalf("%s after the commit = %q %v, want %q", rel, got, ok, want)
		}
	}
	for _, rel := range []string{"gone.txt", "unnamed.txt"} {
		if _, ok := publishedBytes(t, b, id, rel); ok {
			t.Fatalf("%s is on disk after the commit", rel)
		}
	}
	if n := changesSince(t, h, cursor); n != 1 {
		t.Fatalf("the commit made %d changes, want 1", n)
	}
	if _, err := os.Stat(stageDirOf(t, b, id, pid)); !os.IsNotExist(err) {
		t.Fatalf("the stage outlived its commit: %v", err)
	}
	if n := b.FS.OpenPublishes("admin"); n != 0 {
		t.Fatalf("open publishes after the commit = %d", n)
	}
	if rec := commitPublish(t, h, id, pid, `{"files":["a.txt"]}`); rec.Code != 404 || errCode(t, rec.Body.String()) != "no-such-publish" {
		t.Fatalf("a second commit: %d %s", rec.Code, rec.Body)
	}
	if rec := fileGet(t, h, "/site/"+id+"/c/d.txt"); rec.Code != 200 || rec.Body.String() != "new d" {
		t.Fatalf("/site of a committed file = %d %q", rec.Code, rec.Body)
	}
}

// A commit naming a path with no finished staged upload changes nothing,
// names every such path, and leaves the publish open to be finished.
func TestACommitRefusesAnIncompletePublish(t *testing.T) {
	h, b := publishAPI(t)
	id := createShare(t, h, "s")
	uploadGetSlug(t, h, id, "keep.txt", "kept")
	before := readListed(t, h, id)
	pid := openPublish(t, h, testToken, id)
	data := []byte(strings.Repeat("x", 100))
	if rec := stageChunk(t, h, id, pid, "x.bin", data, 0, 50, "x-session"); rec.Code != http.StatusAccepted {
		t.Fatalf("chunk: %d %s", rec.Code, rec.Body)
	}
	rec := commitPublish(t, h, id, pid, `{"files":["x.bin","never.txt"]}`)
	if rec.Code != http.StatusConflict || errCode(t, rec.Body.String()) != "publish-incomplete" {
		t.Fatalf("commit of an incomplete publish: %d %s", rec.Code, rec.Body)
	}
	var refused struct {
		Missing []string `json:"missing"`
	}
	unmarshal(t, rec, &refused)
	if !reflect.DeepEqual(refused.Missing, []string{"never.txt", "x.bin"}) {
		t.Fatalf("missing = %v", refused.Missing)
	}
	if after := readListed(t, h, id); !reflect.DeepEqual(before, after) {
		t.Fatalf("a refused commit changed the share: %+v", after)
	}
	if _, err := os.Stat(filepath.Join(stageDirOf(t, b, id, pid), "commit.json")); !os.IsNotExist(err) {
		t.Fatalf("a refused commit left its journal: %v", err)
	}

	if rec := stageChunk(t, h, id, pid, "x.bin", data, 50, 100, "x-session"); rec.Code != http.StatusCreated {
		t.Fatalf("last chunk: %d %s", rec.Code, rec.Body)
	}
	stageFile(t, h, id, pid, "never.txt", "now")
	if rec := commitPublish(t, h, id, pid, `{"files":["x.bin","never.txt"]}`); rec.Code != 200 {
		t.Fatalf("commit once complete: %d %s", rec.Code, rec.Body)
	}
	if got, _ := publishedBytes(t, b, id, "x.bin"); got != string(data) {
		t.Fatalf("x.bin = %q", got)
	}
}

// A base hash that no longer matches refuses the commit with nothing
// changed; the publish stays open and commits with the right base.
func TestACommitConflictKeepsThePublishOpen(t *testing.T) {
	h, b := publishAPI(t)
	id := createShare(t, h, "s")
	uploadGetSlug(t, h, id, "a.txt", "old")
	pid := openPublish(t, h, testToken, id)
	stageFile(t, h, id, pid, "a.txt", "new")
	rec := commitPublish(t, h, id, pid, `{"files":["a.txt"],"base":{"a.txt":"`+sha("something else")+`"}}`)
	if rec.Code != http.StatusConflict || errCode(t, rec.Body.String()) != "publish-conflict" {
		t.Fatalf("stale base: %d %s", rec.Code, rec.Body)
	}
	if got, _ := publishedBytes(t, b, id, "a.txt"); got != "old" {
		t.Fatalf("a refused commit moved bytes: %q", got)
	}
	if _, err := os.Stat(filepath.Join(stageDirOf(t, b, id, pid), "commit.json")); !os.IsNotExist(err) {
		t.Fatalf("a refused commit left its journal: %v", err)
	}
	if rec := commitPublish(t, h, id, pid, `{"files":["a.txt"],"base":{"a.txt":"`+sha("old")+`"}}`); rec.Code != 200 {
		t.Fatalf("commit with the right base: %d %s", rec.Code, rec.Body)
	}
	if got, _ := publishedBytes(t, b, id, "a.txt"); got != "new" {
		t.Fatalf("a.txt = %q", got)
	}
}

// An abort removes everything staged, and the publish is gone for every
// route.
func TestAbortRemovesTheStage(t *testing.T) {
	h, b := publishAPI(t)
	id := createShare(t, h, "s")
	before := readListed(t, h, id)
	pid := openPublish(t, h, testToken, id)
	stageFile(t, h, id, pid, "a.txt", "staged")
	if rec := doReq(t, h, "DELETE", "/api/shares/"+id+"/publishes/"+pid, testToken, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("abort: %d %s", rec.Code, rec.Body)
	}
	if _, err := os.Stat(stageDirOf(t, b, id, pid)); !os.IsNotExist(err) {
		t.Fatalf("the stage outlived its abort: %v", err)
	}
	if n := b.FS.OpenPublishes("admin"); n != 0 {
		t.Fatalf("open publishes after the abort = %d", n)
	}
	if after := readListed(t, h, id); !reflect.DeepEqual(before, after) {
		t.Fatalf("an abort changed the share: %+v", after)
	}
	for _, rec := range []*httptest.ResponseRecorder{
		doReq(t, h, "PUT", "/api/shares/"+id+"/files/b.txt?publish="+pid, testToken, "late"),
		commitPublish(t, h, id, pid, `{"files":["a.txt"]}`),
		doReq(t, h, "DELETE", "/api/shares/"+id+"/publishes/"+pid, testToken, ""),
		doReq(t, h, "GET", "/api/shares/"+id+"/uploads/a.txt?session=test-session&publish="+pid, testToken, ""),
	} {
		if rec.Code != http.StatusNotFound || errCode(t, rec.Body.String()) != "no-such-publish" {
			t.Fatalf("a route after the abort: %d %s", rec.Code, rec.Body)
		}
	}
}

// A Receive Inbox holds what strangers sent: no publish opens there, and
// every other publish route finds none.
func TestPublishRoutesRefuseAnInbox(t *testing.T) {
	h, _ := publishAPI(t)
	id := createShareBody(t, h, `{"name":"drop","receive":true}`)
	rec := doReq(t, h, "POST", "/api/shares/"+id+"/publishes", testToken, `{}`)
	if rec.Code != http.StatusConflict || errCode(t, rec.Body.String()) != "publish-inbox" {
		t.Fatalf("open on an inbox: %d %s", rec.Code, rec.Body)
	}
	pid := shareid.NewPublishID()
	for _, rec := range []*httptest.ResponseRecorder{
		doReq(t, h, "PUT", "/api/shares/"+id+"/files/a.txt?publish="+pid, testToken, "x"),
		doReq(t, h, "POST", "/api/shares/"+id+"/batch?publish="+pid, testToken, string(tarOf(t, map[string]string{"a.txt": "x"}, nil))),
		doReq(t, h, "GET", "/api/shares/"+id+"/uploads/a.txt?session=test-session&publish="+pid, testToken, ""),
		commitPublish(t, h, id, pid, `{"files":["a.txt"]}`),
		doReq(t, h, "DELETE", "/api/shares/"+id+"/publishes/"+pid, testToken, ""),
	} {
		if rec.Code != http.StatusNotFound || errCode(t, rec.Body.String()) != "no-such-publish" {
			t.Fatalf("a publish route on an inbox: %d %s", rec.Code, rec.Body)
		}
	}
}

// An owner holds at most eight open publishes across their shares; a commit,
// an abort or a share's deletion frees one, and another account's count is
// its own.
func TestPublishLimit(t *testing.T) {
	h, b := publishAPI(t)
	one, two := createShare(t, h, "one"), createShare(t, h, "two")
	var pids []string
	for i := 0; i < 8; i++ {
		id := one
		if i%2 == 1 {
			id = two
		}
		pids = append(pids, openPublish(t, h, testToken, id))
	}
	rec := doReq(t, h, "POST", "/api/shares/"+one+"/publishes", testToken, `{}`)
	if rec.Code != http.StatusConflict || errCode(t, rec.Body.String()) != "publish-limit" {
		t.Fatalf("a ninth publish: %d %s", rec.Code, rec.Body)
	}
	bob := seedUser(t, b.DB, "bob")
	bobs := createShareAs(t, h, bob, `{"name":"bob's"}`)
	if rec := doReq(t, h, "POST", "/api/shares/"+bobs+"/publishes", bob, `{}`); rec.Code != http.StatusCreated {
		t.Fatalf("another account's publish: %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "DELETE", "/api/shares/"+one+"/publishes/"+pids[0], testToken, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("abort: %d %s", rec.Code, rec.Body)
	}
	openPublish(t, h, testToken, one)
	if rec := doReq(t, h, "DELETE", "/api/shares/"+two, testToken, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete share: %d %s", rec.Code, rec.Body)
	}
	if n := b.FS.OpenPublishes("admin"); n != 4 {
		t.Fatalf("open publishes after deleting a share holding four = %d, want 4", n)
	}
	openPublish(t, h, testToken, one)
}

// A publish is the share owner's: another account sees neither the share
// nor the publish, and a publish id names nothing on another share.
func TestAPublishIsTheOwners(t *testing.T) {
	h, b := publishAPI(t)
	id, other := createShare(t, h, "s"), createShare(t, h, "t")
	pid := openPublish(t, h, testToken, id)
	bob := seedUser(t, b.DB, "bob")
	if rec := doReq(t, h, "POST", "/api/shares/"+id+"/publishes", bob, `{}`); rec.Code != http.StatusNotFound {
		t.Fatalf("open on another account's share: %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/a.txt?publish="+pid, bob, "x"); rec.Code != http.StatusNotFound {
		t.Fatalf("stage into another account's publish: %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "DELETE", "/api/shares/"+id+"/publishes/"+pid, bob, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("abort another account's publish: %d %s", rec.Code, rec.Body)
	}
	for _, rec := range []*httptest.ResponseRecorder{
		doReq(t, h, "PUT", "/api/shares/"+other+"/files/a.txt?publish="+pid, testToken, "x"),
		doReq(t, h, "PUT", "/api/shares/"+id+"/files/a.txt?publish=not-a-publish", testToken, "x"),
		commitPublish(t, h, other, pid, `{"files":["a.txt"]}`),
	} {
		if rec.Code != http.StatusNotFound || errCode(t, rec.Body.String()) != "no-such-publish" {
			t.Fatalf("a publish named on the wrong share: %d %s", rec.Code, rec.Body)
		}
	}
	if !b.FS.StageExists(id, pid) {
		t.Fatal("the publish closed")
	}
}

// The batch stages every entry into a publish and answers each staged; the
// share does not move until the commit.
func TestABatchStagesIntoAPublish(t *testing.T) {
	h, b := publishAPI(t)
	id := createShare(t, h, "s")
	before := readListed(t, h, id)
	pid := openPublish(t, h, testToken, id)
	body := tarOf(t, map[string]string{"a.txt": "AA", "d/b.txt": "BBB"}, []string{"a.txt", "d/b.txt"})
	rec := doReq(t, h, "POST", "/api/shares/"+id+"/batch?publish="+pid, testToken, string(body))
	if rec.Code != 200 {
		t.Fatalf("staged batch: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Files     []stagedAnswer `json:"files"`
		Committed int            `json:"committed"`
	}
	unmarshal(t, rec, &out)
	if out.Committed != 2 || len(out.Files) != 2 {
		t.Fatalf("staged batch answered %s", rec.Body)
	}
	for _, f := range out.Files {
		if !f.Staged || f.SHA256 == "" {
			t.Fatalf("a batch entry not staged: %s", rec.Body)
		}
	}
	if after := readListed(t, h, id); !reflect.DeepEqual(before, after) {
		t.Fatalf("a staged batch changed the share: %+v", after)
	}
	if rec := commitPublish(t, h, id, pid, `{"files":["a.txt","d/b.txt"]}`); rec.Code != 200 {
		t.Fatalf("commit: %d %s", rec.Code, rec.Body)
	}
	if got, _ := publishedBytes(t, b, id, "d/b.txt"); got != "BBB" {
		t.Fatalf("d/b.txt = %q", got)
	}
}

// The status route answers inside the publish: a part's missing ranges, a
// finished upload's size and hash, nothing for a path not staged there.
func TestTheStatusRouteAnswersInsideAPublish(t *testing.T) {
	h, _ := publishAPI(t)
	id := createShare(t, h, "s")
	uploadGetSlug(t, h, id, "done.txt", "committed already")
	pid := openPublish(t, h, testToken, id)
	data := []byte(strings.Repeat("y", 100))
	if rec := stageChunk(t, h, id, pid, "y.bin", data, 0, 40, "y-session"); rec.Code != http.StatusAccepted {
		t.Fatalf("chunk: %d %s", rec.Code, rec.Body)
	}
	stageFile(t, h, id, pid, "z.txt", "zz")
	status := func(rel, session string) map[string]any {
		rec := doReq(t, h, "GET", "/api/shares/"+id+"/uploads/"+rel+"?session="+session+"&publish="+pid, testToken, "")
		if rec.Code != 200 {
			t.Fatalf("status %s: %d %s", rel, rec.Code, rec.Body)
		}
		var out map[string]any
		unmarshal(t, rec, &out)
		return out
	}
	if st := status("y.bin", "y-session"); st["complete"] != false || st["offset"] != float64(40) || st["total"] != float64(100) {
		t.Fatalf("a staged part's status: %v", st)
	}
	if st := status("y.bin", "other-session"); st["complete"] != false || st["offset"] != float64(0) {
		t.Fatalf("another session's status: %v", st)
	}
	if st := status("z.txt", "test-session"); st["complete"] != true || st["staged"] != true || st["sha256"] != sha("zz") || st["size"] != float64(2) {
		t.Fatalf("a finished staged upload's status: %v", st)
	}
	if st := status("done.txt", "test-session"); st["complete"] != false || st["offset"] != float64(0) {
		t.Fatalf("a committed file not staged in the publish: %v", st)
	}
}

// A path a linked source already lists is refused at staging, before any
// byte is sent, and at the commit when the source gained it meanwhile.
func TestALinkedCollisionIsRefusedAtStagingAndAtTheCommit(t *testing.T) {
	h, b, vol := linkedTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"sources":["photo/2024"],"name":"one"}`)
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var cr struct{ ID string }
	unmarshal(t, rec, &cr)
	pid := openPublish(t, h, testToken, cr.ID)
	if rec := doReq(t, h, "PUT", "/api/shares/"+cr.ID+"/files/a.jpg?publish="+pid, testToken, "x"); rec.Code != 400 || errCode(t, rec.Body.String()) != "path-taken" {
		t.Fatalf("staging over a linked entry: %d %s", rec.Code, rec.Body)
	}
	stageFile(t, h, cr.ID, pid, "new.jpg", "N")
	if err := os.WriteFile(filepath.Join(vol, "photo", "2024", "new.jpg"), []byte("on the server"), 0o644); err != nil {
		t.Fatal(err)
	}
	if rec := commitPublish(t, h, cr.ID, pid, `{"files":["new.jpg"]}`); rec.Code != 400 || errCode(t, rec.Body.String()) != "path-taken" {
		t.Fatalf("commit over a linked entry: %d %s", rec.Code, rec.Body)
	}
	if !b.FS.StageExists(cr.ID, pid) {
		t.Fatal("a refused commit closed the publish")
	}
}

// A text share holds one file a replace changes: no publish opens there.
func TestATextShareTakesNoPublish(t *testing.T) {
	h, _ := publishAPI(t)
	id := createShareBody(t, h, `{"name":"Note","text":true}`)
	rec := doReq(t, h, "POST", "/api/shares/"+id+"/publishes", testToken, `{}`)
	if rec.Code != http.StatusConflict || errCode(t, rec.Body.String()) != "text-share" {
		t.Fatalf("open on a text share: %d %s", rec.Code, rec.Body)
	}
}

// The commit takes at most 20,000 files to publish and as many to delete,
// and refuses a body naming nothing, an unclean path or a path twice.
// (TestEveryRouteNamesAnUnknownField holds both bodies to strict decoding.)
func TestPublishCommitBodiesAreBounded(t *testing.T) {
	h, _ := publishAPI(t)
	id := createShare(t, h, "s")
	pid := openPublish(t, h, testToken, id)
	paths := make([]string, publishMaxFiles+1)
	for i := range paths {
		paths[i] = fmt.Sprintf("f/%05d.txt", i)
	}
	body, _ := json.Marshal(map[string]any{"files": paths})
	if rec := commitPublish(t, h, id, pid, string(body)); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("commit of %d files: %d %s", len(paths), rec.Code, rec.Body)
	}
	for _, body := range []string{`{}`, `{"files":["../x"]}`, `{"files":["a.txt","a.txt"]}`, `{"files":["a.txt"],"delete":["a.txt"]}`,
		`{"files":["a.txt"],"base":{"a.txt":"","b.txt":""}}`} {
		if rec := commitPublish(t, h, id, pid, body); rec.Code != http.StatusBadRequest {
			t.Fatalf("commit %s: %d %s", body, rec.Code, rec.Body)
		}
	}
}

// A commit and an abort of one publish never interleave: the share ends
// either with every file committed and its bytes in place or with nothing,
// never a row naming bytes that are not there.
func TestACommitAndAnAbortOfOnePublishNeverInterleave(t *testing.T) {
	h, b := publishAPI(t)
	id := createShare(t, h, "s")
	names := []string{"a.txt", "b.txt", "c/d.txt"}
	for round := 0; round < 20; round++ {
		pid := openPublish(t, h, testToken, id)
		for _, rel := range names {
			stageFile(t, h, id, pid, rel, rel+strconv.Itoa(round))
		}
		var wg sync.WaitGroup
		var committed bool
		wg.Add(2)
		go func() {
			defer wg.Done()
			body, _ := json.Marshal(map[string]any{"files": names})
			committed = commitPublish(t, h, id, pid, string(body)).Code == 200
		}()
		go func() {
			defer wg.Done()
			doReq(t, h, "DELETE", "/api/shares/"+id+"/publishes/"+pid, testToken, "")
		}()
		wg.Wait()
		for _, rel := range names {
			got, ok := publishedBytes(t, b, id, rel)
			if committed && got != rel+strconv.Itoa(round) {
				t.Fatalf("round %d: committed, but %s holds %q %v", round, rel, got, ok)
			}
		}
		listed := readListed(t, h, id)
		var paths []string
		for _, f := range listed.Files {
			paths = append(paths, f.Path)
			if _, ok := publishedBytes(t, b, id, f.Path); !ok {
				t.Fatalf("round %d: %s is listed with no bytes", round, f.Path)
			}
		}
		sort.Strings(paths)
		if len(paths) != 0 && len(paths) != len(names) {
			t.Fatalf("round %d: half a publish is listed: %v", round, paths)
		}
	}
}

// A publish whose commit journal remains has rows that may already name
// its staged bytes: staging into it, whole, by chunk or in a batch, is
// refused 409 conflict as its commit and abort are, and what is staged
// stays as the journal found it.
func TestStagingIntoACommittingPublishIsRefused(t *testing.T) {
	h, b := publishAPI(t)
	id := createShare(t, h, "s")
	pid := openPublish(t, h, testToken, id)
	want := stageFile(t, h, id, pid, "a.txt", "staged")
	if err := b.FS.WriteJournal(id, pid, sharefs.Journal{Files: []string{"a.txt"}}); err != nil {
		t.Fatal(err)
	}
	batch := tarOf(t, map[string]string{"a.txt": "other"}, []string{"a.txt"})
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"whole":   doReq(t, h, "PUT", "/api/shares/"+id+"/files/a.txt?publish="+pid, testToken, "other"),
		"chunk":   stageChunk(t, h, id, pid, "a.txt", []byte("other"), 0, 2, "s2"),
		"another": doReq(t, h, "PUT", "/api/shares/"+id+"/files/b.txt?publish="+pid, testToken, "b"),
		"batch":   doReq(t, h, "POST", "/api/shares/"+id+"/batch?publish="+pid, testToken, string(batch)),
		"commit":  commitPublish(t, h, id, pid, `{"files":["a.txt"]}`),
		"abort":   doReq(t, h, "DELETE", "/api/shares/"+id+"/publishes/"+pid, testToken, ""),
	} {
		if rec.Code != http.StatusConflict || errCode(t, rec.Body.String()) != "conflict" {
			t.Fatalf("%s into a committing publish: %d %s", name, rec.Code, rec.Body)
		}
	}
	got, ok := b.FS.StagedFile(id, pid, "a.txt")
	if !ok || got.SHA256 != want.SHA256 {
		t.Fatalf("the staged a.txt changed under a journal: %+v %v", got, ok)
	}
	if _, ok := b.FS.StagedFile(id, pid, "b.txt"); ok {
		t.Fatal("b.txt was staged under a journal")
	}
}

// A rename that fails on a running server leaves rows naming staged bytes.
// The commit marks its journal once the rows are written, with the paths
// as the rows spell them, so the next boot finishes it path by path even
// after a later write superseded one of them: here an ordinary upload
// replaces x/a.txt before the restart. Afterwards every row's bytes are in
// files/ with its hash, and the sweep loses nothing.
func TestARenameThatFailsIsFinishedAtTheNextBootPathByPath(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes into any directory")
	}
	h, b := publishAPI(t)
	id := createShare(t, h, "site")
	for rel, body := range map[string]string{"x/old.txt": "x", "d/old.txt": "d", "gone.txt": "bye"} {
		uploadGetSlug(t, h, id, rel, body)
	}
	pid := openPublish(t, h, testToken, id)
	stageFile(t, h, id, pid, "x/a.txt", "staged a")
	stageFile(t, h, id, pid, "d/c.txt", "staged c")
	files, err := b.FS.ShareDir(id)
	if err != nil {
		t.Fatal(err)
	}
	locked := []string{filepath.Join(files, "files", "x"), filepath.Join(files, "files", "d")}
	for _, dir := range locked {
		if err := os.Chmod(dir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(dir, 0o700) })
	}
	if rec := commitPublish(t, h, id, pid, `{"files":["x/a.txt","d/c.txt"],"delete":["gone.txt"]}`); rec.Code != http.StatusInternalServerError {
		t.Fatalf("a commit whose renames fail: %d %s", rec.Code, rec.Body)
	}
	j, held, err := b.FS.ReadJournal(id, pid)
	if err != nil || !held || j.Rows == nil {
		t.Fatalf("the journal after the rows: %+v %v %v", j, held, err)
	}
	wantRenames := []sharefs.Rename{{From: "x/a.txt", To: "x/a.txt"}, {From: "d/c.txt", To: "d/c.txt"}}
	if !reflect.DeepEqual(j.Rows.Renames, wantRenames) || !reflect.DeepEqual(j.Rows.Deleted, []string{"gone.txt"}) {
		t.Fatalf("the journal's rows mark = %+v", j.Rows)
	}

	os.Chmod(locked[0], 0o700)
	uploadGetSlug(t, h, id, "x/a.txt", "newest a")
	os.Chmod(locked[1], 0o700)

	fs, err := sharefs.Open(b.FS.DataDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Orphans(func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if finished, reopened, err := housekeep.FinishPublishes(b.DB, fs); err != nil || finished != 1 || reopened != 0 {
		t.Fatalf("FinishPublishes = %d finished, %d reopened, %v", finished, reopened, err)
	}
	everyRowHoldsItsBytes := func() {
		t.Helper()
		listed := readListed(t, h, id)
		for _, f := range listed.Files {
			got, ok := publishedBytes(t, b, id, f.Path)
			if !ok || sha(got) != f.SHA256 {
				t.Fatalf("row %s (sha256 %s) names %q (present %v)", f.Path, f.SHA256, got, ok)
			}
		}
		if len(listed.Files) != 4 {
			t.Fatalf("the share lists %d files, want 4", len(listed.Files))
		}
	}
	everyRowHoldsItsBytes()
	for rel, want := range map[string]string{"x/a.txt": "newest a", "d/c.txt": "staged c"} {
		if got, _ := publishedBytes(t, b, id, rel); got != want {
			t.Fatalf("%s = %q, want %q", rel, got, want)
		}
	}
	if _, ok := publishedBytes(t, b, id, "gone.txt"); ok {
		t.Fatal("the deleted file is still on disk")
	}
	if fs.StageExists(id, pid) {
		t.Fatal("the publish survived the boot pass")
	}
	fs.AbandonedWindow = 1
	fs.SweepStages()
	everyRowHoldsItsBytes()
}

// While a commit's journal remains, a move overlapping a path it names (the
// path, a folder above it, or one beneath it, as from or as to) is refused
// 409 conflict: moving the rows would leave the boot pass a row it cannot
// find and a part it then drops. A move clear of the journal goes through,
// and once the boot pass has finished the publish the refused moves do.
func TestAMoveOverlappingAJournalWaitsForTheBootPass(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes into any directory")
	}
	h, b := publishAPI(t)
	id := createShare(t, h, "site")
	for rel, body := range map[string]string{"d/old.txt": "d", "other.txt": "o", "keep.txt": "k"} {
		uploadGetSlug(t, h, id, rel, body)
	}
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
	if rec := commitPublish(t, h, id, pid, `{"files":["d/c.txt"]}`); rec.Code != http.StatusInternalServerError {
		t.Fatalf("a commit whose rename fails: %d %s", rec.Code, rec.Body)
	}
	for _, mv := range [][2]string{{"d", "e"}, {"d/c.txt", "c.txt"}, {"other.txt", "d/c.txt"}, {"other.txt", "d"}, {"keep.txt", "d/c.txt/deeper"}} {
		code, body := moveReq(t, h, id, testToken, mv[0], mv[1])
		if code != http.StatusConflict || errCode(t, body) != "conflict" {
			t.Fatalf("move %s to %s with the journal present: %d %s", mv[0], mv[1], code, body)
		}
	}
	if code, body := moveReq(t, h, id, testToken, "other.txt", "z/other.txt"); code != http.StatusOK {
		t.Fatalf("a move clear of the journal: %d %s", code, body)
	}

	os.Chmod(locked, 0o700)
	fs, err := sharefs.Open(b.FS.DataDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Orphans(func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if finished, _, err := housekeep.FinishPublishes(b.DB, fs); err != nil || finished != 1 {
		t.Fatalf("FinishPublishes = %d finished, %v", finished, err)
	}
	if code, body := moveReq(t, h, id, testToken, "d", "e"); code != http.StatusOK {
		t.Fatalf("the folder move after the boot pass: %d %s", code, body)
	}
	listed := readListed(t, h, id)
	for _, f := range listed.Files {
		got, ok := publishedBytes(t, b, id, f.Path)
		if !ok || sha(got) != f.SHA256 {
			t.Fatalf("row %s (sha256 %s) names %q (present %v)", f.Path, f.SHA256, got, ok)
		}
	}
	if got, _ := publishedBytes(t, b, id, "e/c.txt"); got != "staged c" {
		t.Fatalf("e/c.txt = %q", got)
	}
}
