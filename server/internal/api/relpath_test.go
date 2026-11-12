package api

import (
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"hyperdrop/server/internal/linked"
	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/shareid"
)

// café spelled both ways: composed (NFC) and decomposed (NFD), the spelling
// a Mac's filesystem hands out.
const (
	cafeNFC = "café"
	cafeNFD = "café"
)

// Every route that names a share's own entry takes the NFC spelling of the
// path it is sent, so a client that sends the decomposed one reaches the
// same entry: the upload stores it composed, and the status query, the
// ?replaces= donation, a preparing report, the entry page, a batch entry
// and the delete all find it.
func TestEveryRouteThatNamesAnEntryTakesItsNFCSpelling(t *testing.T) {
	h, b := newTestAPIBackend(t)
	nfd := url.PathEscape(cafeNFD + ".txt")
	id := createShare(t, h, "accents")

	rec := doReqResume(t, h, "/api/shares/"+id+"/files/"+nfd, "hello", "0", "5")
	if rec.Code != 201 {
		t.Fatalf("upload = %d %s", rec.Code, rec.Body)
	}
	var up uploadDone
	unmarshal(t, rec, &up)
	if up.Path != cafeNFC+".txt" {
		t.Fatalf("stored path %q, want the NFC %q", up.Path, cafeNFC+".txt")
	}
	if st := statusOf(t, h, id, nfd, "test-session"); !st.Complete {
		t.Fatalf("status under the NFD spelling = %+v, want the commit", st)
	}

	rec = doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"entry":"`+cafeNFD+`.txt"}`)
	if rec.Code != 200 {
		t.Fatalf("entry = %d %s", rec.Code, rec.Body)
	}
	if d, err := b.DB.Share(id); err != nil || d.Entry != cafeNFC+".txt" {
		t.Fatalf("entry recorded as %q (%v), want the NFC spelling", d.Entry, err)
	}

	rec = doReqResume(t, h, "/api/shares/"+id+"/files/new.txt?replaces="+url.QueryEscape(cafeNFD+".txt"), "fresh", "0", "5")
	if rec.Code != 201 {
		t.Fatalf("replace = %d %s", rec.Code, rec.Body)
	}
	var replaced uploadDone
	unmarshal(t, rec, &replaced)
	if replaced.Slug != up.Slug {
		t.Fatalf("the replace took slug %q, want the donated %q", replaced.Slug, up.Slug)
	}

	rec = postBatch(t, h, id, testToken, tarOf(t, map[string]string{cafeNFD + ".md": "batched"}, nil), "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"path":"`+cafeNFC+`.md"`) {
		t.Fatalf("batch = %d %s, want the entry stored NFC", rec.Code, rec.Body)
	}
	rec = doReq(t, h, "DELETE", "/api/shares/"+id+"/files/"+url.PathEscape(cafeNFD+".md"), testToken, "")
	if rec.Code != 200 {
		t.Fatalf("delete under the NFD spelling = %d %s", rec.Code, rec.Body)
	}
	if paths := sharePaths(t, h, testToken, id); len(paths) != 1 || paths[0] != "new.txt" {
		t.Fatalf("share lists %v, want new.txt alone", paths)
	}

	rec = doReq(t, h, "POST", "/api/shares", testToken,
		`{"name":"declared","files":[{"path":"`+cafeNFD+`.mp4","size":5}]}`)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	var created shareResp
	unmarshal(t, rec, &created)
	if len(created.Files) != 1 || created.Files[0].Path != cafeNFC+".mp4" {
		t.Fatalf("manifest = %+v, want the NFC path", created.Files)
	}
	if code := report(t, h, testToken, created.ID, url.PathEscape(cafeNFD+".mp4"), `{"fraction":0.5,"stage":"encoding"}`); code != 204 {
		t.Fatalf("preparing under the NFD spelling = %d", code)
	}
}

// A live share's manifest and entry take the same rule, so the path the
// server asks the sharer for is the one the reference client keys its
// files by.
func TestALiveSharesPathsTakeTheirNFCSpelling(t *testing.T) {
	h := newTestAPI(t)
	sh := createLiveShare(t, h, testToken, `{"name":"live","entry":"`+cafeNFD+`.html","files":[`+
		`{"path":"`+cafeNFD+`.html","size":5,"mime":"text/html","mtime":"2026-08-06T10:00:00Z"}]}`)
	if len(sh.Files) != 1 || sh.Files[0].Path != cafeNFC+".html" || sh.Entry != cafeNFC+".html" {
		t.Fatalf("live share = %+v, want the NFC spelling", sh)
	}
}

// A linked entry keeps the server filesystem's bytes, so a relpath the
// server is sent (always NFC once received) matches a decomposed one in NFC:
// the delete is refused as a linked entry's, and a hide takes it out of
// the listing whichever spelling the client sent.
func TestALinkedEntryIsMatchedInNFC(t *testing.T) {
	vol := t.TempDir()
	if err := os.MkdirAll(filepath.Join(vol, "web"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{cafeNFD + ".txt", "plain.txt"} {
		if err := os.WriteFile(filepath.Join(vol, "web", name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	roots, err := linked.NewRoots(nil, []string{vol}, nil)
	if err != nil {
		t.Fatal(err)
	}
	b := testBackendWithRoots(t, roots)
	h := New(b, "2.0.0", testDomain(t), nil)
	id := linkedShare(t, b, "web")

	rec := doReq(t, h, "DELETE", "/api/shares/"+id+"/files/"+url.PathEscape(cafeNFC+".txt"), testToken, "")
	if rec.Code != http.StatusConflict || errCode(t, rec.Body.String()) != "share-linked" {
		t.Fatalf("delete of the linked entry = %d %s, want 409 share-linked", rec.Code, rec.Body)
	}
	for _, spelled := range []string{cafeNFD, cafeNFC} {
		rec = doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"linked":{"web":{"hide":["`+spelled+`.txt"]}}}`)
		if rec.Code != 200 {
			t.Fatalf("hide %q = %d %s", spelled, rec.Code, rec.Body)
		}
		if paths := sharePaths(t, h, testToken, id); len(paths) != 1 || paths[0] != "plain.txt" {
			t.Fatalf("after hiding %q the share lists %v, want plain.txt alone", spelled, paths)
		}
		rec = doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"linked":{"web":{"show":["`+spelled+`.txt"]}}}`)
		if rec.Code != 200 {
			t.Fatalf("show %q = %d %s", spelled, rec.Code, rec.Body)
		}
		if paths := sharePaths(t, h, testToken, id); len(paths) != 2 {
			t.Fatalf("after showing %q the share lists %v, want both", spelled, paths)
		}
	}
}

func deepPath(n int, leaf string) string {
	return strings.Repeat("d/", n-1) + leaf
}

func TestAnUploadDeeperThanTheCapIsRefused(t *testing.T) {
	h, b := newTestAPIBackend(t)
	id := createShare(t, h, "deep")
	ok, deep := deepPath(shareid.MaxRelPathDepth, "f.txt"), deepPath(shareid.MaxRelPathDepth+1, "f.txt")

	if rec := doReqResume(t, h, "/api/shares/"+id+"/files/"+deep, "x", "0", "1"); rec.Code != 400 {
		t.Fatalf("single PUT too deep = %d %s, want 400", rec.Code, rec.Body)
	}
	rec := postBatch(t, h, id, testToken, tarOf(t, map[string]string{deep: "x"}, nil), "")
	if rec.Code != 400 {
		t.Fatalf("batch too deep = %d %s, want 400", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "POST", "/api/shares/"+id+"/folders", testToken, `{"path":"`+deepPath(shareid.MaxRelPathDepth+1, "x")+`"}`); rec.Code != 400 {
		t.Fatalf("folder too deep = %d %s, want 400", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"m","files":[{"path":"`+deep+`","size":1}]}`); rec.Code != 400 {
		t.Fatalf("manifest too deep = %d %s, want 400", rec.Code, rec.Body)
	}

	if rec := doReqResume(t, h, "/api/shares/"+id+"/files/"+ok, "x", "0", "1"); rec.Code != 201 {
		t.Fatalf("PUT at the cap = %d %s, want 201", rec.Code, rec.Body)
	}
	rec = doReq(t, h, "POST", "/api/shares/"+id+"/move", testToken, `{"from":"`+ok+`","to":"`+deep+`"}`)
	if rec.Code != 400 {
		t.Fatalf("move destination too deep = %d %s, want 400", rec.Code, rec.Body)
	}
	if _, err := b.DB.File(id, ok); err != nil {
		t.Fatalf("the move source vanished: %v", err)
	}
	if _, err := b.DB.File(id, deep); err == nil {
		t.Fatal("a row was written for a refused path")
	}
	if _, err := os.Stat(filepath.Join(b.FS.DataDir(), "shares", id, "files", filepath.FromSlash(deep))); err == nil {
		t.Fatal("bytes were stored for a refused path")
	}
	if parts, _ := os.ReadDir(filepath.Join(b.FS.DataDir(), "shares", id, "parts")); len(parts) != 0 {
		t.Fatalf("%d parts staged for refused paths", len(parts))
	}
}

func TestAFileAlreadyDeeperThanTheCapStaysReachable(t *testing.T) {
	h, b := newTestAPIBackend(t)
	id := createShare(t, h, "old")
	rel := deepPath(shareid.MaxRelPathDepth+2, "old.txt")
	dir := filepath.Join(b.FS.DataDir(), "shares", id, "files", filepath.FromSlash(path.Dir(rel)))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Skipf("the filesystem cannot hold the path: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "old.txt"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := b.DB.CommitFile(metadb.CommitInput{ShareID: id, Path: rel, Size: 3, Mime: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	if paths := sharePaths(t, h, testToken, id); len(paths) != 1 || paths[0] != rel {
		t.Fatalf("listing = %v, want the deep file", paths)
	}
	if rec := doReq(t, h, "GET", "/download/"+id+"/"+f.Slug, testToken, ""); rec.Code != 200 || rec.Body.String() != "old" {
		t.Fatalf("download = %d %q", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "DELETE", "/api/shares/"+id+"/files/"+rel, testToken, ""); rec.Code != 200 {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body)
	}
}

func TestAFolderMoveIsHeldToTheCapByItsDeepestEntry(t *testing.T) {
	h, b := newTestAPIBackend(t)
	id := createShare(t, h, "tree")
	leaf := "t/" + strings.Repeat("d/", 98) + "f.txt" // 100 segments
	if rec := doReqResume(t, h, "/api/shares/"+id+"/files/"+leaf, "x", "0", "1"); rec.Code != 201 {
		t.Fatalf("seed = %d %s", rec.Code, rec.Body)
	}
	move := func(from, to string) int {
		return doReq(t, h, "POST", "/api/shares/"+id+"/move", testToken, `{"from":"`+from+`","to":"`+to+`"}`).Code
	}
	prefix := func(n int) string { return strings.Repeat("m/", n-1) + "x" }

	if code := move("t", prefix(30)); code != 400 {
		t.Fatalf("move landing 129 deep = %d, want 400", code)
	}
	if _, err := b.DB.File(id, leaf); err != nil {
		t.Fatalf("a refused move changed the share: %v", err)
	}
	if code := move("t", prefix(29)); code != 200 {
		t.Fatalf("move landing 128 deep = %d, want 200", code)
	}
	if code := doReq(t, h, "POST", "/api/shares/"+id+"/folders", testToken, `{"path":"`+deepPath(shareid.MaxRelPathDepth+1, "x")+`"}`).Code; code != 400 {
		t.Fatalf("folder too deep = %d", code)
	}
}

func TestADeepFileMovesOutToAShallowFolder(t *testing.T) {
	h, b := newTestAPIBackend(t)
	id := createShare(t, h, "out")
	rel := deepPath(shareid.MaxRelPathDepth+2, "old.txt")
	dir := filepath.Join(b.FS.DataDir(), "shares", id, "files", filepath.FromSlash(path.Dir(rel)))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Skipf("the filesystem cannot hold the path: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "old.txt"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := b.DB.CommitFile(metadb.CommitInput{ShareID: id, Path: rel, Size: 3, Mime: "text/plain"}); err != nil {
		t.Fatal(err)
	}
	if rec := doReq(t, h, "POST", "/api/shares/"+id+"/move", testToken, `{"from":"`+rel+`","to":"a/b/old.txt"}`); rec.Code != 200 {
		t.Fatalf("move out = %d %s", rec.Code, rec.Body)
	}
}
