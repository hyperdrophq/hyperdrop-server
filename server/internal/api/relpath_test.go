package api

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hyperdrop/server/internal/linked"
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
