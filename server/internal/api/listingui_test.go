package api

import (
	"net/http"
	"strings"
	"testing"
)

func TestSingleFileShareStillRedirects(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	id, _ := shareWithFiles(t, h, "one", map[string]string{"a.txt": "alpha"})
	rec := doReq(t, h, "GET", "/share/"+id, "", "")
	if rec.Code != http.StatusFound {
		t.Fatalf("single-file /share → %d, want 302", rec.Code)
	}
}

// An explicit folder with nothing in it is a row marked empty, its own page
// says so, and a share of folders alone shows folder rows rather than
// "No files yet".
func TestListingRendersAnEmptyFolder(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "site")
	// Two files, so the link lists rather than opening the one file.
	uploadGetSlug(t, h, id, "a.txt", "a")
	uploadGetSlug(t, h, id, "b.txt", "b")
	if code, body := mkdirReq(t, h, id, testToken, "drafts"); code != 200 {
		t.Fatalf("create = %d %s", code, body)
	}
	page := doReq(t, h, "GET", "/share/"+id, "", "").Body.String()
	if !strings.Contains(page, ">drafts<") || !strings.Contains(page, `<span class="count">empty</span>`) {
		t.Errorf("empty folder missing or miscounted: %s", page)
	}
	rec := doReq(t, h, "GET", "/share/"+id+"?dir=drafts", "", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Nothing in this folder.") {
		t.Errorf("empty folder page = %d %s", rec.Code, rec.Body)
	}
	only := createShare(t, h, "plan")
	if code, body := mkdirReq(t, h, only, testToken, "drafts"); code != 200 {
		t.Fatalf("create = %d %s", code, body)
	}
	page = doReq(t, h, "GET", "/share/"+only, "", "").Body.String()
	if strings.Contains(page, "No files yet") || !strings.Contains(page, ">drafts<") {
		t.Errorf("a folders-only share should show its folder rows: %s", page)
	}
}

// A visitor takes one folder home without opening it (the row's own Download)
// and from inside it (the second button). The whole-share button stays: the
// folder one is an addition to it, not a replacement.
func TestListingOffersEachFolderAsItsOwnZip(t *testing.T) {
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "multi", map[string]string{
		"evidence/a.txt": "alpha",
		"evidence/b.txt": "bravo",
		"notes.txt":      "note",
	})
	root := doReq(t, h, "GET", "/share/"+id, "", "").Body.String()
	if !strings.Contains(root, `href="/zip/`+id+`">Download all`) {
		t.Errorf("root page lost Download all: %s", root)
	}
	if !strings.Contains(root, `href="/zip/`+id+`?dir=evidence">Download`) {
		t.Errorf("folder row has no Download: %s", root)
	}
	if strings.Contains(root, "Download this folder") {
		t.Errorf("the root IS the whole share; it needs no folder button: %s", root)
	}
	inside := doReq(t, h, "GET", "/share/"+id+"?dir=evidence", "", "").Body.String()
	if !strings.Contains(inside, `href="/zip/`+id+`?dir=evidence">Download this folder`) {
		t.Errorf("folder page has no folder button: %s", inside)
	}
}

// An empty folder record has nothing to archive, and the route refuses it, so
// the row offers no link into that refusal.
func TestListingOffersNoZipForAnEmptyFolder(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "site")
	uploadGetSlug(t, h, id, "a.txt", "a")
	uploadGetSlug(t, h, id, "b.txt", "b")
	if code, body := mkdirReq(t, h, id, testToken, "drafts"); code != 200 {
		t.Fatalf("create = %d %s", code, body)
	}
	root := doReq(t, h, "GET", "/share/"+id, "", "").Body.String()
	if strings.Contains(root, "dir=drafts\">Download") {
		t.Errorf("empty folder row offers a download: %s", root)
	}
	inside := doReq(t, h, "GET", "/share/"+id+"?dir=drafts", "", "").Body.String()
	if strings.Contains(inside, "Download this folder") {
		t.Errorf("empty folder page offers a download: %s", inside)
	}
}
