package api

import (
	"net/http"
	"strings"
	"testing"

	"hyperdrop/server/internal/shareid"
)

// unheldSlug is well formed and names no file.
const unheldSlug = "00000000-0000-4000-8000-000000000000"

type fileLinkFiles []struct {
	Path    string `json:"path"`
	Slug    string `json:"slug"`
	FileKey string `json:"fileKey"`
}

type fileLinkShare struct {
	ID    string        `json:"id"`
	Files fileLinkFiles `json:"files"`
}

func getFileLinkShare(t *testing.T, h http.Handler, token, id string) fileLinkShare {
	t.Helper()
	rec := doReq(t, h, "GET", "/api/shares/"+id, token, "")
	if rec.Code != 200 {
		t.Fatalf("get: %d %s", rec.Code, rec.Body)
	}
	var out fileLinkShare
	unmarshal(t, rec, &out)
	return out
}

type mintAnswer struct {
	Links []struct {
		Slug    string `json:"slug"`
		FileKey string `json:"fileKey"`
	} `json:"links"`
}

func TestMintFileLinksAnswersKeysForHeldSlugs(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "s")
	uploadFile(t, h, testToken, id, "a.txt", "A")
	uploadFile(t, h, testToken, id, "b.txt", "B")
	sh := getFileLinkShare(t, h, testToken, id)
	a, b := sh.Files[0].Slug, sh.Files[1].Slug
	for _, f := range sh.Files {
		if f.FileKey != "" {
			t.Fatalf("a file with no key carries %q", f.FileKey)
		}
	}
	unheld := unheldSlug
	body := `{"slugs":["` + b + `","` + unheld + `","` + a + `"]}`
	rec := doReq(t, h, "POST", "/api/shares/"+id+"/file-links", testToken, body)
	if rec.Code != 200 {
		t.Fatalf("mint: %d %s", rec.Code, rec.Body)
	}
	var first mintAnswer
	unmarshal(t, rec, &first)
	if len(first.Links) != 2 || first.Links[0].Slug != b || first.Links[1].Slug != a {
		t.Fatalf("links: %+v", first.Links)
	}
	for _, l := range first.Links {
		if !shareid.ValidFileKey(l.FileKey) {
			t.Fatalf("key %q", l.FileKey)
		}
	}
	rec = doReq(t, h, "POST", "/api/shares/"+id+"/file-links", testToken, body)
	var again mintAnswer
	unmarshal(t, rec, &again)
	if len(again.Links) != 2 || again.Links[0] != first.Links[0] || again.Links[1] != first.Links[1] {
		t.Fatalf("a second mint changed keys: %+v vs %+v", again.Links, first.Links)
	}
}

func TestMintFileLinksOnALinkedEntry(t *testing.T) {
	h, b, _ := linkedTestAPI(t)
	id := linkedShare(t, b, "photo/2024")
	// A linked entry's slug is assigned by the walk the mint route composes.
	rec := doReq(t, h, "POST", "/api/shares/"+id+"/file-links", testToken, `{"slugs":["`+unheldSlug+`"]}`)
	if rec.Code != 200 {
		t.Fatalf("mint of an unheld slug: %d %s", rec.Code, rec.Body)
	}
	sh := getFileLinkShare(t, h, testToken, id)
	if len(sh.Files) == 0 {
		t.Fatal("no linked entries")
	}
	rec = doReq(t, h, "POST", "/api/shares/"+id+"/file-links", testToken, `{"slugs":["`+sh.Files[0].Slug+`"]}`)
	var out mintAnswer
	unmarshal(t, rec, &out)
	if rec.Code != 200 || len(out.Links) != 1 {
		t.Fatalf("mint: %d %s", rec.Code, rec.Body)
	}
	if got := getFileLinkShare(t, h, testToken, id).Files[0].FileKey; got != out.Links[0].FileKey {
		t.Fatalf("linked entry fileKey = %q, want %q", got, out.Links[0].FileKey)
	}
}

func TestMintFileLinksIsOwnerScoped(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	alice := seedUser(t, um, "alice")
	bob := seedUser(t, um, "bob")
	id := createShareAs(t, h, alice, `{"name":"a"}`)
	uploadFile(t, h, alice, id, "a.txt", "A")
	slug := getFileLinkShare(t, h, alice, id).Files[0].Slug
	for name, tok := range map[string]string{"bob": bob, "admin": testToken} {
		rec := doReq(t, h, "POST", "/api/shares/"+id+"/file-links", tok, `{"slugs":["`+slug+`"]}`)
		if rec.Code != 404 {
			t.Errorf("%s mint: %d", name, rec.Code)
		}
		rec = doReq(t, h, "DELETE", "/api/shares/"+id+"/file-links/"+slug, tok, "")
		if rec.Code != 404 {
			t.Errorf("%s stop: %d", name, rec.Code)
		}
	}
}

func TestMintFileLinksRefusesAnInbox(t *testing.T) {
	h := newTestAPI(t)
	id := createInbox(t, h, `{"name":"in","receive":true}`)
	rec := doReq(t, h, "POST", "/api/shares/"+id+"/file-links", testToken, `{"slugs":["`+unheldSlug+`"]}`)
	if rec.Code != 409 || errCode(t, rec.Body.String()) != "file-link-inbox" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestMintFileLinksBounds(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "s")
	slugs := func(n int) string {
		s := make([]string, n)
		for i := range s {
			s[i] = `"` + unheldSlug + `"`
		}
		return `{"slugs":[` + strings.Join(s, ",") + `]}`
	}
	for name, body := range map[string]string{
		"none":    `{"slugs":[]}`,
		"absent":  `{}`,
		"1001":    slugs(1001),
		"unknown": `{"slugs":["` + unheldSlug + `"],"x":1}`,
		"badslug": `{"slugs":["../x"]}`,
	} {
		if rec := doReq(t, h, "POST", "/api/shares/"+id+"/file-links", testToken, body); rec.Code != 400 {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	if rec := doReq(t, h, "POST", "/api/shares/"+id+"/file-links", testToken, slugs(1000)); rec.Code != 200 {
		t.Errorf("1000: %d %s", rec.Code, rec.Body)
	}
}

func TestMintFileLinksOnALiveShareIs404(t *testing.T) {
	h := newTestLiveShareHandler(t)
	mux := h.routes()
	rec := doReq(t, mux, "POST", "/api/live-share", testToken, liveShareKeysBody)
	var created liveShareKeyedOut
	unmarshal(t, rec, &created)
	slug := created.Files[0].Slug
	rec = doReq(t, mux, "POST", "/api/shares/"+created.ID+"/file-links", testToken, `{"slugs":["`+slug+`"]}`)
	if rec.Code != 404 {
		t.Fatalf("mint: %d %s", rec.Code, rec.Body)
	}
	rec = doReq(t, mux, "DELETE", "/api/shares/"+created.ID+"/file-links/"+slug, testToken, "")
	if rec.Code != 404 {
		t.Fatalf("stop: %d %s", rec.Code, rec.Body)
	}
}

func TestStopFileLinkIs204EitherWay(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "s")
	uploadFile(t, h, testToken, id, "a.txt", "A")
	slug := getFileLinkShare(t, h, testToken, id).Files[0].Slug
	doReq(t, h, "POST", "/api/shares/"+id+"/file-links", testToken, `{"slugs":["`+slug+`"]}`)
	if getFileLinkShare(t, h, testToken, id).Files[0].FileKey == "" {
		t.Fatal("no key after mint")
	}
	for i := 0; i < 2; i++ {
		if rec := doReq(t, h, "DELETE", "/api/shares/"+id+"/file-links/"+slug, testToken, ""); rec.Code != 204 {
			t.Fatalf("stop %d: %d %s", i, rec.Code, rec.Body)
		}
	}
	if got := getFileLinkShare(t, h, testToken, id).Files[0].FileKey; got != "" {
		t.Fatalf("key after stop: %q", got)
	}
}

func TestOwnerShareCarriesFileKey(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "s")
	uploadFile(t, h, testToken, id, "a.txt", "A")
	uploadFile(t, h, testToken, id, "b.txt", "B")
	sh := getFileLinkShare(t, h, testToken, id)
	rec := doReq(t, h, "POST", "/api/shares/"+id+"/file-links", testToken, `{"slugs":["`+sh.Files[0].Slug+`"]}`)
	var out mintAnswer
	unmarshal(t, rec, &out)
	key := out.Links[0].FileKey

	check := func(where string, files fileLinkFiles) {
		for _, f := range files {
			want := ""
			if f.Slug == sh.Files[0].Slug {
				want = key
			}
			if f.FileKey != want {
				t.Errorf("%s: %s fileKey %q, want %q", where, f.Path, f.FileKey, want)
			}
		}
	}
	check("get", getFileLinkShare(t, h, testToken, id).Files)
	rec = doReq(t, h, "GET", "/api/shares", testToken, "")
	var list struct {
		Shares []fileLinkShare `json:"shares"`
	}
	unmarshal(t, rec, &list)
	found := false
	for _, s := range list.Shares {
		if s.ID == id {
			found = true
			check("list", s.Files)
		}
	}
	if !found {
		t.Fatal("share missing from the listing")
	}
}

func TestPublicPagesNeverCarryFileKeys(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "s")
	slug := uploadGetSlug(t, h, id, "a.txt", "A")
	uploadFile(t, h, testToken, id, "b.txt", "B")
	key := mintFileKey(t, h, testToken, id, slug)
	for _, p := range []string{"/share/" + id, "/gallery/" + id, "/site/" + id + "/",
		"/share/" + id + "?files=1", "/share/" + id + "/status"} {
		rec := doReq(t, h, "GET", p, "", "")
		if strings.Contains(rec.Body.String(), key) || strings.Contains(rec.Body.String(), "fileKey") {
			t.Errorf("%s carries the key", p)
		}
	}
	// The probes reach the file: the listing names it and the status poll
	// answers it, so a key left out of them is left out of a page that
	// describes the file.
	if rec := doReq(t, h, "GET", "/share/"+id+"?files=1", "", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), "a.txt") {
		t.Fatalf("?files=1 = %d, does not list the file", rec.Code)
	}
	if rec := doReq(t, h, "GET", "/share/"+id+"/status", "", ""); rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("status = %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
}

func TestALiveSharesPublicPagesNeverCarryFileKeys(t *testing.T) {
	h := newTestLiveShareHandler(t)
	mux := h.routes()
	rec := doReq(t, mux, "POST", "/api/live-share", testToken, liveShareKeysBody)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var created liveShareKeyedOut
	unmarshal(t, rec, &created)
	for _, p := range []string{"/share/" + created.ID, "/share/" + created.ID + "?files=1",
		"/share/" + created.ID + "/status", "/gallery/" + created.ID} {
		rec := doReq(t, mux, "GET", p, "", "")
		body := rec.Body.String()
		for _, f := range created.Files {
			if !shareid.ValidFileKey(f.FileKey) {
				t.Fatalf("%s has no key", f.Path)
			}
			if strings.Contains(body, f.FileKey) {
				t.Errorf("%s carries the key of %s", p, f.Path)
			}
		}
		if strings.Contains(body, "fileKey") {
			t.Errorf("%s names a fileKey field", p)
		}
	}
	if rec := doReq(t, mux, "GET", "/share/"+created.ID, "", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), "b.txt") {
		t.Fatalf("the live listing = %d, does not list its files", rec.Code)
	}
}
