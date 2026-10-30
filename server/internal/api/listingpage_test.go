package api

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"hyperdrop/server/internal/metadb"
)

// committedShare creates a share owned by the seeded admin and commits every
// path straight into the database, as listingscale_test.go does: the pages
// read rows, and no byte behind them.
func committedShare(t *testing.T, b Backend, o metadb.CreateOptions, mime string, paths ...string) string {
	t.Helper()
	o.Owner = metadb.DefaultAdminName
	if o.Name == "" {
		o.Name = "big"
	}
	d, err := b.DB.CreateShare(o)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		if _, err := b.DB.CommitFile(metadb.CommitInput{ShareID: d.ID, Path: p, Size: 1, Mime: mime}); err != nil {
			t.Fatal(err)
		}
	}
	return d.ID
}

// numbered is n relpaths printed from format.
func numbered(format string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf(format, i)
	}
	return out
}

var (
	rowNameRe  = regexp.MustCompile(`<div class="row">\s*<a class="name" href="[^"]*">([^<]*)</a>`)
	dirNameRe  = regexp.MustCompile(`<div class="folder">[\s\S]*?<a class="name" href="[^"]*">([^<]*)</a>`)
	moreLinkRe = regexp.MustCompile(`<a class="more[^"]*" href="([^"]*)"`)
)

// listed is the names a listing page shows, folders then files.
func listed(body string) (dirs, files []string) {
	for _, m := range dirNameRe.FindAllStringSubmatch(body, -1) {
		dirs = append(dirs, html.UnescapeString(m[1]))
	}
	for _, m := range rowNameRe.FindAllStringSubmatch(body, -1) {
		files = append(files, html.UnescapeString(m[1]))
	}
	return
}

// moreLink is the page's More address, "" when it has none.
func moreLink(t *testing.T, body string) string {
	t.Helper()
	m := moreLinkRe.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	return html.UnescapeString(m[1])
}

// A folder of exactly 500 children is one page, exactly as before paging:
// no More link, and every folder row counted and sized.
func TestAShareOfFiveHundredHasNoMoreLink(t *testing.T) {
	h, _, b := newMultiUserAPI(t)
	paths := append(numbered("f%03d.txt", 498), "g/1", "g/2", "h/deep/1")
	id := committedShare(t, b, metadb.CreateOptions{Folder: true}, "text/plain", paths...)
	rec := doReq(t, h, "GET", "/share/"+id, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	dirs, files := listed(body)
	if len(dirs) != 2 || len(files) != 498 {
		t.Fatalf("%d folders and %d files, want 2 and 498", len(dirs), len(files))
	}
	if strings.Contains(body, "after=") || moreLink(t, body) != "" {
		t.Error("a page of 500 children must carry no More link")
	}
	if !strings.Contains(body, `<span class="count">2 files</span>`) || !strings.Contains(body, `<span class="size">`+humanSize(2)+`</span>`) {
		t.Error("folder rows on a single page keep their count and size")
	}
	if !strings.Contains(body, "501 files") {
		t.Error("the header counts the whole share")
	}
}

// 501 children are two pages. The first shows 500 and links the rest by the
// 500th child's key; the second shows the one left, and a lone file there is
// a page of the listing, never the one-file redirect.
func TestAShareOfFiveHundredAndOneHasMore(t *testing.T) {
	h, _, b := newMultiUserAPI(t)
	paths := append(numbered("f%03d.txt", 499), "g/1", "h.txt")
	id := committedShare(t, b, metadb.CreateOptions{Folder: true}, "text/plain", paths...)
	body := doReq(t, h, "GET", "/share/"+id, "", "").Body.String()
	dirs, files := listed(body)
	if len(dirs)+len(files) != 500 || slices.Contains(files, "h.txt") || !slices.Contains(dirs, "g") {
		t.Fatalf("first page: %d folders, %d files, h.txt=%v", len(dirs), len(files), slices.Contains(files, "h.txt"))
	}
	more := moreLink(t, body)
	u, err := url.Parse(more)
	if err != nil || u.Path != "/share/"+id || u.Query().Get("after") != "g/" {
		t.Fatalf("More link %q", more)
	}
	if strings.Contains(body, `<span class="count">1 file</span>`) {
		t.Error("a paged page shows no folder counts")
	}
	if !strings.Contains(body, "501 files") {
		t.Error("the header counts the whole share on every page")
	}
	rec := doReq(t, h, "GET", more, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("second page → %d (Location %q)", rec.Code, rec.Header().Get("Location"))
	}
	body = rec.Body.String()
	dirs, files = listed(body)
	if len(dirs) != 0 || !slices.Equal(files, []string{"h.txt"}) || moreLink(t, body) != "" {
		t.Fatalf("second page: dirs %v files %v more %q", dirs, files, moreLink(t, body))
	}
	if !strings.Contains(body, "501 files") {
		t.Error("the header counts the whole share on every page")
	}
}

// The More link keeps the folder shown and the files=1 escape hatch.
func TestMoreKeepsTheFolderAndTheFilesFlag(t *testing.T) {
	h, _, b := newMultiUserAPI(t)
	id := committedShare(t, b, metadb.CreateOptions{Folder: true}, "text/plain", numbered("d/f%03d.txt", 501)...)
	body := doReq(t, h, "GET", "/share/"+id+"?dir=d&files=1", "", "").Body.String()
	u, err := url.Parse(moreLink(t, body))
	if err != nil || u.Query().Get("dir") != "d" || u.Query().Get("files") != "1" || u.Query().Get("after") != "f499.txt" {
		t.Fatalf("More link %q", moreLink(t, body))
	}
	_, files := listed(doReq(t, h, "GET", u.String(), "", "").Body.String())
	if !slices.Equal(files, []string{"f500.txt"}) {
		t.Fatalf("second page %v", files)
	}
}

// after is a stranger's string: whatever it holds, the page answers 200 with
// the children that sort after it, and it is never echoed into the page.
func TestAnyAfterValueIsSafe(t *testing.T) {
	h, _, b := newMultiUserAPI(t)
	id := committedShare(t, b, metadb.CreateOptions{Folder: true}, "text/plain",
		"a.txt", "b.txt", "zz.txt", "zzz/1", `q"<b>.txt`)
	for _, after := range []string{"zz-missing", "../x", strings.Repeat("a", 10<<10), `"><script>alert(1)</script>`, "zz/", "%00"} {
		rec := doReq(t, h, "GET", "/share/"+id+"?after="+url.QueryEscape(after), "", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("after %.20q → %d", after, rec.Code)
		}
		body := rec.Body.String()
		if strings.Contains(body, "<script>alert") {
			t.Fatalf("after %.20q reached the page unescaped", after)
		}
		dirs, files := listed(body)
		for _, d := range dirs {
			if d+"/" <= after {
				t.Errorf("after %.20q listed folder %q", after, d)
			}
		}
		for _, f := range files {
			if f <= after {
				t.Errorf("after %.20q listed %q", after, f)
			}
		}
	}
	body := doReq(t, h, "GET", "/share/"+id+"?after=zz-missing", "", "").Body.String()
	dirs, files := listed(body)
	if !slices.Equal(dirs, []string{"zzz"}) || !slices.Equal(files, []string{"zz.txt"}) {
		t.Fatalf("after zz-missing: %v %v", dirs, files)
	}
}

// galleryJSON is the item list a gallery page inlines.
func galleryJSON(t *testing.T, body string) []galleryItem {
	t.Helper()
	m := regexp.MustCompile(`<script type="application/json" id="data"[^>]*>([\s\S]*?)</script>`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no item list in %.300s", body)
	}
	var items []galleryItem
	if err := json.Unmarshal([]byte(m[1]), &items); err != nil {
		t.Fatal(err)
	}
	return items
}

// A gallery is flat: it pages by relpath, 500 tiles, then More.
func TestTheGalleryPagesToo(t *testing.T) {
	h, _, b := newMultiUserAPI(t)
	id := committedShare(t, b, metadb.CreateOptions{Folder: true, Media: true}, "image/jpeg", numbered("p%03d.jpg", 501)...)
	last, err := b.DB.File(id, "p500.jpg")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.DB.SetGallery(id, map[string]metadb.GalleryItem{last.Slug: {Width: 40, Height: 30}}); err != nil {
		t.Fatal(err)
	}
	body := doReq(t, h, "GET", "/share/"+id, "", "").Body.String()
	items := galleryJSON(t, body)
	if len(items) != 500 || items[0].Name != "p000.jpg" || items[499].Name != "p499.jpg" {
		t.Fatalf("first page holds %d tiles", len(items))
	}
	if !strings.Contains(body, "501 files") {
		t.Error("the gallery's header counts the whole share")
	}
	u, err := url.Parse(moreLink(t, body))
	if err != nil || u.Path != "/share/"+id || u.Query().Get("after") != "p499.jpg" {
		t.Fatalf("More link %q", moreLink(t, body))
	}
	body = doReq(t, h, "GET", u.String(), "", "").Body.String()
	items = galleryJSON(t, body)
	if len(items) != 1 || items[0].Name != "p500.jpg" || items[0].W != 40 || moreLink(t, body) != "" {
		t.Fatalf("second page %+v more %q", items, moreLink(t, body))
	}
}

// A linked share's walk and its uploads interleave by relpath, across a page
// boundary, each linked row with its slug.
func TestALinkedShareMergesInPathOrder(t *testing.T) {
	h, b, vol := linkedTestAPI(t)
	src := filepath.Join(vol, "photo", "many")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	var stored []string
	for i := 0; i < 1000; i++ {
		name := fmt.Sprintf("l%03d.txt", i)
		if i%2 == 0 {
			os.WriteFile(filepath.Join(src, name), []byte("L"), 0o644)
		} else {
			stored = append(stored, name)
		}
	}
	id := committedShare(t, b, metadb.CreateOptions{Folder: true, Sources: []string{"photo/many"}}, "text/plain", stored...)
	body := doReq(t, h, "GET", "/share/"+id, "", "").Body.String()
	_, files := listed(body)
	if !slices.Equal(files, numbered("l%03d.txt", 500)) {
		t.Fatalf("first page holds %d files, from %v to %v", len(files), files[:min(2, len(files))], files[max(0, len(files)-2):])
	}
	if strings.Contains(body, `/view/`+id+`/"`) || strings.Contains(body, `/download/`+id+`/"`) {
		t.Error("a linked row carries no slug")
	}
	if !strings.Contains(body, "1000 files") {
		t.Error("the header counts the walk and the uploads")
	}
	more := moreLink(t, body)
	if u, err := url.Parse(more); err != nil || u.Query().Get("after") != "l499.txt" {
		t.Fatalf("More link %q", more)
	}
	_, files = listed(doReq(t, h, "GET", more, "", "").Body.String())
	want := numbered("l%03d.txt", 1000)[500:]
	if !slices.Equal(files, want) {
		t.Fatalf("second page holds %d files", len(files))
	}
}

// The owner's bearer read and the zip are not pages: the API answers every file.
func TestTheOwnersReadsStayWhole(t *testing.T) {
	h, _, b := newMultiUserAPI(t)
	id := committedShare(t, b, metadb.CreateOptions{Folder: true}, "text/plain", numbered("f%03d.txt", 501)...)
	var out struct {
		Files []struct {
			Path string `json:"path"`
		} `json:"files"`
	}
	rec := doReq(t, h, "GET", "/api/shares/"+id, testToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("owner read → %d", rec.Code)
	}
	unmarshal(t, rec, &out)
	if len(out.Files) != 501 {
		t.Fatalf("owner read lists %d files, want 501", len(out.Files))
	}
}

// ?dir= is a query of its own, not page one of the share: a folder sorting
// after the first 500 relpaths renders, and so does one deeper inside it.
func TestADeepFolderPastTheFirstPageStillRenders(t *testing.T) {
	h, _, b := newMultiUserAPI(t)
	paths := append(numbered("a/%03d.txt", 600), "zz/deep/x.txt", "zz/y.txt")
	id := committedShare(t, b, metadb.CreateOptions{Folder: true}, "text/plain", paths...)
	rec := doReq(t, h, "GET", "/share/"+id+"?dir=zz%2Fdeep", "", "")
	if _, files := listed(rec.Body.String()); rec.Code != http.StatusOK || !slices.Equal(files, []string{"x.txt"}) {
		t.Fatalf("zz/deep → %d, files %v", rec.Code, files)
	}
	rec = doReq(t, h, "GET", "/share/"+id+"?dir=zz", "", "")
	dirs, files := listed(rec.Body.String())
	if rec.Code != http.StatusOK || !slices.Equal(dirs, []string{"deep"}) || !slices.Equal(files, []string{"y.txt"}) {
		t.Fatalf("zz → %d, %v %v", rec.Code, dirs, files)
	}
	if !strings.Contains(rec.Body.String(), `<span class="count">1 file</span>`) {
		t.Error("a single page keeps its folder counts")
	}
	if rec := doReq(t, h, "GET", "/share/"+id+"?dir=zz%2Fnope", "", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("a folder the share does not hold → %d", rec.Code)
	}
	if rec := doReq(t, h, "GET", "/share/"+id+"?dir=zz&after=zzzz", "", ""); rec.Code != http.StatusOK {
		t.Fatalf("a folder paged past its end → %d", rec.Code)
	}
}

// A site's entry is looked up by its path, so one sorting after the 500th
// relpath still opens the site.
func TestASiteEntryPastTheFiveHundredthPathStillRedirects(t *testing.T) {
	h, _, b := newMultiUserAPI(t)
	id := committedShare(t, b, metadb.CreateOptions{Folder: true, Entry: "zz/index.html"}, "text/html",
		append(numbered("a%03d.html", 600), "zz/index.html")...)
	rec := doReq(t, h, "GET", "/share/"+id, "", "")
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/site/"+id+"/zz/index.html" {
		t.Fatalf("→ %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

// A share of exactly one file still hands out that file, wherever it sits.
func TestAOneFileShareStillRedirects(t *testing.T) {
	h, _, b := newMultiUserAPI(t)
	id := committedShare(t, b, metadb.CreateOptions{}, "text/plain", "deep/one.txt")
	f, err := b.DB.File(id, "deep/one.txt")
	if err != nil {
		t.Fatal(err)
	}
	rec := doReq(t, h, "GET", "/share/"+id, "", "")
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/view/"+id+"/"+f.Slug {
		t.Fatalf("→ %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

// Subfolder totals read every row beneath each subfolder, so only a share of
// at most publicFolderTotalsMax entries counts them: at 10,000 the root's one
// folder row is counted and sized, at 10,001 it is uncounted, and the root
// still renders.
func TestABigShareListsItsFoldersUncounted(t *testing.T) {
	h, _, b := newMultiUserAPI(t)
	id := committedShare(t, b, metadb.CreateOptions{Folder: true}, "text/plain",
		numbered("a/%05d.txt", publicFolderTotalsMax)...)
	body := doReq(t, h, "GET", "/share/"+id, "", "").Body.String()
	if !strings.Contains(body, fmt.Sprintf(`<span class="count">%d files</span>`, publicFolderTotalsMax)) {
		t.Fatalf("a share of %d entries counts its folders", publicFolderTotalsMax)
	}
	if _, err := b.DB.CommitFile(metadb.CommitInput{ShareID: id, Path: "a/more.txt", Size: 1, Mime: "text/plain"}); err != nil {
		t.Fatal(err)
	}
	rec := doReq(t, h, "GET", "/share/"+id, "", "")
	body = rec.Body.String()
	dirs, _ := listed(body)
	if rec.Code != http.StatusOK || !slices.Equal(dirs, []string{"a"}) || moreLink(t, body) != "" {
		t.Fatalf("root → %d, folders %v, more %q", rec.Code, dirs, moreLink(t, body))
	}
	if strings.Contains(body, " files</span>") || strings.Contains(body, `<span class="size">`+humanSize(publicFolderTotalsMax+1)+`</span>`) {
		t.Error("a share past publicFolderTotalsMax shows its folders uncounted")
	}
	if !strings.Contains(body, fmt.Sprintf("%d files", publicFolderTotalsMax+1)) {
		t.Error("the header still counts the whole share")
	}
}
