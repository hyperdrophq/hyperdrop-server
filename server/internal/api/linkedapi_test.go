package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/linked"
	"hyperdrop/server/internal/metadb"
)

// A server says it can serve linked shares only while it HAS a folder to
// serve them from: the app shows its server picker on that answer alone.
// A server says it can serve linked shares only while it HAS a folder to
// serve them from: the app shows its server picker on that answer alone.
func TestHealthReportsSourcesOnlyWithARoot(t *testing.T) {
	// A fresh map per read: decoding into one that already holds keys adds
	// to it, so a reused map would carry sources from the answer before.
	health := func(h http.Handler) map[string]any {
		out := map[string]any{}
		unmarshal(t, doReq(t, h, "GET", "/api/health", "", ""), &out)
		return out
	}
	bare := New(testBackend(t), "2.0.0", testDomain(t), nil)
	if out := health(bare); out["sources"] != nil {
		t.Fatalf("sources reported with no roots: %v", out)
	}
	// A volume that holds no folder yet is scanned and answers no root,
	// which is the same answer as a server configured with none.
	empty, err := linked.NewRoots(nil, []string{t.TempDir()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	none := New(testBackendWithRoots(t, empty), "2.0.0", testDomain(t), nil)
	if out := health(none); out["sources"] != nil {
		t.Fatalf("sources reported for a volume holding no folder: %v", out)
	}
	h, _, _ := linkedTestAPI(t)
	if out := health(h); out["sources"] != true {
		t.Fatalf("health = %v", out)
	}
}

// userSourceRoots decodes rec into a FRESH struct so an omitted sourceRoots
// key reads as nil rather than leaking a value from an earlier response.
func userSourceRoots(t *testing.T, rec *httptest.ResponseRecorder) []string {
	t.Helper()
	var res struct {
		User struct {
			SourceRoots []string `json:"sourceRoots"`
		} `json:"user"`
	}
	unmarshal(t, rec, &res)
	return res.User.SourceRoots
}

func TestSourceRootsRoundTripOnUsers(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/users", testToken,
		`{"username":"bob","quotaBytes":1,"sourceRoots":["photo/2024","public-share"]}`)
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	roots := userSourceRoots(t, rec)
	if len(roots) != 2 || roots[0] != "photo/2024" {
		t.Fatalf("echo = %+v", roots)
	}
	rec = doReq(t, h, "PATCH", "/api/users/bob", testToken, `{"sourceRoots":[]}`)
	roots = userSourceRoots(t, rec)
	if rec.Code != 200 || len(roots) != 0 {
		t.Fatalf("clear: %d %+v", rec.Code, roots)
	}
	rec = doReq(t, h, "PATCH", "/api/users/bob", testToken, `{"sourceRoots":["../etc"]}`)
	if rec.Code != 400 {
		t.Fatalf("bad root accepted: %d", rec.Code)
	}
	rec = doReq(t, h, "PATCH", "/api/users/bob", testToken, `{"quotaBytes":5}`)
	roots = userSourceRoots(t, rec)
	if rec.Code != 200 || len(roots) != 0 {
		t.Fatalf("absent field changed the list: %+v", roots)
	}
}

func TestShareViewCarriesSourceAndSourceMissing(t *testing.T) {
	h, b, vol := linkedTestAPI(t)
	id := linkedShare(t, b, "photo/2024")
	var out struct {
		Source        string                  `json:"source"`
		SourceMissing bool                    `json:"sourceMissing"`
		Files         []struct{ Path string } `json:"files"`
	}
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+id, testToken, ""), &out)
	if out.Source != "photo/2024" || out.SourceMissing || len(out.Files) != 2 {
		t.Fatalf("%+v", out)
	}
	os.RemoveAll(filepath.Join(vol, "photo"))
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+id, testToken, ""), &out)
	if !out.SourceMissing {
		t.Fatalf("%+v", out)
	}
}

func TestSourcesListsRootsPerAccount(t *testing.T) {
	h, m := linkedTestAPIUsers(t)
	var out struct {
		Roots []struct{ Path, Name string } `json:"roots"`
	}
	unmarshal(t, doReq(t, h, "GET", "/api/sources", testToken, ""), &out)
	if len(out.Roots) != 2 || out.Roots[0].Path != "photo" || out.Roots[1].Path != "public-share" {
		t.Fatalf("admin roots = %+v", out.Roots)
	}
	bobRoots := []string{"photo/2024", "homes"}
	bob := seedUser(t, m, "bob")
	if _, err := m.UpdateUser("bob", metadb.Settings{SourceRoots: &bobRoots}); err != nil {
		t.Fatal(err)
	}
	unmarshal(t, doReq(t, h, "GET", "/api/sources", bob, ""), &out)
	if len(out.Roots) != 1 || out.Roots[0].Path != "photo/2024" || out.Roots[0].Name != "2024" {
		t.Fatalf("bob roots = %+v", out.Roots)
	}
	if rec := doReq(t, h, "GET", "/api/sources?all=1", bob, ""); rec.Code != 403 {
		t.Fatalf("all=1 for a user: %d", rec.Code)
	}
	eve := seedUser(t, m, "eve")
	rec := doReq(t, h, "GET", "/api/sources", eve, "")
	unmarshal(t, rec, &out)
	if rec.Code != 200 || len(out.Roots) != 0 {
		t.Fatalf("no allowlist: %d %+v", rec.Code, out.Roots)
	}
}

func TestBrowseListsOneLevelInsideAllowedRootsOnly(t *testing.T) {
	h, m := linkedTestAPIUsers(t)
	var out struct {
		Path  string                  `json:"path"`
		Dirs  []struct{ Name string } `json:"dirs"`
		Files []struct {
			Name     string `json:"name"`
			Size     int64  `json:"size"`
			Viewable bool   `json:"viewable"`
		} `json:"files"`
	}
	unmarshal(t, doReq(t, h, "GET", "/api/sources/browse?path=photo", testToken, ""), &out)
	if len(out.Dirs) != 1 || out.Dirs[0].Name != "2024" || len(out.Files) != 0 {
		t.Fatalf("photo: %+v", out)
	}
	unmarshal(t, doReq(t, h, "GET", "/api/sources/browse?path=photo/2024", testToken, ""), &out)
	if len(out.Files) != 2 || out.Files[0].Name != "a.jpg" || out.Files[0].Size != 4 || !out.Files[0].Viewable {
		t.Fatalf("2024: %+v", out)
	}
	for path, code := range map[string]int{
		// A hidden path is refused at the SOURCE, not merely left out of a
		// listing: browse must not open what no share may ever serve.
		"photo/../homes": 400, "homes": 403, "photo/2099": 404, "": 400,
		"photo/.git": 400, "photo/2024/@eaDir": 400,
	} {
		if rec := doReq(t, h, "GET", "/api/sources/browse?path="+path, testToken, ""); rec.Code != code {
			t.Errorf("%q: %d, want %d (%s)", path, rec.Code, code, rec.Body)
		}
	}
	bobRoots := []string{"photo/2024"}
	bob := seedUser(t, m, "bob")
	if _, err := m.UpdateUser("bob", metadb.Settings{SourceRoots: &bobRoots}); err != nil {
		t.Fatal(err)
	}
	if rec := doReq(t, h, "GET", "/api/sources/browse?path=photo", bob, ""); rec.Code != 403 {
		t.Fatalf("bob above his root: %d", rec.Code)
	}
	if rec := doReq(t, h, "GET", "/api/sources/browse?path=photo/2024", bob, ""); rec.Code != 200 {
		t.Fatalf("bob in his root: %d", rec.Code)
	}
}

func TestCreateLinkedShareValidatesAndTakesUploadsBesideItsSource(t *testing.T) {
	h, _, _ := linkedTestAPI(t)
	for body, code := range map[string]int{
		// An inbox's content is never published; a source is.
		`{"source":"photo/2024","receive":true,"name":"n"}`: 400,
		// An upload cannot take a linked entry's own name (a.jpg is served
		// by the source); a name the source does not serve is welcome.
		`{"source":"photo/2024","files":[{"path":"a.jpg","size":1}]}`: 400,
		`{"source":"../x"}`:        400,
		`{"source":"homes/alice"}`: 403,
		`{"source":"photo/2099"}`:  404,
		// A share pointed straight at a hidden folder would publish the
		// deleted files a NAS keeps in #recycle.
		`{"source":"photo/#recycle"}`:  400,
		`{"source":"photo/2024/.git"}`: 400,
	} {
		if rec := doReq(t, h, "POST", "/api/shares", testToken, body); rec.Code != code {
			t.Errorf("%s: %d, want %d (%s)", body, rec.Code, code, rec.Body)
		}
	}
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"source":"photo/2024","name":"trip"}`)
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		ID     string                  `json:"id"`
		Source string                  `json:"source"`
		Folder bool                    `json:"folder"`
		Files  []struct{ Slug string } `json:"files"`
	}
	unmarshal(t, rec, &out)
	if out.Source != "photo/2024" || !out.Folder || len(out.Files) != 2 {
		t.Fatalf("%+v", out)
	}
	// A linked entry cannot be deleted (its file is the server's own), and
	// an upload cannot take one of the source's own names; the source stays
	// flat when an upload lands beside it, so the entries never move.
	if rec := doReq(t, h, "DELETE", "/api/shares/"+out.ID+"/files/a.jpg", testToken, ""); rec.Code != 409 || !strings.Contains(rec.Body.String(), "share-linked") {
		t.Errorf("delete linked: %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "PUT", "/api/shares/"+out.ID+"/files/a.jpg", testToken, "x"); rec.Code != 400 {
		t.Errorf("upload onto a linked entry's name: %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "PUT", "/api/shares/"+out.ID+"/files/new.txt", testToken, "x"); rec.Code != 201 {
		t.Errorf("upload beside the source: %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "DELETE", "/api/shares/"+out.ID+"/files/a.jpg", testToken, ""); rec.Code != 409 {
		t.Errorf("linked entry stays put after an upload: %d %s", rec.Code, rec.Body)
	}
	rec = doReq(t, h, "PATCH", "/api/shares/"+out.ID, testToken, `{"name":"renamed","listing":true}`)
	if rec.Code != 200 {
		t.Fatalf("patch: %d %s", rec.Code, rec.Body)
	}
	rec = doReq(t, h, "POST", "/api/shares", testToken, `{"source":"photo/2024/a.jpg"}`)
	// A fresh struct: shareOut's folder field is omitempty, so a false value
	// leaves the key absent and reusing out would keep its stale true from
	// the folder share created above.
	var one struct {
		Source string                  `json:"source"`
		Folder bool                    `json:"folder"`
		Files  []struct{ Slug string } `json:"files"`
	}
	unmarshal(t, rec, &one)
	if rec.Code != 201 || one.Folder || len(one.Files) != 1 {
		t.Fatalf("one file: %d %+v", rec.Code, one)
	}
}

func TestCreateLinkedGalleryGatesOnPlayability(t *testing.T) {
	h, _, vol := linkedTestAPI(t)
	if rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"source":"photo/2024","media":true}`); rec.Code != 201 {
		t.Fatalf("gallery of jpgs: %d %s", rec.Code, rec.Body)
	}
	// A HEIC is bucketed as a photo by extension (mediaKind's name fallback)
	// but is not in GalleryPlayable's strict allowlist, so it is a TILED
	// file the gallery cannot show: exactly what galleryRefusal exists to
	// inbox. A plain document (e.g. notes.txt) would not do this: it is
	// never tiled, so it lands in the gallery's own unconstrained file list
	// instead of tripping the gate.
	os.WriteFile(filepath.Join(vol, "photo", "2024", "photo.heic"), []byte("heic"), 0o644)
	// Taken after photo.heic lands, so the only difference a refused create
	// could make is a second share appearing: the first share is linked to
	// the same folder and would otherwise pick up photo.heic in its own live
	// listing regardless of what this test does next.
	before := doReq(t, h, "GET", "/api/shares", testToken, "").Body.String()
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"source":"photo/2024","media":true}`)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "not-gallery-playable") {
		t.Fatalf("gallery with a non-playable file: %d %s", rec.Code, rec.Body)
	}
	if after := doReq(t, h, "GET", "/api/shares", testToken, "").Body.String(); after != before {
		t.Fatalf("a refused create left a share behind:\nbefore %s\nafter  %s", before, after)
	}
}

func TestLinkedShareCanBecomeAGalleryWhenItsFilesPlay(t *testing.T) {
	h, b, vol := linkedTestAPI(t)
	id := linkedShare(t, b, "photo/2024")
	if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"media":true}`); rec.Code != 200 {
		t.Fatalf("gallery: %d %s", rec.Code, rec.Body)
	}
	// A HEIC is bucketed as a photo by extension but is not in
	// GalleryPlayable's strict allowlist, exactly as in
	// TestCreateLinkedGalleryGatesOnPlayability: a plain document would not
	// trip the gate, since it is never tiled.
	os.WriteFile(filepath.Join(vol, "photo", "2024", "photo.heic"), []byte("heic"), 0o644)
	if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"media":false}`); rec.Code != 200 {
		t.Fatalf("leave: %d", rec.Code)
	}
	if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"media":true}`); rec.Code != 400 {
		t.Fatalf("a non-playable file in the folder must refuse the gallery: %d", rec.Code)
	}
}

// A picked file can be looked at before it is shared: the owner's client
// fetches its bytes through the same two boundaries browse applies, and the
// answer is an attachment so a client never saves a page as the file.
func TestSourceFileServesBytesInsideAllowedRootsOnly(t *testing.T) {
	h, m := linkedTestAPIUsers(t)
	rec := doReq(t, h, "GET", "/api/sources/file?path=photo/2024/a.jpg", testToken, "")
	if rec.Code != 200 || rec.Body.String() != "AAAA" {
		t.Fatalf("file: %d %q", rec.Code, rec.Body.String())
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment") || !strings.Contains(cd, "a.jpg") {
		t.Fatalf("disposition %q", cd)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "image/jpeg" {
		t.Fatalf("type %q", ct)
	}
	if rec.Header().Get("Cross-Origin-Resource-Policy") != "same-origin" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("headers %v", rec.Header())
	}
	for path, code := range map[string]int{
		// A folder has no bytes to serve; the listing route is for those.
		"photo/2024": 400, "photo": 400,
		"photo/../homes/x": 400, "homes/alice/a": 403, "photo/2024/none.jpg": 404, "": 400,
		"photo/.git/x": 400, "photo/2024/@eaDir/t.jpg": 400,
	} {
		if rec := doReq(t, h, "GET", "/api/sources/file?path="+path, testToken, ""); rec.Code != code {
			t.Errorf("%q: %d, want %d (%s)", path, rec.Code, code, rec.Body)
		}
	}
	bobRoots := []string{"photo/2024"}
	bob := seedUser(t, m, "bob")
	if _, err := m.UpdateUser("bob", metadb.Settings{SourceRoots: &bobRoots}); err != nil {
		t.Fatal(err)
	}
	if rec := doReq(t, h, "GET", "/api/sources/file?path=photo/2024/a.jpg", bob, ""); rec.Code != 200 {
		t.Fatalf("bob in his root: %d", rec.Code)
	}
	if rec := doReq(t, h, "GET", "/api/sources/file?path=photo/2024/../2024/a.jpg", bob, ""); rec.Code != 400 {
		t.Fatalf("bob with a dot segment: %d", rec.Code)
	}
	if rec := doReq(t, h, "GET", "/api/sources/file?path=photo/2024/a.jpg", "", ""); rec.Code != 401 {
		t.Fatalf("anonymous: %d", rec.Code)
	}
}

// Several picks make ONE linked share. Each source lists under its own
// name, a folder's files below it and a file as itself, so two sources can
// hold files of the same name without colliding; the names themselves must
// differ. Every byte still opens through the source root's os.Root.
func TestMultiSourceLinkedShareListsEachUnderItsName(t *testing.T) {
	h, _, _ := linkedTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"sources":["photo/2024","public-share/index.html"],"name":"mix"}`)
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		ID      string   `json:"id"`
		Source  string   `json:"source"`
		Sources []string `json:"sources"`
		Folder  bool     `json:"folder"`
		Files   []struct {
			Path string `json:"path"`
			Slug string `json:"slug"`
		} `json:"files"`
	}
	unmarshal(t, rec, &out)
	if out.Source != "photo/2024" || len(out.Sources) != 2 || out.Sources[1] != "public-share/index.html" || !out.Folder {
		t.Fatalf("%+v", out)
	}
	var paths []string
	slugs := map[string]string{}
	for _, f := range out.Files {
		paths = append(paths, f.Path)
		slugs[f.Path] = f.Slug
	}
	if strings.Join(paths, ",") != "2024/a.jpg,2024/b.jpg,index.html" {
		t.Fatalf("paths %v", paths)
	}
	for rel, want := range map[string]string{"2024/a.jpg": "AAAA", "index.html": "<h1>hi</h1>"} {
		rec := doReq(t, h, "GET", "/download/"+out.ID+"/"+slugs[rel], "", "")
		if rec.Code != 200 || rec.Body.String() != want {
			t.Fatalf("%s: %d %q", rel, rec.Code, rec.Body.String())
		}
	}
	// The zip carries every source's files under the same names.
	rec = doReq(t, h, "GET", "/zip/"+out.ID, "", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "2024/a.jpg") || !strings.Contains(rec.Body.String(), "index.html") {
		t.Fatalf("zip: %d", rec.Code)
	}
	// A later read walks the same way.
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+out.ID, testToken, ""), &out)
	if len(out.Files) != 3 || len(out.Sources) != 2 {
		t.Fatalf("re-read: %+v", out)
	}
	for body, code := range map[string]int{
		// Two sources of one name would list on top of each other.
		`{"sources":["photo/2024","photo/2024"]}`: 400,
		// One of several failing refuses the whole share, not the rest.
		`{"sources":["photo/2024","homes/alice"]}`:         403,
		`{"sources":["photo/2024","photo/2099"]}`:          404,
		`{"sources":["photo/2024","photo/.git"]}`:          400,
		`{"sources":["photo/2024"],"source":"photo/2024"}`: 400,
	} {
		if rec := doReq(t, h, "POST", "/api/shares", testToken, body); rec.Code != code {
			t.Errorf("%s: %d, want %d (%s)", body, rec.Code, code, rec.Body)
		}
	}
	// ONE source in the list is the single-source share: its files list
	// without a prefix, exactly as `source` makes them.
	rec = doReq(t, h, "POST", "/api/shares", testToken, `{"sources":["photo/2024"]}`)
	if rec.Code != 201 {
		t.Fatalf("single: %d %s", rec.Code, rec.Body)
	}
	unmarshal(t, rec, &out)
	if len(out.Files) != 2 || out.Files[0].Path != "a.jpg" || out.Source != "photo/2024" || len(out.Sources) != 1 {
		t.Fatalf("single: %+v", out)
	}
}

// A share holds uploads AND server sources at once. Stored files keep their
// rows, their bytes and their quota; linked entries come from the walk and
// cost nothing;
// each file says which it is. Linked entries list under their source's name
// whenever the share holds anything else, and a share that started as one
// bare folder re-keys its slugs when it first gains an upload, so no link
// ever dies.
func TestMixedShareHoldsUploadsAndSources(t *testing.T) {
	h, _, _ := linkedTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"sources":["photo/2024"],"files":[{"path":"notes.txt","size":5}],"name":"mix"}`)
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	type file struct {
		Path    string `json:"path"`
		Slug    string `json:"slug"`
		Linked  bool   `json:"linked"`
		Pending bool   `json:"pending"`
	}
	var out struct {
		ID    string `json:"id"`
		Files []file `json:"files"`
	}
	unmarshal(t, rec, &out)
	byPath := func(fs []file) map[string]file {
		m := map[string]file{}
		for _, f := range fs {
			m[f.Path] = f
		}
		return m
	}
	m := byPath(out.Files)
	// A single source stays flat when it holds an upload: its entries list
	// bare (a.jpg), not under the source's own folder name.
	if len(m) != 3 || !m["a.jpg"].Linked || m["notes.txt"].Linked || !m["notes.txt"].Pending {
		t.Fatalf("files %+v", out.Files)
	}
	// The upload lands beside the linked entries.
	if rec := doReq(t, h, "PUT", "/api/shares/"+out.ID+"/files/notes.txt", testToken, "hello"); rec.Code/100 != 2 {
		t.Fatalf("put: %d %s", rec.Code, rec.Body)
	}
	out.Files = nil // a decode into a slice with capacity keeps stale fields
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+out.ID, testToken, ""), &out)
	m = byPath(out.Files)
	if m["notes.txt"].Pending || m["notes.txt"].Linked || !m["b.jpg"].Linked {
		t.Fatalf("after put: %+v", out.Files)
	}
	for rel, want := range map[string]string{"notes.txt": "hello", "a.jpg": "AAAA"} {
		rec := doReq(t, h, "GET", "/download/"+out.ID+"/"+m[rel].Slug, "", "")
		if rec.Code != 200 || rec.Body.String() != want {
			t.Fatalf("%s: %d %q", rel, rec.Code, rec.Body.String())
		}
	}
	rec = doReq(t, h, "GET", "/zip/"+out.ID, "", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "a.jpg") || !strings.Contains(rec.Body.String(), "notes.txt") {
		t.Fatalf("zip: %d", rec.Code)
	}
	// An upload onto a linked entry's own name would list on top of it; a
	// name the source does not serve (2024/x.txt) is a new stored path.
	if rec := doReq(t, h, "PUT", "/api/shares/"+out.ID+"/files/a.jpg", testToken, "x"); rec.Code != 400 {
		t.Fatalf("upload onto a linked entry: %d %s", rec.Code, rec.Body)
	}
	// Only stored bytes count against the owner: the walk's bytes live on
	// the server's own disk. (The share's own totalSize still says what it
	// lists, stored and linked alike.)
	var usage struct {
		HyperdropBytes int64 `json:"hyperdropBytes"`
	}
	unmarshal(t, doReq(t, h, "GET", "/api/usage", testToken, ""), &usage)
	if usage.HyperdropBytes != 5 {
		t.Fatalf("stored bytes %d, want the 5 uploaded", usage.HyperdropBytes)
	}
	// A linked file cannot be deleted; a stored one can.
	if rec := doReq(t, h, "DELETE", "/api/shares/"+out.ID+"/files/a.jpg", testToken, ""); rec.Code != 409 {
		t.Fatalf("delete linked: %d", rec.Code)
	}
	if rec := doReq(t, h, "DELETE", "/api/shares/"+out.ID+"/files/notes.txt", testToken, ""); rec.Code != 200 {
		t.Fatalf("delete stored: %d %s", rec.Code, rec.Body)
	}
	// Sources change like any other field, validated exactly like create.
	if rec := doReq(t, h, "PATCH", "/api/shares/"+out.ID, testToken, `{"sources":["photo/2024","public-share/index.html"]}`); rec.Code != 200 {
		t.Fatalf("patch sources: %d %s", rec.Code, rec.Body)
	}
	out.Files = nil
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+out.ID, testToken, ""), &out)
	m = byPath(out.Files)
	if !m["index.html"].Linked || !m["2024/a.jpg"].Linked || len(m) != 3 {
		t.Fatalf("after patch: %+v", out.Files)
	}
	for body, code := range map[string]int{
		`{"sources":["photo/2024","photo/2024"]}`: 400,
		`{"sources":["homes/alice"]}`:             403,
	} {
		if rec := doReq(t, h, "PATCH", "/api/shares/"+out.ID, testToken, body); rec.Code != code {
			t.Errorf("patch %s: %d, want %d (%s)", body, rec.Code, code, rec.Body)
		}
	}
	rec = doReq(t, h, "POST", "/api/shares", testToken, `{"receive":true,"name":"r"}`)
	var recv struct {
		ID string `json:"id"`
	}
	unmarshal(t, rec, &recv)
	if rec := doReq(t, h, "PATCH", "/api/shares/"+recv.ID, testToken, `{"sources":["photo/2024"]}`); rec.Code != 400 {
		t.Fatalf("sources on an inbox: %d", rec.Code)
	}

	// A bare single-folder share STAYS flat when it first gains an upload:
	// the entries keep their bare names and their slugs, so no folder named
	// after the source appears and every link copied before still works.
	out.Files = nil
	rec = doReq(t, h, "POST", "/api/shares", testToken, `{"source":"photo/2024"}`)
	unmarshal(t, rec, &out)
	m = byPath(out.Files)
	bare := m["a.jpg"].Slug
	if bare == "" {
		t.Fatalf("bare listing: %+v", out.Files)
	}
	if rec := doReq(t, h, "PUT", "/api/shares/"+out.ID+"/files/readme.txt", testToken, "hi"); rec.Code/100 != 2 {
		t.Fatalf("put into a bare linked share: %d %s", rec.Code, rec.Body)
	}
	out.Files = nil
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+out.ID, testToken, ""), &out)
	m = byPath(out.Files)
	if m["a.jpg"].Slug != bare || m["2024/a.jpg"].Slug != "" {
		t.Fatalf("entries stay flat after the first upload: %+v", out.Files)
	}
	if rec := doReq(t, h, "GET", "/download/"+out.ID+"/"+bare, "", ""); rec.Code != 200 || rec.Body.String() != "AAAA" {
		t.Fatalf("old link after an upload: %d %q", rec.Code, rec.Body.String())
	}
}

// An upload lands inside a folder the source serves, single source or
// several, the way a drop onto that folder in the app means it to. Only an
// entry the source already serves is taken: a file of that name, the
// folder's own name, or anything beneath one of its files.
func TestUploadsLandInsideALinkedFolder(t *testing.T) {
	h, _, vol := linkedTestAPI(t)
	os.MkdirAll(filepath.Join(vol, "photo", "2024", "sub"), 0o755)
	os.WriteFile(filepath.Join(vol, "photo", "2024", "sub", "c.jpg"), []byte("CC"), 0o644)
	type file struct {
		Path   string `json:"path"`
		Slug   string `json:"slug"`
		Linked bool   `json:"linked"`
	}
	var out struct {
		ID    string `json:"id"`
		Files []file `json:"files"`
	}
	byPath := func(fs []file) map[string]file {
		m := map[string]file{}
		for _, f := range fs {
			m[f.Path] = f
		}
		return m
	}
	put := func(id, rel, body string) int {
		rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/"+rel, testToken, body)
		if rec.Code/100 != 2 {
			t.Logf("PUT %s: %d %s", rel, rec.Code, rec.Body)
		}
		return rec.Code
	}
	refused := func(id, rel string) {
		rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/"+rel, testToken, "x")
		if rec.Code != 400 || !strings.Contains(rec.Body.String(), "path-taken") {
			t.Errorf("PUT %s: %d %s, want 400 path-taken", rel, rec.Code, rec.Body)
		}
	}

	// One flat source: an upload inside its subfolder lists beside the
	// folder's own files and is served out of the share's own directory.
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"sources":["photo/2024"],"name":"one"}`)
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	unmarshal(t, rec, &out)
	one := out.ID
	if code := put(one, "sub/new.txt", "new"); code/100 != 2 {
		t.Fatalf("put into a linked subfolder: %d", code)
	}
	out.Files = nil
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+one, testToken, ""), &out)
	m := byPath(out.Files)
	if len(m) != 4 || m["sub/new.txt"].Linked || !m["sub/c.jpg"].Linked {
		t.Fatalf("files %+v", out.Files)
	}
	if rec := doReq(t, h, "GET", "/download/"+one+"/"+m["sub/new.txt"].Slug, "", ""); rec.Code != 200 || rec.Body.String() != "new" {
		t.Fatalf("download the upload: %d %q", rec.Code, rec.Body.String())
	}
	if rec := doReq(t, h, "GET", "/zip/"+one, "", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), "sub/new.txt") || !strings.Contains(rec.Body.String(), "sub/c.jpg") {
		t.Fatalf("zip: %d", rec.Code)
	}
	refused(one, "sub")             // the folder's own name
	refused(one, "sub/c.jpg")       // a file the source serves
	refused(one, "sub/c.jpg/x.txt") // beneath a file
	refused(one, "a.jpg")
	if code := put(one, "sub/deeper/also.txt", "also"); code/100 != 2 {
		t.Fatalf("put into a folder the source does not have: %d", code)
	}

	// The source gaining a file of the upload's name later does not make two
	// rows of it: the upload shadows the linked entry, and its bytes serve.
	os.WriteFile(filepath.Join(vol, "photo", "2024", "sub", "new.txt"), []byte("nas"), 0o644)
	out.Files = nil
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+one, testToken, ""), &out)
	seen := 0
	for _, f := range out.Files {
		if f.Path == "sub/new.txt" {
			seen++
			if f.Linked {
				t.Fatalf("linked row for a stored path: %+v", f)
			}
		}
	}
	if seen != 1 {
		t.Fatalf("sub/new.txt listed %d times", seen)
	}
	if rec := doReq(t, h, "GET", "/download/"+one+"/"+m["sub/new.txt"].Slug, "", ""); rec.Body.String() != "new" {
		t.Fatalf("served %q, want the upload", rec.Body.String())
	}

	// Several sources: the first segment picks the source, and an upload
	// inside a folder source lands under its name; a file source is taken
	// whole, and a name no source has is free at the top level.
	rec = doReq(t, h, "POST", "/api/shares", testToken, `{"sources":["photo/2024","public-share/index.html"],"name":"two"}`)
	if rec.Code != 201 {
		t.Fatalf("create several: %d %s", rec.Code, rec.Body)
	}
	unmarshal(t, rec, &out)
	two := out.ID
	if code := put(two, "2024/sub/two.txt", "new2"); code/100 != 2 {
		t.Fatalf("put under a folder source: %d", code)
	}
	if code := put(two, "loose.txt", "loose"); code/100 != 2 {
		t.Fatalf("put at the top level: %d", code)
	}
	out.Files = nil
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+two, testToken, ""), &out)
	m = byPath(out.Files)
	if m["2024/sub/two.txt"].Linked || !m["2024/sub/c.jpg"].Linked || m["loose.txt"].Slug == "" {
		t.Fatalf("files %+v", out.Files)
	}
	if rec := doReq(t, h, "GET", "/download/"+two+"/"+m["2024/sub/two.txt"].Slug, "", ""); rec.Code != 200 || rec.Body.String() != "new2" {
		t.Fatalf("download under a source: %d %q", rec.Code, rec.Body.String())
	}
	refused(two, "2024")
	refused(two, "2024/a.jpg")
	refused(two, "index.html")
	refused(two, "index.html/x.txt")

	// The create-time manifest is judged by the same rule.
	for body, code := range map[string]int{
		`{"sources":["photo/2024"],"files":[{"path":"sub/plan.txt","size":1}]}`: 201,
		`{"sources":["photo/2024"],"files":[{"path":"sub/c.jpg","size":1}]}`:    400,
		`{"sources":["photo/2024"],"files":[{"path":"sub","size":1}]}`:          400,
	} {
		if rec := doReq(t, h, "POST", "/api/shares", testToken, body); rec.Code != code {
			t.Errorf("%s: %d, want %d (%s)", body, rec.Code, code, rec.Body)
		}
	}
}

// A second source joining lists the first one's entries under its folder's
// base name, and the last extra source leaving lists them bare again. The
// SLUG has to follow the name, both ways: it is what every link already
// copied names, and a re-minted slug is a dead link.
func TestASourceJoiningAndLeavingKeepsEveryLinkedSlug(t *testing.T) {
	h, _, _ := linkedTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"source":"photo/2024","name":"trip"}`)
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var made struct {
		ID string `json:"id"`
	}
	unmarshal(t, rec, &made)
	bare := linkedEntry(t, h, made.ID, "a.jpg").Slug

	if rec := doReq(t, h, "PATCH", "/api/shares/"+made.ID, testToken,
		`{"sources":["photo/2024","public-share/index.html"]}`); rec.Code != 200 {
		t.Fatalf("join: %d %s", rec.Code, rec.Body)
	}
	if got := linkedEntry(t, h, made.ID, "2024/a.jpg").Slug; got != bare {
		t.Fatalf("prefixed slug %s, want the bare one %s", got, bare)
	}
	if rec := doReq(t, h, "GET", "/download/"+made.ID+"/"+bare, "", ""); rec.Code != 200 || rec.Body.String() != "AAAA" {
		t.Fatalf("the link copied before the join: %d %q", rec.Code, rec.Body.String())
	}

	if rec := doReq(t, h, "PATCH", "/api/shares/"+made.ID, testToken,
		`{"sources":["photo/2024"]}`); rec.Code != 200 {
		t.Fatalf("leave: %d %s", rec.Code, rec.Body)
	}
	if got := linkedEntry(t, h, made.ID, "a.jpg").Slug; got != bare {
		t.Fatalf("slug after the extra source left is %s, want %s", got, bare)
	}
	if rec := doReq(t, h, "GET", "/download/"+made.ID+"/"+bare, "", ""); rec.Code != 200 || rec.Body.String() != "AAAA" {
		t.Fatalf("the same link after the leave: %d %q", rec.Code, rec.Body.String())
	}
}

// The folder flag says how a listing page draws a share, so it follows what
// the share points at: a share of one file that is pointed at a folder reads
// as a folder afterwards.
func TestPointingAShareAtAFolderMakesItAFolderShare(t *testing.T) {
	h, _, _ := linkedTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"source":"public-share/index.html","name":"page"}`)
	var made struct {
		ID     string `json:"id"`
		Folder bool   `json:"folder"`
	}
	unmarshal(t, rec, &made)
	if rec.Code != 201 || made.Folder {
		t.Fatalf("a share of one file: %d %+v", rec.Code, made)
	}
	rec = doReq(t, h, "PATCH", "/api/shares/"+made.ID, testToken, `{"sources":["photo/2024"]}`)
	var edited struct {
		Folder bool `json:"folder"`
	}
	unmarshal(t, rec, &edited)
	if rec.Code != 200 || !edited.Folder {
		t.Fatalf("pointed at a folder: %d %+v", rec.Code, edited)
	}
	var reread struct {
		Folder bool `json:"folder"`
	}
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+made.ID, testToken, ""), &reread)
	if !reread.Folder {
		t.Fatalf("re-read: %+v", reread)
	}
}

// A source removed from a share takes its links with it: added back later,
// its entries serve under fresh slugs and a link copied before the removal
// stays dead. The source that stayed keeps its links through both edits.
func TestARemovedSourceDoesNotReviveItsLinksWhenAddedBack(t *testing.T) {
	h, _, vol := linkedTestAPI(t)
	if err := os.MkdirAll(filepath.Join(vol, "extra"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vol, "extra", "n.txt"), []byte("N"), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"sources":["photo/2024","public-share","extra"],"name":"three"}`)
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var made struct {
		ID string `json:"id"`
	}
	unmarshal(t, rec, &made)
	oldIndex := linkedEntry(t, h, made.ID, "public-share/index.html").Slug
	photo := linkedEntry(t, h, made.ID, "2024/a.jpg").Slug
	if rec := doReq(t, h, "PATCH", "/api/shares/"+made.ID, testToken, `{"sources":["photo/2024","extra"]}`); rec.Code != 200 {
		t.Fatalf("remove: %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "PATCH", "/api/shares/"+made.ID, testToken, `{"sources":["photo/2024","extra","public-share"]}`); rec.Code != 200 {
		t.Fatalf("add back: %d %s", rec.Code, rec.Body)
	}
	if got := linkedEntry(t, h, made.ID, "public-share/index.html").Slug; got == oldIndex {
		t.Fatalf("the re-added source's entry kept its old slug %s", got)
	}
	if rec := doReq(t, h, "GET", "/download/"+made.ID+"/"+oldIndex, "", ""); rec.Code != 404 {
		t.Fatalf("a link copied before the removal: %d, want 404", rec.Code)
	}
	if got := linkedEntry(t, h, made.ID, "2024/a.jpg").Slug; got != photo {
		t.Fatalf("the staying source's slug moved: %s, want %s", got, photo)
	}
}

// A folder in a browse answer is dated by the newest file inside it, not by
// its own mtime: a NAS indexer moves the latter every time it rewrites the
// folder's thumbnails, and a picker sorting by date would put a folder of
// September footage above one of today's.
func TestBrowseDatesAFolderByItsNewestFile(t *testing.T) {
	h, _, vol := linkedTestAPI(t)
	sept := func(day int) time.Time { return time.Date(2026, 9, day, 12, 0, 0, 0, time.UTC) }
	day := filepath.Join(vol, "photo", "2024")
	os.Chtimes(filepath.Join(day, "a.jpg"), sept(20), sept(20))
	os.Chtimes(filepath.Join(day, "b.jpg"), sept(19), sept(19))
	os.MkdirAll(filepath.Join(day, "@eaDir"), 0o755)
	os.Chtimes(day, sept(30), sept(30))
	var out struct {
		Dirs []struct {
			Name  string    `json:"name"`
			MTime time.Time `json:"mtime"`
		} `json:"dirs"`
	}
	unmarshal(t, doReq(t, h, "GET", "/api/sources/browse?path=photo", testToken, ""), &out)
	if len(out.Dirs) != 1 || !out.Dirs[0].MTime.Equal(sept(20)) {
		t.Fatalf("2024 is dated %+v, want the newest file inside, %v", out.Dirs, sept(20))
	}
}
