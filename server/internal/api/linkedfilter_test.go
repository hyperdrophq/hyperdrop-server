package api

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hyperdrop/server/internal/linked"
	"hyperdrop/server/internal/metadb"
)

type linkedView struct {
	ID    string `json:"id"`
	Files []struct {
		Path string `json:"path"`
		Slug string `json:"slug"`
	} `json:"files"`
	Linked map[string]struct {
		Fixed  bool `json:"fixed"`
		Hidden int  `json:"hidden"`
	} `json:"linked"`
}

// Removing one file of a shared folder hides it from the share and kills its
// link, touches nothing on disk, and can be undone by showing it again.
func TestHidingALinkedFileThroughPatch(t *testing.T) {
	h, _, vol := linkedTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"source":"photo/2024","name":"trip"}`)
	var made linkedView
	unmarshal(t, rec, &made)
	slugA := ""
	for _, f := range made.Files {
		if f.Path == "a.jpg" {
			slugA = f.Slug
		}
	}
	if slugA == "" {
		t.Fatalf("no a.jpg in %+v", made)
	}
	if rec := doReq(t, h, "GET", "/download/"+made.ID+"/"+slugA, "", ""); rec.Code != 200 {
		t.Fatalf("download before: %d", rec.Code)
	}

	rec = doReq(t, h, "PATCH", "/api/shares/"+made.ID, testToken,
		`{"linked":{"photo/2024":{"hide":["a.jpg"]}}}`)
	if rec.Code != 200 {
		t.Fatalf("patch: %d %s", rec.Code, rec.Body)
	}
	var after linkedView
	unmarshal(t, rec, &after)
	if len(after.Files) != 1 || after.Files[0].Path != "b.jpg" {
		t.Fatalf("files = %+v, want b.jpg alone", after.Files)
	}
	if after.Linked["photo/2024"].Hidden != 1 {
		t.Fatalf("linked = %+v", after.Linked)
	}
	if rec := doReq(t, h, "GET", "/download/"+made.ID+"/"+slugA, "", ""); rec.Code != 404 {
		t.Fatalf("download of a hidden file: %d, want 404", rec.Code)
	}
	if _, err := os.Stat(filepath.Join(vol, "photo/2024/a.jpg")); err != nil {
		t.Fatal("the file on disk was touched")
	}

	rec = doReq(t, h, "PATCH", "/api/shares/"+made.ID, testToken,
		`{"linked":{"photo/2024":{"show":["a.jpg"]}}}`)
	// A fresh struct: linked is omitempty, and decoding into `after` would
	// keep its stale map when the key is absent.
	var shown linkedView
	unmarshal(t, rec, &shown)
	if rec.Code != 200 || len(shown.Files) != 2 || len(shown.Linked) != 0 {
		t.Fatalf("show: %d %+v", rec.Code, shown)
	}
	if rec := doReq(t, h, "GET", "/download/"+made.ID+"/"+slugA, "", ""); rec.Code != 200 {
		t.Fatalf("download after show: %d, want the same link back", rec.Code)
	}
}

// A folder fixed at pick time does not grow with the folder, and the record
// says it is fixed.
func TestFixingALinkedFolderThroughPatch(t *testing.T) {
	h, _, vol := linkedTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"source":"photo/2024","name":"trip"}`)
	var made linkedView
	unmarshal(t, rec, &made)
	rec = doReq(t, h, "PATCH", "/api/shares/"+made.ID, testToken,
		`{"linked":{"photo/2024":{"fixed":true}}}`)
	if rec.Code != 200 {
		t.Fatalf("patch: %d %s", rec.Code, rec.Body)
	}
	os.WriteFile(filepath.Join(vol, "photo/2024/c.jpg"), []byte("c"), 0o644)
	var got linkedView
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+made.ID, testToken, ""), &got)
	if len(got.Files) != 2 || !got.Linked["photo/2024"].Fixed {
		t.Fatalf("got %+v, want two files and fixed", got)
	}
	rec = doReq(t, h, "PATCH", "/api/shares/"+made.ID, testToken,
		`{"linked":{"photo/2024":{"fixed":false}}}`)
	var live linkedView
	unmarshal(t, rec, &live)
	if rec.Code != 200 || len(live.Files) != 3 || len(live.Linked) != 0 {
		t.Fatalf("live again: %d %+v", rec.Code, live)
	}
}

func TestLinkedEditRefusals(t *testing.T) {
	h, _, _ := linkedTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"source":"photo/2024","name":"trip"}`)
	var made linkedView
	unmarshal(t, rec, &made)
	rec = doReq(t, h, "PATCH", "/api/shares/"+made.ID, testToken,
		`{"linked":{"photo/2099":{"hide":["x"]}}}`)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "not-a-source") {
		t.Fatalf("unknown source: %d %s", rec.Code, rec.Body)
	}
	for _, bad := range []string{"../a.jpg", "/a.jpg", "a//b", ".", ""} {
		rec = doReq(t, h, "PATCH", "/api/shares/"+made.ID, testToken,
			`{"linked":{"photo/2024":{"hide":["`+bad+`"]}}}`)
		if rec.Code != 400 || !strings.Contains(rec.Body.String(), "bad-source") {
			t.Fatalf("hide %q: %d %s", bad, rec.Code, rec.Body)
		}
	}
	rec = doReq(t, h, "POST", "/api/shares", testToken, `{"receive":true,"name":"in"}`)
	var inbox struct{ ID string }
	unmarshal(t, rec, &inbox)
	rec = doReq(t, h, "PATCH", "/api/shares/"+inbox.ID, testToken,
		`{"linked":{"photo/2024":{"hide":["x"]}}}`)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "source-exclusive") {
		t.Fatalf("inbox: %d %s", rec.Code, rec.Body)
	}
}

// Removing a file from a folder that is already FIXED takes it off what the
// share shows, the same way it does on a live one, and the source stays fixed.
func TestHidingOnAFixedSourceRemovesTheEntryAndKeepsItFixed(t *testing.T) {
	h, _, vol := linkedTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"source":"photo/2024","name":"trip"}`)
	var made linkedView
	unmarshal(t, rec, &made)
	rec = doReq(t, h, "PATCH", "/api/shares/"+made.ID, testToken,
		`{"linked":{"photo/2024":{"fixed":true,"hide":["a.jpg"]}}}`)
	var after linkedView
	unmarshal(t, rec, &after)
	if rec.Code != 200 {
		t.Fatalf("patch: %d %s", rec.Code, rec.Body)
	}
	if len(after.Files) != 1 || after.Files[0].Path != "b.jpg" {
		t.Fatalf("files = %+v, want b.jpg alone", after.Files)
	}
	if !after.Linked["photo/2024"].Fixed {
		t.Fatalf("linked = %+v, want fixed", after.Linked)
	}
	// Fixed still means fixed: a file arriving in the folder afterwards is
	// not in the list the share was fixed with.
	os.WriteFile(filepath.Join(vol, "photo/2024/c.jpg"), []byte("c"), 0o644)
	var got linkedView
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+made.ID, testToken, ""), &got)
	if len(got.Files) != 1 || got.Files[0].Path != "b.jpg" {
		t.Fatalf("files = %+v, want b.jpg alone", got.Files)
	}
}

// Each source of a share shows its own walk minus its OWN filter: one fixed
// and one live in the same share stay that way.
func TestTwoSourcesFilterIndependently(t *testing.T) {
	h, _, vol := linkedTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"sources":["photo/2024","public-share"],"name":"two"}`)
	var made linkedView
	unmarshal(t, rec, &made)
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	rec = doReq(t, h, "PATCH", "/api/shares/"+made.ID, testToken,
		`{"linked":{"public-share":{"fixed":true},"photo/2024":{"hide":["a.jpg"]}}}`)
	if rec.Code != 200 {
		t.Fatalf("patch: %d %s", rec.Code, rec.Body)
	}
	os.WriteFile(filepath.Join(vol, "public-share/late.html"), []byte("late"), 0o644)
	os.WriteFile(filepath.Join(vol, "photo/2024/c.jpg"), []byte("c"), 0o644)
	var got linkedView
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+made.ID, testToken, ""), &got)
	want := map[string]bool{"2024/b.jpg": true, "2024/c.jpg": true, "public-share/index.html": true}
	if len(got.Files) != len(want) {
		t.Fatalf("files = %+v, want %v", got.Files, want)
	}
	for _, f := range got.Files {
		if !want[f.Path] {
			t.Fatalf("files = %+v, want %v", got.Files, want)
		}
	}
	if !got.Linked["public-share"].Fixed || got.Linked["photo/2024"].Hidden != 1 {
		t.Fatalf("linked = %+v", got.Linked)
	}
}

// A source that leaves the share takes its gallery tiles with it: the rows
// in the sources transaction, the thumbs/<slug>.jpg sidecars after it. The
// staying source keeps its tile.
func TestARemovedSourceTakesItsTiles(t *testing.T) {
	h, b, _ := linkedTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"sources":["photo/2024","public-share"],"name":"two"}`)
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var made linkedView
	unmarshal(t, rec, &made)
	var got linkedView
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+made.ID, testToken, ""), &got)
	slugs := map[string]string{}
	for _, f := range got.Files {
		slugs[f.Path] = f.Slug
	}
	stay, gone := slugs["2024/b.jpg"], slugs["public-share/index.html"]
	if stay == "" || gone == "" {
		t.Fatalf("files = %+v", got.Files)
	}
	for _, slug := range []string{stay, gone} {
		if rec := doReq(t, h, "PUT", "/api/shares/"+made.ID+"/thumbs/"+slug, testToken,
			string(aJPEG(t, 8, 6))); rec.Code != 204 {
			t.Fatalf("thumb %s: %d %s", slug, rec.Code, rec.Body)
		}
	}
	if err := b.DB.SetGallery(made.ID, map[string]metadb.GalleryItem{
		stay: {Width: 8, Height: 6}, gone: {Width: 8, Height: 6}}); err != nil {
		t.Fatal(err)
	}
	if rec := doReq(t, h, "PATCH", "/api/shares/"+made.ID, testToken,
		`{"sources":["photo/2024"]}`); rec.Code != 200 {
		t.Fatalf("sources: %d %s", rec.Code, rec.Body)
	}
	tiles, err := b.FS.ThumbSlugs(made.ID)
	if err != nil {
		t.Fatal(err)
	}
	if tiles[gone] || !tiles[stay] {
		t.Fatalf("tiles = %v, want %s alone", tiles, stay)
	}
	items, err := b.DB.Gallery(made.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := items[gone]; ok {
		t.Fatalf("gallery rows = %v, the removed source's row stayed", items)
	}
}

// A source that leaves the share takes its filter with it, so the same folder
// added back later shows everything it holds.
func TestReplacingSourcesForgetsTheirFilters(t *testing.T) {
	h, _, _ := linkedTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"source":"photo/2024","name":"trip"}`)
	var made linkedView
	unmarshal(t, rec, &made)
	if rec := doReq(t, h, "PATCH", "/api/shares/"+made.ID, testToken,
		`{"linked":{"photo/2024":{"hide":["a.jpg"]}}}`); rec.Code != 200 {
		t.Fatalf("hide: %d %s", rec.Code, rec.Body)
	}
	for _, sources := range []string{`["public-share"]`, `["photo/2024"]`} {
		if rec := doReq(t, h, "PATCH", "/api/shares/"+made.ID, testToken,
			`{"sources":`+sources+`}`); rec.Code != 200 {
			t.Fatalf("sources %s: %d %s", sources, rec.Code, rec.Body)
		}
	}
	var got linkedView
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+made.ID, testToken, ""), &got)
	if len(got.Files) != 2 || len(got.Linked) != 0 {
		t.Fatalf("got %+v, want the folder live again", got)
	}
}

// A filter is refused rather than truncated, on both caps: a folder too big
// to record cannot be fixed, and a hide list past the cap is turned away. A
// truncated answer would claim to be the folder.
func TestALinkedFilterIsRefusedRatherThanTruncated(t *testing.T) {
	h, b, vol := linkedTestAPI(t)
	id := linkedShare(t, b, "photo/2024")
	hide := make([]string, metadb.MaxFilterPaths+1)
	for i := range hide {
		hide[i] = fmt.Sprintf("gone/%d.txt", i)
	}
	body, err := json.Marshal(map[string]any{"linked": map[string]any{
		"photo/2024": map[string]any{"hide": hide}}})
	if err != nil {
		t.Fatal(err)
	}
	rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, string(body))
	if rec.Code != 413 || errCode(t, rec.Body.String()) != "linked-filter-too-big" {
		t.Fatalf("hide past the cap: %d %s", rec.Code, rec.Body)
	}

	big := filepath.Join(vol, "photo", "big")
	if err := os.MkdirAll(big, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= linked.MaxWalk; i++ {
		if err := os.WriteFile(filepath.Join(big, fmt.Sprintf("f%d.txt", i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	huge := linkedShare(t, b, "photo/big")
	rec = doReq(t, h, "PATCH", "/api/shares/"+huge, testToken,
		`{"linked":{"photo/big":{"fixed":true}}}`)
	if rec.Code != 400 || errCode(t, rec.Body.String()) != "source-too-big-to-fix" {
		t.Fatalf("fixing a folder the walk cannot hold: %d %s", rec.Code, rec.Body)
	}
}

// A rejected combined add+fix must never leave the new source live, even
// when the rejection occurs inside the database transaction at the cap.
func TestCombinedSourceFilterFailurePublishesNothing(t *testing.T) {
	h, _, _ := linkedTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{}`)
	var made linkedView
	unmarshal(t, rec, &made)
	hidden := make([]string, metadb.MaxFilterPaths+1)
	for i := range hidden {
		hidden[i] = fmt.Sprintf("hidden-%d", i)
	}
	body, _ := json.Marshal(map[string]any{"sources": []string{"photo/2024"}, "linked": map[string]any{"photo/2024": map[string]any{"fixed": true, "hide": hidden}}})
	rec = doReq(t, h, "PATCH", "/api/shares/"+made.ID, testToken, string(body))
	if rec.Code/100 == 2 {
		t.Fatalf("oversized filter accepted: %s", rec.Body)
	}
	var after struct {
		Sources []string `json:"sources"`
		Files   []any    `json:"files"`
	}
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+made.ID, testToken, ""), &after)
	if len(after.Sources) != 0 || len(after.Files) != 0 {
		t.Fatalf("failed attachment published sources/files: %+v", after)
	}
}

func TestFixedAttachmentRefusesPendingManifestCollision(t *testing.T) {
	h, _, _ := linkedTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"files":[{"path":"a.jpg","size":1}]}`)
	var made linkedView
	unmarshal(t, rec, &made)
	rec = doReq(t, h, "PATCH", "/api/shares/"+made.ID, testToken, `{"sources":["photo/2024"],"linked":{"photo/2024":{"fixed":true}}}`)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "path-taken") {
		t.Fatalf("collision = %d %s", rec.Code, rec.Body)
	}
}

func TestEmptyCreateThenFixedAttachmentNeverShowsLateFiles(t *testing.T) {
	h, _, vol := linkedTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{}`)
	var made linkedView
	unmarshal(t, rec, &made)
	// A client killed before PATCH leaves no linked content, even if cleanup
	// never runs. The owner can discover the id through its change feed safely.
	var before struct {
		Sources []string `json:"sources"`
		Files   []any    `json:"files"`
	}
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+made.ID, testToken, ""), &before)
	if len(before.Sources) != 0 || len(before.Files) != 0 {
		t.Fatalf("empty creation publishes sources: %+v", before)
	}
	rec = doReq(t, h, "PATCH", "/api/shares/"+made.ID, testToken, `{"sources":["photo/2024"],"linked":{"photo/2024":{"fixed":true}}}`)
	if rec.Code != 200 {
		t.Fatalf("attach: %d %s", rec.Code, rec.Body)
	}
	if err := os.WriteFile(filepath.Join(vol, "photo", "2024", "late.jpg"), []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	var after linkedView
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+made.ID, testToken, ""), &after)
	if !after.Linked["photo/2024"].Fixed || len(after.Files) != 2 {
		t.Fatalf("fixed selection changed: %+v", after)
	}
	for _, f := range after.Files {
		if f.Path == "late.jpg" {
			t.Fatal("late file became public")
		}
	}
	rec = doReq(t, h, "GET", "/zip/"+made.ID, "", "")
	if strings.Contains(rec.Body.String(), "late.jpg") {
		t.Fatal("late file appeared in anonymous zip")
	}
}

// Fixing walks the folder, so a source the owner's allowlist no longer
// covers is never fixed: the walk would read a folder the account may not
// share, and its answer would say whether that folder exists and how big it
// is. Hiding on it writes a row and walks nothing, so it stays open.
func TestARevokedSourceIsNeverFixed(t *testing.T) {
	h, _, _ := linkedTestAPI(t)
	bob := grantedUser(t, h, "bob", "photo/2024")
	var made revokedView
	unmarshal(t, doReq(t, h, "POST", "/api/shares", bob, `{"source":"photo/2024","name":"trip"}`), &made)
	if rec := doReq(t, h, "PATCH", "/api/users/bob", testToken, `{"sourceRoots":[],"confirmRevoke":true}`); rec.Code != 200 {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body)
	}
	rec := doReq(t, h, "PATCH", "/api/shares/"+made.ID, bob, `{"linked":{"photo/2024":{"fixed":true}}}`)
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), `"code":"source-revoked"`) {
		t.Fatalf("fixing a revoked source: %d %s, want 409 source-revoked", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "PATCH", "/api/shares/"+made.ID, bob, `{"linked":{"photo/2024":{"hide":["a.jpg"]}}}`); rec.Code != 200 {
		t.Fatalf("hiding on a revoked source: %d %s", rec.Code, rec.Body)
	}
}

// A name the walk lists can be hidden, a backslash in it included (an
// ordinary byte in a Linux file name), while a path that is not clean and
// local is still refused.
func TestAListedNameWithABackslashCanBeHidden(t *testing.T) {
	h, _, vol := linkedTestAPI(t)
	if err := os.WriteFile(filepath.Join(vol, "photo/2024", `a\b.jpg`), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"source":"photo/2024","name":"trip"}`)
	var made linkedView
	unmarshal(t, rec, &made)
	listed := false
	for _, f := range made.Files {
		listed = listed || f.Path == `a\b.jpg`
	}
	if !listed {
		t.Fatalf("the walk does not list the name: %+v", made.Files)
	}
	rec = doReq(t, h, "PATCH", "/api/shares/"+made.ID, testToken,
		`{"linked":{"photo/2024":{"hide":["a\\b.jpg"]}}}`)
	if rec.Code != 200 {
		t.Fatalf("hide: %d %s", rec.Code, rec.Body)
	}
	var after linkedView
	unmarshal(t, rec, &after)
	for _, f := range after.Files {
		if f.Path == `a\b.jpg` {
			t.Fatalf("the hidden name is still listed: %+v", after.Files)
		}
	}
	for _, bad := range []string{"../a.jpg", "a/../b", "a/./b", "a/"} {
		rec = doReq(t, h, "PATCH", "/api/shares/"+made.ID, testToken,
			`{"linked":{"photo/2024":{"hide":["`+bad+`"]}}}`)
		if rec.Code != 400 || !strings.Contains(rec.Body.String(), "bad-source") {
			t.Fatalf("hide %q: %d %s", bad, rec.Code, rec.Body)
		}
	}
}

// A fixed linked source shows the names it was fixed to and the bytes of
// those names. A listed file swapped for a link to an unlisted one serves
// nothing under either name, on every route that reads the bytes.
func TestAFilteredLinkedShareNeverServesAHiddenEntryThroughALink(t *testing.T) {
	h, _, vol := linkedTestAPI(t)
	dir := filepath.Join(vol, "photo/2024")
	os.WriteFile(filepath.Join(dir, "private.txt"), []byte("TOPSECRET"), 0o644)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"source":"photo/2024","name":"trip"}`)
	var made linkedView
	unmarshal(t, rec, &made)
	if rec := doReq(t, h, "PATCH", "/api/shares/"+made.ID, testToken,
		`{"linked":{"photo/2024":{"fixed":true,"hide":["private.txt"]}}}`); rec.Code != 200 {
		t.Fatalf("patch: %d %s", rec.Code, rec.Body)
	}
	slug := linkedEntry(t, h, made.ID, "a.jpg").Slug
	if err := os.Remove(filepath.Join(dir, "a.jpg")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("private.txt", filepath.Join(dir, "a.jpg")); err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{
		"/view/" + made.ID + "/" + slug,
		"/download/" + made.ID + "/" + slug,
		"/zip/" + made.ID,
		"/site/" + made.ID + "/a.jpg",
	} {
		rec := doReq(t, h, "GET", p, "", "")
		if strings.Contains(rec.Body.String(), "TOPSECRET") {
			t.Errorf("%s answered the unlisted bytes", p)
		}
		if p != "/zip/"+made.ID && rec.Code == 200 {
			t.Errorf("%s: %d, want a refusal", p, rec.Code)
		}
	}

	rec = doReq(t, h, "GET", "/api/shares/"+made.ID, testToken, "")
	var raw map[string]any
	unmarshal(t, rec, &raw)
	for _, f := range raw["files"].([]any) {
		if _, ok := f.(map[string]any)["target"]; ok {
			t.Errorf("a listed file carries a target key: %v", f)
		}
	}
	if strings.Contains(strings.ToLower(rec.Body.String()), `"target"`) {
		t.Errorf("the listing JSON has a target key: %s", rec.Body)
	}
}
