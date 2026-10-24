package api

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func createTextShare(t *testing.T, h http.Handler) string {
	t.Helper()
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"Note","text":true}`)
	if rec.Code != 201 {
		t.Fatalf("create text share = %d %s", rec.Code, rec.Body)
	}
	var out struct {
		ID   string `json:"id"`
		Text bool   `json:"text"`
	}
	unmarshal(t, rec, &out)
	if !out.Text {
		t.Fatalf("create response lacks text:true: %s", rec.Body)
	}
	return out.ID
}

func TestATextShareIsCreatedAloneOrNotAtAll(t *testing.T) {
	// linkedTestAPI, not newTestAPI: the source case needs a folder that
	// actually resolves, so its refusal exercises the text+source rule
	// rather than a 404 for a source that was never there.
	h, _, _ := linkedTestAPI(t)
	createTextShare(t, h)
	for name, body := range map[string]string{
		"receive": `{"name":"n","text":true,"receive":true}`,
		"media":   `{"name":"n","text":true,"media":true}`,
		"listing": `{"name":"n","text":true,"listing":true}`,
		"entry":   `{"name":"n","text":true,"entry":"index.html"}`,
		"source":  `{"name":"n","text":true,"source":"photo"}`,
		"files":   `{"name":"n","text":true,"files":[{"path":"a.txt","size":1},{"path":"b.txt","size":1}]}`,
	} {
		if rec := doReq(t, h, "POST", "/api/shares", testToken, body); rec.Code != 400 {
			t.Errorf("%s: create = %d %s, want 400", name, rec.Code, rec.Body)
		}
	}
	// One declared file is the ordinary way to create a text share with its
	// content already named.
	if rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"name":"n","text":true,"files":[{"path":"a.txt","size":1}]}`); rec.Code != 201 {
		t.Fatalf("one file = %d %s, want 201", rec.Code, rec.Body)
	}
	// An ordinary share reports no text field at all.
	id := createShare(t, h, "plain")
	var row map[string]any
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+id, testToken, ""), &row)
	if _, ok := row["text"]; ok {
		t.Fatalf("an ordinary share carries text: %v", row)
	}
}

func TestATextShareHoldsOneFileAndKeepsWhatItOpensAs(t *testing.T) {
	h := newTestAPI(t)
	id := createTextShare(t, h)
	if rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/note.txt", testToken, "hello"); rec.Code != 201 {
		t.Fatalf("first file = %d %s", rec.Code, rec.Body)
	}
	// A second path is refused; the same path is a re-upload; replaceAll under
	// a new name is the one content change a text share takes.
	rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/other.txt", testToken, "x")
	if rec.Code != 409 || errCode(t, rec.Body.String()) != "text-share" {
		t.Fatalf("second path = %d %s, want 409 text-share", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/note.txt", testToken, "hello again"); rec.Code != 201 {
		t.Fatalf("re-upload = %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/renamed.txt?replaceAll=1", testToken, "new"); rec.Code != 201 {
		t.Fatalf("replaceAll = %d %s", rec.Code, rec.Body)
	}
	var row struct {
		Files []struct{ Path string } `json:"files"`
	}
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+id, testToken, ""), &row)
	if len(row.Files) != 1 || row.Files[0].Path != "renamed.txt" {
		t.Fatalf("after replaceAll: %+v", row.Files)
	}
	// The file cannot be removed.
	rec = doReq(t, h, "DELETE", "/api/shares/"+id+"/files/renamed.txt", testToken, "")
	if rec.Code != 409 || errCode(t, rec.Body.String()) != "text-share" {
		t.Fatalf("delete = %d %s, want 409 text-share", rec.Code, rec.Body)
	}
	// What the link opens is settled; name, password and expiry are not.
	for name, body := range map[string]string{
		"listing": `{"listing":true}`,
		"media":   `{"media":true}`,
		"entry":   `{"entry":"renamed.txt"}`,
		"sources": `{"sources":["docs"]}`,
		"linked":  `{"linked":{"docs":{"fixed":true}}}`,
	} {
		rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, body)
		if rec.Code != 409 || errCode(t, rec.Body.String()) != "text-share" {
			t.Errorf("%s: patch = %d %s, want 409 text-share", name, rec.Code, rec.Body)
		}
	}
	for name, body := range map[string]string{
		"name":     `{"name":"Renamed"}`,
		"password": `{"password":"pw"}`,
		"expiry":   `{"expiresInSeconds":3600}`,
	} {
		if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, body); rec.Code != 200 {
			t.Errorf("%s: patch = %d %s, want 200", name, rec.Code, rec.Body)
		}
	}
}

// A ?replaces= naming a path the share does not hold names nothing to
// replace, so it must not exempt the upload from the one-file rule: without
// this check the upload would commit as a second file and the ReplaceEntry
// that follows would fail to place it, orphaning a file no delete can
// remove because a text share's delete route is itself refused.
func TestATextShareRefusesAReplacesOfAPathItDoesNotHold(t *testing.T) {
	h := newTestAPI(t)
	id := createTextShare(t, h)
	if rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/note.txt", testToken, "hello"); rec.Code != 201 {
		t.Fatalf("first file = %d %s", rec.Code, rec.Body)
	}
	rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/other.txt?replaces=nope.txt", testToken, "x")
	if rec.Code != 409 || errCode(t, rec.Body.String()) != "text-share" {
		t.Fatalf("bogus replaces = %d %s, want 409 text-share", rec.Code, rec.Body)
	}
	var row struct {
		Files []struct{ Path string } `json:"files"`
	}
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+id, testToken, ""), &row)
	if len(row.Files) != 1 || row.Files[0].Path != "note.txt" {
		t.Fatalf("after bogus replaces: %+v, want only note.txt", row.Files)
	}
}

// ?replaces= naming the file the share actually holds is the one content
// change a text share takes, even under a brand new name.
func TestATextShareAcceptsAReplacesOfItsOwnFile(t *testing.T) {
	h := newTestAPI(t)
	id := createTextShare(t, h)
	if rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/note.txt", testToken, "hello"); rec.Code != 201 {
		t.Fatalf("first file = %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/renamed.txt?replaces=note.txt", testToken, "new"); rec.Code != 201 {
		t.Fatalf("replaces = %d %s", rec.Code, rec.Body)
	}
	var row struct {
		Files []struct{ Path string } `json:"files"`
	}
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+id, testToken, ""), &row)
	if len(row.Files) != 1 || row.Files[0].Path != "renamed.txt" {
		t.Fatalf("after replaces: %+v, want only renamed.txt", row.Files)
	}
}

func TestABatchCannotWidenATextShare(t *testing.T) {
	h := newTestAPI(t)
	id := createTextShare(t, h)
	if rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/note.txt", testToken, "hello"); rec.Code != 201 {
		t.Fatalf("first file = %d %s", rec.Code, rec.Body)
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "b.txt", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	tw.Write([]byte("b"))
	tw.Close()
	req := httptest.NewRequest("POST", "/api/shares/"+id+"/batch", &buf)
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Content-Type", "application/x-tar")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out struct {
		Code      string `json:"code"`
		Committed int    `json:"committed"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if rec.Code != 409 || out.Code != "text-share" || out.Committed != 0 {
		t.Fatalf("batch = %d %s", rec.Code, rec.Body)
	}
}

// A tar of two distinct paths against a text share that holds NO file yet
// must refuse the second entry exactly as it would against one that already
// holds its first file: the view a batch starts from is a snapshot taken
// once, before the loop, so the rule has to see what THIS batch already
// committed, not only what was on disk when the request began. The first
// entry stays committed: a batch is not atomic, and every other refusal in
// this handler keeps the files that landed before the one that didn't.
func TestABatchCannotAddTwoFilesToAnEmptyTextShare(t *testing.T) {
	h := newTestAPI(t)
	id := createTextShare(t, h)
	body := tarOf(t, map[string]string{"a.txt": "a", "b.txt": "b"}, []string{"a.txt", "b.txt"})
	req := httptest.NewRequest("POST", "/api/shares/"+id+"/batch", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Content-Type", "application/x-tar")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out struct {
		Code      string `json:"code"`
		Committed int    `json:"committed"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if rec.Code != 409 || out.Code != "text-share" || out.Committed != 1 {
		t.Fatalf("batch = %d %s, want 409 text-share committed=1", rec.Code, rec.Body)
	}
	var row struct {
		Files []struct{ Path string } `json:"files"`
	}
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+id, testToken, ""), &row)
	if len(row.Files) != 1 || row.Files[0].Path != "a.txt" {
		t.Fatalf("after refusal: %+v, want only a.txt", row.Files)
	}
}

// A text share's one allowed content change is a replace: a folder record and
// a rename are both something else.
func TestATextShareRefusesAFolder(t *testing.T) {
	h := newTestAPI(t)
	id := createTextShare(t, h)
	rec := doReq(t, h, "POST", "/api/shares/"+id+"/folders", testToken, `{"path":"sub"}`)
	if rec.Code != 409 || errCode(t, rec.Body.String()) != "text-share" {
		t.Fatalf("mkdir = %d %s, want 409 text-share", rec.Code, rec.Body)
	}
}

func TestATextShareRefusesAMove(t *testing.T) {
	h := newTestAPI(t)
	id := createTextShare(t, h)
	if rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/note.txt", testToken, "hello"); rec.Code != 201 {
		t.Fatalf("first file = %d %s", rec.Code, rec.Body)
	}
	rec := doReq(t, h, "POST", "/api/shares/"+id+"/move", testToken, `{"from":"note.txt","to":"renamed.txt"}`)
	if rec.Code != 409 || errCode(t, rec.Body.String()) != "text-share" {
		t.Fatalf("move = %d %s, want 409 text-share", rec.Code, rec.Body)
	}
}
