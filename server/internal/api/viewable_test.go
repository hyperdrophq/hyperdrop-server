package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// uploadEcho PUTs body as rel into share id and returns the decoded echo.
func uploadEcho(t *testing.T, h http.Handler, id, rel, body string) map[string]any {
	t.Helper()
	rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/"+rel, testToken, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload %s: status %d: %s", rel, rec.Code, rec.Body)
	}
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	return out
}

// unviewable names a file by an extension no mime table maps, so its type is
// sniffed from bytes that read as application/octet-stream on every host.
// A real extension would not do: the type comes from the host's table first,
// and Debian's maps .pkg to an +xml type.
const unviewable = "app.unviewable"

func TestUploadEchoViewable(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "v")
	if out := uploadEcho(t, h, id, "a.txt", "text"); out["viewable"] != true {
		t.Errorf("a.txt viewable = %v, want true", out["viewable"])
	}
	if out := uploadEcho(t, h, id, unviewable, "\x00\x01\xff"); out["viewable"] != false {
		t.Errorf("%s viewable = %v, want false", unviewable, out["viewable"])
	}
}

func TestListSharesViewable(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "v")
	uploadEcho(t, h, id, "a.txt", "text")
	rec := doReq(t, h, "GET", "/api/shares", testToken, "")
	var out struct {
		Shares []struct {
			Files []struct {
				Path     string `json:"path"`
				Viewable *bool  `json:"viewable"`
			} `json:"files"`
		} `json:"shares"`
	}
	unmarshal(t, rec, &out)
	f := out.Shares[0].Files[0]
	if f.Viewable == nil || !*f.Viewable {
		t.Fatalf("list viewable = %v, want present and true", f.Viewable)
	}
}

func TestUploadStatusCarriesViewable(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "v")
	uploadEcho(t, h, id, "a.txt", "text")
	rec := doReq(t, h, "GET", "/api/shares/"+id+"/uploads/a.txt?session=test-session", testToken, "")
	var st map[string]any
	unmarshal(t, rec, &st)
	if st["complete"] != true || st["viewable"] != true {
		t.Errorf("upload status = %v, want complete+viewable", st)
	}
}

func TestViewRouteAttachmentForNonViewable(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "v")
	txt := uploadEcho(t, h, id, "a.txt", "text")
	bin := uploadEcho(t, h, id, unviewable, "\x00\x01\xff")

	get := func(slug string) string {
		rec := doReq(t, h, "GET", "/view/"+id+"/"+slug, "", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /view: %d", rec.Code)
		}
		return rec.Header().Get("Content-Disposition")
	}
	if d := get(txt["slug"].(string)); !strings.HasPrefix(d, "inline") {
		t.Errorf("viewable disposition = %q, want inline", d)
	}
	if d := get(bin["slug"].(string)); !strings.HasPrefix(d, "attachment") {
		t.Errorf("non-viewable disposition = %q, want attachment", d)
	}
}

// A name that maps to a JSON or XML type over binary content is neither
// viewable nor served inline as that type, stored or linked; the same name
// over text keeps its type.
func TestABinaryFileUnderAStructuredTextNameIsNotViewable(t *testing.T) {
	binary := "{\x00\x01\x02\xff}"
	h := newTestAPI(t)
	id := createShare(t, h, "mixed")
	if echo := uploadEcho(t, h, id, "blob.json", binary); echo["viewable"] != false {
		t.Errorf("binary .json upload viewable = %v, want false", echo["viewable"])
	}
	if echo := uploadEcho(t, h, id, "data.json", `{"a":1}`); echo["viewable"] != true {
		t.Errorf("JSON .json upload viewable = %v, want true", echo["viewable"])
	}

	lh, b, vol := linkedTestAPI(t)
	if err := os.WriteFile(filepath.Join(vol, "photo", "2024", "blob.json"), []byte(binary), 0o644); err != nil {
		t.Fatal(err)
	}
	lid := linkedShare(t, b, "photo/2024")
	e := linkedEntry(t, lh, lid, "blob.json")
	rec := doReq(t, lh, "GET", "/view/"+lid+"/"+e.Slug, "", "")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/octet-stream" ||
		!strings.HasPrefix(rec.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("linked binary .json /view = %d %q %q, want an octet-stream attachment", rec.Code,
			rec.Header().Get("Content-Type"), rec.Header().Get("Content-Disposition"))
	}
}
