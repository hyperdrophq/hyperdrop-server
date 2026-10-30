package api

import (
	"io"
	"net/http"
	"testing"

	"hyperdrop/server/internal/metadb"
)

// A read resolved a slug and then opens its file by path: when another file
// has taken that path since (the first deleted, a new one uploaded under the
// same name), the open answers nothing rather than the newcomer's bytes, on
// every route that opens a stored file. The slug a replace keeps still opens.
func TestOpenStoredRefusesAPathAnotherFileHasTaken(t *testing.T) {
	h, hd, _ := publishAPIParts(t)
	id := createShare(t, h, "reuse")
	first := uploadGetSlug(t, h, id, "a.txt", "the first file")
	uploadGetSlug(t, h, id, "keep.txt", "kept")
	if rec := doReq(t, h, "DELETE", "/api/shares/"+id+"/files/a.txt", testToken, ""); rec.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	second := uploadGetSlug(t, h, id, "a.txt", "another file under the same name")
	if second == first {
		t.Fatalf("the new file took the old slug %s", first)
	}

	if file, _, _, err := hd.openStored(id, "a.txt", first); err == nil {
		file.Close()
		t.Fatal("openStored opened another file's bytes for a stale slug")
	}
	v := shareView{Share: metadb.Share{ID: id}}
	stale := fileView{File: metadb.File{Path: "a.txt", Slug: first}}
	if rs, _, _, err := hd.openEntry(v, stale); err == nil {
		rs.Close()
		t.Fatal("openEntry opened another file's bytes for a stale slug")
	}

	file, _, row, err := hd.openStored(id, "a.txt", second)
	if err != nil {
		t.Fatalf("the current slug: %v", err)
	}
	defer file.Close()
	if b, _ := io.ReadAll(file); string(b) != "another file under the same name" || row.Slug != second {
		t.Fatalf("the current slug opened %q under %s", b, row.Slug)
	}
}
