package api

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
)

// putTile declares an empty file named name and puts a tile of n bytes on it.
func putTile(t *testing.T, f *quotaFixture, name string, n int) int {
	t.Helper()
	if rec := putRange(t, f.h, f.token, f.id, name, "sess-"+name, 0, 0, 0, nil); rec.Code != 201 {
		t.Fatalf("file %s = %d %s", name, rec.Code, rec.Body)
	}
	file, err := f.b.DB.File(f.id, name)
	if err != nil {
		t.Fatal(err)
	}
	return doReqBare(t, f.h, "PUT", "/api/shares/"+f.id+"/thumbs/"+file.Slug, f.token, string(paddedJPEG(t, n))).Code
}

func usedBytes(t *testing.T, f *quotaFixture) int64 {
	t.Helper()
	var me struct {
		UsedBytes int64 `json:"usedBytes"`
	}
	rec := doReq(t, f.h, "GET", "/api/me", f.token, "")
	if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil {
		t.Fatalf("%v: %s", err, rec.Body)
	}
	return me.UsedBytes
}

// A tile lands on the disk like the file beside it, so it spends the account's
// quota, however small the file it was made for.
func TestATileCountsAgainstTheQuota(t *testing.T) {
	f := quotaAccount(t, 50<<10)
	if code := putTile(t, f, "a", 30<<10); code != 204 {
		t.Fatalf("first tile = %d", code)
	}
	if got := usedBytes(t, f); got != 30<<10 {
		t.Fatalf("usedBytes = %d, want the tile's %d", got, 30<<10)
	}
	if code := putTile(t, f, "b", 30<<10); code != 507 {
		t.Fatalf("a tile past the quota = %d, want 507", code)
	}
	rec := putRange(t, f.h, f.token, f.id, "c.bin", "sess-c", 0, 1, 30<<10, []byte{1})
	if rec.Code != 507 || errCode(t, rec.Body.String()) != "quota" {
		t.Fatalf("a file past the quota the tile spent = %d %s", rec.Code, rec.Body)
	}
}

// A replaced tile costs only what it adds, so re-making a gallery's tiles on a
// nearly full account still works.
func TestReplacingATileChargesTheDifference(t *testing.T) {
	f := quotaAccount(t, 50<<10)
	if code := putTile(t, f, "a", 40<<10); code != 204 {
		t.Fatalf("first tile = %d", code)
	}
	file, _ := f.b.DB.File(f.id, "a")
	path := "/api/shares/" + f.id + "/thumbs/" + file.Slug
	if rec := doReqBare(t, f.h, "PUT", path, f.token, string(paddedJPEG(t, 45<<10))); rec.Code != 204 {
		t.Fatalf("a larger tile that fits = %d %s", rec.Code, rec.Body)
	}
	if got := usedBytes(t, f); got != 45<<10 {
		t.Fatalf("usedBytes = %d, want %d", got, 45<<10)
	}
}

// A file's delete takes its tile's charge with it, and a share's delete all of
// them.
func TestRemovingAFileOrShareGivesATilesRoomBack(t *testing.T) {
	f := quotaAccount(t, 100<<10)
	if code := putTile(t, f, "a", 30<<10); code != 204 {
		t.Fatalf("tile = %d", code)
	}
	if code := putTile(t, f, "b", 30<<10); code != 204 {
		t.Fatalf("tile = %d", code)
	}
	if rec := doReq(t, f.h, "DELETE", "/api/shares/"+f.id+"/files/a", f.token, ""); rec.Code >= 300 {
		t.Fatalf("delete file = %d %s", rec.Code, rec.Body)
	}
	if got := usedBytes(t, f); got != 30<<10 {
		t.Fatalf("after the file's delete usedBytes = %d", got)
	}
	if rec := doReq(t, f.h, "DELETE", "/api/shares/"+f.id, f.token, ""); rec.Code >= 300 {
		t.Fatalf("delete share = %d %s", rec.Code, rec.Body)
	}
	if got := usedBytes(t, f); got != 0 {
		t.Fatalf("after the share's delete usedBytes = %d", got)
	}
}

// A batch's tiles are decoration: the ones past the quota are named and skipped,
// and the request still succeeds with the ones that fit.
func TestABatchSkipsTilesPastTheQuota(t *testing.T) {
	f := quotaAccount(t, 50<<10)
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	for i := range 3 {
		name := fmt.Sprintf("f%d", i)
		if rec := putRange(t, f.h, f.token, f.id, name, "sess-"+name, 0, 0, 0, nil); rec.Code != 201 {
			t.Fatalf("file = %d %s", rec.Code, rec.Body)
		}
		file, _ := f.b.DB.File(f.id, name)
		tile := paddedJPEG(t, 20<<10)
		tw.WriteHeader(&tar.Header{Name: file.Slug + ".jpg", Typeflag: tar.TypeReg, Mode: 0o600, Size: int64(len(tile))})
		tw.Write(tile)
	}
	tw.Close()
	rec := doReqBare(t, f.h, "POST", "/api/shares/"+f.id+"/thumbs", f.token, archive.String())
	var res sidecarBatchResult
	unmarshal(t, rec, &res)
	if rec.Code != 200 || res.Stored != 2 || len(res.Skipped) != 1 {
		t.Fatalf("= %d %+v, want 2 stored and 1 skipped", rec.Code, res)
	}
}

// A poster spends the quota the same way, and clearing it gives the room back.
func TestAPosterCountsAgainstTheQuota(t *testing.T) {
	f := quotaAccount(t, 50<<10)
	poster := string(paddedJPEG(t, 40<<10))
	path := "/api/shares/" + f.id + "/poster"
	if rec := doReqBare(t, f.h, "PUT", path, f.token, poster); rec.Code != 204 {
		t.Fatalf("poster = %d %s", rec.Code, rec.Body)
	}
	if got := usedBytes(t, f); got != 40<<10 {
		t.Fatalf("usedBytes = %d", got)
	}
	rec := doReq(t, f.h, "POST", "/api/shares", f.token, `{"name":"two"}`)
	var other struct{ ID string }
	unmarshal(t, rec, &other)
	rec = doReqBare(t, f.h, "PUT", "/api/shares/"+other.ID+"/poster", f.token, poster)
	if rec.Code != 507 || errCode(t, rec.Body.String()) != "quota" {
		t.Fatalf("a poster past the quota = %d %s", rec.Code, rec.Body)
	}
	if rec := doReqBare(t, f.h, "DELETE", path, f.token, ""); rec.Code != 204 {
		t.Fatalf("clear = %d %s", rec.Code, rec.Body)
	}
	if got := usedBytes(t, f); got != 0 {
		t.Fatalf("after the clear usedBytes = %d", got)
	}
}

// An account with no quota has tiles like any other bytes: nothing refuses them.
func TestAnAccountWithNoQuotaKeepsItsTiles(t *testing.T) {
	f := quotaAccount(t, 0)
	if code := putTile(t, f, "a", 30<<10); code != 204 {
		t.Fatalf("tile = %d", code)
	}
}
