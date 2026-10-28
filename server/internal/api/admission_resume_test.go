package api

import (
	"fmt"
	"io"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"hyperdrop/server/internal/metadb"
)

// Every chunk re-admits its upload's declared total against the quota and
// its own bytes against the disk, before a byte of it lands.
func TestEveryChunkRechecksAdmissionBeforeWriting(t *testing.T) {
	for _, tc := range []struct {
		name        string
		quota, free int64
		total       string
		want        int
		code        string
	}{
		{"quota growth", 2, 1000, "101", 507, "quota"},
		{"disk growth", 0, 0, "101", 507, "no-space"},
		{"same total with room only for remainder", 2, 11, "2", 201, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := testBackend(t)
			h := New(b, "test", testDomain(t), nil)
			token := seedUser(t, b.DB, "bob")
			if _, err := b.DB.UpdateUser("bob", metadb.Settings{QuotaBytes: &tc.quota}); err != nil {
				t.Fatal(err)
			}
			rec := doReq(t, h, "POST", "/api/shares", token, `{"name":"test"}`)
			var created struct{ ID string }
			unmarshal(t, rec, &created)
			put := func(start int, total, body string) *httptest.ResponseRecorder {
				req := httptest.NewRequest("PUT", "/api/shares/"+created.ID+"/files/large.bin", strings.NewReader(body))
				req.Header.Set("Authorization", "Bearer "+token)
				req.Header.Set("Upload-Session", "admission-test")
				req.Header.Set("Upload-Range", fmt.Sprintf("%d-%d", start, start+len(body)))
				req.Header.Set("Upload-Total", total)
				r := httptest.NewRecorder()
				h.ServeHTTP(r, req)
				return r
			}
			if first := put(0, "2", "x"); first.Code != 202 {
				t.Fatalf("first=%d %s", first.Code, first.Body)
			}
			b.FS.ReservePercent = 10
			b.FS.DiskSpace = func(string) (int64, int64, error) { return tc.free, 100, nil }
			total, _ := strconv.Atoi(tc.total)
			// A refusal must happen while this is still incomplete, not at commit.
			body := "x"
			if tc.want == 201 {
				body = strings.Repeat("x", total-1)
			}
			got := put(1, tc.total, body)
			if got.Code != tc.want || (tc.code != "" && !strings.Contains(got.Body.String(), `"code":"`+tc.code+`"`)) {
				t.Errorf("second chunk=%d %s; want %d %s", got.Code, got.Body, tc.want, tc.code)
			}
			if tc.want != 201 {
				if size, err := b.FS.PartSize(created.ID, "large.bin"); err != nil || size != 1 {
					t.Errorf("refused chunk changed partial: %d %v", size, err)
				}
			} else if file, err := b.DB.File(created.ID, "large.bin"); err != nil || file.Pending || file.Size != int64(total) {
				t.Errorf("commit=%+v %v", file, err)
			}
		})
	}
}

func TestQuotaLoweredBeforeResumePreservesOriginalFile(t *testing.T) {
	h, db, b := newMultiUserAPI(t)
	token := seedUser(t, db, "alice")
	id := createShareAs(t, h, token, `{"name":"overwrite"}`)
	path := "/api/shares/" + id + "/files/a.txt"
	if rec := doReq(t, h, "PUT", path, token, "abc"); rec.Code != 201 {
		t.Fatalf("seed=%d %s", rec.Code, rec.Body)
	}
	if rec := doReqResumeAs(t, h, path, token, "xxxxx", "0", "10"); rec.Code != 202 {
		t.Fatalf("partial=%d %s", rec.Code, rec.Body)
	}
	quota := int64(5)
	if _, err := db.UpdateUser("alice", metadb.Settings{QuotaBytes: &quota}); err != nil {
		t.Fatal(err)
	}
	rec := doReqResumeAs(t, h, path, token, "xxxxx", "5", "10")
	if rec.Code != 507 || errCode(t, rec.Body.String()) != "quota" {
		t.Fatalf("resume=%d %s", rec.Code, rec.Body)
	}
	f, _, err := b.FS.Open(id, "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil || string(data) != "abc" {
		t.Fatalf("original=%q %v", data, err)
	}
	file, err := db.File(id, "a.txt")
	if err != nil || file.Pending || file.Size != 3 {
		t.Fatalf("original row=%+v %v", file, err)
	}
	if size, err := b.FS.PartSize(id, "a.txt"); err != nil || size != 5 {
		t.Fatalf("partial=%d %v", size, err)
	}
}
