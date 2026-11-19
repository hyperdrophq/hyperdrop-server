package api

import (
	"math"
	"net/http"
	"strconv"
	"testing"

	"hyperdrop/server/internal/metadb"
)

func quotaAccount(t *testing.T, quota int64) *quotaFixture {
	t.Helper()
	b := testBackend(t)
	h := New(b, "test", testDomain(t), nil)
	token := seedUser(t, b.DB, "bob")
	if _, err := b.DB.UpdateUser("bob", metadb.Settings{QuotaBytes: &quota}); err != nil {
		t.Fatal(err)
	}
	rec := doReq(t, h, "POST", "/api/shares", token, `{"name":"q"}`)
	var created struct{ ID string }
	unmarshal(t, rec, &created)
	return &quotaFixture{t: t, b: b, h: h, token: token, id: created.ID}
}

type quotaFixture struct {
	t     *testing.T
	b     Backend
	h     http.Handler
	token string
	id    string
}

// Parts that never finish still occupy the disk, so each one is charged whole
// from its first chunk: an account cannot hold more than its quota by leaving
// every upload one byte short.
func TestEveryStagedPartCountsAgainstTheQuota(t *testing.T) {
	f := quotaAccount(t, 1000)
	if rec := putRange(t, f.h, f.token, f.id, "a.bin", "sess-a", 0, 1, 600, []byte{1}); rec.Code != 202 {
		t.Fatalf("first part = %d %s", rec.Code, rec.Body)
	}
	if rec := putRange(t, f.h, f.token, f.id, "a.bin", "sess-a", 1, 2, 600, []byte{1}); rec.Code != 202 {
		t.Fatalf("the part's own next chunk = %d %s, its charge counted twice", rec.Code, rec.Body)
	}
	rec := putRange(t, f.h, f.token, f.id, "b.bin", "sess-b", 0, 1, 600, []byte{1})
	if rec.Code != 507 || errCode(t, rec.Body.String()) != "quota" {
		t.Fatalf("second part = %d %s, want 507 quota", rec.Code, rec.Body)
	}
}

// A re-upload over a committed file has no pending row, and its part is on the
// disk beside the file until it commits.
func TestAReuploadsPartCountsAgainstTheQuota(t *testing.T) {
	f := quotaAccount(t, 1000)
	for i := range 2 {
		uploadFile(t, f.h, f.token, f.id, "small"+strconv.Itoa(i), "x")
	}
	if rec := putRange(t, f.h, f.token, f.id, "small0", "sess-0", 0, 1, 600, []byte{1}); rec.Code != 202 {
		t.Fatalf("first re-upload = %d %s", rec.Code, rec.Body)
	}
	rec := putRange(t, f.h, f.token, f.id, "small1", "sess-1", 0, 1, 600, []byte{1})
	if rec.Code != 507 || errCode(t, rec.Body.String()) != "quota" {
		t.Fatalf("second re-upload = %d %s, want 507 quota", rec.Code, rec.Body)
	}
}

// A declared total near the top of int64 must not wrap the sum below the quota.
func TestAHugeUploadTotalCannotWrapTheQuota(t *testing.T) {
	f := quotaAccount(t, 10)
	uploadFile(t, f.h, f.token, f.id, "one", "x")
	rec := putRange(t, f.h, f.token, f.id, "big.bin", "sess-big", 0, 1, math.MaxInt64, []byte{1})
	if rec.Code != 507 || errCode(t, rec.Body.String()) != "quota" {
		t.Fatalf("= %d %s, want 507 quota", rec.Code, rec.Body)
	}
}

// A committed part is charged as the file it became, and only as that.
func TestACommitReleasesItsPartsCharge(t *testing.T) {
	f := quotaAccount(t, 1000)
	data := rangedBytes(600)
	if rec := putRange(t, f.h, f.token, f.id, "a.bin", "sess-a", 0, 300, 600, data[:300]); rec.Code != 202 {
		t.Fatalf("first chunk = %d %s", rec.Code, rec.Body)
	}
	if rec := putRange(t, f.h, f.token, f.id, "a.bin", "sess-a", 300, 600, 600, data[300:]); rec.Code != 201 {
		t.Fatalf("last chunk = %d %s", rec.Code, rec.Body)
	}
	if got := f.b.FS.StagedBytes("bob"); got != 0 {
		t.Fatalf("%d bytes still charged after the commit", got)
	}
	if rec := putRange(t, f.h, f.token, f.id, "b.bin", "sess-b", 0, 1, 400, []byte{1}); rec.Code != 202 {
		t.Fatalf("a part that fits beside the file = %d %s", rec.Code, rec.Body)
	}
}

// A deleted share takes its parts' charges with it.
func TestDeletingAShareReleasesItsPartsCharge(t *testing.T) {
	f := quotaAccount(t, 1000)
	if rec := putRange(t, f.h, f.token, f.id, "a.bin", "sess-a", 0, 1, 600, []byte{1}); rec.Code != 202 {
		t.Fatalf("part = %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, f.h, "DELETE", "/api/shares/"+f.id, f.token, ""); rec.Code >= 300 {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body)
	}
	if got := f.b.FS.StagedBytes("bob"); got != 0 {
		t.Fatalf("%d bytes still charged after the delete", got)
	}
}

// An anonymous sender's stalled upload reserves nothing of the owner's quota:
// it runs through no ranged part, so it never reaches the charge.
func TestAnInboxUploadIsNotChargedAsAPart(t *testing.T) {
	f := quotaAccount(t, 1000)
	rec := doReq(t, f.h, "POST", "/api/shares", f.token, `{"name":"in","receive":true}`)
	var created struct{ ID string }
	unmarshal(t, rec, &created)
	if rec := doReqBare(t, f.h, "PUT", "/receive/"+created.ID+"/files/a.txt", "", "hello"); rec.Code != 201 {
		t.Fatalf("inbox upload = %d %s", rec.Code, rec.Body)
	}
	if got := f.b.FS.StagedBytes("bob"); got != 0 {
		t.Fatalf("%d bytes charged for an inbox upload", got)
	}
}
