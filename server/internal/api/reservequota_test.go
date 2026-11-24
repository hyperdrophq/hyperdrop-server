package api

import (
	"fmt"
	"strings"
	"testing"
)

func reservingAccount(t *testing.T, quota int64) (*quotaFixture, func(int64) string) {
	t.Helper()
	f := quotaAccount(t, quota)
	f.b.FS.DiskSpace = func(string) (int64, int64, error) { return 100 << 30, 200 << 30, nil }
	f.b.FS.ReservePercent = 0
	return f, func(reserve int64) string {
		rec := doReq(t, f.h, "POST", "/api/shares", f.token, fmt.Sprintf(`{"name":"r","reserveBytes":%d}`, reserve))
		if rec.Code == 201 {
			var created struct{ ID string }
			unmarshal(t, rec, &created)
			return created.ID
		}
		if rec.Code != 507 || errCode(t, rec.Body.String()) != "quota" {
			t.Fatalf("= %d %s, want 201 or 507 quota", rec.Code, rec.Body)
		}
		return ""
	}
}

// A reservation promises other uploads' room away, so an account's reservations
// together stay inside its quota: otherwise it could have every other account's
// upload refused for room it never fills.
func TestReservationsTogetherStayInsideTheQuota(t *testing.T) {
	f, reserve := reservingAccount(t, 1000)
	first := reserve(1000)
	if first == "" {
		t.Fatal("a reservation of the whole quota was refused")
	}
	if id := reserve(1); id != "" {
		t.Fatal("a second reservation passed the quota")
	}
	if rec := doReq(t, f.h, "DELETE", "/api/shares/"+first, f.token, ""); rec.Code >= 300 {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body)
	}
	if id := reserve(1000); id == "" {
		t.Fatal("deleting the share did not give its reservation back")
	}
}

// The upload a reservation was made for draws on it rather than being charged
// beside it, down to its last byte of the quota.
func TestAnUploadFitsItsOwnReservation(t *testing.T) {
	f, reserve := reservingAccount(t, 1000)
	id := reserve(1000)
	data := rangedBytes(1000)
	if rec := putRange(t, f.h, f.token, id, "a.bin", "sess-a", 0, 500, 1000, data[:500]); rec.Code != 202 {
		t.Fatalf("first chunk = %d %s", rec.Code, rec.Body)
	}
	if rec := putRange(t, f.h, f.token, id, "a.bin", "sess-a", 500, 1000, 1000, data[500:]); rec.Code != 201 {
		t.Fatalf("last chunk = %d %s", rec.Code, rec.Body)
	}
}

// Another share's reservation counts against an upload elsewhere, and its parts
// are not charged a second time on top of it.
func TestAReservationAndItsPartsCountOnce(t *testing.T) {
	f, reserve := reservingAccount(t, 1000)
	first := reserve(600)
	if rec := putRange(t, f.h, f.token, first, "a.bin", "sess-a", 0, 1, 600, []byte{1}); rec.Code != 202 {
		t.Fatalf("part = %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, f.h, "POST", "/api/shares", f.token, `{"name":"other"}`); rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	var created struct{ ID string }
	unmarshal(t, doReq(t, f.h, "POST", "/api/shares", f.token, `{"name":"other2"}`), &created)
	if rec := putRange(t, f.h, f.token, created.ID, "b.bin", "sess-b", 0, 1, 400, []byte{1}); rec.Code != 202 {
		t.Fatalf("what is left of the quota = %d %s", rec.Code, rec.Body)
	}
	rec := putRange(t, f.h, f.token, created.ID, "c.bin", "sess-c", 0, 1, 1, []byte{1})
	if rec.Code != 507 {
		t.Fatalf("past the quota = %d %s", rec.Code, rec.Body)
	}
}

// A poster is a write to the disk like a tile, and stops at the same reserve.
func TestAPosterIsAdmittedAgainstTheDisk(t *testing.T) {
	h, b := newTestAPIBackend(t)
	id := createShare(t, h, "p")
	b.FS.ReservePercent = 0
	b.FS.DiskSpace = func(string) (int64, int64, error) { return 10, 1 << 30, nil }
	rec := doReqBare(t, h, "PUT", "/api/shares/"+id+"/poster", testToken, posterJPEG(t, "x"))
	if rec.Code != 507 || !strings.Contains(rec.Body.String(), "no-space") {
		t.Fatalf("= %d %s, want 507 no-space", rec.Code, rec.Body)
	}
	if b.FS.HasPoster(id) {
		t.Fatal("the poster landed anyway")
	}
}
