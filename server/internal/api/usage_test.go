package api

import (
	"encoding/json"
	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/sharefs"
	"strings"
	"testing"
)

// newTestAPIWithDisk builds a backend with a fake disk: 1000 bytes total,
// `free` bytes free, 10% reserve.
func newTestAPIWithDisk(t *testing.T, free int64) Backend {
	t.Helper()
	b := testBackend(t)
	b.FS.ReservePercent = 10
	b.FS.DiskSpace = func(string) (int64, int64, error) { return free, 1000, nil }
	return b
}

type usageResp struct {
	Mode           string `json:"mode"`
	TotalBytes     int64  `json:"totalBytes"`
	UsedBytes      int64  `json:"usedBytes"`
	FreeBytes      int64  `json:"freeBytes"`
	HyperdropBytes int64  `json:"hyperdropBytes"`
	ReservePercent int    `json:"reservePercent"`
}

func TestUsageEndpointVPS(t *testing.T) {
	h := New(newTestAPIWithDisk(t, 400), "2.0.0", testDomain(t), nil)

	if rec := doReq(t, h, "GET", "/api/usage", "", ""); rec.Code != 401 {
		t.Errorf("no token: status = %d, want 401", rec.Code)
	}

	id := createShare(t, h, "u")
	if rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/a.bin", testToken, "12345"); rec.Code != 201 {
		t.Fatalf("upload = %d body %s", rec.Code, rec.Body)
	}

	rec := doReq(t, h, "GET", "/api/usage", testToken, "")
	if rec.Code != 200 {
		t.Fatalf("usage = %d body %s", rec.Code, rec.Body)
	}
	var u usageResp
	json.Unmarshal(rec.Body.Bytes(), &u)
	want := usageResp{Mode: "vps", TotalBytes: 1000, UsedBytes: 600, FreeBytes: 400,
		HyperdropBytes: 5, ReservePercent: 10}
	if u != want {
		t.Errorf("usage = %+v, want %+v", u, want)
	}
}

func TestUploadRejectedWhenDiskAlmostFull(t *testing.T) {
	// 50 free of 1000, reserve 100: a 10-byte upload leaves 40 < 100, which
	// is the reserve floor, so it is refused before a byte is staged.
	h := New(newTestAPIWithDisk(t, 50), "2.0.0", testDomain(t), nil)
	id := createShare(t, h, "big")

	rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/big.bin", testToken,
		strings.Repeat("x", 10))
	if rec.Code != 507 {
		t.Fatalf("status = %d body %s, want 507", rec.Code, rec.Body)
	}
	if errCode(t, rec.Body.String()) != "no-space" {
		t.Errorf("code should be no-space, got %s", rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "in reserve") {
		t.Errorf("body should name the reserve, got %s", rec.Body)
	}
}

func TestCreateShareWithReservation(t *testing.T) {
	// 400 free of 1000, 10% reserve (100) → 300 usable.
	b := newTestAPIWithDisk(t, 400)
	h := New(b, "1.0.0", testDomain(t), nil)

	// Fits: share created, reservation held.
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"a","reserveBytes":200}`)
	if rec.Code != 201 {
		t.Fatalf("fitting reservation: %d %s", rec.Code, rec.Body.String())
	}

	// Second upload of 200 does not fit (only 100 usable): 507 and NO share left behind.
	rec = doReq(t, h, "POST", "/api/shares", testToken, `{"name":"b","reserveBytes":200}`)
	if rec.Code != 507 {
		t.Fatalf("overcommit must 507, got %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not enough space") {
		t.Fatalf("message: %s", rec.Body.String())
	}
	page, _ := b.DB.List(metadb.ListQuery{Owner: metadb.DefaultAdminName})
	if len(page.Shares) != 1 {
		t.Fatalf("rejected share must be deleted, have %d", len(page.Shares))
	}

	// No reserveBytes → old-client behavior, always admitted.
	rec = doReq(t, h, "POST", "/api/shares", testToken, `{"name":"c"}`)
	if rec.Code != 201 {
		t.Fatalf("plain create: %d", rec.Code)
	}
}

func TestUsageReportsReserveBytes(t *testing.T) {
	h := New(newTestAPIWithDisk(t, 400), "1.0.0", testDomain(t), nil)
	rec := doReq(t, h, "GET", "/api/usage", testToken, "")
	var out struct {
		ReserveBytes int64 `json:"reserveBytes"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	if out.ReserveBytes != 100 { // 10% of 1000; tiny disk → no floor
		t.Fatalf("reserveBytes = %d", out.ReserveBytes)
	}
}

func TestNoSpaceCarriesACode(t *testing.T) {
	// Without a code the app can only show raw wire text, so the one upload
	// failure a server owner can actually act on offered no action.
	// 400 free of 1000, 10% reserve (100) -> 300 usable.
	h := New(newTestAPIWithDisk(t, 400), "1.0.0", testDomain(t), nil)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"big","reserveBytes":900}`)
	if rec.Code != 507 {
		t.Fatalf("status = %d body %s, want 507", rec.Code, rec.Body)
	}
	var out struct{ Error, Code string }
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Code != "no-space" {
		t.Errorf("code = %q, want %q (body %s)", out.Code, "no-space", rec.Body)
	}
}

// Under the default flat reserve, usage reports no percentage and the
// reserve in bytes, and a refused upload still names the reserve.
func TestTheFlatReserveIsReportedAndNamed(t *testing.T) {
	b := newTestAPIWithDisk(t, 260)
	b.FS.ReservePercent = sharefs.FlatReserve
	h := New(b, "2.0.0", testDomain(t), nil)
	rec := doReq(t, h, "GET", "/api/usage", testToken, "")
	var u struct {
		ReservePercent int   `json:"reservePercent"`
		ReserveBytes   int64 `json:"reserveBytes"`
	}
	json.Unmarshal(rec.Body.Bytes(), &u)
	if u.ReservePercent != 0 || u.ReserveBytes != 250 {
		t.Fatalf("usage reserve = %+v, want 0%% and 250 bytes (a quarter of the 1000-byte disk)", u)
	}
	id := createShare(t, h, "big")
	rec = doReq(t, h, "PUT", "/api/shares/"+id+"/files/big.bin", testToken, strings.Repeat("x", 20))
	if rec.Code != 507 || !strings.Contains(rec.Body.String(), "in reserve") || strings.Contains(rec.Body.String(), "-1%") {
		t.Fatalf("refusal = %d %s, want 507 naming the reserve", rec.Code, rec.Body)
	}
}
