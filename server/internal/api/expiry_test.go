package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/metadb"
)

func TestCreateWithExpiryEchoesExpiresAt(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"x","expiresInSeconds":3600}`)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `"expiresAt"`) {
		t.Fatalf("missing expiresAt: %s", rec.Body)
	}
}

func TestUnexpiredShareServes(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"x"}`)
	var cr struct{ ID string }
	json.Unmarshal(rec.Body.Bytes(), &cr)
	slug := uploadGetSlug(t, h, cr.ID, "a.txt", "data")
	if got := doReq(t, h, "GET", "/download/"+cr.ID+"/"+slug, "", ""); got.Code != 200 {
		t.Fatalf("unexpired share should serve: %d", got.Code)
	}
}

func TestExpiredShareGate404(t *testing.T) {
	h, b := newTestAPIBackend(t)
	past := time.Now().Add(-time.Hour).UTC()
	d, err := b.DB.CreateShare(metadb.CreateOptions{ID: "expiresha1", Name: "x",
		Owner: metadb.DefaultAdminName, ExpiresAt: &past})
	if err != nil {
		t.Fatal(err)
	}
	commitFile(t, b, d.ID, "a.txt", "data")
	got, err := b.DB.Share(d.ID)
	if err != nil {
		t.Fatal(err)
	}
	slug := got.Files[0].Slug
	for _, p := range []string{"/share/" + d.ID, "/download/" + d.ID + "/" + slug, "/view/" + d.ID + "/" + slug, "/zip/" + d.ID} {
		if rec := doReq(t, h, "GET", p, "", ""); rec.Code != 404 {
			t.Errorf("GET %s on expired share = %d, want 404", p, rec.Code)
		}
	}
}

// A count of seconds past what time.Duration can hold is a century, never a
// wrapped negative that lands in the past and expires the share at once.
func TestAnAbsurdExpiryIsACenturyNotThePast(t *testing.T) {
	now := time.Now()
	for _, secs := range []int64{9_300_000_000, 1<<63 - 1} {
		if at := expiryAt(now, secs); at == nil || !at.After(now.Add(99*365*24*time.Hour)) {
			t.Fatalf("expiryAt(%d) = %v", secs, at)
		}
		if at := afterSeconds(now, secs); !at.After(now) {
			t.Fatalf("afterSeconds(%d) = %v", secs, at)
		}
	}
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"x","expiresInSeconds":9223372036854775807}`)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	var cr struct{ ID string }
	json.Unmarshal(rec.Body.Bytes(), &cr)
	slug := uploadGetSlug(t, h, cr.ID, "a.txt", "data")
	if got := doReq(t, h, "GET", "/download/"+cr.ID+"/"+slug, "", ""); got.Code != 200 {
		t.Fatalf("a share with an absurd expiry = %d, want it served", got.Code)
	}
}
