package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestBatchDeleteRemovesEveryOwnedShare(t *testing.T) {
	h := newTestAPI(t)
	a := createShare(t, h, "one")
	b := createShare(t, h, "two")
	body := fmt.Sprintf(`{"ids":[%q,%q]}`, a, b)
	rec := doReq(t, h, "POST", "/api/shares/delete", testToken, body)
	if rec.Code != 200 {
		t.Fatalf("status = %d body %s", rec.Code, rec.Body)
	}
	var out struct {
		Deleted []string    `json:"deleted"`
		Failed  []batchFail `json:"failed"`
	}
	unmarshal(t, rec, &out)
	if len(out.Deleted) != 2 || len(out.Failed) != 0 {
		t.Fatalf("got %+v", out)
	}
	if doReq(t, h, "GET", "/api/shares/"+a, testToken, "").Code != 404 {
		t.Fatal("a still exists")
	}
	if doReq(t, h, "GET", "/api/shares/"+b, testToken, "").Code != 404 {
		t.Fatal("b still exists")
	}
}

func TestBatchDeleteReportsMissingAndKeepsTheRest(t *testing.T) {
	h := newTestAPI(t)
	a := createShare(t, h, "keep-deleting")
	body := fmt.Sprintf(`{"ids":[%q,"abcdefghij",%q]}`, a, a)
	rec := doReq(t, h, "POST", "/api/shares/delete", testToken, body)
	if rec.Code != 200 {
		t.Fatalf("status = %d body %s", rec.Code, rec.Body)
	}
	var out struct {
		Deleted []string    `json:"deleted"`
		Failed  []batchFail `json:"failed"`
	}
	unmarshal(t, rec, &out)
	if len(out.Deleted) != 1 || out.Deleted[0] != a {
		t.Fatalf("deleted = %v", out.Deleted)
	}
	if len(out.Failed) != 1 || out.Failed[0].Code != "not-found" {
		t.Fatalf("failed = %+v", out.Failed)
	}
}

func TestBatchDeleteHidesAnotherAccountsShare(t *testing.T) {
	b := testBackend(t)
	um := b.DB
	h := New(b, "2.0.0", testDomain(t), nil)
	adminID := createShare(t, h, "admin-share")
	aliceTok := seedUser(t, um, "alice")
	aliceRec := doReq(t, h, "POST", "/api/shares", aliceTok, `{"name":"alice-share"}`)
	if aliceRec.Code != 201 {
		t.Fatalf("alice create = %d %s", aliceRec.Code, aliceRec.Body)
	}
	var created struct {
		ID string `json:"id"`
	}
	json.Unmarshal(aliceRec.Body.Bytes(), &created)

	body := fmt.Sprintf(`{"ids":[%q,%q]}`, adminID, created.ID)
	rec := doReq(t, h, "POST", "/api/shares/delete", aliceTok, body)
	if rec.Code != 200 {
		t.Fatalf("status = %d body %s", rec.Code, rec.Body)
	}
	var out struct {
		Deleted []string    `json:"deleted"`
		Failed  []batchFail `json:"failed"`
	}
	unmarshal(t, rec, &out)
	if len(out.Deleted) != 1 || out.Deleted[0] != created.ID {
		t.Fatalf("deleted = %v", out.Deleted)
	}
	if len(out.Failed) != 1 || out.Failed[0].ID != adminID || out.Failed[0].Code != "not-found" {
		t.Fatalf("failed = %+v", out.Failed)
	}
	if doReq(t, h, "GET", "/api/shares/"+adminID, testToken, "").Code != 200 {
		t.Fatal("admin share was deleted by alice")
	}
}

func TestBatchDeleteRefusesEmptyAndOversized(t *testing.T) {
	h := newTestAPI(t)
	if rec := doReq(t, h, "POST", "/api/shares/delete", testToken, `{"ids":[]}`); rec.Code != 400 {
		t.Errorf("empty ids = %d, want 400", rec.Code)
	}
	if rec := doReq(t, h, "POST", "/api/shares/delete", testToken, `{}`); rec.Code != 400 {
		t.Errorf("missing ids = %d, want 400", rec.Code)
	}
	ids := make([]string, maxShareBatch+1)
	for i := range ids {
		ids[i] = fmt.Sprintf("id%08d", i)
	}
	body, _ := json.Marshal(map[string]any{"ids": ids})
	if rec := doReq(t, h, "POST", "/api/shares/delete", testToken, string(body)); rec.Code != 413 {
		t.Errorf("oversized = %d, want 413", rec.Code)
	}
}

func TestBatchEditSetsPasswordOnEveryShare(t *testing.T) {
	h := newTestAPI(t)
	a := createShare(t, h, "one")
	b := createShare(t, h, "two")
	body := fmt.Sprintf(`{"ids":[%q,%q],"password":"secret"}`, a, b)
	rec := doReq(t, h, "POST", "/api/shares/edit", testToken, body)
	if rec.Code != 200 {
		t.Fatalf("status = %d body %s", rec.Code, rec.Body)
	}
	var out struct {
		Updated []struct {
			ID          string `json:"id"`
			HasPassword bool   `json:"hasPassword"`
		} `json:"updated"`
		Failed []batchFail `json:"failed"`
	}
	unmarshal(t, rec, &out)
	if len(out.Updated) != 2 || len(out.Failed) != 0 {
		t.Fatalf("got %+v", out)
	}
	for _, row := range out.Updated {
		if !row.HasPassword {
			t.Fatalf("%s has no password", row.ID)
		}
	}
}

func TestBatchEditRemovesExpiryAndReportsAMiss(t *testing.T) {
	h := newTestAPI(t)
	a := createShare(t, h, "expiring")
	if rec := doReq(t, h, "PATCH", "/api/shares/"+a, testToken, `{"expiresInSeconds":3600}`); rec.Code != 200 {
		t.Fatalf("set expiry = %d %s", rec.Code, rec.Body)
	}
	body := fmt.Sprintf(`{"ids":[%q,"abcdefghij"],"expiresInSeconds":0}`, a)
	rec := doReq(t, h, "POST", "/api/shares/edit", testToken, body)
	if rec.Code != 200 {
		t.Fatalf("status = %d body %s", rec.Code, rec.Body)
	}
	var out struct {
		Updated []struct {
			ID        string     `json:"id"`
			ExpiresAt *time.Time `json:"expiresAt"`
		} `json:"updated"`
		Failed []batchFail `json:"failed"`
	}
	unmarshal(t, rec, &out)
	if len(out.Updated) != 1 || out.Updated[0].ExpiresAt != nil {
		t.Fatalf("updated = %+v", out.Updated)
	}
	if len(out.Failed) != 1 || out.Failed[0].Code != "not-found" {
		t.Fatalf("failed = %+v", out.Failed)
	}
}

func TestBatchEditRefusesAInboxExpiryAndEditsTheRest(t *testing.T) {
	h := newTestAPI(t)
	ordinary := createShare(t, h, "files")
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"share","receive":true}`)
	if rec.Code != 201 {
		t.Fatalf("inbox create = %d %s", rec.Code, rec.Body)
	}
	var created struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)

	body := fmt.Sprintf(`{"ids":[%q,%q],"expiresInSeconds":60}`, ordinary, created.ID)
	got := doReq(t, h, "POST", "/api/shares/edit", testToken, body)
	if got.Code != 200 {
		t.Fatalf("status = %d body %s", got.Code, got.Body)
	}
	var out struct {
		Updated []struct {
			ID        string     `json:"id"`
			ExpiresAt *time.Time `json:"expiresAt"`
		} `json:"updated"`
		Failed []batchFail `json:"failed"`
	}
	unmarshal(t, got, &out)
	if len(out.Updated) != 1 || out.Updated[0].ID != ordinary || out.Updated[0].ExpiresAt == nil {
		t.Fatalf("updated = %+v", out.Updated)
	}
	if len(out.Failed) != 1 || out.Failed[0].ID != created.ID {
		t.Fatalf("failed = %+v", out.Failed)
	}
	if !strings.Contains(out.Failed[0].Error, "expiry") {
		t.Fatalf("want expiry refusal, got %q", out.Failed[0].Error)
	}
}

func TestBatchEditRequiresAChange(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "x")
	body := fmt.Sprintf(`{"ids":[%q]}`, id)
	if rec := doReq(t, h, "POST", "/api/shares/edit", testToken, body); rec.Code != 400 {
		t.Errorf("no change = %d, want 400", rec.Code)
	}
}

func TestBatchRoutesNeedAuth(t *testing.T) {
	h := newTestAPI(t)
	for _, path := range []string{"/api/shares/delete", "/api/shares/edit"} {
		if rec := doReq(t, h, "POST", path, "", `{"ids":["abcdefghij"]}`); rec.Code != 401 {
			t.Errorf("%s no token: %d", path, rec.Code)
		}
	}
}
