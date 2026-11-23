package api

import (
	"strings"
	"testing"
	"time"
)

type pinnedRow struct {
	ID         string     `json:"id"`
	PinnedAt   *time.Time `json:"pinnedAt"`
	ModifiedAt *time.Time `json:"modifiedAt"`
}

func TestPinRoundTripsAndLeavesModifiedAt(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "notes")
	var before pinnedRow
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+id, testToken, ""), &before)
	if before.PinnedAt != nil {
		t.Fatalf("a new share is pinned: %v", before.PinnedAt)
	}

	rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"pinned":true}`)
	if rec.Code != 200 {
		t.Fatalf("pin = %d %s", rec.Code, rec.Body)
	}
	var pinned pinnedRow
	unmarshal(t, rec, &pinned)
	if pinned.PinnedAt == nil {
		t.Fatalf("pin answered no pinnedAt: %s", rec.Body)
	}
	if (before.ModifiedAt == nil) != (pinned.ModifiedAt == nil) ||
		(before.ModifiedAt != nil && !before.ModifiedAt.Equal(*pinned.ModifiedAt)) {
		t.Fatalf("pin moved modifiedAt: %v -> %v", before.ModifiedAt, pinned.ModifiedAt)
	}

	rec = doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"pinned":false}`)
	if rec.Code != 200 {
		t.Fatalf("unpin = %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "pinnedAt") {
		t.Fatalf("unpinned share still reports pinnedAt: %s", rec.Body)
	}
}

// An inbox has its own list and no pin.
func TestPinRefusedOnAnInbox(t *testing.T) {
	h := newTestAPI(t)
	id := createInbox(t, h, `{"name":"inbox","receive":true}`)
	if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"pinned":true}`); rec.Code != 400 {
		t.Fatalf("pin an inbox = %d %s, want 400", rec.Code, rec.Body)
	}
}

// The bulk edit pins several shares in one request.
func TestBatchEditPinsSeveralShares(t *testing.T) {
	h := newTestAPI(t)
	a, b := createShare(t, h, "a"), createShare(t, h, "b")
	rec := doReq(t, h, "POST", "/api/shares/edit", testToken, `{"ids":["`+a+`","`+b+`"],"pinned":true}`)
	if rec.Code != 200 {
		t.Fatalf("batch pin = %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Updated []pinnedRow `json:"updated"`
		Failed  []any       `json:"failed"`
	}
	unmarshal(t, rec, &out)
	if len(out.Updated) != 2 || len(out.Failed) != 0 {
		t.Fatalf("batch pin answered %s", rec.Body)
	}
	for _, row := range out.Updated {
		if row.PinnedAt == nil {
			t.Fatalf("%s not pinned: %s", row.ID, rec.Body)
		}
	}
}

// One batch pins every share at one time, so the pinned shares keep the
// order they had among themselves (newest first) rather than reversing.
func TestBatchPinKeepsTheSharesInTheirOrder(t *testing.T) {
	h := newTestAPI(t)
	a := createShare(t, h, "a")
	time.Sleep(10 * time.Millisecond)
	b := createShare(t, h, "b")
	rec := doReq(t, h, "POST", "/api/shares/edit", testToken, `{"ids":["`+a+`","`+b+`"],"pinned":true}`)
	var out struct {
		Updated []pinnedRow `json:"updated"`
	}
	unmarshal(t, rec, &out)
	if len(out.Updated) != 2 || out.Updated[0].PinnedAt == nil || out.Updated[1].PinnedAt == nil ||
		!out.Updated[0].PinnedAt.Equal(*out.Updated[1].PinnedAt) {
		t.Fatalf("batch pin times differ: %s", rec.Body)
	}
}
