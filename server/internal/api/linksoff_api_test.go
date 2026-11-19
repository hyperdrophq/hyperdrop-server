package api

import (
	"strings"
	"testing"
)

type linksOffRow struct {
	ID       string `json:"id"`
	LinksOff bool   `json:"linksOff"`
}

// A share created with its links off says so in the create answer, in its
// own read and in the listing row.
func TestCreateWithLinksOff(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"name":"a","files":[{"path":"a.txt","size":4}],"linksOff":true}`)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	var created linksOffRow
	unmarshal(t, rec, &created)
	if !created.LinksOff {
		t.Fatalf("create answered links on: %s", rec.Body)
	}

	var got linksOffRow
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+created.ID, testToken, ""), &got)
	if !got.LinksOff {
		t.Fatalf("the share's read says links on")
	}

	var list struct {
		Shares []linksOffRow `json:"shares"`
	}
	unmarshal(t, doReq(t, h, "GET", "/api/shares", testToken, ""), &list)
	if len(list.Shares) != 1 || list.Shares[0].ID != created.ID || !list.Shares[0].LinksOff {
		t.Fatalf("the listing row is not links off: %+v", list.Shares)
	}

	// A share created without the field has its links on, and the answer
	// says nothing about them.
	rec = doReq(t, h, "POST", "/api/shares", testToken, `{"name":"b"}`)
	if rec.Code != 201 || strings.Contains(rec.Body.String(), "linksOff") {
		t.Fatalf("a default create = %d %s", rec.Code, rec.Body)
	}
}

// PATCH turns the links off and back on; on is the field's absence.
func TestPatchTurnsLinksOffAndOn(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "notes")

	rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"linksOff":true}`)
	if rec.Code != 200 {
		t.Fatalf("links off = %d %s", rec.Code, rec.Body)
	}
	var off linksOffRow
	unmarshal(t, rec, &off)
	if !off.LinksOff {
		t.Fatalf("links off answered links on: %s", rec.Body)
	}

	rec = doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"linksOff":false}`)
	if rec.Code != 200 {
		t.Fatalf("links on = %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "linksOff") {
		t.Fatalf("a share with links on still reports linksOff: %s", rec.Body)
	}
}

// The bulk edit turns several shares' links off in one request.
func TestBulkEditLinksOff(t *testing.T) {
	h := newTestAPI(t)
	a, b := createShare(t, h, "a"), createShare(t, h, "b")
	rec := doReq(t, h, "POST", "/api/shares/edit", testToken, `{"ids":["`+a+`","`+b+`"],"linksOff":true}`)
	if rec.Code != 200 {
		t.Fatalf("bulk links off = %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Updated []linksOffRow `json:"updated"`
		Failed  []batchFail   `json:"failed"`
	}
	unmarshal(t, rec, &out)
	if len(out.Updated) != 2 || len(out.Failed) != 0 {
		t.Fatalf("bulk links off answered %s", rec.Body)
	}
	for _, row := range out.Updated {
		if !row.LinksOff {
			t.Fatalf("%s still has links on: %s", row.ID, rec.Body)
		}
	}
}

// An inbox's content is never served, so it has no links to turn off: PATCH
// refuses the field with the refusal every other publish-side field meets on
// an inbox, the bulk edit fails that id alone, and a create refuses it.
func TestLinksOffRefusedOnAnInbox(t *testing.T) {
	h := newTestAPI(t)
	inbox := createInbox(t, h, `{"name":"inbox","receive":true}`)
	pin := doReq(t, h, "PATCH", "/api/shares/"+inbox, testToken, `{"pinned":true}`)

	rec := doReq(t, h, "PATCH", "/api/shares/"+inbox, testToken, `{"linksOff":true}`)
	if rec.Code != pin.Code || errCode(t, rec.Body.String()) != errCode(t, pin.Body.String()) {
		t.Fatalf("links off an inbox = %d %s, want the pin refusal %d %s", rec.Code, rec.Body, pin.Code, pin.Body)
	}
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "an inbox takes no") {
		t.Fatalf("links off an inbox = %d %s, want the inbox's 400", rec.Code, rec.Body)
	}

	share := createShare(t, h, "a")
	rec = doReq(t, h, "POST", "/api/shares/edit", testToken, `{"ids":["`+share+`","`+inbox+`"],"linksOff":true}`)
	if rec.Code != 200 {
		t.Fatalf("bulk = %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Updated []linksOffRow `json:"updated"`
		Failed  []batchFail   `json:"failed"`
	}
	unmarshal(t, rec, &out)
	if len(out.Updated) != 1 || out.Updated[0].ID != share || !out.Updated[0].LinksOff ||
		len(out.Failed) != 1 || out.Failed[0].ID != inbox || out.Failed[0].Code != errCode(t, pin.Body.String()) {
		t.Fatalf("bulk over a share and an inbox answered %s", rec.Body)
	}

	rec = doReq(t, h, "POST", "/api/shares", testToken, `{"name":"in","receive":true,"linksOff":true}`)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "an inbox takes no") {
		t.Fatalf("create an inbox with links off = %d %s, want the inbox's 400", rec.Code, rec.Body)
	}
}

// Turning the links off and on is not a content edit: modifiedAt stays where
// the last upload put it, but each toggle is a change the owner's other
// devices must hear about, so the change feed carries the share.
func TestALinksToggleLeavesModifiedAtAndFeedsTheChange(t *testing.T) {
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "notes", map[string]string{"a.txt": "data"})
	var before pinnedRow
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+id, testToken, ""), &before)
	if before.ModifiedAt == nil {
		t.Fatal("a share holding a file has no modifiedAt to compare")
	}
	for _, body := range []string{`{"linksOff":true}`, `{"linksOff":false}`} {
		cursor := changesCursor(t, h)
		rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, body)
		if rec.Code != 200 {
			t.Fatalf("%s = %d %s", body, rec.Code, rec.Body)
		}
		var after pinnedRow
		unmarshal(t, rec, &after)
		if after.ModifiedAt == nil || !after.ModifiedAt.Equal(*before.ModifiedAt) {
			t.Fatalf("%s moved modifiedAt: %v -> %v", body, before.ModifiedAt, after.ModifiedAt)
		}
		if n := changesSince(t, h, cursor); n != 1 {
			t.Fatalf("%s fed %d changes, want 1", body, n)
		}
	}
}
