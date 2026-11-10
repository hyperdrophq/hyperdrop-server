package api

import (
	"encoding/json"
	"net/url"
	"testing"
	"time"
)

type changesResp struct {
	Reset   bool `json:"reset"`
	Changes []struct {
		Share   *shareOut `json:"share"`
		Deleted string    `json:"deleted"`
	} `json:"changes"`
	Cursor string `json:"cursor"`
	More   bool   `json:"more"`
}

func TestChangesBootstrapsWithResetThenReportsCreateAndDelete(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "GET", "/api/shares/changes", testToken, "")
	if rec.Code != 200 {
		t.Fatalf("status = %d body %s", rec.Code, rec.Body)
	}
	var boot changesResp
	if err := json.Unmarshal(rec.Body.Bytes(), &boot); err != nil {
		t.Fatal(err)
	}
	if !boot.Reset || boot.Cursor == "" {
		t.Fatalf("first call = %+v, want reset with a cursor", boot)
	}

	id := createShare(t, h, "photos")
	rec = doReq(t, h, "GET", "/api/shares/changes?since="+url.QueryEscape(boot.Cursor), testToken, "")
	var after changesResp
	json.Unmarshal(rec.Body.Bytes(), &after)
	if after.Reset || len(after.Changes) != 1 || after.Changes[0].Share == nil ||
		after.Changes[0].Share.ID != id {
		t.Fatalf("after create = %+v, want one share row for %s", after, id)
	}
	if after.Cursor == boot.Cursor {
		t.Fatal("the cursor must advance when changes were reported")
	}

	if rec := doReq(t, h, "DELETE", "/api/shares/"+id, testToken, ""); rec.Code != 200 && rec.Code != 204 {
		t.Fatalf("delete status = %d", rec.Code)
	}
	rec = doReq(t, h, "GET", "/api/shares/changes?since="+url.QueryEscape(after.Cursor), testToken, "")
	var del changesResp
	json.Unmarshal(rec.Body.Bytes(), &del)
	if len(del.Changes) != 1 || del.Changes[0].Deleted != id {
		t.Fatalf("after delete = %+v, want the %s tombstone", del, id)
	}
}

func TestChangesRequiresAToken(t *testing.T) {
	h := newTestAPI(t)
	if rec := doReq(t, h, "GET", "/api/shares/changes", "", ""); rec.Code != 401 {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestChangesIsOwnerScoped(t *testing.T) {
	b := testBackend(t)
	um := b.DB
	h := New(b, "2.0.0", testDomain(t), nil)
	bobToken := seedUser(t, um, "bob")

	rec := doReq(t, h, "GET", "/api/shares/changes", bobToken, "")
	var boot changesResp
	json.Unmarshal(rec.Body.Bytes(), &boot)

	createShare(t, h, "admins-own") // created by admin (testToken)

	rec = doReq(t, h, "GET", "/api/shares/changes?since="+url.QueryEscape(boot.Cursor), bobToken, "")
	var after changesResp
	json.Unmarshal(rec.Body.Bytes(), &after)
	if after.Reset || len(after.Changes) != 0 {
		t.Fatalf("bob sees %+v, want nothing of admin's", after)
	}
	if after.Cursor == boot.Cursor {
		t.Fatal("another owner's churn must still advance an idle owner's cursor, or it falls off the journal")
	}
}

// A cursor older than the rows the prune has removed cannot be honoured:
// the journal does not know what happened in between, so the answer is
// reset and the client re-walks GET /api/shares once.
func TestChangesAnswersResetWhenTheCursorFellBehindThePrune(t *testing.T) {
	h, b := newTestAPIBackend(t)

	rec := doReq(t, h, "GET", "/api/shares/changes", testToken, "")
	var boot changesResp
	if err := json.Unmarshal(rec.Body.Bytes(), &boot); err != nil {
		t.Fatal(err)
	}
	createShare(t, h, "before the prune")
	if _, err := b.DB.PruneChanges(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	rec = doReq(t, h, "GET", "/api/shares/changes?since="+url.QueryEscape(boot.Cursor), testToken, "")
	if rec.Code != 200 {
		t.Fatalf("status = %d body %s", rec.Code, rec.Body)
	}
	var after changesResp
	if err := json.Unmarshal(rec.Body.Bytes(), &after); err != nil {
		t.Fatal(err)
	}
	if !after.Reset || after.Cursor == "" {
		t.Fatalf("changes = %+v, want reset with a cursor to continue from", after)
	}
}

func TestChangesPagesWithMoreThenReportsTheRemainder(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "GET", "/api/shares/changes", testToken, "")
	var boot changesResp
	json.Unmarshal(rec.Body.Bytes(), &boot)

	createShare(t, h, "one")
	createShare(t, h, "two")
	createShare(t, h, "three")

	rec = doReq(t, h, "GET", "/api/shares/changes?since="+url.QueryEscape(boot.Cursor)+"&limit=2", testToken, "")
	var first changesResp
	if err := json.Unmarshal(rec.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if first.Reset || len(first.Changes) != 2 || !first.More {
		t.Fatalf("first page = %+v, want 2 changes and more:true", first)
	}

	rec = doReq(t, h, "GET", "/api/shares/changes?since="+url.QueryEscape(first.Cursor), testToken, "")
	var rest changesResp
	if err := json.Unmarshal(rec.Body.Bytes(), &rest); err != nil {
		t.Fatal(err)
	}
	if rest.Reset || len(rest.Changes) != 1 || rest.More {
		t.Fatalf("continuation = %+v, want the remaining 1 change and more:false", rest)
	}
}

func TestChangesIsNotSwallowedByTheShareIDRoute(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "GET", "/api/shares/changes", testToken, "")
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200 (the literal segment must beat the {id} wildcard)", rec.Code)
	}
}

func TestChangesResolvesRowsWithTheListingFileCap(t *testing.T) {
	old := listMaxFilesPerShare
	listMaxFilesPerShare = 2
	t.Cleanup(func() { listMaxFilesPerShare = old })

	h := newTestAPI(t)
	rec := doReq(t, h, "GET", "/api/shares/changes", testToken, "")
	var boot changesResp
	json.Unmarshal(rec.Body.Bytes(), &boot)

	id := createShare(t, h, "fat")
	for _, name := range []string{"a.txt", "b.txt", "c.txt"} {
		if rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/"+name, testToken, "hello"); rec.Code != 200 && rec.Code != 201 {
			t.Fatalf("upload %s status = %d body %s", name, rec.Code, rec.Body)
		}
	}
	rec = doReq(t, h, "GET", "/api/shares/changes?since="+url.QueryEscape(boot.Cursor), testToken, "")
	var after changesResp
	json.Unmarshal(rec.Body.Bytes(), &after)
	if len(after.Changes) != 1 || after.Changes[0].Share == nil {
		t.Fatalf("changes = %+v, want one coalesced row for %s", after, id)
	}
	row := after.Changes[0].Share
	if len(row.Files) != 2 || !row.FilesTruncated || row.FileCount != 3 {
		t.Fatalf("row = %d files truncated=%v count=%d, want the listing cap applied",
			len(row.Files), row.FilesTruncated, row.FileCount)
	}
}
