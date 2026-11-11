package api

import (
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"hyperdrop/server/internal/metadb"
)

// fillAfter is a request body that reports the disk full once after bytes
// have been read from it, in the reading goroutine, as another writer
// filling the disk mid-body would.
type fillAfter struct {
	r     io.Reader
	after int
	seen  int
	fill  func()
}

func (f *fillAfter) Read(p []byte) (int, error) {
	n, err := f.r.Read(p)
	f.seen += n
	if f.fill != nil && f.seen >= f.after {
		f.fill()
		f.fill = nil
	}
	return n, err
}

// A commit-time quota refusal tells a stranger as little as the check
// before the body does.
func TestAnInboxQuotaRefusalAtCommitNamesNothing(t *testing.T) {
	b := testBackend(t)
	h := New(b, "test", testDomain(t), nil)
	token := seedUser(t, b.DB, "bob")
	quota := int64(1000)
	if _, err := b.DB.UpdateUser("bob", metadb.Settings{QuotaBytes: &quota}); err != nil {
		t.Fatal(err)
	}
	id := createShareAs(t, h, token, `{"name":"inbox","receive":true}`)
	// The quota drops while the body is arriving, past the check before it.
	body := &fillAfter{r: strings.NewReader(strings.Repeat("x", 500)), after: 1, fill: func() {
		low := int64(100)
		if _, err := b.DB.UpdateUser("bob", metadb.Settings{QuotaBytes: &low}); err != nil {
			t.Error(err)
		}
	}}
	req := httptest.NewRequest("PUT", "/receive/"+id+"/files/a.bin", body)
	req.ContentLength = 500
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 507 || errCode(t, rec.Body.String()) != "quota" || strings.ContainsAny(rec.Body.String(), "0123456789") {
		t.Fatalf("a quota refused at commit = %d %s", rec.Code, rec.Body)
	}
}

// A stranger's upload whose next window is refused mid-body answers 507 and
// leaves no part and no pending row: a one-shot body has no resume state.
func TestAnInboxWindowRefusedMidBodyLeavesNothing(t *testing.T) {
	b := testBackend(t)
	b.FS.WriteWindow = 10
	b.FS.ReservePercent = 10
	b.FS.DiskSpace = func(string) (int64, int64, error) { return 1150, 10000, nil } // 150 usable
	h := New(b, "test", testDomain(t), nil)
	id := createInbox(t, h, `{"name":"inbox","receive":true}`)
	body := &fillAfter{r: strings.NewReader(strings.Repeat("x", 30)), after: 10, fill: func() {
		b.FS.DiskSpace = func(string) (int64, int64, error) { return 1000, 10000, nil }
	}}
	req := httptest.NewRequest("PUT", "/receive/"+id+"/files/big.bin", body)
	req.ContentLength = 30
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	noSpaceWithoutFigures(t, "the refused window", rec)
	if n, err := b.FS.PartSize(id, "big.bin"); err != nil || n != 0 {
		t.Fatalf("a part stayed: %d %v", n, err)
	}
	if _, err := b.DB.File(id, "big.bin"); !errors.Is(err, metadb.ErrNotFound) {
		t.Fatalf("a row stayed: %v", err)
	}
}

// A signed-in chunk whose next window is refused mid-body answers 507 and
// keeps what landed as resume state, the way a dropped body does: its
// pending row stays, and the chunk that sends the rest once there is room
// commits the file. An upload nobody resumes is the stalled sweep's.
func TestARangedWindowRefusedMidBodyKeepsWhatLanded(t *testing.T) {
	b := testBackend(t)
	b.FS.WriteWindow = 10
	b.FS.ReservePercent = 10
	room := func(string) (int64, int64, error) { return 1150, 10000, nil } // 150 usable
	b.FS.DiskSpace = room
	h := New(b, "test", testDomain(t), nil)
	share := createShare(t, h, "own")
	data := strings.Repeat("x", 30)
	put := func(start int, body io.Reader) *httptest.ResponseRecorder {
		req := httptest.NewRequest("PUT", "/api/shares/"+share+"/files/big.bin", body)
		req.Header.Set("Authorization", "Bearer "+testToken)
		req.Header.Set("Upload-Session", "test-session")
		req.Header.Set("Upload-Range", fmt.Sprintf("%d-30", start))
		req.Header.Set("Upload-Total", "30")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	body := &fillAfter{r: strings.NewReader(data), after: 10, fill: func() {
		b.FS.DiskSpace = func(string) (int64, int64, error) { return 1000, 10000, nil }
	}}
	noSpaceWithoutFigures(t, "the refused window", put(0, body))
	if n, err := b.FS.PartSize(share, "big.bin"); err != nil || n != 10 {
		t.Fatalf("what landed: %d %v", n, err)
	}
	if f, err := b.DB.File(share, "big.bin"); err != nil || !f.Pending {
		t.Fatalf("the pending row: %+v %v", f, err)
	}
	b.FS.DiskSpace = room
	if rec := put(10, strings.NewReader(data[10:])); rec.Code != 201 {
		t.Fatalf("the rest = %d %s", rec.Code, rec.Body)
	}
	if f, err := b.DB.File(share, "big.bin"); err != nil || f.Pending || f.Size != 30 {
		t.Fatalf("committed: %+v %v", f, err)
	}
}
