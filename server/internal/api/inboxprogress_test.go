package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/metadb"
)

// newTestProgressAPI is newTestWatchAPI with the handler kept, so a test
// can reach the claims and their clock.
func newTestProgressAPI(t *testing.T, timeout time.Duration) (*handler, http.Handler) {
	t.Helper()
	hd := newHandler(testBackend(t), "2.0.0", testDomain(t), nil, Deployment{})
	hd.watch.watchTimeout = timeout
	return hd, hd.routes()
}

type progressResp struct {
	Cursor   string            `json:"cursor"`
	Changed  bool              `json:"changed"`
	Progress *string           `json:"progress"`
	Uploads  []inboxUploadsOut `json:"uploads"`
}

func getProgressWatch(t *testing.T, h http.Handler, token, query string) progressResp {
	t.Helper()
	rec := doReq(t, h, "GET", "/api/shares/watch?"+query, token, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("watch?%s = %d %s", query, rec.Code, rec.Body)
	}
	var out progressResp
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// followQuery is the query that parks a watch following progress from r.
func followQuery(r progressResp) string {
	return "since=" + r.Cursor + "&progress=" + *r.Progress
}

// startUpload opens an anonymous PUT into id whose body the test feeds
// through the returned writer; the channel answers the status once the
// handler returns.
func startUpload(t *testing.T, h http.Handler, id, name string, size int) (*io.PipeWriter, <-chan int) {
	t.Helper()
	pr, pw := io.Pipe()
	req := httptest.NewRequest("PUT", "/receive/"+id+"/files/"+name, pr)
	req.ContentLength = int64(size)
	done := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		done <- rec.Code
	}()
	return pw, done
}

// waitForIncoming waits until the upload into id has received at least
// want bytes, as the claims count them.
func waitForIncoming(t *testing.T, hd *handler, id string, want int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if in := hd.claims.incoming(id); len(in) == 1 && in[0].Bytes >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("the upload never reached %d bytes: %+v", want, hd.claims.incoming(id))
}

// The owner's held watch answers a stranger's upload as it moves: the
// bytes counted so far, the declared total, and the journal cursor
// untouched, because progress is never journaled.
func TestProgressWakesTheOwnersWatchWithTheBytes(t *testing.T) {
	hd, h := newTestProgressAPI(t, 10*time.Second)
	id := createInbox(t, h, `{"name":"inbox","receive":true}`)
	first := getProgressWatch(t, h, testToken, "")
	if first.Progress == nil || first.Uploads != nil {
		t.Fatalf("a first call carries the progress cursor and no uploads: %+v", first)
	}
	pw, done := startUpload(t, h, id, "big.bin", 100)
	if _, err := pw.Write(make([]byte, 40)); err != nil {
		t.Fatal(err)
	}
	waitForIncoming(t, hd, id, 40)

	// The claim moved the progress past the first cursor, and the declared
	// row moved the journal: a watch from there answers at once.
	next := getProgressWatch(t, h, testToken, followQuery(first))
	if len(next.Uploads) != 1 || next.Uploads[0].Share != id || len(next.Uploads[0].Incoming) != 1 {
		t.Fatalf("uploads = %+v", next.Uploads)
	}
	if in := next.Uploads[0].Incoming[0]; in.Name != "big.bin" || in.Total != 100 || in.Bytes != 40 {
		t.Fatalf("incoming = %+v", in)
	}

	// A byte tick wakes a parked watch without moving the journal.
	hd.claims.mu.Lock()
	hd.claims.now = func() time.Time { return time.Now().Add(time.Hour) }
	hd.claims.mu.Unlock()
	woke := make(chan progressResp, 1)
	go func() { woke <- getProgressWatch(t, h, testToken, followQuery(next)) }()
	time.Sleep(150 * time.Millisecond)
	if _, err := pw.Write(make([]byte, 30)); err != nil {
		t.Fatal(err)
	}
	select {
	case b := <-woke:
		if b.Changed || b.Cursor != next.Cursor {
			t.Fatalf("a byte tick moved the journal cursor: %+v", b)
		}
		if *b.Progress == *next.Progress || len(b.Uploads) != 1 || b.Uploads[0].Incoming[0].Bytes <= 40 {
			t.Fatalf("tick answer = %+v", b)
		}
		next = b
	case <-time.After(5 * time.Second):
		t.Fatal("the byte tick never woke the owner's watch")
	}

	// The end: the watch reports the inbox gone from the uploads.
	go func() { woke <- getProgressWatch(t, h, testToken, followQuery(next)) }()
	time.Sleep(150 * time.Millisecond)
	if _, err := pw.Write(make([]byte, 30)); err != nil {
		t.Fatal(err)
	}
	pw.Close()
	if code := <-done; code != http.StatusCreated {
		t.Fatalf("upload = %d", code)
	}
	b := <-woke
	for b.Uploads != nil {
		b = getProgressWatch(t, h, testToken, followQuery(b))
	}
	if *b.Progress == *next.Progress {
		t.Fatalf("the end of the upload did not move the progress: %+v", b)
	}
	if len(hd.claims.byShare) != 0 {
		t.Fatalf("an ended upload left state behind: %+v", hd.claims.byShare)
	}
}

// Byte ticks are paced to one a second per inbox; a claim and an end are
// changes of their own and are never held back.
func TestProgressTicksAtMostOnceASecondPerInbox(t *testing.T) {
	c := newInboxClaims()
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	up, _ := c.claim("share1", "alice", "a.bin", heldBy(func(string) bool { return false }), 100, "")
	afterClaim := c.owners["alice"]
	r := up.Reader(strings.NewReader(strings.Repeat("x", 200)))
	buf := make([]byte, 10)
	for i := 0; i < 5; i++ {
		r.Read(buf)
		now = now.Add(100 * time.Millisecond)
	}
	if c.owners["alice"] != afterClaim {
		t.Fatal("a byte tick inside the claim's second moved the progress")
	}
	// Reads at 0.5 s to 1.4 s: the one at 1.0 s ticks, and the next second
	// has not come.
	for i := 0; i < 10; i++ {
		r.Read(buf)
		now = now.Add(100 * time.Millisecond)
	}
	if got := c.owners["alice"] - afterClaim; got != 1 {
		t.Fatalf("one second of reads moved the progress %d times, want 1", got)
	}
	before := c.owners["alice"]
	up.Finish()
	if c.owners["alice"] != before+1 {
		t.Fatal("the end of an upload must move the progress at once")
	}
	up.Release()
	if c.owners["alice"] != before+1 {
		t.Fatal("releasing an ended upload is not a second change")
	}
	if len(c.byShare) != 0 {
		t.Fatalf("a released upload left %+v", c.byShare)
	}
}

// An upload refused before its body (the disk, a declare that fails) still
// ends: releasing a claim that never finished is the end.
func TestReleaseEndsAnUnfinishedUpload(t *testing.T) {
	c := newInboxClaims()
	up, _ := c.claim("share1", "alice", "a.bin", heldBy(func(string) bool { return false }), 100, "")
	before := c.owners["alice"]
	up.Release()
	if c.owners["alice"] != before+1 {
		t.Fatal("releasing an unfinished upload must report its end")
	}
}

// A finished upload leaves incoming at once, while its name is still held
// against a second sender until the release.
func TestAFinishedUploadIsNotIncoming(t *testing.T) {
	c := newInboxClaims()
	taken := heldBy(func(string) bool { return false })
	up, _ := c.claim("share1", "alice", "a.bin", taken, 100, "")
	up.Finish()
	if in := c.incoming("share1"); len(in) != 0 {
		t.Fatalf("a finished upload is still incoming: %+v", in)
	}
	other, _ := c.claim("share1", "alice", "a.bin", taken, 1, "")
	if other.Name != "a 2.bin" {
		t.Fatalf("a finished claim stopped holding its name: %q", other.Name)
	}
}

// Another account's watch is never woken by, and never answers, this
// account's uploads: the names are the owner's to see.
func TestProgressNeverReachesAnotherAccount(t *testing.T) {
	hd, h := newTestProgressAPI(t, 600*time.Millisecond)
	guest := seedUser(t, hd.db, "guest")
	id := createInbox(t, h, `{"name":"inbox","receive":true}`)
	first := getProgressWatch(t, h, guest, "")
	woke := make(chan progressResp, 1)
	go func() { woke <- getProgressWatch(t, h, guest, followQuery(first)) }()
	time.Sleep(150 * time.Millisecond)
	up, _ := hd.claims.claim(id, metadb.DefaultAdminName, "secret.pdf", heldBy(func(string) bool { return false }), 10, "")
	defer up.Release()
	started := time.Now()
	b := <-woke
	if time.Since(started) < 300*time.Millisecond {
		t.Fatal("another account's upload woke this watch")
	}
	if *b.Progress != *first.Progress || b.Uploads != nil {
		t.Fatalf("another account's upload reached this watch: %+v", b)
	}
}

// Progress is never written: ticks, claims and ends leave the journal
// where it was, so no device re-reads a row for them.
func TestProgressWritesNothingToTheJournal(t *testing.T) {
	hd, h := newTestProgressAPI(t, time.Second)
	id := createInbox(t, h, `{"name":"inbox","receive":true}`)
	before, err := hd.db.Cursor()
	if err != nil {
		t.Fatal(err)
	}
	up, _ := hd.claims.claim(id, metadb.DefaultAdminName, "a.bin", heldBy(func(string) bool { return false }), 100, "")
	hd.claims.now = func() time.Time { return time.Now().Add(time.Hour) }
	io.Copy(io.Discard, up.Reader(strings.NewReader(strings.Repeat("x", 100))))
	up.Finish()
	up.Release()
	after, err := hd.db.Cursor()
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("progress moved the journal: %s -> %s", before, after)
	}
}

// A watch that names a journal cursor but no progress cursor waits for the
// journal alone and answers no progress.
func TestAWatchWithoutProgressIgnoresIt(t *testing.T) {
	hd, h := newTestProgressAPI(t, 500*time.Millisecond)
	id := createInbox(t, h, `{"name":"inbox","receive":true}`)
	first := getProgressWatch(t, h, testToken, "")
	woke := make(chan progressResp, 1)
	go func() { woke <- getProgressWatch(t, h, testToken, "since="+first.Cursor) }()
	time.Sleep(100 * time.Millisecond)
	up, _ := hd.claims.claim(id, metadb.DefaultAdminName, "a.bin", heldBy(func(string) bool { return false }), 100, "")
	defer up.Release()
	b := <-woke
	if b.Changed || b.Progress != nil || b.Uploads != nil {
		t.Fatalf("a watch not following progress answered it: %+v", b)
	}
}

// A progress cursor this process never issued (a restart's, a forged one)
// answers at once with the whole picture, so a client never waits on a
// cursor nothing will move past.
func TestAForeignProgressCursorAnswersAtOnce(t *testing.T) {
	hd, h := newTestProgressAPI(t, 10*time.Second)
	id := createInbox(t, h, `{"name":"inbox","receive":true}`)
	up, _ := hd.claims.claim(id, metadb.DefaultAdminName, "a.bin", heldBy(func(string) bool { return false }), 100, "")
	defer up.Release()
	first := getProgressWatch(t, h, testToken, "")
	for _, foreign := range []string{"1", "nonsense", "99999999999999999999"} {
		started := time.Now()
		b := getProgressWatch(t, h, testToken, "since="+first.Cursor+"&progress="+foreign)
		if time.Since(started) > 2*time.Second || len(b.Uploads) != 1 || *b.Progress == foreign {
			t.Fatalf("progress=%s answered %+v", foreign, b)
		}
	}
}

// The subscriptions of watches that ended leave nothing behind.
func TestProgressSubscriptionsAreFreed(t *testing.T) {
	c := newInboxClaims()
	_, cancel := c.subscribe("alice")
	_, cancel2 := c.subscribe("alice")
	cancel()
	cancel2()
	if len(c.subs) != 0 {
		t.Fatalf("subs = %+v", c.subs)
	}
}
