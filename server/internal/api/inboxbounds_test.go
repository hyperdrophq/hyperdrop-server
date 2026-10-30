package api

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"hyperdrop/server/internal/metadb"
)

// An inbox with no file cap of its own still takes at most
// metadb.InboxMaxFiles files, and zero-byte ones count: they pass every
// byte bound, so the count is the only thing stopping a stranger.
func TestInboxRefusesFilesPastTheServerBound(t *testing.T) {
	defer func(n int) { metadb.InboxMaxFiles = n }(metadb.InboxMaxFiles)
	metadb.InboxMaxFiles = 3
	b := testBackend(t)
	h := New(b, "test", testDomain(t), nil)
	id := createInbox(t, h, `{"name":"inbox","receive":true,"maxBytes":1}`)
	for i := 0; i < 4; i++ {
		req := httptest.NewRequest("PUT", fmt.Sprintf("/receive/%s/files/f%d", id, i), strings.NewReader(""))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		want := 201
		if i == 3 {
			want = 413
		}
		if rec.Code != want {
			t.Fatalf("upload %d = %d %s, want %d", i, rec.Code, rec.Body, want)
		}
	}
	if s, err := b.DB.Share(id); err != nil || len(s.Files) != 3 {
		t.Fatalf("inbox holds %d files, %v", len(s.Files), err)
	}
}

// Senders racing on one name each land under their own: the collision is
// decided against the live rows under the claims' lock, never against a
// snapshot read before another sender committed and released the name.
func TestConcurrentSameNameSendersNeverOverwriteEachOther(t *testing.T) {
	b := testBackend(t)
	h := New(b, "test", testDomain(t), nil)
	id := createInbox(t, h, `{"name":"inbox","receive":true}`)
	const senders = inboxUploadsPerShare
	var wg sync.WaitGroup
	for i := 0; i < senders; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := fmt.Sprintf("sender %02d", i)
			req := httptest.NewRequest("PUT", "/receive/"+id+"/files/report.txt", strings.NewReader(body))
			req.RemoteAddr = fmt.Sprintf("192.0.2.%d:1234", i+1)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != 201 {
				t.Errorf("sender %d = %d %s", i, rec.Code, rec.Body)
			}
		}(i)
	}
	wg.Wait()
	s, err := b.DB.Share(id)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, f := range s.Files {
		fh, _, err := b.FS.Open(id, f.Path)
		if err != nil {
			t.Fatalf("%s: %v", f.Path, err)
		}
		data, _ := io.ReadAll(fh)
		fh.Close()
		seen[string(data)] = true
	}
	if len(s.Files) != senders || len(seen) != senders {
		t.Fatalf("%d rows holding %d distinct bodies, want %d of each", len(s.Files), len(seen), senders)
	}
}

// Two uploads that each fit the disk alone cannot both be admitted while the
// first is still landing: its admission holds its window, so a stranger's
// parallel uploads cannot eat the system reserve between them.
func TestParallelUploadsCannotTogetherPassTheDiskReserve(t *testing.T) {
	b := testBackend(t)
	b.FS.ReservePercent = 10
	b.FS.DiskSpace = func(string) (int64, int64, error) { return 1150, 10000, nil } // 150 usable
	h := New(b, "test", testDomain(t), nil)
	id := createInbox(t, h, `{"name":"inbox","receive":true}`)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	done := make(chan int)
	go func() {
		req := httptest.NewRequest("PUT", "/receive/"+id+"/files/first",
			&inboxHeldBody{Reader: strings.NewReader(strings.Repeat("x", 70)), entered: entered, release: release})
		req.ContentLength = 70
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		done <- rec.Code
	}()
	<-entered
	rec := doReq(t, h, "PUT", "/receive/"+id+"/files/second", "", strings.Repeat("y", 100))
	if rec.Code != 507 || errCode(t, rec.Body.String()) != "no-space" {
		t.Fatalf("second upload = %d %s, want 507 no-space", rec.Code, rec.Body)
	}
	close(release)
	if code := <-done; code != 201 {
		t.Fatalf("first upload = %d", code)
	}
}

// A stranger's file name cannot carry a control character or a bidi
// override: it is shown to the owner in a push banner, a terminal and a
// listing, where either could make one file read as another.
func TestInboxRefusesNamesThatDisplayAsSomethingElse(t *testing.T) {
	h := newTestAPI(t)
	id := createInbox(t, h, `{"name":"inbox","receive":true}`)
	for _, name := range []string{"invoice%E2%80%AEfdp.exe", "a%1B%5B2Jb", "tab%09name", "c1%C2%9Bx", "bad%FFutf8", "iso%E2%81%A6x"} {
		if rec := doReq(t, h, "PUT", "/receive/"+id+"/files/"+name, "", "x"); rec.Code != 400 {
			t.Errorf("%s = %d %s, want 400", name, rec.Code, rec.Body)
		}
	}
	for _, name := range []string{"report.pdf", "caf%C3%A9.txt", "%D7%A9%D7%9C%D7%95%D7%9D.txt", "emoji%F0%9F%98%80.png"} {
		if rec := doReq(t, h, "PUT", "/receive/"+id+"/files/"+name, "", "x"); rec.Code != 201 {
			t.Errorf("%s = %d %s, want 201", name, rec.Code, rec.Body)
		}
	}
}

// The note's limit counts characters, as its message says: 500 letters of a
// script whose letters take three bytes each are a note, not a refusal.
func TestTheInboxNoteLimitCountsCharacters(t *testing.T) {
	h := newTestAPI(t)
	cjk := strings.Repeat("字", inboxNoteLimit)
	id := createInbox(t, h, `{"name":"inbox","receive":true,"note":"`+cjk+`"}`)
	if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"note":"`+cjk+`"}`); rec.Code != 200 {
		t.Fatalf("PATCH with %d characters = %d %s", inboxNoteLimit, rec.Code, rec.Body)
	}
	for _, rec := range []*httptest.ResponseRecorder{
		doReq(t, h, "POST", "/api/shares", testToken, `{"name":"inbox","receive":true,"note":"`+cjk+`x"}`),
		doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"note":"`+cjk+`x"}`),
	} {
		if rec.Code != 400 {
			t.Fatalf("one character past the limit = %d %s", rec.Code, rec.Body)
		}
	}
}

// The per-address bound counts an IPv6 /64 as one address, the way the
// lockouts do: a host holding a /64 would otherwise take every slot of an
// inbox, one address per upload.
func TestTheInboxSlotBoundCountsAnIPv6PrefixAsOneAddress(t *testing.T) {
	_, hd := newTestAPIParts(t)
	h := hd.routes()
	id := createInbox(t, h, `{"name":"inbox","receive":true}`)
	for i := 0; i < inboxUploadsPerAddr; i++ {
		release, ok := hd.inboxSlots.take(id, addrKey(fmt.Sprintf("2001:db8::%x", i+1)))
		if !ok {
			t.Fatalf("slot %d refused", i)
		}
		defer release()
	}
	req := httptest.NewRequest("PUT", "/receive/"+id+"/files/a.txt", strings.NewReader("x"))
	req.RemoteAddr = "[2001:db8::beef]:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 429 || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("another address of the same /64 = %d %s, want 429 with Retry-After", rec.Code, rec.Body)
	}
	req = httptest.NewRequest("PUT", "/receive/"+id+"/files/b.txt", strings.NewReader("x"))
	req.RemoteAddr = "[2001:db8:0:1::1]:1234"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 201 {
		t.Fatalf("an address of another /64 = %d %s, want 201", rec.Code, rec.Body)
	}
}

// An inbox holding as many files as the server's bound takes does not look
// open while it refuses everyone: its page says it is full and offers no
// drop zone, and the owner's view reports the bound as its file cap.
func TestAnInboxAtTheServerBoundReadsAsFull(t *testing.T) {
	defer func(n int) { metadb.InboxMaxFiles = n }(metadb.InboxMaxFiles)
	metadb.InboxMaxFiles = 2
	b := testBackend(t)
	h := New(b, "test", testDomain(t), nil)
	id := createInbox(t, h, `{"name":"inbox","receive":true}`)
	if rec := doReq(t, h, "GET", "/receive/"+id, "", ""); strings.Contains(rec.Body.String(), "is full") ||
		!strings.Contains(rec.Body.String(), `id="zone"`) {
		t.Fatalf("an open inbox's page:\n%s", rec.Body)
	}
	if got := ownerMaxFiles(t, h, id); got != 0 {
		t.Fatalf("maxFiles below the bound = %d, want the stored 0", got)
	}
	for _, name := range []string{"a", "b"} {
		if rec := doReq(t, h, "PUT", "/receive/"+id+"/files/"+name, "", "x"); rec.Code != 201 {
			t.Fatalf("upload %s = %d %s", name, rec.Code, rec.Body)
		}
	}
	rec := doReq(t, h, "GET", "/receive/"+id, "", "")
	if !strings.Contains(rec.Body.String(), "is full") || strings.Contains(rec.Body.String(), `id="zone"`) {
		t.Fatalf("a full inbox's page:\n%s", rec.Body)
	}
	if got := ownerMaxFiles(t, h, id); got != 2 {
		t.Fatalf("maxFiles at the bound = %d, want the bound", got)
	}
	if rec := doReq(t, h, "GET", "/api/shares?kind=receive", testToken, ""); !strings.Contains(rec.Body.String(), `"maxFiles":2`) {
		t.Fatalf("the inbox listing does not report the bound: %s", rec.Body)
	}
}

// A file cap above the server's bound is stored as the bound, so the page
// never advertises more files than the server takes; one stored above it
// already is reported and advertised as the bound.
func TestAFileCapAboveTheServerBoundIsTheBound(t *testing.T) {
	defer func(n int) { metadb.InboxMaxFiles = n }(metadb.InboxMaxFiles)
	metadb.InboxMaxFiles = 3
	b := testBackend(t)
	h := New(b, "test", testDomain(t), nil)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"inbox","receive":true,"maxFiles":50}`)
	var created struct {
		ID       string `json:"id"`
		MaxFiles int    `json:"maxFiles"`
	}
	unmarshal(t, rec, &created)
	if rec.Code != 201 || created.MaxFiles != 3 {
		t.Fatalf("create = %d %s, want maxFiles 3", rec.Code, rec.Body)
	}
	if s, err := b.DB.Share(created.ID); err != nil || s.MaxFiles != 3 {
		t.Fatalf("stored maxFiles = %d, %v", s.MaxFiles, err)
	}
	old, err := b.DB.CreateShare(metadb.CreateOptions{Name: "old", Owner: metadb.DefaultAdminName, Inbox: true, MaxFiles: 50})
	if err != nil {
		t.Fatal(err)
	}
	if got := ownerMaxFiles(t, h, old.ID); got != 3 {
		t.Fatalf("a stored cap above the bound reports %d, want 3", got)
	}
	page := doReq(t, h, "GET", "/receive/"+old.ID, "", "").Body.String()
	if !strings.Contains(page, "3 files") || strings.Contains(page, "50 files") {
		t.Fatalf("the page advertises the stored cap:\n%s", page)
	}
}

// ownerMaxFiles is the maxFiles the owner's read of an inbox reports.
func ownerMaxFiles(t *testing.T, h http.Handler, id string) int {
	t.Helper()
	rec := doReq(t, h, "GET", "/api/shares/"+id, testToken, "")
	var out struct {
		MaxFiles int `json:"maxFiles"`
	}
	unmarshal(t, rec, &out)
	return out.MaxFiles
}

// A stranger's name at the byte limit that collides lands numbered, its stem
// shortened to fit, rather than refused as a name the share cannot hold.
func TestAnInboxNumbersACollidingNameAtTheByteLimit(t *testing.T) {
	h := newTestAPI(t)
	id := createInbox(t, h, `{"name":"inbox","receive":true}`)
	name := strings.Repeat("a", 251) + ".pdf"
	for i, want := range []string{name, strings.Repeat("a", 249) + " 2.pdf"} {
		rec := doReq(t, h, "PUT", "/receive/"+id+"/files/"+name, "", "x")
		var out struct {
			Name string `json:"name"`
		}
		unmarshal(t, rec, &out)
		if rec.Code != 201 || out.Name != want {
			t.Fatalf("upload %d = %d %s, want 201 as %q", i, rec.Code, rec.Body, want)
		}
	}
}
