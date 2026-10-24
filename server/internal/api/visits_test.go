package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// visitorsOf reads the count the owner's client reads, after a flush.
func visitorsOf(t *testing.T, h *handler, mux http.Handler, id string) int {
	t.Helper()
	if err := h.visits.flush(); err != nil {
		t.Fatal(err)
	}
	var row struct {
		Visitors int `json:"visitors"`
	}
	unmarshal(t, doReq(t, mux, "GET", "/api/shares/"+id, testToken, ""), &row)
	return row.Visitors
}

// get performs a GET with the given cookies, User-Agent and peer address.
func get(mux http.Handler, path, ua, addr string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", path, nil)
	req.RemoteAddr = addr
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func visitorCookieOf(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == visitorCookie {
			return c
		}
	}
	return nil
}

func TestTheSharePageMintsTheVisitorCookieAndCountsOnce(t *testing.T) {
	mux, h := newTestAPIParts(t)
	id, slugs := shareWithFiles(t, mux, "s", map[string]string{"a.txt": "data"})
	first := get(mux, "/share/"+id, "Mozilla/5.0", "10.0.0.1:1", nil)
	if first.Code != 302 {
		t.Fatalf("single-file share page = %d, want the redirect", first.Code)
	}
	c := visitorCookieOf(t, first)
	if c == nil {
		t.Fatal("the share page minted no hd_visitor cookie")
	}
	if c.Path != "/" || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.MaxAge != 365*24*3600 || !validVisitor(c.Value) {
		t.Fatalf("cookie shape: %+v", c)
	}
	// The redirect target carries the cookie the page minted: one visitor.
	if rec := get(mux, "/view/"+id+"/"+slugs["a.txt"], "Mozilla/5.0", "10.0.0.2:2", []*http.Cookie{c}); rec.Code != 200 {
		t.Fatalf("view = %d", rec.Code)
	}
	if n := visitorsOf(t, h, mux, id); n != 1 {
		t.Fatalf("one browser = %d visitors, want 1", n)
	}
	// A second browser is a second visitor; the same cookie again is not.
	second := get(mux, "/share/"+id, "Mozilla/5.0", "10.0.0.2:1", nil)
	get(mux, "/view/"+id+"/"+slugs["a.txt"], "Mozilla/5.0", "10.0.0.2:2", []*http.Cookie{visitorCookieOf(t, second)})
	get(mux, "/view/"+id+"/"+slugs["a.txt"], "Mozilla/5.0", "10.0.0.1:3", []*http.Cookie{c})
	if n := visitorsOf(t, h, mux, id); n != 2 {
		t.Fatalf("two browsers = %d visitors, want 2", n)
	}
	// A page carrying a valid cookie mints none.
	if again := get(mux, "/share/"+id, "Mozilla/5.0", "10.0.0.1:4", []*http.Cookie{c}); visitorCookieOf(t, again) != nil {
		t.Fatal("re-minted a cookie the browser already carries")
	}
}

func TestCookielessReadsCountOncePerAddressAndAgent(t *testing.T) {
	mux, h := newTestAPIParts(t)
	id, slugs := shareWithFiles(t, mux, "s", map[string]string{"a.txt": "data"})
	path := "/download/" + id + "/" + slugs["a.txt"]
	get(mux, path, "curl/8.0", "203.0.113.5:40000", nil)
	get(mux, path, "curl/8.0", "203.0.113.5:40001", nil)
	if n := visitorsOf(t, h, mux, id); n != 1 {
		t.Fatalf("curl twice = %d visitors, want 1", n)
	}
	get(mux, path, "Wget/1.21", "203.0.113.5:40002", nil)
	if n := visitorsOf(t, h, mux, id); n != 2 {
		t.Fatalf("a second agent = %d visitors, want 2", n)
	}
	// A cookie not in the minted shape is ignored, so a forged value cannot
	// count as a new visitor per request; the request falls back to address and agent.
	forged := &http.Cookie{Name: visitorCookie, Value: "not-a-minted-value"}
	get(mux, path, "curl/8.0", "203.0.113.5:40003", []*http.Cookie{forged})
	if n := visitorsOf(t, h, mux, id); n != 2 {
		t.Fatalf("a forged cookie = %d visitors, want 2", n)
	}
}

func TestOwnersAndUnfurlersAreNotVisitors(t *testing.T) {
	mux, h := newTestAPIParts(t)
	id, slugs := shareWithFiles(t, mux, "s", map[string]string{"a.txt": "data"})
	req := httptest.NewRequest("GET", "/download/"+id+"/"+slugs["a.txt"], nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("owner fetch = %d", rec.Code)
	}
	get(mux, "/share/"+id, "Slackbot-LinkExpanding 1.0", "198.51.100.1:1", nil)
	get(mux, "/view/"+id+"/"+slugs["a.txt"], "Twitterbot/1.0", "198.51.100.2:1", nil)
	if n := visitorsOf(t, h, mux, id); n != 0 {
		t.Fatalf("owner and bots = %d visitors, want 0", n)
	}
}

func TestTheWaitingPageAndTheZipCount(t *testing.T) {
	mux, h := newTestAPIParts(t)
	rec := doReq(t, mux, "POST", "/api/shares", testToken, `{"name":"p","files":[{"path":"a.txt","size":4},{"path":"b.txt","size":4}]}`)
	var out struct {
		ID string `json:"id"`
	}
	unmarshal(t, rec, &out)
	get(mux, "/share/"+out.ID, "Mozilla/5.0", "10.0.0.9:1", nil) // waiting page: nothing landed yet
	if n := visitorsOf(t, h, mux, out.ID); n != 0 {
		t.Fatalf("the waiting page counted %d", n)
	}
	doReq(t, mux, "PUT", "/api/shares/"+out.ID+"/files/a.txt", testToken, "data")
	doReq(t, mux, "PUT", "/api/shares/"+out.ID+"/files/b.txt", testToken, "data")
	if z := get(mux, "/zip/"+out.ID, "Mozilla/5.0", "10.0.0.9:2", nil); z.Code != 200 {
		t.Fatalf("zip = %d", z.Code)
	}
	if n := visitorsOf(t, h, mux, out.ID); n != 1 {
		t.Fatalf("one zip = %d visitors, want 1", n)
	}
}

func TestInboxPageCountsAndSiteRootOnlyMints(t *testing.T) {
	mux, h := newTestAPIParts(t)
	inbox := createInbox(t, mux, `{"name":"inbox","receive":true}`)
	get(mux, "/receive/"+inbox, "Mozilla/5.0", "10.0.0.3:1", nil)
	if n := visitorsOf(t, h, mux, inbox); n != 1 {
		t.Fatalf("inbox page = %d visitors, want 1", n)
	}
	id, _ := shareWithFiles(t, mux, "site", map[string]string{"index.html": "<html>hi</html>"})
	root := get(mux, "/site/"+id, "Mozilla/5.0", "10.0.0.4:1", nil)
	if root.Code != 301 || visitorCookieOf(t, root) == nil {
		t.Fatalf("site root = %d, cookie %v; want a 301 carrying hd_visitor", root.Code, visitorCookieOf(t, root))
	}
	if n := visitorsOf(t, h, mux, id); n != 0 {
		t.Fatalf("the site root redirect counted %d", n)
	}
	get(mux, "/site/"+id+"/", "Mozilla/5.0", "10.0.0.4:2", []*http.Cookie{visitorCookieOf(t, root)})
	if n := visitorsOf(t, h, mux, id); n != 1 {
		t.Fatalf("the site page = %d visitors, want 1", n)
	}
}

// close must not block when run was never started: newTestAPIParts, like
// every other test constructor, never starts the flusher goroutine, so
// close has to write what is pending without waiting on a done channel
// nothing will ever close.
func TestVisitTrackerCloseWithoutRunDoesNotDeadlock(t *testing.T) {
	_, h := newTestAPIParts(t)
	h.visits.note("share1", [32]byte{1})
	done := make(chan struct{})
	go func() {
		h.visits.close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("close blocked forever with run never started")
	}
}

func TestPendingVisitsFlushOnDrain(t *testing.T) {
	b := testBackend(t)
	srv := NewServer(b, "2.0.0", testDomain(t), nil, Deployment{DataDir: t.TempDir()})
	id, slugs := shareWithFiles(t, srv, "s", map[string]string{"a.txt": "data"})
	get(srv, "/download/"+id+"/"+slugs["a.txt"], "curl/8.0", "203.0.113.9:1", nil)
	srv.Drain()
	d, err := b.DB.Share(id)
	if err != nil {
		t.Fatal(err)
	}
	if d.Visitors != 1 {
		t.Fatalf("after Drain: %d visitors, want 1", d.Visitors)
	}
}
