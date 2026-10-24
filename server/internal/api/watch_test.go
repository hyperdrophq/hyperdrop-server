package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/metadb"
)

// newTestWatchAPI builds the handler directly (rather than through New) so a
// test can shorten the 50 s park: the tests here are about the blocking
// behaviour, and waiting out the real timeout would take minutes.
func newTestWatchAPI(t *testing.T, timeout time.Duration) (http.Handler, *metadb.DB) {
	t.Helper()
	b := testBackend(t)
	h := newHandler(b, "2.0.0", testDomain(t), nil, Deployment{})
	h.watch.watchTimeout = timeout
	return h.routes(), b.DB
}

type watchResp struct {
	Cursor  string `json:"cursor"`
	Changed bool   `json:"changed"`
	Code    string `json:"code"`
}

func getWatch(t *testing.T, h http.Handler, token, since string) (int, watchResp) {
	t.Helper()
	rec := doReq(t, h, "GET", "/api/shares/watch?since="+since, token, "")
	var body watchResp
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
	}
	return rec.Code, body
}

func TestWatchAnswersAFirstCallImmediately(t *testing.T) {
	h, _ := newTestWatchAPI(t, time.Minute)
	start := time.Now()
	code, body := getWatch(t, h, testToken, "")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if body.Changed {
		t.Fatal("a client with no cursor is handed one to watch with, not a re-walk")
	}
	if body.Cursor == "" {
		t.Fatal("the response must always carry the current cursor")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("first call blocked")
	}
}

func TestWatchRequiresAToken(t *testing.T) {
	h, _ := newTestWatchAPI(t, time.Second)
	if code, _ := getWatch(t, h, "", ""); code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", code)
	}
}

func TestWatchWakesWhenAShareIsCreated(t *testing.T) {
	h, db := newTestWatchAPI(t, 10*time.Second)
	_, first := getWatch(t, h, testToken, "")

	done := make(chan watchResp, 1)
	go func() {
		_, b := getWatch(t, h, testToken, first.Cursor)
		done <- b
	}()
	time.Sleep(200 * time.Millisecond) // let the request park
	if _, err := db.CreateShare(metadb.CreateOptions{Name: "woken", Owner: metadb.DefaultAdminName}); err != nil {
		t.Fatal(err)
	}

	select {
	case b := <-done:
		if !b.Changed {
			t.Fatal("creating a share must wake the watcher")
		}
		if b.Cursor == first.Cursor {
			t.Fatal("the cursor must move so the next poll does not re-fire")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("watcher never woke")
	}
}

func TestWatchTimesOutUnchanged(t *testing.T) {
	h, _ := newTestWatchAPI(t, 300*time.Millisecond)
	_, first := getWatch(t, h, testToken, "")
	code, b := getWatch(t, h, testToken, first.Cursor)
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if b.Changed {
		t.Fatal("nothing changed")
	}
	if b.Cursor != first.Cursor {
		t.Fatalf("an unchanged answer must return the same cursor: %q -> %q", first.Cursor, b.Cursor)
	}
}

func TestWatchIsOwnerScoped(t *testing.T) {
	h, db := newTestWatchAPI(t, 900*time.Millisecond)
	guestToken := seedUser(t, db, "guest")
	_, gFirst := getWatch(t, h, guestToken, "")

	done := make(chan watchResp, 1)
	go func() {
		_, b := getWatch(t, h, guestToken, gFirst.Cursor)
		done <- b
	}()
	time.Sleep(150 * time.Millisecond)
	// The ADMIN's share, not the guest's.
	if _, err := db.CreateShare(metadb.CreateOptions{Name: "not yours", Owner: metadb.DefaultAdminName}); err != nil {
		t.Fatal(err)
	}

	select {
	case b := <-done:
		if b.Changed {
			t.Fatal("another account's share must not wake this watcher")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("watcher never returned")
	}
}

// Admin's watch is owner-scoped like everyone's, so a guest's share must not
// wake it.
func TestWatchDoesNotWakeAdminForAnotherOwnersShare(t *testing.T) {
	h, db := newTestWatchAPI(t, 900*time.Millisecond)
	seedUser(t, db, "guest")
	_, first := getWatch(t, h, testToken, "")

	done := make(chan watchResp, 1)
	go func() {
		_, b := getWatch(t, h, testToken, first.Cursor)
		done <- b
	}()
	time.Sleep(150 * time.Millisecond)
	if _, err := db.CreateShare(metadb.CreateOptions{Name: "guest's", Owner: "guest"}); err != nil {
		t.Fatal(err)
	}

	select {
	case b := <-done:
		if b.Changed {
			t.Fatal("another account's share must not wake the admin's watcher")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("admin watcher never returned")
	}
}

func TestWatchRefusesPastThePerOwnerCap(t *testing.T) {
	h, _ := newTestWatchAPI(t, 3*time.Second)
	_, first := getWatch(t, h, testToken, "")

	// Hold watchMaxPerOwner requests open, then try one more.
	for i := 0; i < watchMaxPerOwner; i++ {
		go getWatch(t, h, testToken, first.Cursor)
	}
	time.Sleep(500 * time.Millisecond)
	code, b := getWatch(t, h, testToken, first.Cursor)
	if code != http.StatusTooManyRequests {
		t.Fatalf("want 429 past the cap, got %d", code)
	}
	if b.Code != "too-many-watchers" {
		t.Fatalf("want a code the client can act on, got %q", b.Code)
	}
}

// The route is a literal segment under /api/shares/{id}, so Go's ServeMux must
// prefer it, or "watch" would be read as a share id and 404.
func TestWatchIsNotSwallowedByTheShareIDRoute(t *testing.T) {
	h, _ := newTestWatchAPI(t, time.Second)
	rec := doReq(t, h, "GET", "/api/shares/watch", testToken, "")
	if rec.Code == http.StatusNotFound {
		t.Fatal("GET /api/shares/{id} matched \"watch\" as an id")
	}
	if !strings.Contains(rec.Body.String(), "cursor") {
		t.Fatalf("not the watch response: %s", rec.Body.String())
	}
}

// One person's devices each hold a watch, and a device waking from sleep
// holds a new one while its old connection lingers until the park ends: a
// dozen held watches still leave room for the next.
func TestWatchFitsAPersonsDevicesAndTheirReconnects(t *testing.T) {
	h, _ := newTestWatchAPI(t, 3*time.Second)
	_, first := getWatch(t, h, testToken, "")
	for i := 0; i < 12; i++ {
		go getWatch(t, h, testToken, first.Cursor)
	}
	time.Sleep(500 * time.Millisecond)
	if code, b := getWatch(t, h, testToken, first.Cursor); code != http.StatusOK {
		t.Fatalf("the 13th watch: %d %q, want 200", code, b.Code)
	}
}
