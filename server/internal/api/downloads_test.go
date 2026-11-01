package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"hyperdrop/server/internal/metadb"
)

// The count answers "is anyone pulling this share right now", which an owner
// about to delete or change it needs.
func TestDownloadsCountsWhatIsInFlight(t *testing.T) {
	d := newDownloads()
	if got := d.active("a"); got != 0 {
		t.Fatalf("idle share = %d", got)
	}
	end := d.begin("a", "u")
	if got := d.active("a"); got != 1 {
		t.Errorf("during = %d, want 1", got)
	}
	end()
	if got := d.active("a"); got != 0 {
		t.Errorf("after = %d, want 0", got)
	}
}

func TestDownloadsAreCountedPerShare(t *testing.T) {
	d := newDownloads()
	endA := d.begin("a", "u")
	defer endA()
	if got := d.active("b"); got != 0 {
		t.Errorf("other share = %d, want 0", got)
	}
}

func TestDownloadsCountConcurrentReadersOfOneShare(t *testing.T) {
	d := newDownloads()
	first, second := d.begin("a", "u"), d.begin("a", "u")
	if got := d.active("a"); got != 2 {
		t.Fatalf("two readers = %d", got)
	}
	first()
	if got := d.active("a"); got != 1 {
		t.Errorf("one left = %d", got)
	}
	second()
	if got := d.active("a"); got != 0 {
		t.Errorf("none left = %d", got)
	}
}

// An end() called twice (a handler that both defers and calls it) must not
// push the count below zero and hide a real download.
func TestDownloadsEndIsIdempotent(t *testing.T) {
	d := newDownloads()
	end := d.begin("a", "u")
	end()
	end()
	if got := d.active("a"); got != 0 {
		t.Fatalf("after a double end = %d, want 0", got)
	}
	end2 := d.begin("a", "u")
	defer end2()
	if got := d.active("a"); got != 1 {
		t.Errorf("a later reader = %d, want 1", got)
	}
}

// The map must not grow forever: a share nobody is reading holds no entry.
func TestDownloadsForgetsIdleShares(t *testing.T) {
	d := newDownloads()
	end := d.begin("a", "u")
	end()
	d.mu.Lock()
	n := len(d.n)
	d.mu.Unlock()
	if n != 0 {
		t.Fatalf("tracked shares after everyone left = %d, want 0", n)
	}
}

func TestDownloadsIsSafeUnderConcurrency(t *testing.T) {
	d := newDownloads()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			end := d.begin("a", "u")
			_ = d.active("a")
			end()
		}()
	}
	wg.Wait()
	if got := d.active("a"); got != 0 {
		t.Fatalf("after the storm = %d, want 0", got)
	}
}

// The route is what a client actually reads, so it is tested end to end:
// idle answers zero, a download in flight answers one, and another account
// cannot ask about a share it does not own.
func TestShareDownloadsRouteReportsIdle(t *testing.T) {
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "s", map[string]string{"a.txt": "data"})
	rec := doReq(t, h, "GET", "/api/downloads?id="+id, testToken, "")
	if rec.Code != 200 {
		t.Fatalf("code = %d %s", rec.Code, rec.Body)
	}
	var got struct{ Active int }
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Active != 0 {
		t.Errorf("idle share = %d, want 0", got.Active)
	}
}

// Another account's reads are none of your business: an id you do not own
// answers exactly like an id nobody is reading, so the total says nothing
// about somebody else's share.
func TestShareDownloadsRouteIsOwnerScoped(t *testing.T) {
	b := testBackend(t)
	um := b.DB
	h := newHandler(b, "2.0.0", testDomain(t), nil, Deployment{})
	routes := h.routes()
	id, _ := shareWithFiles(t, routes, "s", map[string]string{"a.txt": "data"})
	defer h.dl.begin(id, metadb.DefaultAdminName)()

	if n := activeDownloadsVia(t, routes, testToken, id); n != 1 {
		t.Fatalf("the owner's answer = %d, want 1", n)
	}
	other := seedUser(t, um, "someone")
	if n := activeDownloadsVia(t, routes, other, id); n != 0 {
		t.Errorf("another account's answer = %d, want 0", n)
	}
}

// One question covers a whole bulk delete: the ids are summed, and the ones
// nobody is reading cost nothing to ask about.
func TestShareDownloadsRouteTotalsTheIDsAsked(t *testing.T) {
	h := newHandler(testBackend(t), "2.0.0", testDomain(t), nil, Deployment{})
	routes := h.routes()
	first, _ := shareWithFiles(t, routes, "a", map[string]string{"a.txt": "data"})
	second, _ := shareWithFiles(t, routes, "b", map[string]string{"b.txt": "data"})
	third, _ := shareWithFiles(t, routes, "c", map[string]string{"c.txt": "data"})
	defer h.dl.begin(first, metadb.DefaultAdminName)()
	defer h.dl.begin(second, metadb.DefaultAdminName)()
	defer h.dl.begin(second, metadb.DefaultAdminName)()

	if n := activeDownloadsVia(t, routes, testToken, first, second, third); n != 3 {
		t.Errorf("total across three shares = %d, want 3", n)
	}
	if n := activeDownloadsVia(t, routes, testToken, third); n != 0 {
		t.Errorf("the idle share alone = %d, want 0", n)
	}
}

func TestShareDownloadsRouteNeedsAnID(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "GET", "/api/downloads", testToken, "")
	if rec.Code != 400 {
		t.Fatalf("no id = %d, want 400", rec.Code)
	}
}

// A served file counts WHILE it is being written, which is the whole point:
// the owner asks mid-download and gets a non-zero answer.
func TestADownloadInFlightIsCounted(t *testing.T) {
	h := New(testBackend(t), "2.0.0", testDomain(t), nil)
	id, slugs := shareWithFiles(t, h, "s", map[string]string{"a.txt": "data"})
	slug := slugs["a.txt"]

	seen := make(chan int, 1)
	// The count is read from INSIDE the response write, which is the only
	// moment a real download is in flight.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/download/"+id+"/"+slug, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.ServeHTTP(&countingRecorder{ResponseRecorder: rec, onWrite: func() {
			select {
			case seen <- activeDownloadsVia(t, h, testToken, id):
			default:
			}
		}}, req)
	}()
	<-done
	select {
	case n := <-seen:
		if n != 1 {
			t.Fatalf("count while serving = %d, want 1", n)
		}
	default:
		t.Fatal("the response wrote no body, so nothing was measured")
	}
	if n := activeDownloadsVia(t, h, testToken, id); n != 0 {
		t.Fatalf("count after serving = %d, want 0", n)
	}
}

// The owner pulling their own bytes is not "someone is downloading this":
// Quick Look, a drag out of the app's list and `hyperdrop fetch` all read
// with the owner's own token, and counting them makes the app warn the owner
// about themselves the moment they go to delete what they just previewed.
func TestTheOwnersOwnFetchIsNotCounted(t *testing.T) {
	h := New(testBackend(t), "2.0.0", testDomain(t), nil)
	id, slugs := shareWithFiles(t, h, "s", map[string]string{"a.txt": "data"})

	seen := make(chan int, 1)
	req := httptest.NewRequest("GET", "/download/"+id+"/"+slugs["a.txt"], nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(&countingRecorder{ResponseRecorder: rec, onWrite: func() {
		select {
		case seen <- activeDownloadsVia(t, h, testToken, id):
		default:
		}
	}}, req)
	if rec.Code != 200 {
		t.Fatalf("the owner's own fetch = %d %s", rec.Code, rec.Body)
	}
	select {
	case n := <-seen:
		if n != 0 {
			t.Fatalf("count while the owner reads their own share = %d, want 0", n)
		}
	default:
		t.Fatal("the response wrote no body, so nothing was measured")
	}
}

// activeDownloadsVia reads the count the way a client does, through the route,
// so the test covers the wiring and not just the counter.
func activeDownloadsVia(t *testing.T, h http.Handler, token string, ids ...string) int {
	t.Helper()
	query := ""
	for _, id := range ids {
		query += "&id=" + id
	}
	rec := doReq(t, h, "GET", "/api/downloads?"+query[1:], token, "")
	if rec.Code != 200 {
		t.Fatalf("downloads route = %d %s", rec.Code, rec.Body)
	}
	var got struct{ Active int }
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	return got.Active
}

// countingRecorder runs a hook the first time the handler writes body bytes.
type countingRecorder struct {
	*httptest.ResponseRecorder
	onWrite func()
	fired   bool
}

func (c *countingRecorder) Write(p []byte) (int, error) {
	if !c.fired {
		c.fired = true
		c.onWrite()
	}
	return c.ResponseRecorder.Write(p)
}

// active is how many reads of one share are in flight.
func (d *downloads) active(shareID string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.n[shareID].count
}
