package ddns

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func emptyUpdaterFor(t *testing.T, srv *httptest.Server) (*Updater, *Store) {
	t.Helper()
	store, err := Load(filepath.Join(t.TempDir(), "ddns"))
	if err != nil {
		t.Fatal(err)
	}
	return NewUpdater(store, &Client{BaseURL: srv.URL}, func(context.Context) (string, bool) {
		return "203.0.113.7", true
	}), store
}

func TestChooseClaimsPersistsAndPublishesAFreshName(t *testing.T) {
	var calls []string
	var claimToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path)
		switch r.URL.Path {
		case "/v1/claim":
			var body struct {
				Token string `json:"token"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			claimToken = body.Token
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"name":"alice","expiresAt":9}`))
		case "/v1/update":
			if r.Header.Get("Authorization") != "Bearer "+claimToken {
				t.Errorf("update authorization = %q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{"ip":"203.0.113.7","state":"tentative","expiresAt":99}`))
		}
	}))
	defer srv.Close()
	u, store := emptyUpdaterFor(t, srv)
	if err := u.Choose(context.Background(), "alice", "server-1"); err != nil {
		t.Fatal(err)
	}
	if got := store.Snapshot(); got.Name != "alice" || got.Token == "" || got.Token != claimToken || got.LastIP != "203.0.113.7" || got.Pending {
		t.Fatalf("state = %+v", got)
	}
	if strings.Join(calls, ",") != "/v1/claim,/v1/update" {
		t.Fatalf("calls = %v", calls)
	}
}

func TestPendingClaimResumesWithTheSameTokenAfterARestart(t *testing.T) {
	var attempts atomic.Int64
	var firstToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/claim" {
			var body struct {
				Token string `json:"token"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if firstToken == "" {
				firstToken = body.Token
			} else if body.Token != firstToken {
				t.Errorf("retry token %q, want %q", body.Token, firstToken)
			}
			if attempts.Add(1) == 1 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"name":"alice","expiresAt":9}`))
			return
		}
		_, _ = w.Write([]byte(`{"ip":"203.0.113.7","state":"tentative","expiresAt":99}`))
	}))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "ddns")
	store, _ := Load(path)
	u := NewUpdater(store, &Client{BaseURL: srv.URL}, func(context.Context) (string, bool) { return "203.0.113.7", true })
	if err := u.Choose(context.Background(), "alice", "server-1"); err == nil {
		t.Fatal("first uncertain claim did not fail")
	}
	if got := store.Snapshot(); !got.Pending || got.Token == "" {
		t.Fatalf("uncertain claim was not staged: %+v", got)
	}
	reloaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	u = NewUpdater(reloaded, &Client{BaseURL: srv.URL}, func(context.Context) (string, bool) { return "203.0.113.7", true })
	if err := u.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := reloaded.Snapshot(); got.Pending || !reloaded.Configured() || got.Token != firstToken {
		t.Fatalf("resumed state = %+v", got)
	}
}

func TestChooseRefusesRenameWithoutContactingRegistry(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path == "/v1/replace" {
			_, _ = w.Write([]byte(`{"name":"bravo","expiresAt":9}`))
			return
		}
		_, _ = w.Write([]byte(`{"ip":"203.0.113.7","state":"tentative","expiresAt":99}`))
	}))
	defer srv.Close()
	u, store := updaterFor(t, srv, func(context.Context) (string, bool) { return "203.0.113.7", true })
	if err := u.Choose(context.Background(), "bravo", "server-1"); err != ErrNamePermanent {
		t.Fatalf("rename: %v", err)
	}
	if got := store.Snapshot(); got.Name != "alice" || got.Token != "tok" {
		t.Fatalf("state = %+v", got)
	}
	if len(calls) != 0 {
		t.Fatalf("calls = %v", calls)
	}
}

func TestRenameRemainsRefusedWhenStorageReturns(t *testing.T) {
	var replacements atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/replace":
			replacements.Add(1)
			_, _ = w.Write([]byte(`{"name":"bravo","expiresAt":9}`))
		case "/v1/update":
			_, _ = w.Write([]byte(`{"ip":"203.0.113.7","state":"tentative","expiresAt":99}`))
		}
	}))
	defer srv.Close()
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := Load(filepath.Join(stateDir, "ddns"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set("alice", "tok"); err != nil {
		t.Fatal(err)
	}
	away := filepath.Join(root, "state-away")
	if err := os.Rename(stateDir, away); err != nil {
		t.Fatal(err)
	}
	u := NewUpdater(store, &Client{BaseURL: srv.URL}, func(context.Context) (string, bool) { return "203.0.113.7", true })
	if err := u.Choose(context.Background(), "bravo", "server-1"); err == nil {
		t.Fatal("missing state directory did not fail persistence")
	}
	if err := os.Rename(away, stateDir); err != nil {
		t.Fatal(err)
	}
	if err := u.Choose(context.Background(), "bravo", "server-1"); err != ErrNamePermanent {
		t.Fatalf("retry: %v", err)
	}
	if replacements.Load() != 0 || store.Snapshot().Name != "alice" {
		t.Fatalf("replacements %d state %+v", replacements.Load(), store.Snapshot())
	}
}

func TestReleaseForgetsNothingUntilTheRegistryAcceptsIt(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"released":true}`))
	}))
	defer srv.Close()
	u, store := updaterFor(t, srv, func(context.Context) (string, bool) { return "203.0.113.7", true })
	if err := u.Release(context.Background()); err == nil {
		t.Fatal("failed release returned success")
	}
	if got := store.Snapshot(); got.Name != "alice" || got.Token != "tok" {
		t.Fatalf("failed release forgot state: %+v", got)
	}
	fail.Store(false)
	if err := u.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := store.Snapshot(); got.Name != "" || got.Token != "" {
		t.Fatalf("successful release kept state: %+v", got)
	}
}

func TestReleaseClearsStateWhenTheRegistryAlreadyForgotTheToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	u, store := updaterFor(t, srv, func(context.Context) (string, bool) { return "203.0.113.7", true })
	if err := u.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.Configured() || store.Snapshot().Token != "" {
		t.Fatalf("unknown central token was kept: %+v", store.Snapshot())
	}
}

// A service that counts posts and answers with whatever address it is told
// the caller came from.
func fakeService(t *testing.T, posts *atomic.Int64, ip *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		posts.Add(1)
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"ip":"` + *ip + `","changed":true,"state":"active","expiresAt":9000}`))
	}))
}

func updaterFor(t *testing.T, srv *httptest.Server, addr func(context.Context) (string, bool)) (*Updater, *Store) {
	t.Helper()
	s, err := Load(filepath.Join(t.TempDir(), "ddns"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Set("alice", "tok"); err != nil {
		t.Fatal(err)
	}
	u := NewUpdater(s, &Client{BaseURL: srv.URL}, addr)
	return u, s
}

// The whole point of the cadence: check often, post rarely. Posting every
// tick would cap the service near seventy servers.
func TestTicksPostOnlyWhenTheAddressChanges(t *testing.T) {
	var posts atomic.Int64
	ip := "203.0.113.7"
	srv := fakeService(t, &posts, &ip)
	defer srv.Close()

	u, s := updaterFor(t, srv, func(context.Context) (string, bool) { return ip, true })
	if err := u.Tick(context.Background()); err != nil {
		t.Fatalf("first tick: %v", err)
	}
	if posts.Load() != 1 {
		t.Fatalf("first tick posted %d times, want 1", posts.Load())
	}
	for i := 0; i < 10; i++ {
		if err := u.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if posts.Load() != 1 {
		t.Fatalf("posted %d times for an unchanged address, want 1", posts.Load())
	}
	if got := s.Snapshot(); got.LastIP != "203.0.113.7" {
		t.Fatalf("lastIP %q", got.LastIP)
	}
}

func TestAMovedAddressPostsAtOnce(t *testing.T) {
	var posts atomic.Int64
	ip := "203.0.113.7"
	srv := fakeService(t, &posts, &ip)
	defer srv.Close()

	u, _ := updaterFor(t, srv, func(context.Context) (string, bool) { return ip, true })
	_ = u.Tick(context.Background())
	ip = "198.51.100.4"
	_ = u.Tick(context.Background())
	if posts.Load() != 2 {
		t.Fatalf("posted %d times, want 2", posts.Load())
	}
}

// The probe and the names service are two different observers of the same
// address and can disagree forever (a multi-homed server, an intercepting
// resolver) with the address never having moved at all. A permanent
// disagreement must post once, when the name is first configured, and
// never again on that account.
func TestAPermanentProbeServiceDisagreementPostsOnlyOnce(t *testing.T) {
	var posts atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		posts.Add(1)
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"ip":"203.0.113.7","changed":true,"state":"active","expiresAt":9000}`))
	}))
	defer srv.Close()

	u, _ := updaterFor(t, srv, func(context.Context) (string, bool) { return "198.51.100.9", true })
	for i := 0; i < 10; i++ {
		if err := u.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if got := posts.Load(); got != 1 {
		t.Fatalf("posted %d times for a permanent probe/service disagreement, want 1", got)
	}
}

// The fix for the disagreement above must not disable change detection: a
// probe that genuinely changes still has to post.
func TestAGenuinelyMovedProbeStillPosts(t *testing.T) {
	var posts atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		posts.Add(1)
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"ip":"203.0.113.7","changed":true,"state":"active","expiresAt":9000}`))
	}))
	defer srv.Close()

	probe := "198.51.100.9"
	u, _ := updaterFor(t, srv, func(context.Context) (string, bool) { return probe, true })
	_ = u.Tick(context.Background())
	probe = "198.51.100.20"
	_ = u.Tick(context.Background())
	if got := posts.Load(); got != 2 {
		t.Fatalf("posted %d times across a genuine probe move, want 2", got)
	}
}

// A failed post must leave the last CONFIRMED probe in place: the next
// tick's move comparison has to run against what last succeeded, not
// against a probe from an attempt that never reached the service.
func TestAFailedPostLeavesLastProbeUntouched(t *testing.T) {
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"ip":"203.0.113.7","changed":true,"state":"active","expiresAt":9000}`))
	}))
	defer srv.Close()

	probe := "198.51.100.9"
	u, s := updaterFor(t, srv, func(context.Context) (string, bool) { return probe, true })
	if err := u.Tick(context.Background()); err != nil {
		t.Fatalf("first tick: %v", err)
	}
	before := s.Snapshot()

	fail.Store(true)
	probe = "198.51.100.20" // a genuine move, so the second tick attempts a post
	if err := u.Tick(context.Background()); err == nil {
		t.Fatal("a failing service was not an error")
	}
	got := s.Snapshot()
	if got.LastProbe != before.LastProbe || got.LastIP != before.LastIP || got.LastUpdate != before.LastUpdate {
		t.Fatalf("a failed post moved the last success: before %+v, after %+v", before, got)
	}
	if got.LastError == "" {
		t.Fatal("nothing recorded for the failure")
	}
}

// The twice-daily heartbeat is what keeps the name: sixty days of silence
// releases it, however unchanged the address has been.
func TestAStaleHeartbeatPostsEvenWithAnUnchangedAddress(t *testing.T) {
	var posts atomic.Int64
	ip := "203.0.113.7"
	srv := fakeService(t, &posts, &ip)
	defer srv.Close()

	u, _ := updaterFor(t, srv, func(context.Context) (string, bool) { return ip, true })
	now := time.Unix(1_000_000, 0)
	u.Now = func() time.Time { return now }
	_ = u.Tick(context.Background())
	_ = u.Tick(context.Background())
	if posts.Load() != 1 {
		t.Fatalf("posted %d, want 1 immediately after the first heartbeat", posts.Load())
	}
	now = now.Add(12*time.Hour - time.Minute)
	_ = u.Tick(context.Background())
	if posts.Load() != 1 {
		t.Fatalf("posted %d before 12 hours elapsed, want 1", posts.Load())
	}
	now = now.Add(time.Minute)
	_ = u.Tick(context.Background())
	if posts.Load() != 2 {
		t.Fatalf("posted %d, want the 12-hour heartbeat", posts.Load())
	}
}

func TestHeartbeatIntervalIsTwelveHours(t *testing.T) {
	if Heartbeat != 12*time.Hour {
		t.Fatalf("heartbeat interval = %s, want 12h", Heartbeat)
	}
}

// Every provider failing is no news, not a reason to post or to forget the
// address we already know.
func TestAnUnknownAddressPostsNothingAndKeepsTheLastOne(t *testing.T) {
	var posts atomic.Int64
	ip := "203.0.113.7"
	srv := fakeService(t, &posts, &ip)
	defer srv.Close()

	known := true
	u, s := updaterFor(t, srv, func(context.Context) (string, bool) {
		if !known {
			return "", false
		}
		return ip, true
	})
	_ = u.Tick(context.Background())
	known = false
	for i := 0; i < 5; i++ {
		_ = u.Tick(context.Background())
	}
	if posts.Load() != 1 {
		t.Fatalf("posted %d times while the address was unknown, want 1", posts.Load())
	}
	if got := s.Snapshot(); got.LastIP != "203.0.113.7" {
		t.Fatalf("forgot the last known address: %+v", got)
	}
}

func TestAFailedPostIsRecordedAndDoesNotAdvanceTheLastUpdate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	u, s := updaterFor(t, srv, func(context.Context) (string, bool) { return "203.0.113.7", true })
	if err := u.Tick(context.Background()); err == nil {
		t.Fatal("a failing service was not an error")
	}
	got := s.Snapshot()
	if got.LastError == "" {
		t.Fatal("nothing was recorded for the app to show")
	}
	if got.LastUpdate != 0 {
		t.Fatalf("a failure advanced lastUpdate: %+v", got)
	}
}

// A persistently failing service must not be hammered every tick: without a
// backoff, an IPv6-only server against a service that answers 400 would
// spend 1,440 requests a day against the budget the whole cadence protects.
func TestAFailingPostIsNotRetriedOnTheVeryNextTick(t *testing.T) {
	var posts atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		posts.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	u, _ := updaterFor(t, srv, func(context.Context) (string, bool) { return "198.51.100.9", true })
	if err := u.Tick(context.Background()); err == nil {
		t.Fatal("the first attempt did not fail")
	}
	if posts.Load() != 1 {
		t.Fatalf("posted %d times on the first attempt, want 1", posts.Load())
	}
	if err := u.Tick(context.Background()); err != nil {
		t.Fatalf("a backed-off tick returned an error: %v", err)
	}
	if posts.Load() != 1 {
		t.Fatalf("posted %d times, want the very next tick to back off and post nothing", posts.Load())
	}
}

// Each further consecutive failure must wait longer than the last, so a
// service that stays down for hours settles near the heartbeat rate rather
// than the tick rate.
func TestConsecutiveFailuresWidenTheBackoff(t *testing.T) {
	var posts atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		posts.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	u, _ := updaterFor(t, srv, func(context.Context) (string, bool) { return "198.51.100.9", true })
	now := time.Unix(1_000_000, 0)
	u.Now = func() time.Time { return now }

	if err := u.Tick(context.Background()); err == nil {
		t.Fatal("the first attempt did not fail")
	}
	if posts.Load() != 1 {
		t.Fatalf("posted %d, want 1", posts.Load())
	}

	// Just short of the first backoff (one tick interval): still skipped.
	now = now.Add(TickInterval - time.Second)
	_ = u.Tick(context.Background())
	if posts.Load() != 1 {
		t.Fatalf("posted %d inside the first backoff window, want 1", posts.Load())
	}

	// The first backoff has elapsed: the second attempt fires, and fails.
	now = now.Add(2 * time.Second)
	if err := u.Tick(context.Background()); err == nil {
		t.Fatal("the second attempt did not fail")
	}
	if posts.Load() != 2 {
		t.Fatalf("posted %d once the first backoff elapsed, want 2", posts.Load())
	}

	// The backoff has doubled: one more tick interval is not enough yet.
	now = now.Add(TickInterval)
	_ = u.Tick(context.Background())
	if posts.Load() != 2 {
		t.Fatalf("posted %d inside the doubled backoff window, want 2", posts.Load())
	}

	now = now.Add(TickInterval + time.Second)
	if err := u.Tick(context.Background()); err == nil {
		t.Fatal("the third attempt did not fail")
	}
	if posts.Load() != 3 {
		t.Fatalf("posted %d once the doubled backoff elapsed, want 3", posts.Load())
	}
}

// A success must clear the backoff outright: a fresh failure right after a
// recovery has to wait only one tick interval, not stay skipped by whatever
// streak the failures had reached before the recovery.
func TestASuccessClearsTheBackoff(t *testing.T) {
	var fail atomic.Bool
	var posts atomic.Int64
	addr := "203.0.113.7"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		posts.Add(1)
		if fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"ip":"` + addr + `","changed":true,"state":"active","expiresAt":9000}`))
	}))
	defer srv.Close()

	u, _ := updaterFor(t, srv, func(context.Context) (string, bool) { return addr, true })
	now := time.Unix(1_000_000, 0)
	u.Now = func() time.Time { return now }

	fail.Store(true)
	if err := u.Tick(context.Background()); err == nil {
		t.Fatal("the first attempt did not fail")
	}
	if posts.Load() != 1 {
		t.Fatalf("posted %d, want 1", posts.Load())
	}

	// Past the first backoff deadline, with a genuine address change so
	// this tick has a reason to attempt, and this time it succeeds.
	fail.Store(false)
	now = now.Add(TickInterval + time.Second)
	addr = "198.51.100.4"
	if err := u.Tick(context.Background()); err != nil {
		t.Fatalf("the recovered attempt failed: %v", err)
	}
	if posts.Load() != 2 {
		t.Fatalf("posted %d on the recovered attempt, want 2", posts.Load())
	}

	// A fresh failure right after the success attempts immediately, proving
	// the backoff was cleared rather than merely still counting down.
	fail.Store(true)
	addr = "198.51.100.9"
	now = now.Add(time.Second)
	if err := u.Tick(context.Background()); err == nil {
		t.Fatal("did not attempt on the tick right after the success")
	}
	if posts.Load() != 3 {
		t.Fatalf("posted %d right after the success, want 3", posts.Load())
	}

	// Advance past the single-interval backoff but not the doubled one.
	// With the reset, failStreak is 1 and backoffUntil is now + TickInterval,
	// so a tick at this point should attempt. Without the reset, failStreak is 2
	// and backoffUntil is now + 2*TickInterval, so it would remain backed off.
	now = now.Add(TickInterval + time.Second)
	if err := u.Tick(context.Background()); err == nil {
		t.Fatal("did not attempt past the single-interval backoff (reset was not cleared)")
	}
	if posts.Load() != 4 {
		t.Fatalf("posted %d past the single-interval backoff, want 4", posts.Load())
	}
}

// A server with no name does nothing at all, which is every server that
// never took one.
func TestAnUnconfiguredServerNeverPosts(t *testing.T) {
	var posts atomic.Int64
	ip := "203.0.113.7"
	srv := fakeService(t, &posts, &ip)
	defer srv.Close()

	s, err := Load(filepath.Join(t.TempDir(), "ddns"))
	if err != nil {
		t.Fatal(err)
	}
	u := NewUpdater(s, &Client{BaseURL: srv.URL}, func(context.Context) (string, bool) {
		return ip, true
	})
	if err := u.Tick(context.Background()); err != nil {
		t.Fatalf("Tick on an unconfigured server: %v", err)
	}
	if posts.Load() != 0 {
		t.Fatalf("posted %d times with no name", posts.Load())
	}
}

// A released name is terminal: the loop must stop trying rather than post
// forever against a name somebody else now holds.
func TestAReleasedNameStopsTheLoop(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusGone)
		_, _ = w.Write([]byte(`{"error":"released"}`))
	}))
	defer srv.Close()

	u, s := updaterFor(t, srv, func(context.Context) (string, bool) { return "203.0.113.7", true })
	err := u.Tick(context.Background())
	if !errors.Is(err, ErrReleased) {
		t.Fatalf("Tick error %v, want ErrReleased", err)
	}
	if got := s.Snapshot(); got.LastError == "" {
		t.Fatal("the release was not recorded where the app can show it")
	}
}

// DELETE /api/ddns racing itself calls Stop twice on the same running
// updater; only one call may close the
// channel. The goroutines line up on a shared start signal so they reach
// Stop as close to simultaneously as the scheduler allows.
func TestStopTwiceDoesNotPanic(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "ddns"))
	if err != nil {
		t.Fatal(err)
	}
	u := NewUpdater(s, &Client{}, func(context.Context) (string, bool) { return "", false })
	u.Start(context.Background())

	const callers = 50
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			u.Stop()
		}()
	}
	close(start)
	wg.Wait()
	u.Stop() // a later call, after every other one returned, must also be safe.
}

// Two Start calls (PUT /api/ddns twice, or a PUT racing the boot-time
// start) must not leave two loops running: both would tick, and double the
// posts. The address function counts its own calls, which happen
// synchronously on loop entry, so two loops show up immediately.
func TestStartTwiceRunsOnlyOneLoop(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"ip":"203.0.113.7","changed":true,"state":"active","expiresAt":9000}`))
	}))
	defer srv.Close()

	u, _ := updaterFor(t, srv, func(context.Context) (string, bool) {
		calls.Add(1)
		return "203.0.113.7", true
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	u.Start(ctx)
	u.Start(ctx)
	time.Sleep(50 * time.Millisecond)
	u.Stop()

	if got := calls.Load(); got != 1 {
		t.Fatalf("the address was probed %d times right after two Start calls, want 1", got)
	}
}

// A name taken through PUT /api/ddns must keep heartbeating: Stop (DELETE)
// followed by Start (a later PUT) has to run the
// loop again, not leave it stopped forever.
func TestStopThenStartRunsAgain(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"ip":"203.0.113.7","changed":true,"state":"active","expiresAt":9000}`))
	}))
	defer srv.Close()

	u, _ := updaterFor(t, srv, func(context.Context) (string, bool) {
		calls.Add(1)
		return "203.0.113.7", true
	})
	ctx := context.Background()

	u.Start(ctx)
	time.Sleep(50 * time.Millisecond)
	u.Stop()
	afterStop := calls.Load()
	if afterStop == 0 {
		t.Fatal("no tick happened before Stop")
	}

	u.Start(ctx)
	time.Sleep(50 * time.Millisecond)
	u.Stop()
	if got := calls.Load(); got <= afterStop {
		t.Fatalf("Start after Stop did not run again: %d ticks before, %d after", afterStop, got)
	}
}

// PUT /api/ddns forces a Tick while Run's loop may be ticking on its own
// schedule. Both must not read the same stale snapshot and post twice for
// one unchanged address.
func TestConcurrentTicksPostAtMostOnce(t *testing.T) {
	var posts atomic.Int64
	ip := "203.0.113.7"
	srv := fakeService(t, &posts, &ip)
	defer srv.Close()

	u, _ := updaterFor(t, srv, func(context.Context) (string, bool) { return ip, true })

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = u.Tick(context.Background())
		}()
	}
	wg.Wait()
	if posts.Load() != 1 {
		t.Fatalf("posted %d times for one unchanged address ticked concurrently, want 1", posts.Load())
	}
}

func TestTakeClaimsPersistsAndPosts(t *testing.T) {
	var claimed, posted int
	var claimToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/v1/claim") {
			claimed++
			var body struct {
				Token string `json:"token"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			claimToken = body.Token
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"name":"alice","fqdn":"alice.hyperdrop.link"}`))
			return
		}
		posted++
		_, _ = w.Write([]byte(`{"ip":"203.0.113.7","changed":true,"state":"tentative","expiresAt":9000}`))
	}))
	defer srv.Close()

	s, err := Load(filepath.Join(t.TempDir(), "ddns"))
	if err != nil {
		t.Fatal(err)
	}
	u := NewUpdater(s, &Client{BaseURL: srv.URL}, func(context.Context) (string, bool) {
		return "203.0.113.7", true
	})
	if err := u.Take(context.Background(), "alice", "srv-abc"); err != nil {
		t.Fatalf("Take: %v", err)
	}
	if claimed != 1 || posted != 1 {
		t.Fatalf("claimed %d, posted %d, want 1 and 1", claimed, posted)
	}
	got := s.Snapshot()
	if got.Name != "alice" || got.Token == "" || got.Token != claimToken || got.LastIP != "203.0.113.7" || got.Pending {
		t.Fatalf("state %+v", got)
	}
}

// A server that already holds a name must not claim another on every boot:
// that burns a claim per restart and would trip the per-address limit.
func TestTakeIsANoOpWhenANameIsAlreadyHeld(t *testing.T) {
	var claimed int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/v1/claim") {
			claimed++
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"name":"x","token":"y"}`))
			return
		}
		// The update path answers 200, matching what Update actually expects,
		// so if the no-op guard is ever removed the test fails on the claim
		// count rather than on an unrelated "answered 201" decode error.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ip":"203.0.113.7"}`))
	}))
	defer srv.Close()

	s, _ := Load(filepath.Join(t.TempDir(), "ddns"))
	_ = s.Set("held", "existing-token")
	u := NewUpdater(s, &Client{BaseURL: srv.URL}, func(context.Context) (string, bool) {
		return "203.0.113.7", true
	})
	if err := u.Take(context.Background(), "held", "srv-abc"); err != nil {
		t.Fatalf("Take: %v", err)
	}
	if claimed != 0 {
		t.Fatalf("claimed %d times for a name already held", claimed)
	}
	if got := s.Snapshot(); got.Token != "existing-token" {
		t.Fatalf("the held token was replaced: %+v", got)
	}
}

// A refused claim records why and stores nothing, so a retry is clean and
// GET /api/ddns can say what happened.
func TestARefusedClaimStoresNothingAndRecordsWhy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"taken"}`))
	}))
	defer srv.Close()

	s, _ := Load(filepath.Join(t.TempDir(), "ddns"))
	u := NewUpdater(s, &Client{BaseURL: srv.URL}, func(context.Context) (string, bool) {
		return "203.0.113.7", true
	})
	err := u.Take(context.Background(), "alice", "srv-abc")
	if !errors.Is(err, ErrNameTaken) {
		t.Fatalf("Take error %v, want ErrNameTaken", err)
	}
	if s.Configured() {
		t.Fatal("a refused claim was persisted")
	}
	// The Synology path has no app to show a refusal in: Package Center is
	// the only place the operator is looking, so LastClaimError is the sole
	// channel that carries the service's own words there.
	if got := u.LastClaimError(); !strings.Contains(got, "taken") {
		t.Fatalf("LastClaimError() = %q, want it to carry the service's reason", got)
	}
}

// A successful Take clears whatever reason an earlier refusal recorded, or
// a stale reason would keep being reported for a name that is now held.
func TestASuccessfulTakeClearsLastClaimError(t *testing.T) {
	refuse := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/v1/claim") {
			if refuse {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":"taken"}`))
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"name":"alice","token":"tok-1"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ip":"203.0.113.7"}`))
	}))
	defer srv.Close()

	s, _ := Load(filepath.Join(t.TempDir(), "ddns"))
	u := NewUpdater(s, &Client{BaseURL: srv.URL}, func(context.Context) (string, bool) {
		return "203.0.113.7", true
	})
	if err := u.Take(context.Background(), "alice", "srv-abc"); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("first Take error %v, want ErrNameTaken", err)
	}
	if u.LastClaimError() == "" {
		t.Fatal("the first refusal recorded no reason")
	}

	refuse = false
	if err := u.Take(context.Background(), "alice", "srv-abc"); err != nil {
		t.Fatalf("second Take: %v", err)
	}
	if got := u.LastClaimError(); got != "" {
		t.Fatalf("LastClaimError() = %q after a successful Take, want empty", got)
	}
}

// A fresh claim must publish immediately even when this updater is mid
// backoff for a name it no longer holds: DELETE /api/ddns clears the store
// but not failStreak or backoffUntil, so without resetting them here the
// address just claimed would resolve nowhere until the backoff lapses.
func TestTakeAfterAFailingStreakPublishesImmediately(t *testing.T) {
	var claimed, posted int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/v1/claim") {
			claimed++
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"name":"alice","token":"tok-1"}`))
			return
		}
		posted++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ip":"203.0.113.7"}`))
	}))
	defer srv.Close()

	s, _ := Load(filepath.Join(t.TempDir(), "ddns"))
	u := NewUpdater(s, &Client{BaseURL: srv.URL}, func(context.Context) (string, bool) {
		return "203.0.113.7", true
	})
	u.failStreak = 3
	u.backoffUntil = u.Now().Add(30 * time.Minute)

	if err := u.Take(context.Background(), "alice", "srv-abc"); err != nil {
		t.Fatalf("Take: %v", err)
	}
	if claimed != 1 || posted != 1 {
		t.Fatalf("claimed %d, posted %d, want 1 and 1: a leftover backoff skipped the first publish", claimed, posted)
	}
	if got := s.Snapshot(); got.LastUpdate == 0 {
		t.Fatal("the first publish never happened: the claimed address resolves nowhere")
	}
}

// A token the registry has refused is dead. Replacing the same name has to
// start a real claim rather than heartbeat a connection that does not exist.
func TestReplacingARefusedTokenStartsAFreshClaim(t *testing.T) {
	for _, refusal := range []string{ErrUnknownToken.Error(), ErrReleased.Error()} {
		t.Run(refusal, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/claim":
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(`{"name":"alice","expiresAt":9}`))
				case "/v1/update":
					_, _ = w.Write([]byte(`{"ip":"203.0.113.7","state":"tentative","expiresAt":99}`))
				}
			}))
			defer srv.Close()
			u, store := updaterFor(t, srv, func(context.Context) (string, bool) { return "203.0.113.7", true })
			if err := store.Record("203.0.113.7", "203.0.113.7", 1, refusal); err != nil {
				t.Fatal(err)
			}

			if err := u.Replace(context.Background(), "alice", "server-1"); err != nil {
				t.Fatalf("replace: %v", err)
			}
			if got := store.Snapshot(); got.Token == "tok" {
				t.Fatalf("replace heartbeat a dead token instead of claiming the name: %+v", got)
			}
		})
	}
}

// A healthy connection to the same name is still just a heartbeat.
func TestReplacingAHealthyConnectionOnlyHeartbeats(t *testing.T) {
	var posts atomic.Int64
	ip := "203.0.113.7"
	srv := fakeService(t, &posts, &ip)
	defer srv.Close()
	u, store := updaterFor(t, srv, func(context.Context) (string, bool) { return ip, true })

	if err := u.Replace(context.Background(), "alice", "server-1"); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if got := store.Snapshot(); got.Token != "tok" {
		t.Fatalf("replace threw away a working connection: %+v", got)
	}
}
