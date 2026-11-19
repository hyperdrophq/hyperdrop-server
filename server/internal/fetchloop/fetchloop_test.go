package fetchloop

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLoopEndsWhenCancelledDuringTheWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	runs := make(chan bool, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		Loop(ctx, time.Hour, func() time.Duration { return time.Hour }, nil, func(nudged bool) { runs <- nudged })
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the loop did not end")
	}
	if len(runs) != 0 {
		t.Fatal("a cancelled wait ran")
	}
}

func TestLoopRunsAfterFirstThenEveryNext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runs := make(chan bool, 3)
	var mu sync.Mutex
	var order []string
	record := func(s string) {
		mu.Lock()
		defer mu.Unlock()
		order = append(order, s)
	}
	go Loop(ctx, 10*time.Millisecond, func() time.Duration { record("next"); return 10 * time.Millisecond },
		nil, func(nudged bool) {
			record("run")
			select {
			case runs <- nudged:
			default:
			}
		})
	for i := range 3 {
		select {
		case nudged := <-runs:
			if nudged {
				t.Fatalf("run %d: a timed run reported a nudge", i)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("run %d did not happen", i)
		}
	}
	cancel()
	mu.Lock()
	defer mu.Unlock()
	// next is asked after each run, never before the first.
	for i, s := range order {
		if want := []string{"run", "next"}[i%2]; s != want {
			t.Fatalf("call %d was %q, want %q (order %v)", i, s, want, order)
		}
	}
}

func TestANudgeDuringARunIsNotLost(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	nudge := make(chan struct{}, 1)
	release := make(chan struct{})
	runs := make(chan bool, 2)
	first := true
	go Loop(ctx, time.Hour, func() time.Duration { return time.Hour }, nudge, func(nudged bool) {
		if first {
			first = false
			// A nudge arrives while this run is still going.
			nudge <- struct{}{}
			<-release
		}
		runs <- nudged
	})
	nudge <- struct{}{}
	close(release)
	for i := range 2 {
		select {
		case nudged := <-runs:
			if !nudged {
				t.Fatalf("run %d was not nudged", i)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("run %d did not happen: the nudge was lost", i)
		}
	}
}

func site(t *testing.T, status int, body string) (*httptest.Server, *string) {
	t.Helper()
	var ua string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua = r.Header.Get("User-Agent")
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &ua
}

func TestGetAtTheLimit(t *testing.T) {
	srv, ua := site(t, http.StatusOK, "12345")
	b, err := Get(context.Background(), srv.Client(), srv.URL+"/f", "hyperdrop-server/1.2.3", 5)
	if err != nil || string(b) != "12345" {
		t.Fatalf("%q %v", b, err)
	}
	if *ua != "hyperdrop-server/1.2.3" {
		t.Fatalf("User-Agent %q", *ua)
	}
}

func TestGetOverTheLimitIsRefused(t *testing.T) {
	srv, _ := site(t, http.StatusOK, "123456")
	b, err := Get(context.Background(), srv.Client(), srv.URL+"/f", "ua", 5)
	if !errors.Is(err, ErrTooLarge) || b != nil {
		t.Fatalf("%q %v", b, err)
	}
	if want := srv.URL + "/f is over 5 bytes"; err.Error() != want {
		t.Fatalf("%q, want %q", err, want)
	}
}

func TestGetRefusesANon200(t *testing.T) {
	srv, _ := site(t, http.StatusNotFound, "gone")
	b, err := Get(context.Background(), srv.Client(), srv.URL+"/f", "ua", 5)
	if err == nil || b != nil || errors.Is(err, ErrTooLarge) {
		t.Fatalf("%q %v", b, err)
	}
	if want := srv.URL + "/f answered 404 Not Found"; err.Error() != want {
		t.Fatalf("%q, want %q", err, want)
	}
}

func TestGetCarriesTheContext(t *testing.T) {
	srv, _ := site(t, http.StatusOK, "x")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Get(ctx, srv.Client(), srv.URL+"/f", "ua", 5); err == nil || !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("%v", err)
	}
}
