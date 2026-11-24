package api

import (
	"testing"
	"time"
)

// SIGTERM's drain reaches the parked long-polls through the Server returned
// by NewServer: forgetting to wire either hub would put the watch
// timeout back into every restart.
func TestServerDrainReleasesAParkedWatch(t *testing.T) {
	srv := NewServer(testBackend(t), "2.0.0", testDomain(t), nil,
		Deployment{DataDir: t.TempDir()})

	_, first := getWatch(t, srv, testToken, "") // resolves the current cursor
	start := time.Now()
	done := make(chan watchResp, 1)
	go func() {
		_, resp := getWatch(t, srv, testToken, first.Cursor)
		done <- resp
	}()
	time.Sleep(50 * time.Millisecond) // let the request park
	srv.Drain()
	select {
	case resp := <-done:
		if resp.Changed {
			t.Fatal("a drain is not a change")
		}
		if time.Since(start) > 2*time.Second {
			t.Fatal("the watch held past the drain")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the drain did not release the parked watch")
	}
}
