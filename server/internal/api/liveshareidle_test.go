package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"hyperdrop/server/internal/liveshare"
	"hyperdrop/server/internal/metadb"
)

// stalledVisitor is a response whose client takes nothing: a write blocks
// until the write deadline set on it has passed, and then fails as a
// connection's does.
type stalledVisitor struct {
	header http.Header

	mu       sync.Mutex
	deadline time.Time
	moved    chan struct{} // closed and replaced when the deadline moves
}

func newStalledVisitor() *stalledVisitor {
	return &stalledVisitor{header: http.Header{}, moved: make(chan struct{})}
}

func (s *stalledVisitor) Header() http.Header { return s.header }
func (s *stalledVisitor) WriteHeader(int)     {}

func (s *stalledVisitor) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deadline = t
	close(s.moved)
	s.moved = make(chan struct{})
	return nil
}

func (s *stalledVisitor) Write([]byte) (int, error) {
	for {
		s.mu.Lock()
		deadline, moved := s.deadline, s.moved
		s.mu.Unlock()
		wait := time.Hour
		if !deadline.IsZero() {
			if wait = time.Until(deadline); wait <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
		}
		select {
		case <-moved:
		case <-time.After(wait):
		}
	}
}

// A visitor that takes nothing of a live file keeps its transfer while nobody
// waits. Once the share is full and a visitor waits in line, the transfer is
// ended: its blocked write fails, its response is aborted as a dropped
// connection is rather than finished, the sharer's upload for it breaks, and
// the visitor in line is offered to the sharer in its place.
func TestALiveTransferHeldIdleIsEndedForAVisitorInLine(t *testing.T) {
	const idleWindow = 300 * time.Millisecond
	h := newTestHandlerLiveShare(t, liveshare.Config{ProbeWindow: 10 * time.Millisecond,
		IdleWindow: idleWindow, MaxJobs: liveshare.MinJobsPerShare})
	mux := h.routes()
	sh := createLiveShare(t, mux, testToken, `{"name":"demo","files":[`+
		`{"path":"f.bin","size":1048576,"mime":"application/octet-stream","mtime":"2026-08-06T10:00:00Z"}]}`)
	path := "/download/" + sh.ID + "/" + sh.Files[0].Slug
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	offers := func(want int) []liveshare.Offer {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			offers, err := h.liveShareReg.Poll(context.Background(), sh.ID, metadb.DefaultAdminName, 20*time.Millisecond)
			if err != nil {
				t.Fatal(err)
			}
			if len(offers) == want {
				return offers
			}
			if time.Now().After(deadline) {
				t.Fatalf("offers = %d, want %d", len(offers), want)
			}
		}
	}
	park := func(addr string) {
		r := httptest.NewRequest("GET", path, nil).WithContext(ctx)
		r.RemoteAddr = addr
		go mux.ServeHTTP(httptest.NewRecorder(), r)
	}

	// The stalled visitor: its request ends with what the handler panicked
	// with, nil for an ordinary return.
	ended := make(chan any, 1)
	go func() {
		defer func() { ended <- recover() }()
		r := httptest.NewRequest("GET", path, nil).WithContext(ctx)
		r.RemoteAddr = "192.0.2.1:1000"
		mux.ServeHTTP(newStalledVisitor(), r)
	}()
	c, ok := h.liveShareReg.Claim(metadb.DefaultAdminName, offers(1)[0].Job)
	if !ok {
		t.Fatal("claim refused")
	}
	sharer := make(chan error, 1)
	go func() {
		chunk := make([]byte, 4<<10)
		for {
			if _, err := c.Write(chunk); err != nil {
				sharer <- err
				return
			}
		}
	}()
	// The rest of the share's places, each waiting for a claim.
	for i := range liveshare.MinJobsPerShare - 1 {
		park(fmt.Sprintf("198.51.100.%d:1000", i+1))
	}
	offers(liveshare.MinJobsPerShare - 1)

	time.Sleep(3 * idleWindow)
	select {
	case v := <-ended:
		t.Fatalf("the transfer ended with nobody in line: %v", v)
	default:
	}

	park("203.0.113.60:1000")
	select {
	case v := <-ended:
		if v != http.ErrAbortHandler {
			t.Fatalf("the idle transfer's request ended with %v, want the response aborted", v)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the idle transfer was not ended for the visitor in line")
	}
	select {
	case <-sharer:
	case <-time.After(5 * time.Second):
		t.Fatal("the sharer's upload for the ended transfer went on")
	}
	offers(liveshare.MinJobsPerShare)
}
