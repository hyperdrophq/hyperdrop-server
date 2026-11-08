package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"hyperdrop/server/internal/linked"
	"hyperdrop/server/internal/metadb"
)

// waitUntilBlocked holds until fn reports true, which a goroutine parking in the
// semaphore makes so moments after it starts.
func waitUntilBlocked(t *testing.T, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !fn() {
		if time.Now().After(deadline) {
			t.Fatal("no waiter showed up")
		}
		time.Sleep(time.Millisecond)
	}
}

// pacedClient takes bytes at rate, moving the clock as it does.
type pacedClient struct {
	clock *time.Time
	rate  float64
}

func (c pacedClient) Write(p []byte) (int, error) {
	if c.rate > 0 {
		*c.clock = c.clock.Add(time.Duration(float64(len(p)) / c.rate * float64(time.Second)))
	}
	return len(p), nil
}

func yieldingWriter(waiting *bool, rate float64) (*stallWriter, *time.Time) {
	clock := new(time.Time)
	*clock = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	s := &stallWriter{w: pacedClient{clock: clock, rate: rate}, rc: http.NewResponseController(httptest.NewRecorder()),
		stall: time.Minute, now: func() time.Time { return *clock },
		since: *clock, started: *clock, yield: func() bool { return *waiting }}
	return s, clock
}

func TestASlowStreamGivesUpItsPlaceOnlyForSomeoneWaiting(t *testing.T) {
	waiting := false
	s, _ := yieldingWriter(&waiting, 100<<10)
	send := func(bytes int) error {
		_, err := s.Write(make([]byte, bytes))
		return err
	}
	if err := send(100 << 10 * 60 * 30); err != nil {
		t.Fatalf("with nobody waiting the stream ended: %v", err)
	}
	waiting = true
	if err := send(1 << 20); !errors.Is(err, errZipYielded) {
		t.Fatalf("= %v, want errZipYielded", err)
	}
}

func TestAYoungSlowStreamKeepsItsPlace(t *testing.T) {
	waiting := true
	s, _ := yieldingWriter(&waiting, 100<<10)
	if _, err := s.Write(make([]byte, 100<<10*60*9)); err != nil {
		t.Fatalf("inside the first %v: %v", zipYieldAfter, err)
	}
}

func TestAFastStreamKeepsItsPlace(t *testing.T) {
	waiting := true
	s, _ := yieldingWriter(&waiting, 1<<20)
	if _, err := s.Write(make([]byte, 1<<20*60*60)); err != nil {
		t.Fatalf("a stream at 1 MiB/s ended: %v", err)
	}
}

// A given-up stream must not read as finished: with no declared length, a clean
// return would leave its reader holding a truncated archive it takes for whole.
func TestAYieldedStreamAbortsTheConnection(t *testing.T) {
	defer func() {
		if r := recover(); r != http.ErrAbortHandler {
			t.Fatalf("recovered %v, want http.ErrAbortHandler", r)
		}
	}()
	abortSlowStream(errZipYielded)
	t.Fatal("it returned")
}

// A linked source counts as the most its walk can find, since the list must be
// paid for before it is read.
func TestAZipsListCostIsKnownBeforeItIsRead(t *testing.T) {
	var v shareView
	v.FileCount = 8000
	if got := zipListBytes(v); got != 8000*zipListBytesPerFile {
		t.Fatalf("stored: %d", got)
	}
	v.Sources = make([]metadb.Source, 2)
	if got, want := zipListBytes(v), int64(8000+2*linked.MaxWalk)*zipListBytesPerFile; got != want {
		t.Fatalf("linked: %d, want %d", got, want)
	}
}
