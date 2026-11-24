package api

import (
	"errors"
	"io"
	"net/http"
	"time"
)

// speedTestMaxBytes caps one upload probe. A client measuring its path streams
// for a few seconds and stops; the cap is what bounds a client that does not.
const speedTestMaxBytes = 64 << 20

// speedTestMaxTime bounds how long one probe may hold the server's one slot.
// Without it a client trickling a byte now and then would keep every other
// account's probe answering speedtest-busy for as long as it liked. Reaching
// it ends the measurement, not the request: the answer counts what arrived,
// so a client asking for a longer probe still gets one, cut at the limit.
const speedTestMaxTime = 30 * time.Second

// speedTest is the upload speed probe: a signed-in client streams bytes at
// this route and the server counts and discards them, so the client can
// measure the path its uploads take without minting a share, charging a
// quota, or writing a byte. The answer carries what arrived and how long the
// server saw it take; the client's own clock is the rate that matters, since
// it includes the bytes still in flight when the server's count ends. One
// probe runs at a time: two at once would measure each other. A body still
// arriving at speedTestMaxTime is read no further and the connection is
// closed after the answer.
func (h *handler) speedTest(w http.ResponseWriter, r *http.Request) {
	if !h.speedTestBusy.CompareAndSwap(false, true) {
		writeErrorCode(w, http.StatusTooManyRequests, "speedtest-busy",
			"another speed test is running on this server")
		return
	}
	defer h.speedTestBusy.Store(false)
	start := time.Now()
	limit := speedTestMaxTime
	if h.speedTestTimeout > 0 {
		limit = h.speedTestTimeout
	}
	if err := http.NewResponseController(w).SetReadDeadline(start.Add(limit)); err != nil {
		// A connection that cannot take a deadline has its body closed instead.
		stop := time.AfterFunc(limit, func() { r.Body.Close() })
		defer stop.Stop()
	}
	n, err := io.Copy(io.Discard, http.MaxBytesReader(w, r.Body, speedTestMaxBytes))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeErrorCode(w, http.StatusRequestEntityTooLarge, "body-too-large",
				"a speed test body is capped at 64 MB")
			return
		}
		if time.Now().Before(start.Add(limit)) {
			writeError(w, http.StatusBadRequest, "the speed test body stopped arriving")
			return
		}
		w.Header().Set("Connection", "close")
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"bytes":   n,
		"seconds": time.Since(start).Seconds(),
	})
}
