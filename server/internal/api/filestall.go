package api

import (
	"io"
	"math"
	"net/http"
	"os"
	"time"
)

// fileStallTimeout is how long one chunk of a file response (/view,
// /download, /site) may wait on its client. A reader that takes nothing for
// that long has its write fail, so the response ends and its file is closed
// rather than both being held for as long as the connection stays open. A
// reader taking a chunk (zipStallChunk) per fileStallTimeout, about 4 KiB/s,
// keeps going, a range request included.
var fileStallTimeout = 60 * time.Second

// stallResponse is a file response whose body goes out in chunks of at most
// zipStallChunk, each under a fresh write deadline (stallWriter).
type stallResponse struct {
	http.ResponseWriter
	sw *stallWriter
}

// withStallDeadlines wraps w for a file response; the returned func clears
// the deadline once the response is done, since the connection carries the
// next request too.
func withStallDeadlines(w http.ResponseWriter) (http.ResponseWriter, func()) {
	rc := http.NewResponseController(w)
	return &stallResponse{ResponseWriter: w, sw: newStallWriter(w, rc, fileStallTimeout, 0)},
		func() { _ = rc.SetWriteDeadline(time.Time{}) }
}

func (s *stallResponse) Write(p []byte) (int, error) { return s.sw.Write(p) }

// ReadFrom sends a file in chunks the writer below sends with sendfile,
// each under its own deadline, cleared once the chunk is sent: a read from
// disk takes no time a client could be blamed for. Any other source (a live
// share's relay from the sharer, a rewritten page) is copied through Write
// instead, so a deadline is armed only while a chunk in hand is written and
// times the client alone: a sharer whose uplink trickles, or falls silent,
// never costs a visitor who keeps reading.
func (s *stallResponse) ReadFrom(src io.Reader) (int64, error) {
	// http.ServeContent hands over the file under an io.LimitedReader; the
	// chunks are cut from that same file so sendfile still recognizes it.
	lr, ok := src.(*io.LimitedReader)
	if !ok {
		lr = &io.LimitedReader{R: src, N: math.MaxInt64}
	}
	if _, file := lr.R.(*os.File); !file {
		return io.Copy(struct{ io.Writer }{s.sw}, src)
	}
	var total int64
	for lr.N > 0 {
		want := min(lr.N, zipStallChunk)
		_ = s.sw.rc.SetWriteDeadline(time.Now().Add(s.sw.stall))
		n, err := readFrom(s.ResponseWriter, &io.LimitedReader{R: lr.R, N: want})
		_ = s.sw.rc.SetWriteDeadline(time.Time{})
		lr.N -= n
		total += n
		if err != nil || n < want {
			return total, err
		}
	}
	return total, nil
}

func (s *stallResponse) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *stallResponse) Unwrap() http.ResponseWriter { return s.ResponseWriter }
