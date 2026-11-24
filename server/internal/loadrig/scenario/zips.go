package scenario

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sync"
	"time"

	"hyperdrop/server/internal/loadrig/report"
	"hyperdrop/server/internal/loadrig/target"
	"hyperdrop/server/internal/loadrig/volume"
)

const (
	valZipEntries   = "zip entries"
	valZipSize      = "zip size"
	valZipPerAddr   = "zips per address (the rest wait)"
	valZipCapShares = "shares at the file cap"

	// zipTailKeep is how much of each zip's end is kept to read its central
	// directory, which takes about 100 bytes a file: 2 MB at the file cap.
	zipTailKeep = 8 << 20
)

// zipSteps are how many zips run at once, one step after another.
var zipSteps = []int{1, 2, 4, 8}

func zipOp(n int) string { return fmt.Sprintf("zip @%d", n) }

// The values each step reports.
func zipFirstByte(n int) string    { return fmt.Sprintf("zip @%d first byte (median)", n) }
func zipFirstByteMax(n int) string { return fmt.Sprintf("zip @%d first byte (max)", n) }
func zipWall(n int) string         { return fmt.Sprintf("zip @%d all done after", n) }
func zipRate(n int) string         { return fmt.Sprintf("zip @%d throughput", n) }

var zipsScenario = Scenario{
	Name: "zips",
	About: "The public zip of a share at the file cap, alone, then 2, 4 and 8 at once (on distinct shares at the " +
		"cap where the plan has them), each read to its end and discarded: time to first byte, total time and " +
		"throughput, and the zip line's refusals. Each zip is checked whole: its Content-Length met and its " +
		"central directory listing every file. At most 3 zips run from one address; the rest wait their turn.",
	Run: zips,
}

func zips(ctx context.Context, e Env, rec *report.Recorder) error {
	var caps []volume.ShareSpec
	for i := 0; i < e.Plan.Shares; i++ {
		if s := e.Plan.Share(i); s.Files == e.Plan.FileCap && visitable(s, time.Now()) {
			caps = append(caps, s)
		}
	}
	if len(caps) == 0 {
		return Skip("the plan holds no share at the file cap")
	}
	rec.Value(valZipCapShares, float64(len(caps)), "shares")
	rec.Value(valSources, float64(e.addresses()), "addresses")
	rec.Value(valZipPerAddr, zipsPerAddress, "zips")

	var once sync.Once
	for _, n := range zipSteps {
		var mu sync.Mutex
		var firsts []time.Duration
		var bytes int64
		began := time.Now()
		err := parallel(ctx, e, rec, n, count(1), func(w int, c *target.Client) error {
			s := caps[w%len(caps)]
			return c.Stream(ctx, zipOp(n), http.MethodGet, "/zip/"+s.ID, "", func(r *http.Response, first time.Duration) error {
				got, err := readZip(r, s.Files, zipTailKeep)
				mu.Lock()
				firsts = append(firsts, first)
				bytes += got.size
				mu.Unlock()
				if err != nil {
					return err
				}
				once.Do(func() {
					rec.Value(valZipSize, mib(got.size), "MiB")
					if got.entries < 0 {
						rec.NotAvailable(valZipEntries, fmt.Sprintf("the central directory is longer than the %d MiB the rig keeps", zipTailKeep>>20))
					} else {
						rec.Value(valZipEntries, float64(got.entries), "files")
					}
				})
				return nil
			})
		})
		if err != nil {
			return err
		}
		wall := time.Since(began)
		if len(firsts) == 0 {
			rec.NotAvailable(zipFirstByte(n), "no zip was served")
			continue
		}
		slices.Sort(firsts)
		rec.Value(zipFirstByte(n), firsts[len(firsts)/2].Seconds(), "s")
		rec.Value(zipFirstByteMax(n), firsts[len(firsts)-1].Seconds(), "s")
		rec.Value(zipWall(n), wall.Seconds(), "s")
		rec.Value(zipRate(n), mib(bytes)/wall.Seconds(), "MiB/s")
	}
	return nil
}

type zipRead struct {
	size int64
	// entries is the number of files the central directory lists, -1 when
	// it begins before the kept tail.
	entries int
}

// readZip reads a zip answer to its end, keeping only its last keep bytes,
// and checks it against the share it was asked for: as long as its
// Content-Length when one is sent, and listing files entries.
func readZip(r *http.Response, files, keep int) (zipRead, error) {
	t := newTail(keep)
	n, err := io.Copy(t, r.Body)
	got := zipRead{size: n, entries: -1}
	if err != nil {
		return got, err
	}
	if r.ContentLength >= 0 && n != r.ContentLength {
		return got, fmt.Errorf("the zip ended after %d bytes of the %d its Content-Length promised", n, r.ContentLength)
	}
	zr, err := zip.NewReader(t.readerAt(n), n)
	switch {
	case errors.Is(err, errBeforeTail):
		return got, nil
	case err != nil:
		return got, fmt.Errorf("not a readable zip: %w", err)
	}
	got.entries = len(zr.File)
	if got.entries != files {
		return got, fmt.Errorf("the zip of a share of %d files lists %d", files, got.entries)
	}
	return got, nil
}

// tail keeps the last len(ring) bytes written to it.
type tail struct {
	ring    []byte
	next    int // where the next byte goes
	wrapped bool
}

func newTail(keep int) *tail { return &tail{ring: make([]byte, keep)} }

func (t *tail) Write(p []byte) (int, error) {
	n := len(p)
	if len(p) > len(t.ring) {
		p = p[len(p)-len(t.ring):]
	}
	for len(p) > 0 {
		c := copy(t.ring[t.next:], p)
		p = p[c:]
		if t.next += c; t.next == len(t.ring) {
			t.next, t.wrapped = 0, true
		}
	}
	return n, nil
}

// bytes is what the tail holds, oldest first.
func (t *tail) bytes() []byte {
	if !t.wrapped {
		return t.ring[:t.next]
	}
	return append(slices.Clone(t.ring[t.next:]), t.ring[:t.next]...)
}

var errBeforeTail = errors.New("read before the kept tail")

// readerAt reads the kept tail of a stream of total bytes at its offsets in
// the stream.
func (t *tail) readerAt(total int64) io.ReaderAt {
	b := t.bytes()
	return tailReader{buf: b, base: total - int64(len(b))}
}

type tailReader struct {
	buf  []byte
	base int64
}

func (r tailReader) ReadAt(p []byte, off int64) (int, error) {
	if off < r.base {
		return 0, errBeforeTail
	}
	i := off - r.base
	if i >= int64(len(r.buf)) {
		return 0, io.EOF
	}
	n := copy(p, r.buf[i:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
