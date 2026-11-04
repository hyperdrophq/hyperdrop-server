package api

import (
	"io"
	"os"
	"strconv"
	"sync"

	"hyperdrop/server/internal/hevctag"
)

// The answer is a handful of offsets per file and the scan that finds them
// reads a header for every box on the way to the sample descriptions. /view
// is a public route, so the answer is remembered rather than found again for
// every visitor and every Range window a player asks for.
//
// Bounded and dropped whole when it fills: the entries are tiny, the cost of
// a miss is one header read, and an eviction policy worth tuning would be
// more state than the thing it protects.
const hevcCacheMax = 2048

type hevcCache struct {
	mu   sync.Mutex
	offs map[string][]int64
	// scans are the keys being scanned right now. A player opening a movie
	// fires several Range requests at once, and each would otherwise find the
	// cache empty and scan the same file; the first scans, the rest wait for
	// its answer.
	scans map[string]*hevcScan
}

// hevcScan is one scan in flight: done closes once offs holds its answer.
type hevcScan struct {
	done chan struct{}
	offs []int64
}

// hevcOffsets answers where this file's `hev1` sample entries are, nil when
// it holds none. Keyed by CONTENT where the file has a content hash, so every
// share holding the same content asks once; a linked file (no hash of its own)
// is keyed by where it lives and what the filesystem last said about it, so
// editing the file on the server re-scans it.
func (h *handler) hevcOffsets(v shareView, rel, sha256 string, fi os.FileInfo, rs io.ReadSeeker) []int64 {
	key := sha256
	if key == "" {
		key = v.ID + "\x00" + rel + "\x00" +
			strconv.FormatInt(fi.Size(), 10) + "\x00" +
			strconv.FormatInt(fi.ModTime().UnixNano(), 10)
	}
	h.hevc.mu.Lock()
	if offs, ok := h.hevc.offs[key]; ok {
		h.hevc.mu.Unlock()
		return offs
	}
	if sc, ok := h.hevc.scans[key]; ok {
		h.hevc.mu.Unlock()
		<-sc.done
		return sc.offs
	}
	sc := &hevcScan{done: make(chan struct{})}
	if h.hevc.scans == nil {
		h.hevc.scans = map[string]*hevcScan{}
	}
	h.hevc.scans[key] = sc
	h.hevc.mu.Unlock()
	// The waiters are released however the scan ends, a panic included: the
	// request's own recovery saves this request, and a scan left in scans
	// would hold every later viewer of the file forever. A scan that did not
	// finish answers them nil, the file served unchanged.
	defer func() {
		h.hevc.mu.Lock()
		defer h.hevc.mu.Unlock()
		delete(h.hevc.scans, key)
		close(sc.done)
	}()

	// Scanned outside the lock: it reads the file, and holding the one lock
	// across that would serialise every viewer of every movie.
	offs := hevctag.Offsets(rs)

	h.hevc.mu.Lock()
	defer h.hevc.mu.Unlock()
	sc.offs = offs
	if h.hevc.offs == nil || len(h.hevc.offs) >= hevcCacheMax {
		h.hevc.offs = make(map[string][]int64, 64)
	}
	h.hevc.offs[key] = offs
	return offs
}
