package api

import (
	"archive/zip"
	"errors"
	"io"
	"log"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"hyperdrop/server/internal/sharefs"
	"hyperdrop/server/internal/shareid"
)

// zipSem caps concurrent zip streams: each one is a full-share disk read,
// and a burst of them saturates a small VPS's disk and starves uploads.
// Waiters hold no resources and give up when their client disconnects.
// The per-owner sub-cap of 1 keeps one account's shares (however popular, or
// however deliberately hammered) from holding every slot: two different owners
// can still stream at once.
var zipSem = newFairSem(2, 1)

// zipAddrs runs one zip stream per client address (addrKey: an IPv4
// address, or an IPv6 address's /64) at a time, taken before zipSem: a
// second stream from one address waits behind its own first and holds
// nothing another address needs, so one address cannot take both of
// zipSem's slots.
var zipAddrs = newKeyedLock()

// zipStallTimeout is how long one chunk of a zip stream may wait on its
// client. A stream holds one of zipSem's slots for as long as it runs, so a
// client that stops reading (a zero TCP window, a byte a second) would
// otherwise hold the slot for good and queue every other zip behind it.
// When a chunk misses the deadline the write fails, the stream ends and the
// slot is free again.
var zipStallTimeout = 60 * time.Second

// zipStallChunk is the most one write deadline covers, so the slowest client
// a stream keeps is zipStallChunk per zipStallTimeout: about 4 KiB/s.
const zipStallChunk = 256 << 10

// zipMinRate is the slowest a zip stream may be read on average, in bytes a
// second over each zipRateWindow. A client reading just fast enough to beat
// each chunk's deadline would otherwise hold a slot of zipSem for hours, so
// a stream that averages less over a window ends there.
const (
	zipMinRate    = 16 << 10
	zipRateWindow = 30 * time.Second
)

// errZipTooSlow ends a stream its client read below its minimum rate.
var errZipTooSlow = errors.New("the client read the stream below its minimum rate")

// stallWriter is a stream's writer: every chunk of at most zipStallChunk
// gets a fresh write deadline, so a stream that keeps moving keeps going and
// one that stops is cut off. The deadline is armed only while a chunk is
// being written and cleared once it is, because over HTTP/2 a deadline
// that fires resets the stream even with no write pending, which would cut
// off a visitor while the source (a live share's sharer) is silent. Where
// the connection cannot take a deadline (a test recorder) the writes go
// through unbounded. With a minRate, a window of zipRateWindow or more that
// averaged less than minRate bytes a second ends the stream with
// errZipTooSlow, judged before each chunk.
type stallWriter struct {
	w       io.Writer
	rc      *http.ResponseController
	stall   time.Duration    // how long one chunk may wait on the client
	minRate float64          // bytes a second; 0 judges no rate
	now     func() time.Time // the rate's clock
	since   time.Time        // when the window began
	sent    int64            // bytes written in the window
}

func newStallWriter(w io.Writer, rc *http.ResponseController, stall time.Duration, minRate int) *stallWriter {
	return &stallWriter{w: w, rc: rc, stall: stall, minRate: float64(minRate), now: time.Now, since: time.Now()}
}

func (s *stallWriter) Write(p []byte) (int, error) {
	n := 0
	for len(p) > 0 {
		if err := s.judgeRate(); err != nil {
			return n, err
		}
		chunk := p[:min(len(p), zipStallChunk)]
		_ = s.rc.SetWriteDeadline(time.Now().Add(s.stall))
		m, err := s.w.Write(chunk)
		_ = s.rc.SetWriteDeadline(time.Time{})
		n += m
		s.sent += int64(m)
		if err != nil {
			return n, err
		}
		p = p[m:]
	}
	return n, nil
}

// judgeRate closes a window once zipRateWindow has passed: errZipTooSlow
// when it averaged below minRate, otherwise a new window starts.
func (s *stallWriter) judgeRate() error {
	if s.minRate == 0 {
		return nil
	}
	now := s.now()
	elapsed := now.Sub(s.since)
	if elapsed < zipRateWindow {
		return nil
	}
	if float64(s.sent) < s.minRate*elapsed.Seconds() {
		return errZipTooSlow
	}
	s.since, s.sent = now, 0
	return nil
}

// zipNoZip64 is the boundary above which the zip needs zip64 records (whose
// lengths the size predictor doesn't model): any single file, or the whole
// archive, at or past 4 GiB.
const zipNoZip64 = 1<<32 - 1

// zipTotalSize predicts the exact byte length of the store-mode zip stream
// for entries by dry-running the very writer zipShare uses with empty
// bodies (headers, descriptors and central directory have data-independent
// lengths) and adding the raw data lengths. ok=false when the archive
// would need zip64 records or 65k+ entries; callers fall back to a
// chunked stream with no declared length there.
func zipTotalSize(entries []fileView, modified time.Time) (int64, bool) {
	if len(entries) >= 0xFFFF {
		return 0, false
	}
	var data int64
	for _, f := range entries {
		if f.Size >= zipNoZip64 {
			return 0, false
		}
		data += f.Size
	}
	cw := &countingWriter{}
	zw := zip.NewWriter(cw)
	for _, f := range entries {
		if _, err := zw.CreateHeader(&zip.FileHeader{Name: f.Path, Method: zip.Store, Modified: modified}); err != nil {
			return 0, false
		}
	}
	if err := zw.Close(); err != nil {
		return 0, false
	}
	total := cw.n + data
	if total >= zipNoZip64 {
		return 0, false
	}
	return total, true
}

type countingWriter struct{ n int64 }

func (c *countingWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

var _ io.Writer = (*countingWriter)(nil)

// zipDownloadName is the archive's basename before the .zip suffix: the
// share's name, or its ID when it has none. Shared by stored and live /zip so
// the same share never downloads under two different names depending on
// which path happened to serve it.
func zipDownloadName(v shareView) string {
	if v.Name != "" {
		return v.Name
	}
	return v.ID
}

// zipFolderName is the archive's basename for a folder zip: the folder's own
// name, which is what the visitor clicked. Never the share's, or every folder
// of a share would download under one name.
func zipFolderName(dir string) string { return path.Base(dir) }

// zipFolderEntries narrows a share's manifest to one folder and rebases the
// names inside the archive onto it, so evidence.zip holds what is IN evidence
// at its root, the same relation the whole-share zip has to the share, whose
// name is not a folder inside it either.
//
// ok is false when dir names no folder holding files: the same answer an
// unknown slug gets, rather than an empty archive that looks like a download
// which worked.
func zipFolderEntries(files []fileView, dir string) ([]fileView, bool) {
	prefix := dir + "/"
	out := make([]fileView, 0, len(files))
	for _, f := range files {
		rest, ok := strings.CutPrefix(f.Path, prefix)
		if !ok {
			continue
		}
		f.Path = rest
		out = append(out, f)
	}
	return out, len(out) > 0
}

// zipShare streams the whole share as an uncompressed zip (Store method: no
// point recompressing arbitrary user files; streaming stays CPU-cheap).
// When the archive fits without zip64 records the response carries an exact
// Content-Length, so recipients get a real progress bar.
func (h *handler) zipShare(w http.ResponseWriter, r *http.Request) {
	noIndex(w)
	v, ok := h.loadPublicShare(w, r)
	if !ok {
		return
	}
	// One folder of the share instead of all of it, named the way the listing
	// page's own folder links name it. Validated exactly as /share validates
	// the same parameter: ServeMux hands over a decoded value, so a path that
	// is not a clean relpath never reaches the manifest.
	dir := r.URL.Query().Get("dir")
	if dir != "" && !shareid.ValidRelPath(dir) {
		h.notFoundPage(w, r)
		return
	}
	// Building a whole archive for a link preview costs a full disk read and
	// a stream slot, and the bot discards it. Hand over the card instead.
	if isUnfurler(r.UserAgent()) {
		h.renderCard(w, h.shareCard(r, v))
		return
	}
	// The whole share is about to stream: count it for the same reason
	// serveFile does, and skip the owner's own pull for the same reason
	// (see downloads).
	owned := h.bearerOwns(r, v)
	if !owned {
		defer h.dl.begin(v.ID, v.Owner)()
	}
	if v.LiveShare {
		if !owned && h.liveShareReg.Online(v.ID) {
			h.recordVisit(v, h.visitorToken(r))
		}
		h.serveLiveShareZip(w, r, v, dir)
		return
	}
	if v.AnyPending() {
		// Can't zip what hasn't arrived: the waiting page reloads into the
		// real zip once every file has committed.
		h.renderWaiting(w, v, nil, false)
		return
	}
	if !owned {
		h.recordVisit(v, h.visitorToken(r))
	}
	addr := addrKey(clientIP(r))
	if !zipAddrs.acquire(r.Context(), addr) {
		return // client gave up behind its own address's stream
	}
	defer zipAddrs.release(addr)
	if !zipSem.acquire(r.Context(), v.Owner) {
		return // client gave up while waiting for a stream slot
	}
	defer zipSem.release(v.Owner)
	id := v.ID
	name := zipDownloadName(v)

	entries := v.Files
	if dir != "" {
		entries, ok = zipFolderEntries(entries, dir)
		if !ok {
			h.notFoundPage(w, r)
			return
		}
		name = zipFolderName(dir)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	now := time.Now()

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", dispositionHeader(false, name+".zip"))
	declared := false
	if !v.Linked() {
		if size, ok := zipTotalSize(entries, now); ok {
			w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
			declared = true
		}
	}

	rc := http.NewResponseController(w)
	// The connection outlives this response (keep-alive), so the deadline
	// the stream set must not outlive it too.
	defer func() { _ = rc.SetWriteDeadline(time.Time{}) }()
	zw := zip.NewWriter(newStallWriter(w, rc, zipStallTimeout, zipMinRate))
	open := h.entryOpener(v)
	defer open.Close()
	for _, f := range entries {
		// The entry's Path is the name INSIDE the archive, which a folder zip
		// has rebased; the bytes are always opened at the share-relative path.
		entry := f
		entry.Path = path.Join(dir, f.Path)
		src, _, err := open.open(entry)
		if err != nil {
			// A file deleted while the stream runs. Without a declared length
			// the archive simply goes on without it; with one, skipping would
			// end the body short of its Content-Length, so the stream is
			// abandoned instead and the client sees a failed download rather
			// than an archive missing a file.
			if declared {
				log.Printf("zip %s: %v", id, err)
				return
			}
			continue
		}
		dst, err := zw.CreateHeader(&zip.FileHeader{Name: f.Path, Method: zip.Store, Modified: now})
		if err == nil {
			_, err = sharefs.CopyBuffer(dst, src) // pooled 1 MB buffer for multi-GB shares
		}
		src.Close()
		if err != nil {
			// Headers are already sent; all we can do is abort the stream.
			log.Printf("zip %s: %v", id, err)
			abortSlowStream(err)
			return
		}
	}
	if err := zw.Close(); err != nil {
		log.Printf("zip %s: %v", id, err)
		abortSlowStream(err)
	}
}

// abortSlowStream drops the connection of a stream ended by errZipTooSlow.
// The connection itself still works, so returning would end a stream with
// no declared length as if it were complete.
func abortSlowStream(err error) {
	if errors.Is(err, errZipTooSlow) {
		panic(http.ErrAbortHandler)
	}
}
