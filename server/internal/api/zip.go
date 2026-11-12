package api

import (
	"archive/zip"
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"hyperdrop/server/internal/linked"
	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/shareid"
)

// zipSlots decides when a zip starts: a full-share disk read that holds the share's
// file list in memory. How many run is the machine's load to decide (zipGate).
var zipSlots = newZipGate(newZipMachine().hasRoom)

// zipListBytes is what v's file list will cost a stream, known before it is read:
// its stored files, and for each linked source the most its walk can find.
func zipListBytes(v shareView) int64 {
	return int64(v.FileCount+len(v.Sources)*linked.MaxWalk) * zipListBytesPerFile
}

// zipWaiting bounds who waits for a stream: behind their own address's stream or for
// zipSlots.
var zipWaiting = newZipLine(sync.OnceValue(func() int { return zipLineLimit(ReadMemory().Limit) }))

// zipsPerAddress is how many zips run from one client address at a time: a home or a
// small office downloads side by side, and with fewer than zipFloor no address can take
// every place that always runs.
const zipsPerAddress = 3

// zipAddrs holds the streams of each client address (addrKey: an IPv4 address, or an
// IPv6 address's /64), taken before zipSlots: one past the limit waits behind its own
// and holds nothing another address needs.
var zipAddrs = newKeyedSem(zipsPerAddress)

// zipStallTimeout is how long one chunk of a zip stream may wait on its
// client. A stream holds its place for as long as it runs, so a
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
// each chunk's deadline would otherwise hold its place for hours, so
// a stream that averages less over a window ends there.
const (
	zipMinRate    = 16 << 10
	zipRateWindow = 30 * time.Second
)

// A stream old and slow enough to be holding others up gives its place to one
// waiting: it has run for zipYieldAfter, its client has taken under zipUsefulRate
// bytes a second of the time spent waiting on it, and the gate started a request
// the line was holding in its place (zipGate.handOver). No stream at a working
// connection's speed ever meets this, and none meets it unless a waiter moves
// because of it. A waiter's own speed is not known before it starts, so any waiter
// counts.
const (
	zipYieldAfter = 10 * time.Minute
)

// errZipYielded ends a stream that gave its slot to one waiting.
var errZipYielded = errors.New("zip stream gave its slot to one waiting")

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
	// yield, when set, reports whether someone took this stream's slot, which then
	// ends.
	yield   func() bool
	counted *zipStreamCounts // when set, adds every write, for zipGate's speed
	started time.Time        // when the stream began
	total   int64            // bytes written since it began
	waited  time.Duration    // time in writes since it began: what the client cost
	blocked time.Duration    // time in writes in the window
}

func newStallWriter(w io.Writer, rc *http.ResponseController, stall time.Duration, minRate int) *stallWriter {
	return &stallWriter{w: w, rc: rc, stall: stall, minRate: float64(minRate), now: time.Now, since: time.Now(), started: time.Now()}
}

func (s *stallWriter) Write(p []byte) (int, error) {
	n := 0
	for len(p) > 0 {
		if err := s.judgeRate(); err != nil {
			return n, err
		}
		if s.shouldYield() {
			return n, errZipYielded
		}
		chunk := p[:min(len(p), zipStallChunk)]
		_ = s.rc.SetWriteDeadline(time.Now().Add(s.stall))
		began := s.now()
		m, err := s.w.Write(chunk)
		spent := s.now().Sub(began)
		s.waited += spent
		s.blocked += spent
		_ = s.rc.SetWriteDeadline(time.Time{})
		n += m
		s.sent += int64(m)
		s.total += int64(m)
		if s.counted != nil {
			s.counted.sent.Add(int64(m))
			s.counted.inClientWrites.Add(int64(spent))
		}
		if err != nil {
			return n, err
		}
		p = p[m:]
	}
	return n, nil
}

// shouldYield reports whether this stream should give up its slot (zipYieldAfter).
func (s *stallWriter) shouldYield() bool {
	if s.yield == nil {
		return false
	}
	if s.now().Sub(s.started) < zipYieldAfter {
		return false
	}
	return float64(s.total) < zipUsefulRate*s.waited.Seconds() && s.yield()
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
	// Only the time spent waiting on the client counts: a share on a slow disk, or
	// many zips sharing one, are not a slow reader.
	if float64(s.sent) < s.minRate*s.blocked.Seconds() {
		return errZipTooSlow
	}
	s.since, s.sent, s.blocked = now, 0, 0
	return nil
}

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
// point recompressing arbitrary user files; streaming stays CPU-cheap). A share of
// stored files is one fixed archive with an exact Content-Length and a validator, so a
// download cut off continues where it stopped (serveStoredZip); one with a linked source
// is walked live and carries neither (streamLinkedZip).
//
// The gate reads the row alone and the file list waits for both stream slots,
// so a request the password refuses, and every request queued for a slot, holds
// no file list however large the share: at most the slots' worth of lists are
// ever in memory at once. A request past the line's size, or past its wait in it
// (zipWaitFor), is told why, on a page that keeps trying.
func (h *handler) zipShare(w http.ResponseWriter, r *http.Request) {
	noIndex(w)
	v, ok := h.loadPublicShareVia(w, r, h.viewMeta)
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
		card, ok := h.visibleShareVia(r, h.publicViewCapped)
		if !ok {
			h.notFoundPage(w, r)
			return
		}
		h.renderCard(w, h.shareCard(r, card))
		return
	}
	revalidate(w)
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
	// Can't zip what hasn't arrived: the waiting page reloads into the real zip
	// once every file has committed. The row's counters answer for its stored
	// files without reading them.
	if v.FileCount > v.Committed {
		h.renderZipWaiting(w, r, v)
		return
	}
	addr := addrKey(clientIP(r))
	leaveLine, ok := zipWaiting.enter(addr, v.ID)
	if !ok {
		writeZipRefusal(w, r, addr)
		return
	}
	defer leaveLine()
	waiting, stopWaiting := context.WithTimeout(r.Context(), zipWaitFor(r))
	defer stopWaiting()
	if !zipAddrs.acquire(waiting, addr) {
		if r.Context().Err() == nil {
			writeBusyPage(w, r, zipAddressPage)
		}
		return
	}
	defer zipAddrs.release(addr)
	listBytes := zipListBytes(v)
	turn := zipTurn{owner: v.Owner, share: v.ID}
	if !zipSlots.acquire(waiting, turn, listBytes) {
		busyUnlessGone(w, r)
		return
	}
	defer zipSlots.release(turn, listBytes)
	leaveLine()
	// The wait can be long, so this read also answers for what changed during it.
	v, ok = h.visibleShareVia(r, h.publicView)
	if !ok {
		h.notFoundPage(w, r)
		return
	}
	if v.SourceMissing {
		h.renderUnavailable(w, r, v)
		return
	}
	if v.AnyPending() {
		h.renderZipWaiting(w, r, v)
		return
	}
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
	if !owned && r.Method != http.MethodHead {
		h.recordVisit(v, h.visitorToken(r))
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", dispositionHeader(false, name+".zip"))
	if v.Linked() {
		h.streamLinkedZip(w, r, v, dir, entries, listBytes)
		return
	}
	h.serveStoredZip(w, r, v, dir, entries, listBytes)
}

// zipStream is the writer a stream's bytes go through, and the call that ends it.
func zipStream(w http.ResponseWriter, listBytes int64) (*stallWriter, func()) {
	rc := http.NewResponseController(w)
	sw := newStallWriter(w, rc, zipStallTimeout, zipMinRate)
	sw.yield = func() bool { return zipSlots.handOver(listBytes) }
	counts, untrack := zipSlots.track()
	sw.counted = counts
	return sw, func() {
		untrack()
		// The connection outlives this response (keep-alive), so the deadline
		// the stream set must not outlive it too.
		_ = rc.SetWriteDeadline(time.Time{})
	}
}

// streamLinkedZip walks a share with a linked source. Its files are whatever the walk
// finds and no row holds their CRCs, so it declares no length and promises no bytes: an
// entry gone by the time it is reached is left out, and the visitor starts over.
func (h *handler) streamLinkedZip(w http.ResponseWriter, r *http.Request, v shareView, dir string, entries []fileView, listBytes int64) {
	if r.Method == http.MethodHead {
		return
	}
	now := time.Now()
	sw, end := zipStream(w, listBytes)
	defer end()
	zw := zip.NewWriter(sw)
	open := h.entryOpener(v)
	defer open.Close()
	for _, f := range entries {
		// The entry's Path is the name INSIDE the archive, which a folder zip
		// has rebased; the bytes are always opened at the share-relative path.
		entry := f
		entry.Path = path.Join(dir, f.Path)
		// Each entry opens under the share's swap lock (openStored), so it
		// is one version of that file; entries opened on either side of a
		// publish's commit carry their own side's bytes.
		src, _, _, err := open.open(entry)
		if err != nil {
			continue
		}
		dst, err := zw.CreateHeader(&zip.FileHeader{Name: f.Path, Method: zip.Store, Modified: now})
		if err == nil {
			_, err = zipCopy(dst, src)
		}
		src.Close()
		if err != nil {
			// Headers are already sent; all we can do is abort the stream.
			log.Printf("zip %s: %v", v.ID, err)
			abortSlowStream(err)
			return
		}
	}
	if err := zw.Close(); err != nil {
		log.Printf("zip %s: %v", v.ID, err)
		abortSlowStream(err)
	}
}

// serveStoredZip answers a share of stored files: the whole archive, or the one range a
// resume asks for. Every failure past the headers drops the connection, so the client
// sees a download it can resume rather than a short file it takes for whole.
func (h *handler) serveStoredZip(w http.ResponseWriter, r *http.Request, v shareView, dir string, entries []fileView, listBytes int64) {
	files := make([]zipFile, len(entries))
	for i, f := range entries {
		crc, known := f.CRC32()
		files[i] = zipFile{name: f.Path, size: f.Size, modified: zipEntryTime(f), crc: crc, hasCRC: known}
	}
	a := newZipArchive(files)
	etag := zipETag(v.ID, dir, entries)
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("ETag", etag)
	start, end, partial := int64(0), a.total-1, false
	if rng := r.Header.Get("Range"); rng != "" && r.Method == http.MethodGet {
		// A validator that does not match means another archive: the whole of this
		// one, never its tail stitched onto the other's head. Only the ETag can say:
		// a date cannot prove the bytes are the same.
		if ifRange := r.Header.Get("If-Range"); ifRange == "" || ifRange == etag {
			if zipRangePastEnd(rng, a.total) {
				w.Header().Del("Content-Type")
				w.Header().Del("Content-Disposition")
				w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", a.total))
				w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
				return
			}
			if s, e, p, ok := parseLiveShareRange(rng, a.total); ok {
				start, end, partial = s, e, p
			}
		}
	}
	w.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
	if partial {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, a.total))
		w.WriteHeader(http.StatusPartialContent)
	}
	if r.Method == http.MethodHead {
		return
	}
	sw, finish := zipStream(w, listBytes)
	defer finish()
	src := &zipStoredSource{h: h, id: v.ID, dir: dir, entries: entries, opener: h.entryOpener(v), flushedAt: time.Now()}
	defer src.opener.Close()
	out := bufio.NewWriter(sw)
	err := a.writeRange(r.Context(), out, start, end, src)
	if err == nil {
		err = out.Flush()
	}
	src.flush()
	if err != nil {
		log.Printf("zip %s: %v", v.ID, err)
		panic(http.ErrAbortHandler)
	}
}

// zipRangePastEnd reports a single range that starts at or past the archive's end, the
// one form answered 416: anything else a server may ignore.
func zipRangePastEnd(header string, total int64) bool {
	spec, ok := strings.CutPrefix(header, "bytes=")
	if !ok || strings.Contains(spec, ",") {
		return false
	}
	first, _, ok := strings.Cut(spec, "-")
	if !ok || first == "" {
		return false
	}
	n, err := strconv.ParseInt(first, 10, 64)
	return err == nil && n >= total
}

// zipEntryTime is the time an entry carries: when the file was uploaded, in UTC, so
// the same file reads the same on every request and in every server's time zone.
func zipEntryTime(f fileView) time.Time {
	switch {
	case f.CommittedAt != nil:
		return f.CommittedAt.UTC()
	case f.AddedAt != nil:
		return f.AddedAt.UTC()
	}
	return time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)
}

// zipETag names one archive: the share, the folder, and every entry's name, bytes and
// time. Two responses under one tag are the same bytes, which is what lets a resume be
// stitched to what came before.
func zipETag(id, dir string, entries []fileView) string {
	sum := sha256.New()
	fmt.Fprintf(sum, "zip1\x00%s\x00%s\x00", id, dir)
	for _, f := range entries {
		fmt.Fprintf(sum, "%s\x00%d\x00%s\x00%d\n", f.Path, f.Size, f.SHA256, zipEntryTime(f).Unix())
	}
	return `"` + hex.EncodeToString(sum.Sum(nil)[:16]) + `"`
}

// renderZipWaiting answers a zip whose files have not all arrived: the waiting page for
// a person, and for a resume a refusal it can retry. A browser takes a 200 to its Range
// for the whole new file and would save the page as the zip.
func (h *handler) renderZipWaiting(w http.ResponseWriter, r *http.Request, v shareView) {
	if r.Header.Get("Range") != "" {
		writeBusy(w, r)
		return
	}
	h.renderWaiting(w, v, nil, false)
}

// zipWaitFor is how long a request waits for its turn. A person looking at a browser
// tab is better told; a resume or a program has no page to show.
func zipWaitFor(r *http.Request) time.Duration {
	if r.Method == http.MethodGet && (r.Header.Get("Range") != "" || !strings.Contains(r.Header.Get("Accept"), "text/html")) {
		return zipWaitLimit
	}
	return zipFreshWait
}

// writeZipRefusal answers a request the line has no place for: an address already
// running all it may is told that rather than blamed on the server.
func writeZipRefusal(w http.ResponseWriter, r *http.Request, addr string) {
	if zipAddrs.full(addr) {
		writeBusyPage(w, r, zipAddressPage)
		return
	}
	writeBusy(w, r)
}

// zipCRCFlushAfter and zipCRCFlushEvery are how many measured CRCs, or how long, a
// stream holds before writing them: a stream cut off keeps what it wrote, and most
// streams measure nothing.
const (
	zipCRCFlushAfter = 256
	zipCRCFlushEvery = 5 * time.Second
)

// zipStoredSource opens a stored archive's files and keeps the CRCs its stream measures.
type zipStoredSource struct {
	h         *handler
	id, dir   string
	entries   []fileView
	opener    *entryOpener
	measured  []metadb.FileCRC
	flushedAt time.Time
}

// open opens entry i, which must still be the bytes the archive was laid out for. The
// stream has declared its length and may hold their CRC, so other bytes end it.
func (s *zipStoredSource) open(i int) (io.ReadSeekCloser, error) {
	f := s.entries[i]
	// The entry's Path is the name INSIDE the archive, which a folder zip has rebased;
	// the bytes are always opened at the share-relative path.
	full := path.Join(s.dir, f.Path)
	entry := f
	entry.Path = full
	// It opens under the share's swap lock (openStored), so it is one version of the file.
	src, _, opened, err := s.opener.open(entry)
	if err != nil {
		return nil, err
	}
	if opened.Size != f.Size || opened.SHA256 != f.SHA256 {
		src.Close()
		return nil, fmt.Errorf("%s changed while the stream ran", full)
	}
	return src, nil
}

func (s *zipStoredSource) measuredCRC(i int, crc uint32) {
	f := s.entries[i]
	s.measured = append(s.measured, metadb.FileCRC{Path: path.Join(s.dir, f.Path), SHA256: f.SHA256, CRC32: crc})
	if len(s.measured) >= zipCRCFlushAfter || time.Since(s.flushedAt) >= zipCRCFlushEvery {
		s.flush()
	}
}

func (s *zipStoredSource) flush() {
	s.flushedAt = time.Now()
	if len(s.measured) == 0 {
		return
	}
	if err := s.h.db.SetFileCRCs(s.id, s.measured); err != nil {
		log.Printf("zip %s: keeping CRCs: %v", s.id, err)
	}
	s.measured = s.measured[:0]
}

// zipCopyBufs pools what a stream copies through, one chunk each: a client that stops
// reading pins its stream's buffer until the stall cuts it off, so this is the memory
// a crowd of them holds.
var zipCopyBufs = sync.Pool{New: func() any { b := make([]byte, zipStallChunk); return &b }}

// zipCopy copies src into dst through a pooled buffer. The wrappers hide WriterTo and
// ReaderFrom so io.CopyBuffer uses it.
func zipCopy(dst io.Writer, src io.Reader) (int64, error) {
	bp := zipCopyBufs.Get().(*[]byte)
	defer zipCopyBufs.Put(bp)
	return io.CopyBuffer(struct{ io.Writer }{dst}, struct{ io.Reader }{src}, *bp)
}

// abortSlowStream drops the connection of a stream ended by errZipTooSlow or
// errZipYielded. The connection itself still works, so returning would end a
// stream with no declared length as if it were complete.
func abortSlowStream(err error) {
	if errors.Is(err, errZipTooSlow) || errors.Is(err, errZipYielded) {
		panic(http.ErrAbortHandler)
	}
}
