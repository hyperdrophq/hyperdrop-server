// Relaying live bytes on /view, /download and /zip
// (server/internal/liveshare). A stored share reads from a file on this box; a
// live share reads from a pipe fed by the sharer's own connected client, so
// the same three routes need a second body source with no disk underneath it
// at all.

package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"hyperdrop/server/internal/liveshare"
	"hyperdrop/server/internal/mimetype"
)

// liveShareClaimWait bounds how long a visitor's request waits for the sharer's
// client to start sending. Past it the honest answer is "not available right
// now", not a longer hang.
const liveShareClaimWait = 30 * time.Second

// liveShareETag is strong despite being built from size and mtime, which would
// normally only justify a weak tag: the sharer's own client refuses to keep
// sending when either value stops matching what it started with (the same
// source-changed rule the zip and staging paths enforce), so two different
// bodies can never answer under one tag. That enforced rule is what makes
// If-Range resume safe with no content hash to tag with, since a live file
// is never hashed.
func liveShareETag(f fileView) string {
	var ns int64
	if f.CommittedAt != nil {
		ns = f.CommittedAt.UnixNano()
	}
	return `"` + strconv.FormatInt(f.Size, 10) + "-" + strconv.FormatInt(ns, 10) + `"`
}

// parseLiveShareRange handles the single-range form only: "bytes=a-b", "bytes=a-",
// "bytes=-n". Anything else (multi-range, unparseable) reports ok=false and
// the caller serves the whole file with 200, which RFC 7233 permits: a
// server that cannot honor a Range request is always allowed to ignore it.
func parseLiveShareRange(header string, size int64) (start, end int64, partial, ok bool) {
	if header == "" {
		return 0, size - 1, false, true
	}
	spec, found := strings.CutPrefix(header, "bytes=")
	if !found || strings.Contains(spec, ",") {
		return 0, size - 1, false, false
	}
	a, b, found := strings.Cut(spec, "-")
	if !found {
		return 0, size - 1, false, false
	}
	if a == "" { // suffix form: last n bytes
		n, err := strconv.ParseInt(b, 10, 64)
		if err != nil || n <= 0 || size == 0 {
			// An empty file has no last bytes to name: the whole (empty)
			// file with 200, never a 206 whose range ends before it starts.
			return 0, size - 1, false, false
		}
		if n > size {
			n = size
		}
		return size - n, size - 1, true, true
	}
	s, err := strconv.ParseInt(a, 10, 64)
	if err != nil || s < 0 || s >= size {
		return 0, size - 1, false, false
	}
	e := size - 1
	if b != "" {
		e, err = strconv.ParseInt(b, 10, 64)
		if err != nil || e < s {
			return 0, size - 1, false, false
		}
		if e > size-1 {
			e = size - 1
		}
	}
	return s, e, true, true
}

// liveShareOffline answers for a share whose owner's client is not connected
// right now. Retry-After names a real number so a client can back off
// sensibly instead of hammering a share that just went quiet.
func liveShareOffline(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "30")
	http.Error(w, "the person sharing this is offline right now, try again in a moment", http.StatusServiceUnavailable)
}

// liveShareBusyRetry is the Retry-After of a visitor turned away because the
// share already holds liveshare.MaxJobsPerShare transfers, or because its
// address (addrKey: an IPv4 address, an IPv6 address's /64) held
// liveshare.MaxJobsPerAddress for as long as NewJob waits.
const liveShareBusyRetry = "5"

// writeNewJobError answers a NewJob refusal: a share at its job cap, or a
// visitor that waited out its address's places, is busy (503, nothing
// reaches the sharer); a visitor that left while it waited is answered
// nothing; any other refusal is a share gone.
func writeNewJobError(w http.ResponseWriter, r *http.Request, err error) {
	if r.Context().Err() != nil {
		return
	}
	if errors.Is(err, liveshare.ErrBusy) {
		w.Header().Set("Retry-After", liveShareBusyRetry)
		http.Error(w, "the server is busy, try again in a moment", http.StatusServiceUnavailable)
		return
	}
	http.NotFound(w, r)
}

// writeLiveShareJobError answers a job.Body failure that happened BEFORE any
// bytes were sent, so nothing has been written to w yet and the status code
// is still ours to choose. A *liveshare.FailedError names why the SHARER's own
// client ended the job; anything else (most commonly a claim-wait timeout,
// which stays a plain wrapped liveshare.ErrJobFailed) is indistinguishable from
// the share simply being offline right now.
func writeLiveShareJobError(w http.ResponseWriter, r *http.Request, err error) {
	var fe *liveshare.FailedError
	if errors.As(err, &fe) {
		switch fe.Code {
		case "live-share-ended":
			// The share is gone outright (deleted, or its grace expired),
			// not merely unreachable: a 404 says so instead of inviting a
			// retry that can never succeed.
			http.NotFound(w, r)
			return
		case "source-changed":
			http.Error(w, "the file changed on the sharer's device while it was being sent - ask them to share it again", http.StatusConflict)
			return
		case "source-gone":
			http.Error(w, "the file is no longer on the sharer's device", http.StatusConflict)
			return
		}
	}
	liveShareOffline(w)
}

// serveLiveShareFile is serveStoredFile's relay twin: same headers, same
// disposition rule, but the bytes come from the sharer's client through a
// job instead of from disk. Two differences follow from that: there is
// never a negotiated content encoding (there is no stored representation to
// compress, and http.ServeContent's Range handling needs a ReadSeeker a
// pipe cannot be, so Range is parsed and applied here instead).
func (h *handler) serveLiveShareFile(w http.ResponseWriter, r *http.Request, v shareView, f fileView, inline bool) {
	if !h.liveShareReg.Online(v.ID) {
		liveShareOffline(w)
		return
	}
	if inline && !mimetype.Viewable(f.Mime) {
		inline = false
	}
	etag := liveShareETag(f)
	start, end, partial, ok := parseLiveShareRange(r.Header.Get("Range"), f.Size)
	// If-Range: a validator that does not match downgrades a resume
	// attempt to the full file, exactly as it would for a stored file.
	ifRange := r.Header.Get("If-Range")
	if !ok || (partial && ifRange != "" && ifRange != etag) {
		start, end, partial = 0, f.Size-1, false
	}
	length := end - start + 1
	mt := f.Mime
	if mt == "" {
		mt = "application/octet-stream"
	}
	// Every one of these headers is pure manifest data (size, mime, mtime),
	// known without ever touching the sharer's uplink. writeHeaders is
	// shared by the HEAD path below and the GET path once its job succeeds,
	// so the two can never answer with different headers for the same
	// request.
	writeHeaders := func() {
		revalidate(w)
		sandboxDocument(w, mt)
		w.Header().Set("Content-Type", mt)
		w.Header().Set("Content-Disposition", dispositionHeader(inline, path.Base(f.Path)))
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("ETag", etag)
		w.Header().Set("Content-Length", strconv.FormatInt(length, 10))
		if partial {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, f.Size))
			w.WriteHeader(http.StatusPartialContent)
		}
	}
	if r.Method == http.MethodHead {
		// A HEAD needs nothing a job could answer, so it never creates one:
		// no wait, and no charge against the sharer's own connection.
		writeHeaders()
		return
	}
	jEnd := end
	if end == f.Size-1 {
		jEnd = -1 // "to EOF" keeps the wire shape the same for a whole file
	}
	job, err := h.liveShareReg.NewJob(r.Context(), v.ID, addrKey(clientIP(r)), "file", f.Path, start, jEnd)
	if err != nil {
		writeNewJobError(w, r, err)
		return
	}
	body, err := job.Body(r.Context(), liveShareClaimWait)
	if err != nil {
		// Nothing has been written to w yet, so the status is still ours to
		// pick: writeLiveShareJobError reads WHY the job failed rather than
		// answering every case as "offline".
		writeLiveShareJobError(w, r, err)
		return
	}
	defer body.Close()
	stopWhenGone(r, body)
	writeHeaders()
	// A short copy here is the sharer aborting (its own source changed mid
	// read, or its connection dropped) AFTER headers were already sent, so
	// the declared Content-Length is what turns that into a visible
	// truncation on the visitor's end in every client: abort rather than
	// let a partial file look complete.
	io.Copy(w, io.LimitReader(body, length))
}

// serveLiveShareZip relays the share as one archive: exact Content-Length
// from the sharer client's own zipStreamSize prediction (the same predictor
// the CLI already trusts to declare Upload-Total for a stored zip share),
// and no ranges, matching stored /zip.
//
// dir narrows it to one folder, carried to the sharer in the job's Path (the
// field a zip job leaves empty), so the client re-plans the archive for that
// subtree. Its length is the one thing that cannot come along: the client
// predicts the WHOLE share's size, so a folder zip streams without a
// Content-Length rather than with a wrong one.
func (h *handler) serveLiveShareZip(w http.ResponseWriter, r *http.Request, v shareView, dir string) {
	rec, ok := h.liveShareReg.Get(v.ID)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !h.liveShareReg.Online(v.ID) {
		liveShareOffline(w)
		return
	}
	name := zipDownloadName(v)
	if dir != "" {
		name = zipFolderName(dir)
	}
	writeHeaders := func() {
		revalidate(w)
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", dispositionHeader(false, name+".zip"))
		if rec.ZipSize > 0 && dir == "" {
			w.Header().Set("Content-Length", strconv.FormatInt(rec.ZipSize, 10))
		}
	}
	if r.Method == http.MethodHead {
		writeHeaders()
		return
	}
	job, err := h.liveShareReg.NewJob(r.Context(), v.ID, addrKey(clientIP(r)), "zip", dir, 0, -1)
	if err != nil {
		writeNewJobError(w, r, err)
		return
	}
	body, err := job.Body(r.Context(), liveShareClaimWait)
	if err != nil {
		writeLiveShareJobError(w, r, err)
		return
	}
	defer body.Close()
	stopWhenGone(r, body)
	writeHeaders()
	io.Copy(w, body)
}

// stopWhenGone closes a claimed job's body once the visitor's request ends.
// The claim wait watches the visitor; after the claim the copy blocks in the
// pipe, which never learns the visitor left, so a sharer that sent headers
// and then nothing would pin both requests. Closing the pipe ends the copy
// here and fails the sharer's next write.
func stopWhenGone(r *http.Request, body io.Closer) {
	context.AfterFunc(r.Context(), func() { body.Close() })
}
