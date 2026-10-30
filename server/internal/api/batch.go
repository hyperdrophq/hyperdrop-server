package api

import (
	"archive/tar"
	"errors"
	"io"
	"log"
	"net/http"

	"hyperdrop/server/internal/metadb"
)

// Batched upload: many small files in ONE request, as a tar stream.
//
// The per-file PUT is bandwidth-bound for a big file and latency-bound for a
// small one, and on a distant server latency wins by a mile. Measured against
// a VPS ~0.5 s away, 765k files through a 4-worker pool is ~26 hours of pure
// round-trips no matter how fast the link is. One stream carrying 500 files
// costs one round-trip instead of 500.
//
// Deliberately NOT a replacement for the per-file PUT: a large file still goes
// on its own, because that path is resumable (ranged chunks) and a tar stream
// is not. Resume granularity here is the batch: a client that loses one re-reads
// the share's entries and re-sends only what's missing, which is cheap because
// a batch is bounded.
const (
	// batchMaxFiles bounds entries per request, so one caller can't hold a
	// connection (and a write-lock cadence) indefinitely.
	batchMaxFiles = 2000
	// batchMaxBytes bounds the ORIGINAL (post-decompression) bytes a single
	// batch may carry. Quotas still apply per file as it commits.
	batchMaxBytes = 512 << 20
	// batchMaxEntries bounds every header, directories included, which carry
	// no bytes and commit nothing: room for a folder per file twice over,
	// and an end to a stream of them that would otherwise hold the
	// connection. The reference client sends no directory entries.
	batchMaxEntries = 4 * batchMaxFiles
)

// uploadBatch unpacks a tar stream into the share, committing each entry
// exactly as a single-file PUT would (same staging and commit path → same
// hashing, dedup, slug minting, quota re-check). With ?publish=<pid> each
// entry is staged into that open publish instead (uploadBatchStaged).
func (h *handler) uploadBatch(w http.ResponseWriter, r *http.Request) {
	v, u, ok := h.ownedShareMeta(w, r)
	if !ok {
		return
	}
	pid, staged := publishParam(r)
	if staged {
		if err := h.stageableRefusal(v, u, pid); err != nil {
			writeRefusal(w, err)
			return
		}
	}
	body, cleanup, _, err := decodeBody(w, r)
	if err != nil {
		return // decodeBody has already answered
	}
	defer cleanup()

	meter := newTarMeter(body)
	tr := tar.NewReader(meter)
	if staged {
		h.uploadBatchStaged(w, tr, meter, v, u, pid)
		return
	}
	committed := make([]fileOut, 0, 16)
	var total int64
	for entries := 1; ; entries++ {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// A truncated stream (client died mid-batch): report what landed
			// so the caller knows what not to resend.
			writeBatchResult(w, committed, meter.nextRefusal(err))
			return
		}
		meter.entry(hdr)
		if err := meter.metaRefusal(); err != nil {
			writeBatchResult(w, committed, err)
			return
		}
		if entries > batchMaxEntries {
			writeBatchResult(w, committed, refuse(http.StatusRequestEntityTooLarge, "",
				"batch holds more than the limit of entries"))
			return
		}
		if hdr.Typeflag == tar.TypeDir {
			continue // directories are implied by the file paths
		}
		if hdr.Typeflag != tar.TypeReg {
			writeBatchResult(w, committed, refuse(http.StatusBadRequest, "",
				"batch may only contain regular files (got type "+string(rune(hdr.Typeflag))+" for "+hdr.Name+")"))
			return
		}
		hdr.Name = h.spelled(v.ID, relPath(hdr.Name), "")
		if tooDeep(hdr.Name) {
			writeBatchResult(w, committed, entryRefusal(hdr.Name, errPathTooDeep))
			return
		}
		if len(committed) >= batchMaxFiles {
			writeBatchResult(w, committed, refuse(http.StatusRequestEntityTooLarge, "",
				"batch holds more than the limit of files"))
			return
		}
		if total+hdr.Size > batchMaxBytes {
			writeBatchResult(w, committed, refuse(http.StatusRequestEntityTooLarge, "",
				"batch exceeds the per-request byte limit"))
			return
		}
		// A batched file takes the source's name rule exactly as a single
		// PUT does: a name the source already serves is refused, and the
		// files before it stay committed.
		if err := h.sourceNameRefusal(v, hdr.Name); err != nil {
			writeBatchResult(w, committed, entryRefusal(hdr.Name, err))
			return
		}
		if err := textShareRefusal(v, hdr.Name, false); err != nil {
			writeBatchResult(w, committed, entryRefusal(hdr.Name, err))
			return
		}
		// The same admission, staging and commit the single-file PUT makes,
		// so a batched file is indistinguishable from an individually
		// uploaded one. The entry is not resumable: one body, one part, one
		// commit.
		hold, err := h.admitBytes(u, v.ID, hdr.Name, hdr.Size)
		if err != nil {
			writeBatchResult(w, committed, entryRefusal(hdr.Name, err))
			return
		}
		// A row this entry declares is this entry's to withdraw if its
		// bytes never land: a stream that dies must leave no entry nothing
		// will ever fill. Its one-shot part goes with it.
		withdraw, err := h.declareOwn(v.ID, hdr.Name, hdr.Size)
		if err != nil {
			hold.Release()
			writeBatchResult(w, committed, entryRefusal(hdr.Name, err))
			return
		}
		// The hold ends once the bytes have landed: the commit only renames.
		n, err := h.fs.Write(v.ID, hdr.Name, hold.Reader(io.LimitReader(tarBody{tr}, hdr.Size)))
		hold.Release()
		if err == nil && n != hdr.Size {
			h.fs.Discard(v.ID, hdr.Name)
			withdraw()
			writeBatchResult(w, committed, refuse(http.StatusBadRequest, "",
				hdr.Name+": batch entry shorter than its header"))
			return
		}
		if err != nil {
			withdraw()
			writeBatchResult(w, committed, entryRefusal(hdr.Name, err))
			return
		}
		f, err := h.commitUpload(metadb.CommitInput{ShareID: v.ID, Path: hdr.Name}, hdr.Size)
		if err != nil {
			h.fs.Discard(v.ID, hdr.Name)
			withdraw()
			writeBatchResult(w, committed, entryRefusal(hdr.Name, err))
			return
		}
		total += f.Size
		committed = append(committed, toFileOut(fileView{File: f}))
		// v.Files is a snapshot taken before the loop started: a text share
		// holding no file yet would otherwise pass textShareRefusal on every
		// entry, this batch's own earlier commits never being reflected in
		// it. Folding each commit back in is what makes a second, distinct
		// path in the SAME batch refuse against the one this batch already
		// gave the share.
		if v.Text {
			v.Files = []fileView{{File: f}}
		}
	}
	// One line per batch (not per file): low volume, and it's the only way an
	// operator can tell batched uploads from per-file ones in the logs.
	log.Printf("batch: share %s committed %d files, %d bytes", v.ID, len(committed), total)
	writeBatchResult(w, committed, nil)
}

// uploadBatchStaged stages each regular entry of tr into publish pid as the
// staged single-file PUT does, under the batch's caps and with a plain
// batch's admission and name refusals; no row is declared and nothing
// commits. The answer lists every staged entry with "staged":true.
func (h *handler) uploadBatchStaged(w http.ResponseWriter, tr *tar.Reader, meter *tarMeter, v shareView, u metadb.User, pid string) {
	stagedFiles := make([]stagedOut, 0, 16)
	var total int64
	for entries := 1; ; entries++ {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			writeBatchResult(w, stagedFiles, meter.nextRefusal(err))
			return
		}
		meter.entry(hdr)
		if err := meter.metaRefusal(); err != nil {
			writeBatchResult(w, stagedFiles, err)
			return
		}
		if entries > batchMaxEntries {
			writeBatchResult(w, stagedFiles, refuse(http.StatusRequestEntityTooLarge, "",
				"batch holds more than the limit of entries"))
			return
		}
		if hdr.Typeflag == tar.TypeDir {
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			writeBatchResult(w, stagedFiles, refuse(http.StatusBadRequest, "",
				"batch may only contain regular files (got type "+string(rune(hdr.Typeflag))+" for "+hdr.Name+")"))
			return
		}
		name := relPath(hdr.Name)
		if tooDeep(name) {
			writeBatchResult(w, stagedFiles, entryRefusal(name, errPathTooDeep))
			return
		}
		if len(stagedFiles) >= batchMaxFiles {
			writeBatchResult(w, stagedFiles, refuse(http.StatusRequestEntityTooLarge, "",
				"batch holds more than the limit of files"))
			return
		}
		if total+hdr.Size > batchMaxBytes {
			writeBatchResult(w, stagedFiles, refuse(http.StatusRequestEntityTooLarge, "",
				"batch exceeds the per-request byte limit"))
			return
		}
		if err := h.sourceNameRefusal(v, name); err != nil {
			writeBatchResult(w, stagedFiles, entryRefusal(name, err))
			return
		}
		hold, err := h.admitStaged(u, v.ID, pid, name, hdr.Size)
		if err != nil {
			writeBatchResult(w, stagedFiles, entryRefusal(name, err))
			return
		}
		s, err := h.fs.WriteStaged(v.ID, pid, name, hold.Reader(io.LimitReader(tarBody{tr}, hdr.Size)))
		hold.Release()
		if err == nil && s.Size != hdr.Size {
			h.fs.DiscardStaged(v.ID, pid, name)
			writeBatchResult(w, stagedFiles, refuse(http.StatusBadRequest, "",
				name+": batch entry shorter than its header"))
			return
		}
		if err != nil {
			writeBatchResult(w, stagedFiles, entryRefusal(name, h.stagedRefusal(v.ID, pid, err)))
			return
		}
		total += s.Size
		stagedFiles = append(stagedFiles, toStagedOut(s))
	}
	log.Printf("batch: share %s staged %d files, %d bytes", v.ID, len(stagedFiles), total)
	writeBatchResult(w, stagedFiles, nil)
}

// tarRefusal is a broken batch stream's refusal: the request body's own
// failure as it is (408 body-incomplete or 400 bad-body), and a tar stream
// that breaks inside a body that arrived whole as 400 bad-body.
func tarRefusal(err error) error {
	var r *refusal
	if errors.As(err, &r) {
		return r
	}
	return errBadBody("the batch's tar stream ends early: " + err.Error())
}

// tarBody reads one batch entry's bytes, answering a stream that breaks
// inside the entry as tarRefusal does.
type tarBody struct{ r io.Reader }

func (t tarBody) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if err != nil && err != io.EOF {
		err = tarRefusal(err)
	}
	return n, err
}

// writeBatchResult always reports the files that DID commit (or, into a
// publish, that were staged), because a partial batch must not look like
// nothing happened, or a retry would re-send everything. A nil err is the
// 200 of a batch that landed whole; otherwise err's status, and its code
// when it has one, the same code the single-file route sends.
func writeBatchResult[F fileOut | stagedOut](w http.ResponseWriter, files []F, err error) {
	out := map[string]any{"files": files, "committed": len(files)}
	status := http.StatusOK
	if err != nil {
		r := refusalOf(err)
		status, out["error"] = r.status, r.msg
		if r.code != "" {
			out["code"] = r.code
		}
	}
	writeJSON(w, status, out)
}

// entryRefusal is err as the refusal of one named batch entry: the same
// status and code, the message prefixed with the entry's name.
func entryRefusal(name string, err error) error {
	r := refusalOf(err)
	return refuse(r.status, r.code, name+": "+r.msg)
}
