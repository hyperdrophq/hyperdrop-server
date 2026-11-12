package api

import "net/http"

// shareStatus is the JSON the waiting pages poll: per-file upload progress.
// Unlike the HTML routes it never renders the password form or the
// unavailable page: a missing or stale access cookie is a 401 and a missing
// source is a 200 body of {"unavailable":true}, both left for the page
// script to react to, because res.json() runs unconditionally and an HTML
// answer would throw there.
//
// The gate reads the share's row alone (viewMeta), and the answer comes from
// the share's fileLookup, so a poll of a stored share costs its counters, the
// first statusFileLimit rows and the one file ?slug= names, whatever the
// share holds. A linked share is composed through its walk, because its
// linked entries are counted, listed and sized in the answer and the walk is
// what says whether a source can be read at all.
func (h *handler) shareStatus(w http.ResponseWriter, r *http.Request) {
	sh, ok := h.visibleShareVia(r, h.viewMeta)
	if !ok {
		writeError(w, http.StatusNotFound, "share not found")
		return
	}
	if sh.PasswordHash != "" && !h.validAccess(r, sh.ID, sh.PasswordGen) {
		writeError(w, http.StatusUnauthorized, "password required")
		return
	}
	lookup, err := h.lookupFor(sh)
	if err != nil {
		writeError(w, http.StatusNotFound, "share not found")
		return
	}
	// A share whose source cannot be read gets the same outcome as every
	// other public read, an unavailable answer, but stays JSON: the waiting
	// page's poll treats {"unavailable":true} like a completed upload and
	// reloads onto the share page, which renders the HTML unavailable page.
	if lookup.v.SourceMissing {
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, map[string]bool{"unavailable": true})
		return
	}
	// A big share must not turn a POLL LOOP into a per-file payload plus a
	// stat storm: 10k pending files meant ~1 MiB of JSON and 10k filesystem
	// stats on every tick, for the whole upload. The waiting page only ever
	// needs detail for the ONE file it's waiting on (it passes ?slug=), plus
	// the aggregate; everything else is counts.
	wantSlug := r.URL.Query().Get("slug")
	p, err := lookup.progress(statusFileLimit, wantSlug)
	if err != nil {
		writeError(w, http.StatusNotFound, "share not found")
		return
	}
	// In-flight partial sizes cost a stat each, worth it for a handful of
	// files (where a smooth bar matters), pointless for thousands.
	measurePartials := p.files <= statusStatLimit
	// uploaded is every landed byte plus the partials measured below, each
	// counted once: the wanted file's entry is the window's when the window
	// holds it.
	uploaded := p.committedBytes
	status := func(f fileView, measure bool) fileStatus {
		st := fileStatus{Slug: f.Slug, Path: f.Path, Size: f.Size, Complete: !f.Pending}
		if !f.Pending {
			st.Bytes = f.Size
			return st
		}
		// The sender's own word on a file whose bytes have not started: the
		// page shows that phase ahead of the upload's.
		if rep, ok := h.prep.get(sh.ID, f.Path); ok {
			st.Preparing = &prepOut{Stage: string(rep.Stage), Fraction: rep.Fraction}
		}
		if measure {
			// Best-effort: a racing commit or fs error reads as 0, and the
			// next poll corrects it.
			if n, err := h.fs.PartSize(sh.ID, f.Path); err == nil {
				st.Bytes = n
				uploaded += n
			}
		}
		return st
	}
	files := make([]fileStatus, 0, len(p.window))
	var wanted *fileStatus
	for _, f := range p.window {
		st := status(f, measurePartials || f.Slug == wantSlug)
		if p.wanted != nil && wanted == nil && f.Slug == p.wanted.Slug && f.Path == p.wanted.Path {
			e := st
			wanted = &e
		}
		files = append(files, st)
	}
	if p.wanted != nil && wanted == nil {
		st := status(*p.wanted, true)
		wanted = &st
	}
	w.Header().Set("Cache-Control", "no-store")
	out := map[string]any{
		"complete": p.committed == p.files, "uploadedBytes": uploaded, "totalBytes": p.committedBytes + p.pendingBytes,
		"counts": map[string]int{"total": p.files, "completed": p.committed, "pending": p.files - p.committed},
		// How many pending files the sender is still preparing, so the
		// whole-share page can show that phase before any byte moves.
		"preparing": h.prep.fresh(sh.ID),
	}
	// The per-file array stays for shares small enough that a client may want
	// it; past the cap it's truncated and callers use `file`/counts instead.
	out["files"] = files
	if p.files > statusFileLimit {
		out["truncated"] = true
	}
	if wanted != nil {
		out["file"] = wanted
	}
	writeJSON(w, http.StatusOK, out)
}

// fileStatus is one file's entry in the status answer.
type fileStatus struct {
	Slug     string `json:"slug"`
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	Bytes    int64  `json:"bytes"`
	Complete bool   `json:"complete"`
	// Preparing is the sender's fresh report on a pending file, absent when
	// there is none or the file has committed.
	Preparing *prepOut `json:"preparing,omitempty"`
}

// uploadProgress is what the status answer is composed from: the share's
// file and byte totals, the first window files in the order the answer
// lists them, and the file a slug names.
type uploadProgress struct {
	files, committed             int
	committedBytes, pendingBytes int64 // pendingBytes is what the pending files declared
	window                       []fileView
	wanted                       *fileView
}

// progress answers the share's upload state with at most window files
// listed. A lookup answering from rows reads it in one snapshot
// (metadb.UploadProgress): the counters, the first files by path and the
// slug's one row. A composed view already holds every file, in the order its
// listing gives them, and is counted as it stands; the last file carrying
// the slug is the wanted one.
func (l fileLookup) progress(window int, slug string) (uploadProgress, error) {
	if l.db == nil {
		p := uploadProgress{files: len(l.v.Files)}
		for i, f := range l.v.Files {
			if f.Pending {
				p.pendingBytes += f.Size
			} else {
				p.committed++
				p.committedBytes += f.Size
			}
			if i < window {
				p.window = append(p.window, f)
			}
			if f.Slug == slug {
				e := f
				p.wanted = &e
			}
		}
		return p, nil
	}
	mp, err := l.db.UploadProgress(l.v.ID, window, slug)
	if err != nil {
		return uploadProgress{}, err
	}
	p := uploadProgress{files: mp.Files, committed: mp.Committed, committedBytes: mp.Bytes,
		pendingBytes: mp.PendingBytes, window: make([]fileView, 0, len(mp.Window))}
	for _, f := range mp.Window {
		p.window = append(p.window, fileView{File: f})
	}
	if mp.Wanted != nil {
		p.wanted = &fileView{File: *mp.Wanted}
	}
	return p, nil
}

// Bounds for the waiting page's poll: how many per-file entries a status
// response carries, and how many in-flight partial sizes it will stat.
const (
	statusFileLimit = 500
	statusStatLimit = 64
)
