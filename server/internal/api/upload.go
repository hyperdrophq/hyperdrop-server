package api

import (
	"errors"
	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/mimetype"
	"hyperdrop/server/internal/sharefs"
	"net/http"
)

// commitUpload commits a part Write staged whole, of size bytes (see
// commitWith): a batch entry's or an inbox upload's.
func (h *handler) commitUpload(in metadb.CommitInput, size int64) (metadb.File, error) {
	var check func() error
	if in.Anonymous {
		// A stranger's upload never replaces a file, whoever committed it.
		// Every commit writes its row under the path's lock, which check runs
		// under, so a committed row it does not see cannot land before this
		// commit's own; refusing here leaves the owner's bytes untouched.
		// On a volume that folds case the row it must not replace is the
		// one its name folds onto (metadb.Spelling).
		check = func() error {
			p, err := h.db.Spelling(in.ShareID, in.Path, "")
			if err != nil {
				return err
			}
			if f, err := h.db.File(in.ShareID, p); err == nil && !f.Pending {
				return metadb.PathTaken(in.Path)
			} else if err != nil && !errors.Is(err, metadb.ErrNotFound) {
				return err
			}
			return nil
		}
	}
	return h.commitWith(in, func(record sharefs.Record) (sharefs.Committed, error) {
		return h.fs.CommitChecked(in.ShareID, in.Path, size, check, record)
	})
}

// commitWith is the second half of every upload whose bytes are staged:
// commit renames the staged part into files/ (Commit for a part Write
// staged, CommitRanged for a ranged one) and writes the row through record, under
// the path's lock. The rename comes first because a crash between leaves a
// pending row and a file nothing serves, which the client's retry
// overwrites and the stalled sweep removes; the other order would leave a
// committed row naming bytes that are not there. A row the database refuses
// (quota, cap, a closed inbox) takes its bytes with it, and the file layer
// puts back what the path held, so a refused overwrite leaves the previous
// version served as it was. in names the path and who is committing; the
// staged part fills in what the bytes are.
func (h *handler) commitWith(in metadb.CommitInput, commit func(sharefs.Record) (sharefs.Committed, error)) (metadb.File, error) {
	id, rel := in.ShareID, in.Path
	var f metadb.File
	refused := false
	_, err := commit(func(c sharefs.Committed) error {
		in.Size, in.SHA256, in.Mime = c.Size, c.SHA256, c.Mime
		var err error
		f, err = h.db.CommitFile(in)
		refused = err != nil
		return err
	})
	switch {
	case refused:
		// When the previous bytes could not be put back they went with the
		// refused ones, and a link must never serve a path whose file is
		// gone, so a committed row for it goes too.
		if before, err := h.db.File(id, rel); err == nil && !before.Pending {
			if _, err := h.fs.Stat(id, rel); errors.Is(err, sharefs.ErrNotFound) {
				_, _, _ = h.db.RemoveFiles(id, []string{rel})
			}
		}
		return metadb.File{}, err
	case err != nil:
		// A path the filesystem refuses can never commit, so its part is
		// not resume state.
		if errors.Is(err, sharefs.ErrBadPath) {
			h.fs.Discard(id, rel)
		}
		return metadb.File{}, err
	}
	h.prep.forgetFile(id, rel)
	return f, nil
}

// declareOwn declares rel's pending row before a batch entry's first byte
// and answers the func that withdraws it when the entry fails, so a lost
// connection leaves no entry nothing will ever fill. Only a row this request
// created is withdrawn: one the creation manifest declared keeps its slug
// for the retry.
func (h *handler) declareOwn(id, rel string, size int64) (withdraw func(), err error) {
	_, heldErr := h.db.File(id, rel)
	ours := errors.Is(heldErr, metadb.ErrNotFound)
	if _, err := h.db.DeclareFile(id, rel, size); err != nil {
		return nil, err
	}
	return func() {
		if ours {
			_ = h.db.RemovePending(id, rel)
		}
	}, nil
}

func (h *handler) uploadFile(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rel := relPathParam(r)
	v, u, ok := h.ownedShareMeta(w, r)
	if !ok {
		return
	}
	if err := h.copyRefusal(v); err != nil {
		writeRefusal(w, err)
		return
	}
	if tooDeep(rel) {
		writeRefusal(w, errPathTooDeep)
		return
	}
	// ?publish=<pid> stages the upload into an open publish (publish.go):
	// under the relpath as sent, which the commit spells, and with no
	// replace, since the commit's own list decides what goes.
	pid, staged := publishParam(r)
	var replaces string
	var replaceAll bool
	if staged {
		if err := h.stagingRefusal(v, u, pid, rel); err != nil {
			writeRefusal(w, err)
			return
		}
		if q := r.URL.Query(); q.Has("replaces") || q.Has("replaceAll") {
			writeError(w, http.StatusBadRequest, "a staged upload takes no replaces or replaceAll: the commit names what it deletes")
			return
		}
	} else {
		rel = h.spelled(id, rel, "")
		// The one refusal a linked source imposes on an upload's name.
		if err := h.sourceNameRefusal(v, rel); err != nil {
			writeRefusal(w, err)
			return
		}
		// ?replaces=<oldpath>: once this upload commits, the new file inherits
		// oldpath's public slug and oldpath is removed, so links keep working.
		// ?replaceAll=1: on commit the new file becomes the share's ONLY file
		// (slug inheritance per metadb.ReplaceAll): whole-share replacement.
		replaces = relPath(r.URL.Query().Get("replaces"))
		replaceAll = r.URL.Query().Get("replaceAll") == "1"
		if replaces != "" && replaceAll {
			writeError(w, http.StatusBadRequest, "replaces and replaceAll are mutually exclusive")
			return
		}
		if err := textShareRefusal(v, rel, textShareReplacing(v, replaces, replaceAll)); err != nil {
			writeRefusal(w, err)
			return
		}
	}

	// Optional transport compression: the body is decompressed while being
	// received, so everything downstream (ranges, sizes, hashes, and the
	// Upload-Total a decoded body is checked against) stays in original bytes.
	body, cleanup, _, err := decodeBody(w, r)
	if err != nil {
		return // decodeBody has already answered
	}
	defer cleanup()

	session := r.Header.Get("Upload-Session")
	if !validUploadSession(session) {
		writeError(w, http.StatusBadRequest, "invalid Upload-Session")
		return
	}

	if r.Header.Get("Upload-Range") == "" {
		writeError(w, http.StatusBadRequest, "Upload-Range and Upload-Total are required")
		return
	}
	p := uploadPut{id: id, rel: rel, session: session, replaces: replaces,
		replaceAll: replaceAll, u: u, body: body}
	if staged {
		h.uploadStaged(w, r, p, pid)
		return
	}
	h.uploadRanged(w, r, p)
}

// applyReplaces runs the ?replaces= slug transfer (or the ?replaceAll=1
// whole-share collapse) after a committed upload, returning the entry with
// its final (inherited) slug and removing the bytes and tiles of what it
// replaced.
func (h *handler) applyReplaces(id, rel, replaces string, replaceAll bool, entry metadb.File) (metadb.File, error) {
	if replaces == "" && !replaceAll {
		return entry, nil
	}
	// The paths and slugs the rows are about to lose, read before the write:
	// afterwards there is nothing left to name the bytes and the tiles. A
	// whole-share replace loses every other file; ?replaces= loses one row
	// at most, so that row alone is read.
	var before []metadb.File
	if replaceAll {
		all, err := h.db.Share(id)
		if err != nil {
			return entry, err
		}
		before = all.Files
	} else {
		old, err := h.db.File(id, replaces)
		switch {
		case err == nil:
			before = []metadb.File{old}
		case !errors.Is(err, metadb.ErrNotFound):
			return entry, err
		}
	}
	var d metadb.Share
	var err error
	if replaceAll {
		d, err = h.db.ReplaceAll(id, rel)
	} else {
		d, err = h.db.ReplaceEntry(id, rel, replaces)
	}
	// A replace naming nothing the share holds is the request's mistake,
	// not a missing share: the upload itself has committed.
	if errors.Is(err, metadb.ErrNotFound) {
		return entry, refuse(http.StatusBadRequest, "", err.Error())
	}
	if err != nil {
		return entry, err
	}
	for _, f := range before {
		if f.Path == rel || (!replaceAll && f.Path != replaces) {
			continue
		}
		h.removeUnnamed(id, f.Path)
		h.fs.RemoveThumb(id, f.Slug)
	}
	for _, f := range d.Files {
		if f.Path == rel {
			entry = f
			break
		}
	}
	return entry, nil
}

// spaceMessage keeps the server-wide detail (how much room is left, how much
// other uploads have promised) for the admin and gives a guest the bare fact.
// /api/usage is admin-only for the same reason: a 507 a guest can trigger at
// will must not become a side channel for it. Quota messages are NOT routed
// through here: those describe the caller's own account.
func spaceMessage(err error, isAdmin bool) string {
	if isAdmin {
		return err.Error()
	}
	return "not enough space on the server right now, ask whoever runs it"
}

// writeUploadDone sends the 201 upload response, echoing the stored size (the
// client hard-fails on mismatch) and the file's public slug.
func (h *handler) writeUploadDone(w http.ResponseWriter, f metadb.File) {
	writeJSON(w, http.StatusCreated, map[string]any{
		"path": f.Path, "size": f.Size, "slug": f.Slug,
		"sha256": f.SHA256, "viewable": mimetype.Viewable(f.Mime)})
}

// uploadStatus tells a resuming client where an upload stands for its
// session. The session's own ranged part answers first (its missing
// ranges), so a session re-sending a file it committed before reads the new
// bytes, not the old commit; then this session's commit (so a commit whose
// answer was lost is never read as another device's part); then another
// session's part, which is resumed from 0; then any commit; then nothing
// staged.
func (h *handler) uploadStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rel := relPathParam(r)
	v, u, ok := h.ownedShareMeta(w, r)
	if !ok {
		return
	}
	// ?publish=<pid> asks inside an open publish (stagedStatus).
	pid, staged := publishParam(r)
	if staged {
		if err := h.publishOf(v, u, pid); err != nil {
			writeRefusal(w, err)
			return
		}
	} else {
		rel = h.spelled(id, rel, "")
	}
	session := r.URL.Query().Get("session")
	if !validUploadSession(session) {
		writeError(w, http.StatusBadRequest, "invalid session")
		return
	}
	if staged {
		h.stagedStatus(w, id, pid, rel, session)
		return
	}
	if st, ok := h.fs.PartRanges(id, rel, session); ok {
		writeJSON(w, http.StatusOK, map[string]any{"offset": st.Prefix, "complete": false,
			"total": st.Total, "missing": st.Missing})
		return
	}
	pending, err := h.fs.PartSize(id, rel)
	if err != nil {
		writeRefusal(w, err)
		return
	}
	f, held, err := h.statusFile(v, id, rel)
	if err != nil {
		writeRefusal(w, err)
		return
	}
	if held && !f.Pending && f.UploadSession == session {
		writeJSON(w, http.StatusOK, completeStatus(f))
		return
	}
	if pending > 0 {
		// A partial belongs to the session that staged it; anyone else's
		// resume point is 0 (their first chunk starts a fresh part).
		writeJSON(w, http.StatusOK, map[string]any{"offset": 0, "complete": false})
		return
	}
	if held && !f.Pending {
		writeJSON(w, http.StatusOK, completeStatus(f))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"offset": 0, "complete": false})
}

// statusFile is the row the status route answers from: the windowed view's,
// or for a stored path past the window the row itself (a stored file
// outranks a linked entry of the same path).
func (h *handler) statusFile(v shareView, id, rel string) (fileView, bool, error) {
	f, ok := v.FileByPath(rel)
	if v.Truncated {
		stored, err := h.db.File(id, rel)
		switch {
		case err == nil:
			return fileView{File: stored}, true, nil
		case !errors.Is(err, metadb.ErrNotFound):
			return fileView{}, false, err
		}
	}
	return f, ok, nil
}

// completeStatus answers a committed file: its size, slug and hash, and the
// session that committed it, so a client whose commit answer was lost can
// tell its own commit from another device's same-size one.
func completeStatus(f fileView) map[string]any {
	return map[string]any{"offset": f.Size, "complete": true, "size": f.Size, "slug": f.Slug,
		"sha256": f.SHA256, "viewable": mimetype.Viewable(f.Mime), "session": f.UploadSession}
}

// validUploadSession bounds the required client-minted upload-session identity.
func validUploadSession(s string) bool {
	if len(s) < 6 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return true
}
