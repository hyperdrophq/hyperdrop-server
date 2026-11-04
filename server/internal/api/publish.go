package api

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"sync"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/sharefs"
	"hyperdrop/server/internal/shareid"
)

// A publish is the owner's staging area inside one share: uploads sent with
// ?publish=<pid> land in the share's stage/<pid>/ and declare no row, so
// the listing, the file count, the site and the change feed never see them;
// one commit then makes every named file live and deletes the named files
// in one step, and an abort drops what was staged. The share's readers
// resolve a row and open its bytes under the swap lock the commit holds
// across its transaction and renames, so each file response comes
// entirely from before or entirely from after a commit.
//
// The routes:
//
//	POST   /api/shares/{id}/publishes              open one: 201 {"publish":"<pid>"}
//	PUT    /api/shares/{id}/files/{path...}?publish=<pid>   a staged ranged upload
//	POST   /api/shares/{id}/batch?publish=<pid>    a staged batch
//	GET    /api/shares/{id}/uploads/{path...}?publish=<pid>  where a staged upload stands
//	POST   /api/shares/{id}/publishes/{pid}/commit make it live
//	DELETE /api/shares/{id}/publishes/{pid}        abort: 204

const (
	// publishMaxFiles bounds the files one commit makes live, and the files
	// it deletes, each: the client's per-share cap (core/api.ShareMaxFiles).
	publishMaxFiles = 20000
	// publishMaxOpen bounds the publishes one owner holds open across
	// their shares (sharefs.OpenPublishes counts them).
	publishMaxOpen = 8
	// publishCommitMaxBody bounds the commit's JSON body: 20,000 relpaths to
	// make live and as many to delete, each with its base hash.
	publishCommitMaxBody = 32 << 20
)

var (
	errNoSuchPublish = refuse(http.StatusNotFound, "no-such-publish",
		"no such publish is open on this share: it was committed, aborted or swept, or never opened")
	errPublishInbox = refuse(http.StatusConflict, "publish-inbox",
		"a Receive Inbox holds what strangers sent: it takes no publish")
	errPublishText = refuse(http.StatusConflict, "text-share",
		"a text share holds one file: replace it rather than publishing into it")
	errPublishCommitted = refuse(http.StatusConflict, "conflict",
		"this publish's rows are committed and its files are still being moved into place; the server finishes it within minutes")
)

// publishIncomplete refuses a commit naming paths with no finished staged
// upload, listing them.
func publishIncomplete(missing []string) error {
	sort.Strings(missing)
	return &refusal{status: http.StatusConflict, code: "publish-incomplete",
		msg:   fmt.Sprintf("%d of the files to publish have no finished upload in it", len(missing)),
		extra: map[string]any{"missing": missing}}
}

// publishParam reads ?publish=: the publish id and whether the request
// names one at all.
func publishParam(r *http.Request) (string, bool) {
	q := r.URL.Query()
	if !q.Has("publish") {
		return "", false
	}
	return q.Get("publish"), true
}

// publishOf refuses (no-such-publish) unless pid is a publish u opened on
// share v and still open. An inbox never holds one.
func (h *handler) publishOf(v shareView, u metadb.User, pid string) error {
	if v.Inbox || !shareid.ValidPublishID(pid) {
		return errNoSuchPublish
	}
	owner, err := h.fs.StageOwner(v.ID, pid)
	if err != nil || owner != u.Username {
		return errNoSuchPublish
	}
	return nil
}

// stagingRefusal is what a staged upload of rel into publish pid is refused
// before its first byte: the publish itself, one whose commit journal
// remains, a text share, and a name a linked source of the share already
// lists.
func (h *handler) stagingRefusal(v shareView, u metadb.User, pid, rel string) error {
	if err := h.stageableRefusal(v, u, pid); err != nil {
		return err
	}
	return h.sourceNameRefusal(v, rel)
}

// stageableRefusal is what any staged upload into publish pid is refused:
// the publish itself, one whose commit journal remains (its rows may
// already name what is staged, so 409 conflict until the housekeeping or
// boot pass finishes it, as its commit and abort answer), and a text
// share. The file layer re-checks the journal under each part's lock
// (sharefs.ErrStageCommitting).
func (h *handler) stageableRefusal(v shareView, u metadb.User, pid string) error {
	if err := h.publishOf(v, u, pid); err != nil {
		return err
	}
	if _, held, err := h.fs.ReadJournal(v.ID, pid); held || err != nil {
		return errPublishCommitted
	}
	if v.Text {
		return errPublishText
	}
	return nil
}

// stagedRefusal is err from a staged write as the route answers it: the
// publish gone (aborted, committed or swept mid-upload) is no-such-publish.
func (h *handler) stagedRefusal(id, pid string, err error) error {
	if errors.Is(err, sharefs.ErrNoStage) || !h.fs.StageExists(id, pid) {
		return errNoSuchPublish
	}
	return err
}

// stagedOut is a finished staged upload as the upload routes answer it.
type stagedOut struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Staged bool   `json:"staged"`
}

func toStagedOut(s sharefs.Staged) stagedOut {
	return stagedOut{Path: s.Path, Size: s.Size, SHA256: s.SHA256, Staged: true}
}

// publishLocks holds one mutex per {share, publish}, counted so the map
// keeps none nobody holds or waits for: a commit and an abort of one
// publish never run at once, since an abort removes the stage without the
// path locks the commit holds.
type publishLocks struct {
	mu sync.Mutex
	m  map[string]*publishLock
}

type publishLock struct {
	mu sync.Mutex
	n  int
}

// lock takes the mutex of publish pid on share id and answers its release.
func (p *publishLocks) lock(id, pid string) func() {
	k := id + "\x00" + pid
	p.mu.Lock()
	if p.m == nil {
		p.m = map[string]*publishLock{}
	}
	l := p.m[k]
	if l == nil {
		l = &publishLock{}
		p.m[k] = l
	}
	l.n++
	p.mu.Unlock()
	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		p.mu.Lock()
		if l.n--; l.n == 0 {
			delete(p.m, k)
		}
		p.mu.Unlock()
	}
}

// publishOpen answers POST /api/shares/{id}/publishes: a new publish on the
// caller's share, 201 {"publish":"<pid>"}. The body is {} or empty. An
// inbox is refused publish-inbox, a text share text-share, and an owner
// already holding publishMaxOpen open publishes publish-limit.
func (h *handler) publishOpen(w http.ResponseWriter, r *http.Request) {
	v, u, ok := h.ownedShareVia(w, r, h.viewMeta)
	if !ok {
		return
	}
	var in struct{}
	if !decodeOptionalJSONBody(w, r, 1<<10, &in) {
		return
	}
	switch {
	case v.Inbox:
		writeRefusal(w, errPublishInbox)
		return
	case v.Text:
		writeRefusal(w, errPublishText)
		return
	}
	// One open at a time, so two cannot both pass the count.
	h.publishOpenMu.Lock()
	defer h.publishOpenMu.Unlock()
	if h.fs.OpenPublishes(u.Username) >= publishMaxOpen {
		writeErrorCode(w, http.StatusConflict, "publish-limit",
			"this account already has "+strconv.Itoa(publishMaxOpen)+" publishes open: commit or abort one first")
		return
	}
	pid := shareid.NewPublishID()
	if err := h.fs.OpenStage(v.ID, pid, u.Username); err != nil {
		writeRefusal(w, err)
		return
	}
	// A share deleted while the stage was made has no rows to commit into:
	// its stage goes, or it would hold one of the owner's publishes.
	if _, err := h.db.ShareCapped(v.ID, 1); err != nil {
		_ = h.fs.RemoveStage(v.ID, pid)
		writeRefusal(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"publish": pid})
}

// publishAbort answers DELETE /api/shares/{id}/publishes/{pid}: 204 once
// everything staged in the publish is removed. A publish whose commit
// journal remains (its rows committed, its renames stopped by an error) is
// not removed: the housekeeping or boot pass finishes it.
func (h *handler) publishAbort(w http.ResponseWriter, r *http.Request) {
	v, u, ok := h.ownedShareVia(w, r, h.viewMeta)
	if !ok {
		return
	}
	pid := r.PathValue("pid")
	if err := h.publishOf(v, u, pid); err != nil {
		writeRefusal(w, err)
		return
	}
	unlock := h.publishes.lock(v.ID, pid)
	defer unlock()
	if !h.fs.StageExists(v.ID, pid) {
		writeRefusal(w, errNoSuchPublish)
		return
	}
	if _, held, err := h.fs.ReadJournal(v.ID, pid); held || err != nil {
		writeRefusal(w, errPublishCommitted)
		return
	}
	if err := h.fs.RemoveStage(v.ID, pid); err != nil {
		writeRefusal(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// publishCommitIn is the commit's body: the staged relpaths to make live,
// the stored relpaths to delete, and the sha256 the client last saw for a
// path it replaces or deletes.
type publishCommitIn struct {
	Files  []string          `json:"files"`
	Delete []string          `json:"delete"`
	Base   map[string]string `json:"base"`
}

// publishCommit answers POST /api/shares/{id}/publishes/{pid}/commit: every
// path in files goes live and every path in delete goes, in one step, and
// the publish closes. The answer is the share as GET /api/shares/{id} gives
// it plus "published":{"files":N,"deleted":N}.
//
// Under the publish's own mutex (no abort of it runs meanwhile), WithSwap
// holds the path locks of every named path and the share lock shared. Its
// prepare step reads the staged records and writes and syncs the journal;
// its swap step, under the swap lock, decides the rows in one transaction
// (metadb.PublishFiles, which also wakes the share's watchers once), marks
// the journal, renames the parts into place, removes the deleted bytes and
// retires the stage, which is purged once every lock is released. A
// refusal before the rows (publish-incomplete, publish-conflict,
// path-taken, text-share, quota) drops the journal, moves nothing and
// leaves the publish open to be committed again. A rename that fails after
// the rows keeps the journal and the stage for the housekeeping pass (or
// the boot pass) to finish.
func (h *handler) publishCommit(w http.ResponseWriter, r *http.Request) {
	v, u, ok := h.ownedShareVia(w, r, h.viewMeta)
	if !ok {
		return
	}
	pid := r.PathValue("pid")
	if err := h.publishOf(v, u, pid); err != nil {
		writeRefusal(w, err)
		return
	}
	var in publishCommitIn
	if !decodeJSONBody(w, r, publishCommitMaxBody, &in) {
		return
	}
	files, deletes := relPaths(in.Files), relPaths(in.Delete)
	if len(files) > publishMaxFiles || len(deletes) > publishMaxFiles {
		writeError(w, http.StatusRequestEntityTooLarge,
			"a publish holds at most "+strconv.Itoa(publishMaxFiles)+" files to publish and as many to delete")
		return
	}
	if len(files)+len(deletes) == 0 {
		writeError(w, http.StatusBadRequest, "a commit names files to publish or delete")
		return
	}
	// base names at most one hash per path the commit names.
	if len(in.Base) > len(files)+len(deletes) {
		writeError(w, http.StatusBadRequest, "base names more paths than the commit publishes and deletes")
		return
	}
	for _, p := range files {
		if tooDeep(p) {
			writeRefusal(w, errPathTooDeep)
			return
		}
	}
	named := make(map[string]bool, len(files)+len(deletes))
	for _, p := range append(append([]string{}, files...), deletes...) {
		if !shareid.ValidRelPath(p) {
			writeError(w, http.StatusBadRequest, "not a clean relative path: "+p)
			return
		}
		if named[p] {
			writeError(w, http.StatusBadRequest, p+" is named twice in one commit")
			return
		}
		named[p] = true
	}
	base := make(map[string]string, len(in.Base))
	for p, sum := range in.Base {
		base[relPath(p)] = sum
	}
	if v.Text {
		writeRefusal(w, errPublishText)
		return
	}
	// The database knows a linked entry only by its slug cache, so the
	// source's own walk judges every new name, as it does at staging.
	if v.Linked() {
		specs, err := h.dbSpecs(v.Share)
		if err != nil {
			writeRefusal(w, err)
			return
		}
		for _, p := range files {
			if err := h.sourceSpecNameRefusal(specs, v.Prefixed(), p); err != nil {
				writeRefusal(w, err)
				return
			}
		}
	}

	unlock := h.publishes.lock(v.ID, pid)
	defer unlock()
	var res metadb.PublishResult
	var commits []metadb.PublishCommit
	retired := false
	locked := append(append([]string{}, files...), deletes...)
	prepare := func() error {
		staged, err := h.fs.StagedFiles(v.ID, pid)
		if err != nil {
			return err
		}
		if _, held, err := h.fs.ReadJournal(v.ID, pid); held || err != nil {
			return errPublishCommitted
		}
		commits = make([]metadb.PublishCommit, 0, len(files))
		var missing []string
		for _, p := range files {
			s, ok := staged[p]
			if !ok {
				missing = append(missing, p)
				continue
			}
			commits = append(commits, metadb.PublishCommit{Path: p, Size: s.Size, SHA256: s.SHA256, Mime: s.Mime})
		}
		if len(missing) > 0 {
			return publishIncomplete(missing)
		}
		if err := h.fs.WriteJournal(v.ID, pid, sharefs.Journal{Files: files, Delete: deletes}); err != nil {
			return err
		}
		if h.publishPrepared != nil {
			h.publishPrepared(v.ID, pid)
		}
		return nil
	}
	swap := func() error {
		var err error
		res, err = h.db.PublishFiles(v.ID, commits, deletes, base)
		if err != nil {
			if rerr := h.fs.RemoveJournal(v.ID, pid); rerr != nil {
				log.Printf("publish %s/%s: removing the journal of a refused commit: %v", v.ID, pid, rerr)
			}
			return err
		}
		renames := make([]sharefs.Rename, len(files))
		for i, p := range files {
			renames[i] = sharefs.Rename{From: p, To: res.Files[i].Path}
		}
		removes := make([]string, len(res.Deleted))
		for i, f := range res.Deleted {
			removes[i] = f.Path
		}
		// The journal is marked before the first rename, so a rename that
		// fails is finished path by path (by the housekeeping pass, or at
		// the next boot), whatever writes land on those paths meanwhile.
		// Unmarked, a journal is judged by the rows alone, which is right
		// after a crash in this step but cannot tell a later write from a
		// commit never written.
		marked := sharefs.Journal{Files: files, Delete: deletes, Rows: &sharefs.JournalRows{Renames: renames, Deleted: removes}}
		if err := h.fs.WriteJournal(v.ID, pid, marked); err != nil {
			log.Printf("publish %s/%s: marking the journal after its rows: %v", v.ID, pid, err)
		}
		if err := h.fs.SwapIn(v.ID, pid, renames, removes); err != nil {
			log.Printf("publish %s/%s: rows committed, moving files failed; housekeeping finishes it: %v", v.ID, pid, err)
			return err
		}
		if err := h.fs.RetireStageLocked(v.ID, pid); err != nil {
			log.Printf("publish %s/%s: retiring the committed stage: %v", v.ID, pid, err)
			return nil
		}
		retired = true
		return nil
	}
	err := h.fs.WithSwap(v.ID, locked, prepare, swap)
	if retired {
		// What was staged and not committed goes with no lock held.
		if perr := h.fs.PurgeStage(v.ID, pid); perr != nil {
			log.Printf("publish %s/%s: removing the committed stage: %v", v.ID, pid, perr)
		}
	}
	// res holds rows only once the transaction wrote them: a committed or
	// deleted file has nothing left to prepare.
	for _, f := range append(append([]metadb.File{}, res.Files...), res.Deleted...) {
		h.prep.forgetFile(v.ID, f.Path)
	}
	if err != nil {
		writeRefusal(w, err)
		return
	}
	// Tiles take path locks of their own, so they go after WithSwap: a
	// deleted file's slug no longer resolves, so its tile serves nothing.
	for _, f := range res.Deleted {
		h.fs.RemoveThumb(v.ID, f.Slug)
	}
	full, err := h.view(v.ID)
	if err != nil {
		writeRefusal(w, err)
		return
	}
	out := h.resolvedRow(full)
	if pw := h.readablePassword(full.Share); pw != "" {
		out.Password = pw
		w.Header().Set("Cache-Control", "no-store")
	}
	type published struct {
		Files   int `json:"files"`
		Deleted int `json:"deleted"`
	}
	writeJSON(w, http.StatusOK, struct {
		shareOut
		Published published `json:"published"`
	}{out, published{Files: len(res.Files), Deleted: len(res.Deleted)}})
}

// uploadStaged stages one chunk of a ranged upload into publish pid, or a
// whole empty file. Admission is a plain upload's, with every byte the
// owner's open publishes hold charged beside the committed ones: the quota
// as an advisory check per chunk (stagedRoom), the disk per chunk. A new
// path past the publish's file cap is refused 409 publish-limit. The chunk
// that fills the last gap records the file's digest and type
// (FinishStaged) and answers 201 with its path, size and sha256 and
// "staged":true; nothing commits and no row is declared.
func (h *handler) uploadStaged(w http.ResponseWriter, r *http.Request, p uploadPut, pid string) {
	total, rg, err := parseUploadHeaders(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if total == 0 {
		var probe [1]byte
		if n, readErr := p.body.Read(probe[:]); n != 0 || !errors.Is(readErr, io.EOF) {
			writeError(w, http.StatusBadRequest, "body exceeds Upload-Total")
			return
		}
		s, err := h.fs.WriteStaged(p.id, pid, p.rel, p.body)
		if err != nil {
			writeRefusal(w, h.stagedRefusal(p.id, pid, err))
			return
		}
		writeJSON(w, http.StatusCreated, toStagedOut(s))
		return
	}
	if err := h.stagedRoom(p.u, p.id, pid, p.rel, total); err != nil {
		writeRefusal(w, err)
		return
	}
	hold, err := h.fs.AdmitWrite(p.id, p.u.Username, rg.Len())
	if err != nil {
		writeRefusal(w, err)
		return
	}
	defer hold.Release()
	st, err := h.fs.WriteRangeStaged(p.id, pid, p.rel, hold.Reader(p.body), rg, total, p.session)
	switch {
	case errors.Is(err, sharefs.ErrPartChanged):
		writeError(w, http.StatusConflict, err.Error())
	case err != nil:
		writeRefusal(w, h.stagedRefusal(p.id, pid, err))
	case st.Complete:
		s, err := h.fs.FinishStaged(p.id, pid, p.rel, p.session, total)
		switch {
		case errors.Is(err, sharefs.ErrNotFound):
			writeError(w, http.StatusConflict, "the upload is no longer staged; ask for the missing ranges")
		case err != nil:
			writeRefusal(w, h.stagedRefusal(p.id, pid, err))
		default:
			writeJSON(w, http.StatusCreated, toStagedOut(s))
		}
	default:
		writeJSON(w, http.StatusAccepted, map[string]any{"missing": st.Missing})
	}
}

// stagedStatus answers the status route inside publish pid: a finished
// staged upload of rel as complete with its size and sha256 and
// "staged":true (whichever session sent it: the client compares the hash
// with its own), this session's part still uploading with its missing
// ranges, and otherwise offset 0.
func (h *handler) stagedStatus(w http.ResponseWriter, id, pid, rel, session string) {
	if s, ok := h.fs.StagedFile(id, pid, rel); ok {
		writeJSON(w, http.StatusOK, map[string]any{"offset": s.Size, "complete": true,
			"size": s.Size, "sha256": s.SHA256, "staged": true})
		return
	}
	if st, ok := h.fs.PartRangesStaged(id, pid, rel, session); ok {
		writeJSON(w, http.StatusOK, map[string]any{"offset": st.Prefix, "complete": false,
			"total": st.Total, "missing": st.Missing})
		return
	}
	if !h.fs.StageExists(id, pid) {
		writeRefusal(w, errNoSuchPublish)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"offset": 0, "complete": false})
}
