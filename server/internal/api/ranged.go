package api

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/sharefs"
)

// uploadPut is one upload PUT after uploadFile's shared checks: the share,
// the path, the session, the replace it asks for, the account and the
// decoded body.
type uploadPut struct {
	id, rel, session, replaces string
	replaceAll                 bool
	u                          metadb.User
	body                       io.Reader
}

// errCommittedBySession refuses a fresh part for a session whose upload of
// the path is committed or being committed.
var errCommittedBySession = errors.New("this upload is committed")

// rangedCommits counts the ranged commits in flight per share, path and
// session. A commit is two steps, the rename (CommitRanged) and then the
// row, and between them the part is gone while the row is still pending; a
// late chunk of the same session must not stage a fresh part there, or the
// status route would read the committed upload as one still running.
type rangedCommits struct {
	mu sync.Mutex
	n  map[string]int
}

func rangedCommitKey(id, rel, session string) string { return id + "\x00" + rel + "\x00" + session }

// begin marks a commit in flight until the returned end runs.
func (c *rangedCommits) begin(id, rel, session string) (end func()) {
	k := rangedCommitKey(id, rel, session)
	c.mu.Lock()
	if c.n == nil {
		c.n = map[string]int{}
	}
	c.n[k]++
	c.mu.Unlock()
	return func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.n[k]--; c.n[k] <= 0 {
			delete(c.n, k)
		}
	}
}

func (c *rangedCommits) active(id, rel, session string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n[rangedCommitKey(id, rel, session)] > 0
}

// committedBy reports whether f is session's committed upload of total bytes.
func committedBy(f metadb.File, session string, total int64) bool {
	return !f.Pending && f.UploadSession == session && f.Size == total
}

// parseUploadRange reads "<start>-<end>", end exclusive, against total. The
// one zero-length range is 0-0, an empty file's.
func parseUploadRange(s string, total int64) (sharefs.Range, error) {
	a, b, ok := strings.Cut(s, "-")
	start, err1 := strconv.ParseInt(a, 10, 64)
	end, err2 := strconv.ParseInt(b, 10, 64)
	// Digits only: ParseInt alone would take a sign ("+1-5").
	if !ok || err1 != nil || err2 != nil || !allDigits(a) || !allDigits(b) {
		return sharefs.Range{}, fmt.Errorf("invalid Upload-Range %q", s)
	}
	if total == 0 && start == 0 && end == 0 {
		return sharefs.Range{}, nil
	}
	if start < 0 || start >= end || end > total {
		return sharefs.Range{}, fmt.Errorf("Upload-Range %q is outside [0, %d)", s, total)
	}
	return sharefs.Range{Start: start, End: end}, nil
}

func allDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

// uploadRanged stages one chunk of a ranged upload and commits the file once
// every byte is in. A failed chunk leaves the file's pending row to the
// stalled sweep: other chunks of the same upload may be landing beside it. A ranged part is committed only through
// CommitRanged, which checks that no range is missing.
func (h *handler) uploadRanged(w http.ResponseWriter, r *http.Request, p uploadPut) {
	total, err := strconv.ParseInt(r.Header.Get("Upload-Total"), 10, 64)
	if err != nil || total < 0 {
		writeError(w, http.StatusBadRequest, "invalid Upload-Total")
		return
	}
	rg, err := parseUploadRange(r.Header.Get("Upload-Range"), total)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// A chunk of an upload this session already committed (a retry, one
	// re-sent because the commit's answer was lost, or an unchanged file
	// sent again, whose derived session is the same) is answered with that
	// commit, and nothing is staged again. A replace it carries still runs,
	// once: an unchanged file re-sent as a replace must still collapse.
	if f, err := h.db.File(p.id, p.rel); err == nil && committedBy(f, p.session, total) {
		replaces := p.replaces
		if replaces != "" && replaces != p.rel {
			if _, err := h.db.File(p.id, replaces); errors.Is(err, metadb.ErrNotFound) {
				replaces = "" // applied by the commit or an earlier retry
			}
		}
		entry, err := h.applyReplaces(p.id, p.rel, replaces, p.replaceAll, f)
		if err != nil {
			writeRefusal(w, err)
			return
		}
		h.writeUploadDone(w, entry)
		return
	}
	finish := func(commit func(sharefs.Record) (sharefs.Committed, error)) {
		entry, err := func() (metadb.File, error) {
			// Deferred, so a panic recovered by net/http never leaves the
			// mark set and every later chunk of this upload refused.
			defer h.committing.begin(p.id, p.rel, p.session)()
			return h.commitWith(metadb.CommitInput{ShareID: p.id, Path: p.rel, UploadSession: p.session,
				Replaces: p.replaces, ReplaceAll: p.replaceAll}, commit)
		}()
		if errors.Is(err, sharefs.ErrNotFound) {
			// A sibling chunk committed first: its commit answers this one.
			if f, ferr := h.db.File(p.id, p.rel); ferr == nil && committedBy(f, p.session, total) {
				h.writeUploadDone(w, f)
				return
			}
			writeError(w, http.StatusConflict, "the upload is no longer staged; ask for the missing ranges")
			return
		}
		if err != nil {
			writeRefusal(w, err)
			return
		}
		entry, err = h.applyReplaces(p.id, p.rel, p.replaces, p.replaceAll, entry)
		if err != nil {
			writeRefusal(w, err)
			return
		}
		h.writeUploadDone(w, entry)
	}
	if total == 0 {
		var probe [1]byte
		if n, readErr := p.body.Read(probe[:]); n != 0 || !errors.Is(readErr, io.EOF) {
			writeError(w, http.StatusBadRequest, "body exceeds Upload-Total")
			return
		}
		if _, err := h.fs.Write(p.id, p.rel, p.body); err != nil {
			writeRefusal(w, err)
			return
		}
		finish(func(record sharefs.Record) (sharefs.Committed, error) { return h.fs.Commit(p.id, p.rel, 0, record) })
		return
	}
	// Every chunk re-admits the declared total against the quota, and its
	// own bytes against the disk, drawing on the share's reservation first.
	if err := h.ownerRoom(p.u, p.id, p.rel, total); err != nil {
		writeRefusal(w, err)
		return
	}
	hold, err := h.fs.AdmitWrite(p.id, p.u.Username, rg.Len())
	if err != nil {
		writeRefusal(w, err)
		return
	}
	defer hold.Release()
	// declare runs once for a fresh part, under the part's meta lock and
	// before its first byte: the pending row first (rows are the truth).
	// It refuses when this session's upload is committed or mid-commit, so
	// a late chunk never stages a part beside a commit.
	declare := func() error {
		if h.committing.active(p.id, p.rel, p.session) {
			return errCommittedBySession
		}
		if f, err := h.db.File(p.id, p.rel); err == nil && committedBy(f, p.session, total) {
			return errCommittedBySession
		}
		_, err := h.db.DeclareFile(p.id, p.rel, total)
		return err
	}
	st, err := h.fs.WriteRange(p.id, p.rel, hold.Reader(p.body), rg, total, p.session, declare)
	switch {
	case errors.Is(err, errCommittedBySession):
		if f, ferr := h.db.File(p.id, p.rel); ferr == nil && committedBy(f, p.session, total) {
			h.writeUploadDone(w, f)
			return
		}
		writeError(w, http.StatusConflict, "the upload is being committed; ask where it stands")
	case errors.Is(err, sharefs.ErrPartChanged):
		// No code: the reference client reads an uncoded 409 as "ask where
		// the upload stands and send again".
		writeError(w, http.StatusConflict, err.Error())
	case err != nil:
		// The ranges that landed stay as resume state, whether the body
		// dropped or its next window was refused (507 no-space): a sibling
		// chunk may be landing beside them, and the client resumes from
		// what the status route reports once there is room. An upload
		// nobody resumes is the stalled sweep's, part and pending row.
		writeRefusal(w, err)
	case st.Complete:
		finish(func(record sharefs.Record) (sharefs.Committed, error) {
			return h.fs.CommitRanged(p.id, p.rel, total, p.session, record)
		})
	default:
		writeJSON(w, http.StatusAccepted, map[string]any{"missing": st.Missing})
	}
}
