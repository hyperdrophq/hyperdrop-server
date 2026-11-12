package api

import (
	"net/http"
	"sync"
	"time"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/shareid"
)

// A preparing report is what a sender says about a pending file whose bytes
// have not started arriving because the sender is still making them (a
// video being re-encoded on its Mac). It is decoration about work that has
// not reached this server: kept in memory and never written as a row, so it
// moves neither modifiedAt nor the change journal, and a restart loses at
// most the two seconds until the sender's next report. Two things read it:
// the status poll, which relays it to the waiting page, and the empty sweep,
// which takes a fresh report as proof the share is alive.

// preparingStale is how old a report may be and still be shown: past it the
// waiting page falls back to its upload copy rather than claim a progress the
// sender may no longer be making. The sweep uses its own, longer window.
const preparingStale = 5 * time.Minute

// preparingBodyLimit caps the report's JSON body: two short fields.
const preparingBodyLimit = 1 << 10

type prepStage string

const (
	prepEncoding prepStage = "encoding"
	prepRemuxing prepStage = "remuxing"
)

// prepReport is one file's newest report.
type prepReport struct {
	Stage    prepStage
	Fraction float64
	At       time.Time
}

// prepTracker holds every share's reports by file path.
type prepTracker struct {
	mu  sync.Mutex
	m   map[string]map[string]prepReport
	now func() time.Time
}

func newPrepTracker() *prepTracker {
	return &prepTracker{m: map[string]map[string]prepReport{}, now: time.Now}
}

// set records the newest report for one file.
func (t *prepTracker) set(shareID, path string, stage prepStage, fraction float64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	files := t.m[shareID]
	if files == nil {
		files = map[string]prepReport{}
		t.m[shareID] = files
	}
	files[path] = prepReport{Stage: stage, Fraction: fraction, At: t.now()}
}

// get answers one file's report when it is fresher than preparingStale.
func (t *prepTracker) get(shareID, path string) (prepReport, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	rep, ok := t.m[shareID][path]
	if !ok || t.now().Sub(rep.At) >= preparingStale {
		return prepReport{}, false
	}
	return rep, true
}

// fresh counts the share's files with a report fresher than preparingStale.
func (t *prepTracker) fresh(shareID string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	now := t.now()
	for _, rep := range t.m[shareID] {
		if now.Sub(rep.At) < preparingStale {
			n++
		}
	}
	return n
}

// ReportedSince answers whether any file of the share was reported on after
// since: the empty sweep's liveness question, which outlives preparingStale
// by design (a sender that reported an hour ago is still the sweep's reason
// to wait, where it is no longer the page's reason to show a percentage).
func (t *prepTracker) ReportedSince(shareID string, since time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, rep := range t.m[shareID] {
		if rep.At.After(since) {
			return true
		}
	}
	return false
}

// forgetFile drops one file's report: the file committed or its row went.
func (t *prepTracker) forgetFile(shareID, path string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.m[shareID], path)
	if len(t.m[shareID]) == 0 {
		delete(t.m, shareID)
	}
}

// forgetShare drops every report of a share that no longer exists.
func (t *prepTracker) forgetShare(shareID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.m, shareID)
}

// prepOut is a report as the status poll relays it.
type prepOut struct {
	Stage    string  `json:"stage"`
	Fraction float64 `json:"fraction"`
}

// reportPreparing is PUT /api/shares/{id}/preparing/{path...}: the owner
// reports how far a pending file's preparation has come. Only a PENDING row
// takes a report, because a committed file has nothing left to prepare and a
// report on one is a client bug rather than a state to record.
func (h *handler) reportPreparing(w http.ResponseWriter, r *http.Request) {
	v, _, ok := h.ownedShareMeta(w, r)
	if !ok {
		return
	}
	rel := relPathParam(r)
	if !shareid.ValidRelPath(rel) {
		writeError(w, http.StatusBadRequest, "path must be a clean relative path")
		return
	}
	var in struct {
		Fraction float64 `json:"fraction"`
		Stage    string  `json:"stage"`
	}
	if !decodeJSONBody(w, r, preparingBodyLimit, &in) {
		return
	}
	if in.Fraction < 0 || in.Fraction > 1 {
		writeError(w, http.StatusBadRequest, "fraction must be between 0 and 1")
		return
	}
	stage := prepStage(in.Stage)
	if stage != prepEncoding && stage != prepRemuxing {
		writeError(w, http.StatusBadRequest, "stage must be encoding or remuxing")
		return
	}
	f, err := h.db.File(v.ID, rel)
	if err != nil || !f.Pending {
		writeRefusal(w, metadb.ErrNotFound)
		return
	}
	h.prep.set(v.ID, rel, stage, in.Fraction)
	w.WriteHeader(http.StatusNoContent)
}

// PreparingReportedSince is the empty sweep's liveness question: whether a
// sender reported on any file of the share after since.
func (s *Server) PreparingReportedSince(shareID string, since time.Time) bool {
	return s.h.prep.ReportedSince(shareID, since)
}
