package api

import (
	"math"
	"net/http"
)

// downloads counts the byte-serving requests in flight per share, so an owner
// about to delete files from a share (or add some) can be told that someone is
// pulling it right now.
//
// In memory and per instance on purpose: no stream survives a restart, so a
// count that resets with one is the correct count. A share nobody is reading
// holds no entry, which is what keeps the table bounded by concurrency rather
// than by how many shares exist.
//
// Each read is counted under its share's OWNER and id together, which is what
// lets the route answer for several shares at once without reading a single
// meta file: the counter already knows whose share each id is, and an id
// nobody is reading needs no answer beyond zero.
type downloads struct {
	reads slotTable
}

func newDownloads() *downloads {
	return &downloads{}
}

// downloadKey is the key the count of owner's reads of shareID is held
// under. A username holds no space, so the first space ends the owner
// whatever an id asked about holds.
func downloadKey(owner, shareID string) string {
	return owner + " " + shareID
}

// begin records one in-flight read of shareID and returns the release. The
// release is idempotent: a handler that both defers it and calls it early must
// not push the count below zero and hide a real download. A read is never
// refused: the table's total is unbounded and the key has no cap.
func (d *downloads) begin(shareID, owner string) func() {
	release, _ := d.reads.take(math.MaxInt, slotCap{key: downloadKey(owner, shareID)})
	return release
}

// activeFor totals the reads in flight across ids, counting only the shares
// this account owns: an id belonging to somebody else answers the same as an
// id nobody is reading, so the total tells a caller nothing about shares that
// are not theirs.
func (d *downloads) activeFor(owner string, ids []string) int {
	total := 0
	for _, id := range ids {
		total += d.reads.held(downloadKey(owner, id))
	}
	return total
}

// maxDownloadQueryIDs bounds one question. A bulk delete asks about its whole
// selection, which is why this is generous rather than small; it exists so a
// hand-built URL cannot make the server walk an unbounded list.
const maxDownloadQueryIDs = 1000

// shareDownloads answers how many reads of the named shares are in flight,
// which is what lets an owner's client warn before deleting files someone is
// pulling, and say afterwards that an add missed the downloads already
// running. One question covers a whole bulk delete, so a client never has to
// choose between asking N times and not asking.
//
// A route of its own rather than a field on the share view: the listing is
// served to clients from their offline replica, and a number that stale would
// be worse than no number at all.
func (h *handler) shareDownloads(w http.ResponseWriter, r *http.Request) {
	ids := r.URL.Query()["id"]
	if len(ids) == 0 {
		writeErrorCode(w, http.StatusBadRequest, "bad-request", "no id given")
		return
	}
	if len(ids) > maxDownloadQueryIDs {
		writeErrorCode(w, http.StatusBadRequest, "bad-request", "too many ids")
		return
	}
	writeJSON(w, http.StatusOK,
		map[string]int{"active": h.dl.activeFor(reqUser(r).Username, ids)})
}
