package api

import (
	"net/http"
	"strconv"

	"hyperdrop/server/internal/metadb"
)

// Changes page bounds: each entry may cost a disk read to resolve, so the
// page is capped like the listing.
const (
	changesDefaultLimit = 500
	changesMaxLimit     = 2000
)

// shareChanges answers which shares changed since the caller's cursor: full
// listing rows for upserts, bare ids for deletions. A cursor the journal
// cannot honour (unparseable, or older than the rows the prune has already
// removed) answers reset:true, and the client re-walks GET /api/shares.
func (h *handler) shareChanges(w http.ResponseWriter, r *http.Request) {
	u := reqUser(r)
	limit := changesDefaultLimit
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 {
		limit = min(v, changesMaxLimit)
	}
	batch, err := h.db.Since(r.URL.Query().Get("since"), u.Username, limit)
	if err != nil {
		writeRefusal(w, err)
		return
	}
	if batch.Reset {
		writeJSON(w, http.StatusOK, map[string]any{"reset": true, "cursor": batch.Next})
		return
	}
	type changeOut struct {
		Share   *shareOut `json:"share,omitempty"`
		Deleted string    `json:"deleted,omitempty"`
	}
	// Since already scopes to the owner; the same check here so a row
	// reaching the output can never be another account's.
	ids := make([]string, 0, len(batch.Changes))
	for _, c := range batch.Changes {
		if c.Owner == u.Username && !c.Deleted {
			ids = append(ids, c.ShareID)
		}
	}
	shares, err := h.db.SharesByID(ids, listMaxFilesPerShare)
	if err != nil {
		writeRefusal(w, err)
		return
	}
	byID := make(map[string]metadb.Share, len(shares))
	for _, d := range shares {
		byID[d.ID] = d
	}
	out := make([]changeOut, 0, len(batch.Changes))
	for _, c := range batch.Changes {
		if c.Owner != u.Username {
			continue
		}
		d, ok := byID[c.ShareID]
		if c.Deleted || !ok {
			// A share the read did not find was deleted between the journal
			// read and this one. Absence is the truth either way.
			out = append(out, changeOut{Deleted: c.ShareID})
			continue
		}
		so := h.resolvedRow(h.viewFrom(d))
		out = append(out, changeOut{Share: &so})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"changes": out, "cursor": batch.Next, "more": batch.More,
	})
}
