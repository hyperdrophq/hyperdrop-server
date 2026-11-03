package api

import (
	"net/http"
	"time"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/shareid"
)

// How many share ids one batch request may name. Matches the downloads
// question's cap: one bulk pane selection is the loaded listing window,
// which is never larger than this.
const maxShareBatch = 1000

type batchFail struct {
	ID    string `json:"id"`
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}

// failErr reports one id's failure the way the single-share routes report
// theirs: the same machine-readable code and the same wording, so a bulk
// pane need not know which route it came from.
func failErr(id string, err error) batchFail {
	r := refusalOf(err)
	return batchFail{ID: id, Error: r.msg, Code: r.code}
}

// readShareIDs parses {"ids":[...]} from the body: non-empty, capped,
// first-occurrence order with duplicates dropped.
func readShareIDs(w http.ResponseWriter, r *http.Request) ([]string, bool) {
	var req struct {
		IDs []string `json:"ids"`
	}
	if !decodeJSONBody(w, r, 1<<20, &req) || !checkBatchIDs(w, req.IDs) {
		return nil, false
	}
	out := uniqueIDs(req.IDs)
	if len(out) == 0 {
		writeError(w, http.StatusBadRequest, "ids is required")
		return nil, false
	}
	return out, true
}

// checkBatchIDs refuses an empty ids list and one over maxShareBatch.
func checkBatchIDs(w http.ResponseWriter, ids []string) bool {
	if len(ids) == 0 {
		writeError(w, http.StatusBadRequest, "ids is required")
		return false
	}
	if len(ids) > maxShareBatch {
		writeError(w, http.StatusRequestEntityTooLarge, "too many ids (limit 1000)")
		return false
	}
	return true
}

// uniqueIDs keeps the first occurrence of each non-empty id, in order.
func uniqueIDs(ids []string) []string {
	seen := make(map[string]bool, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// deleteShares removes many shares the caller owns in one request. Per-id
// failures stay in "failed"; the rest still delete. A missing or foreign id
// is not-found, the same as DELETE /api/shares/{id}.
func (h *handler) deleteShares(w http.ResponseWriter, r *http.Request) {
	ids, ok := readShareIDs(w, r)
	if !ok {
		return
	}
	u := reqUser(r)
	deleted := make([]string, 0, len(ids))
	failed := make([]batchFail, 0)
	for _, id := range ids {
		if err := h.deleteOwned(id, u); err != nil {
			failed = append(failed, failErr(id, err))
			continue
		}
		deleted = append(deleted, id)
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": deleted, "failed": failed})
}

func (h *handler) deleteOwned(id string, u metadb.User) error {
	if err := h.ownsShare(id, u); err != nil {
		return err
	}
	return h.removeShare(id)
}

// ownsShare is the ownership gate without a response and without a source
// walk: a batch cannot abort the whole request on one missing id, and a
// delete has no use for what the share holds. A share of another account
// answers ErrNotFound, indistinguishable from one that does not exist.
func (h *handler) ownsShare(id string, u metadb.User) error {
	if !shareid.ValidID(id) {
		return metadb.ErrNotFound
	}
	d, err := h.db.ShareCapped(id, 1)
	if err != nil {
		return err
	}
	if d.Owner != u.Username {
		return metadb.ErrNotFound
	}
	return nil
}

// ownedRow is ownsShare for the batch edit, which answers the row it wrote
// and so needs the view the single-share routes gate on.
func (h *handler) ownedRow(id string, u metadb.User) (shareView, error) {
	if !shareid.ValidID(id) {
		return shareView{}, metadb.ErrNotFound
	}
	v, err := h.viewCapped(id)
	if err != nil {
		return shareView{}, err
	}
	if v.Owner != u.Username {
		return shareView{}, metadb.ErrNotFound
	}
	return v, nil
}

type editSharesReq struct {
	IDs              []string `json:"ids"`
	Password         *string  `json:"password"`
	ExpiresInSeconds *int64   `json:"expiresInSeconds"`
	Pinned           *bool    `json:"pinned"`
}

// editShares applies one password, expiry and/or pin change to many shares
// the caller owns. The fields use PATCH /api/shares/{id} pointer semantics.
// Name, entry, gallery and inbox-only fields are not accepted: a bulk
// pane only ever sets or clears a password, an expiry or a pin. One bcrypt
// of the password covers every share.
func (h *handler) editShares(w http.ResponseWriter, r *http.Request) {
	var req editSharesReq
	if !decodeJSONBody(w, r, 1<<20, &req) || !checkBatchIDs(w, req.IDs) {
		return
	}
	if req.Password == nil && req.ExpiresInSeconds == nil && req.Pinned == nil {
		writeError(w, http.StatusBadRequest, "nothing to change")
		return
	}
	if req.ExpiresInSeconds != nil && *req.ExpiresInSeconds < 0 {
		writeError(w, http.StatusBadRequest, "negative duration")
		return
	}
	ids := uniqueIDs(req.IDs)
	if len(ids) == 0 {
		writeError(w, http.StatusBadRequest, "ids is required")
		return
	}

	var hash string
	if req.Password != nil {
		var ok bool
		if hash, ok = hashPassword(w, *req.Password); !ok {
			return
		}
	}

	u := reqUser(r)
	updated := make([]any, 0, len(ids))
	failed := make([]batchFail, 0)
	pinAt := time.Now().UTC()
	for _, id := range ids {
		row, fail := h.editOwned(id, u, req, hash, pinAt)
		if fail != nil {
			fail.ID = id
			failed = append(failed, *fail)
			continue
		}
		updated = append(updated, row)
	}
	writeJSON(w, http.StatusOK, map[string]any{"updated": updated, "failed": failed})
}

// editOwned applies one batch row's change through the shared edit, so a
// bulk pane and a single PATCH refuse the same things in the same words.
func (h *handler) editOwned(id string, u metadb.User, req editSharesReq, hash string, pinAt time.Time) (any, *batchFail) {
	v, err := h.ownedRow(id, u)
	if err != nil {
		fail := failErr(id, err)
		return nil, &fail
	}
	edit := shareUpdate{Password: req.Password, ExpiresInSeconds: req.ExpiresInSeconds, Pinned: req.Pinned, pinAt: pinAt}
	edited, err := h.applyEdit(v, u, edit, hash)
	if err != nil {
		fail := failErr(id, err)
		return nil, &fail
	}
	return h.resolvedRow(edited), nil
}
