package api

import (
	"net/http"
	"time"

	"hyperdrop/server/internal/shareid"
)

// maxFileLinkSlugs bounds one mint request.
const maxFileLinkSlugs = 1000

// fillFileKeys sets each entry's fileKey from the share's file_links rows:
// one read per share answered. An inbox's entries never carry one.
func (h *handler) fillFileKeys(so *shareOut) {
	if so.Inbox || len(so.Files) == 0 {
		return
	}
	keys, err := h.db.FileKeys(so.ID)
	if err != nil || len(keys) == 0 {
		return
	}
	for i := range so.Files {
		so.Files[i].FileKey = keys[so.Files[i].Slug]
	}
}

// mintFileLinks answers POST /api/shares/{id}/file-links {"slugs":[...]}:
// the direct-link key of each named file the share holds, minted when the
// file has none. A slug the share does not hold is left out of the answer.
// The share is composed through ownedShare first, which gives a linked
// entry its slug.
func (h *handler) mintFileLinks(w http.ResponseWriter, r *http.Request) {
	v, _, ok := h.ownedShare(w, r)
	if !ok {
		return
	}
	var body struct {
		Slugs []string `json:"slugs"`
	}
	if !decodeJSONBody(w, r, 256<<10, &body) {
		return
	}
	if len(body.Slugs) == 0 || len(body.Slugs) > maxFileLinkSlugs {
		writeError(w, http.StatusBadRequest, "slugs takes 1 to 1000 file slugs")
		return
	}
	for _, s := range body.Slugs {
		if !shareid.ValidSlug(s) {
			writeError(w, http.StatusBadRequest, "slugs holds a value that is not a file slug")
			return
		}
	}
	keys, err := h.db.MintFileKeys(v.ID, body.Slugs, time.Now())
	if err != nil {
		writeRefusal(w, err)
		return
	}
	type link struct {
		Slug    string `json:"slug"`
		FileKey string `json:"fileKey"`
	}
	links := make([]link, 0, len(keys))
	for _, s := range body.Slugs {
		if k, held := keys[s]; held {
			links = append(links, link{Slug: s, FileKey: k})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"links": links})
}

// stopFileLink answers DELETE /api/shares/{id}/file-links/{slug}: the file's
// key is deleted, and the answer is 204 whether or not it had one.
func (h *handler) stopFileLink(w http.ResponseWriter, r *http.Request) {
	v, _, ok := h.ownedShareMeta(w, r)
	if !ok {
		return
	}
	slug := r.PathValue("slug")
	if !shareid.ValidSlug(slug) {
		writeError(w, http.StatusBadRequest, "not a file slug")
		return
	}
	if err := h.db.StopFileKey(v.ID, slug, time.Now()); err != nil {
		writeRefusal(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
