package api

import (
	"net/http"

	"hyperdrop/server/internal/shareid"
)

// deleteFile removes ONE file entry from a share the caller owns:
// DELETE /api/shares/{id}/files/{path...}. The file's slug dies with it
// (its links answer 404), the share's other links keep working, and when
// the removed entry was the share's entry page the link falls back to the
// file listing. Responds with the updated sanitized share.
func (h *handler) deleteFile(w http.ResponseWriter, r *http.Request) {
	v, _, ok := h.ownedShareMeta(w, r)
	if !ok {
		return
	}
	rel := relPathParam(r)
	if !shareid.ValidRelPath(rel) {
		writeError(w, http.StatusBadRequest, "path must be a clean relative path")
		return
	}
	if err := v.contentEditRefusal(editDeleteFile); err != nil {
		writeRefusal(w, err)
		return
	}
	// A linked entry lives on the server's own disk: the share can let go
	// of the source, never delete the file. A stored file beside it deletes as ever.
	if f, held := v.FileByPath(rel); held && f.Linked {
		writeRefusal(w, errShareLinked)
		return
	}
	out, err := h.removeFiles(v.ID, []string{rel})
	if err != nil {
		writeRefusal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, h.resolvedRow(h.viewFrom(out)))
}
