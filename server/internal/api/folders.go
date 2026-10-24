package api

import (
	"net/http"

	"hyperdrop/server/internal/shareid"
)

// createFolder records one explicit folder in a share the caller owns:
// POST /api/shares/{id}/folders {"path"}. Responds with the updated
// sanitized share. A name the share's source lists is refused exactly as an
// upload there would be.
func (h *handler) createFolder(w http.ResponseWriter, r *http.Request) {
	v, _, ok := h.ownedShareMeta(w, r)
	if !ok {
		return
	}
	var body struct {
		Path string `json:"path"`
	}
	if !decodeJSONBody(w, r, 64<<10, &body) {
		return
	}
	rel := relPath(body.Path)
	if !shareid.ValidRelPath(rel) {
		writeError(w, http.StatusBadRequest, "path must be a clean relative path")
		return
	}
	if err := v.contentEditRefusal(editAddFolder); err != nil {
		writeRefusal(w, err)
		return
	}
	// A name the source lists is the linked half of "the name is taken";
	// the rows answer for stored files and folder records.
	if err := h.sourceNameRefusal(v, rel); err != nil {
		writeRefusal(w, err)
		return
	}
	out, err := h.db.AddFolder(v.ID, rel)
	if err != nil {
		writeRefusal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, h.resolvedRow(h.viewFrom(out)))
}

// deleteFolder removes the explicit folder records at a path and beneath
// it: DELETE /api/shares/{id}/folders/{path...}. Refused while a stored
// file sits inside; nothing here deletes files.
func (h *handler) deleteFolder(w http.ResponseWriter, r *http.Request) {
	v, _, ok := h.ownedShareMeta(w, r)
	if !ok {
		return
	}
	rel := relPathParam(r)
	if !shareid.ValidRelPath(rel) {
		writeError(w, http.StatusBadRequest, "path must be a clean relative path")
		return
	}
	if err := v.contentEditRefusal(editDeleteFolder); err != nil {
		writeRefusal(w, err)
		return
	}
	out, err := h.db.RemoveFolder(v.ID, rel)
	if err != nil {
		writeRefusal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, h.resolvedRow(h.viewFrom(out)))
}
