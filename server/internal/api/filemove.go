package api

import (
	"errors"
	"log"
	"net/http"
	"path"

	"hyperdrop/server/internal/linked"
	"hyperdrop/server/internal/sharefs"
	"hyperdrop/server/internal/shareid"
)

// moveFile relocates ONE stored file, or every stored entry beneath one
// folder, within a share the caller owns: POST /api/shares/{id}/move
// {"from","to"}. Every moved entry keeps its slug, so the links already sent
// keep working; only the listing changes. Responds with the updated
// sanitized share.
//
// A linked entry (served live from a server folder) is the folder's, not
// the share's, so it neither moves nor gets moved onto; a destination the
// source already lists is refused exactly as an upload there would be.
func (h *handler) moveFile(w http.ResponseWriter, r *http.Request) {
	v, _, ok := h.ownedShare(w, r)
	if !ok {
		return
	}
	var body struct {
		From string `json:"from"`
		To   string `json:"to"`
	}
	if !decodeJSONBody(w, r, 64<<10, &body) {
		return
	}
	from, to := relPath(body.From), relPath(body.To)
	if !shareid.ValidRelPath(from) || !shareid.ValidRelPath(to) {
		writeError(w, http.StatusBadRequest, "from and to must be clean relative paths")
		return
	}
	if err := v.contentEditRefusal(editMove); err != nil {
		writeRefusal(w, err)
		return
	}
	if v.Linked() {
		if err := h.linkedMoveRefusal(v, from, to); err != nil {
			writeRefusal(w, err)
			return
		}
	}
	out, err := h.db.MoveEntries(v.ID, from, to)
	if err != nil {
		writeRefusal(w, err)
		return
	}
	// Rows first, bytes after: for that instant the rows name the new path
	// while the bytes are still at the old one, and serving one path from
	// the other's bytes would be worse than an error the caller can retry.
	// When the bytes refuse to move the rows follow them back, so a failed
	// move leaves the share exactly as it stood rather than listing a name
	// nothing can serve.
	//
	// Nothing on disk at `from` is not a failure: a folder RECORD has no
	// directory of its own, so a move of empty folders moves rows alone.
	if err := h.fs.Rename(v.ID, from, to); err != nil && !errors.Is(err, sharefs.ErrNotFound) {
		log.Printf("move %s %s to %s: %v", v.ID, from, to, err)
		if _, back := h.db.MoveEntries(v.ID, to, from); back != nil {
			log.Printf("move %s: returning the rows from %s to %s: %v", v.ID, to, from, back)
		}
		// The request was valid and the rows took it; the bytes refusing
		// is the server's failure, whatever sharefs called it, answered by
		// reference like every other 500.
		writeRefusal(w, internalError(err))
		return
	}
	writeJSON(w, http.StatusOK, h.resolvedRow(h.viewFrom(out)))
}

// linkedMoveRefusal refuses a move that touches what the share's sources
// serve: a linked entry at or beneath `from` (409 share-linked), a linked
// entry standing at, beneath or above a destination (400 path-taken), and a
// destination the source lists under that name (400 path-taken, the upload
// rule, asked of `to` itself: every destination sits beneath it, and the
// walked entries answer for those). A linked entry is compared in NFC, the
// spelling from and to arrive in (relPath).
func (h *handler) linkedMoveRefusal(v shareView, from, to string) error {
	var dests []string
	linkedPaths := make(map[string]bool)
	for _, f := range v.Files {
		p := f.Path
		if f.Linked {
			p = relPath(p)
			linkedPaths[p] = true
		}
		if !linked.Under(p, from) {
			continue
		}
		if f.Linked {
			return errShareLinked
		}
		dests = append(dests, to+p[len(from):])
	}
	taken := func(dest string) error {
		return refuse(http.StatusBadRequest, "path-taken", "a source already lists under the name "+dest)
	}
	for _, dest := range dests {
		// The destination itself, or a folder above it, is a linked FILE;
		// or a linked entry sits beneath the destination.
		for dir := dest; dir != "." && dir != "/"; dir = path.Dir(dir) {
			if linkedPaths[dir] {
				return taken(dest)
			}
		}
	}
	for p := range linkedPaths {
		if linked.Under(p, to) {
			return taken(to)
		}
	}
	return h.sourceNameRefusal(v, to)
}
