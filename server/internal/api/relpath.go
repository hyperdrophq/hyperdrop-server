package api

import (
	"net/http"
	"strconv"

	"golang.org/x/text/unicode/norm"

	"hyperdrop/server/internal/shareid"
)

// relPath is the one spelling rule for a relpath a request names as a
// share's own entry: Unicode NFC, the rule core/relpath applies on the
// client. Every such path goes through it before anything reads or records
// it: an upload's path and its ?replaces=, a status query, a delete, a
// move, a folder, a batch entry, a manifest entry, a preparing report, an
// entry page, a hidden or shown linked path, a live share's file and a
// Receive Inbox upload's name. Two spellings of café are then one path on
// every route, whichever client sent it, so the staged part, the manifest's
// slug, the ?replaces= match and a delete all agree.
//
// A linked entry keeps the server filesystem's bytes, which a folder copied
// from a Mac often holds decomposed, so what matches a received relpath
// against one compares the two in NFC (shareView.FileByPath, the linked
// filters). A path a read looks up is not rewritten: /site tries the
// request's spelling, then NFC, then NFD (siteSpellings); ?dir= names a
// folder exactly as the listing printed it; and a source path names the
// server's own filesystem byte for byte.
func relPath(s string) string { return norm.NFC.String(s) }

// spelled is rel as the share spells it (metadb.Spelling): on a data volume
// that folds case, an upload, a batch entry, an upload's status and a move's
// destination name the file or folder they fold onto, so the staged part,
// the path lock, the stored file and the row all use one spelling. moving is
// a move's source, left out of what the destination can fold onto. A read
// that fails answers rel, and the store spells it again inside its write.
func (h *handler) spelled(id, rel, moving string) string {
	if p, err := h.db.Spelling(id, rel, moving); err == nil {
		return p
	}
	return rel
}

// relPathParam is the {path...} wildcard through relPath.
func relPathParam(r *http.Request) string { return relPath(r.PathValue("path")) }

// errPathTooDeep refuses a path a request would create deeper than
// shareid.MaxRelPathDepth segments: a 400 like any other unusable path.
var errPathTooDeep = refuse(http.StatusBadRequest, "path-too-deep",
	"a path holds at most "+strconv.Itoa(shareid.MaxRelPathDepth)+" folders and a name")

// tooDeep reports whether rel is a clean path past the creation depth cap.
// A path that is not clean at all is refused by the route's own check.
func tooDeep(rel string) bool {
	return shareid.ValidRelPath(rel) && !shareid.ValidNewRelPath(rel)
}

// relPaths is relPath over a list, nil for nil.
func relPaths(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = relPath(s)
	}
	return out
}
