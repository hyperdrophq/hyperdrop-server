package api

import (
	"fmt"
	"io"
	"net/http"
	"unicode/utf8"
)

// A text share is one text file: the note the app or the CLI published. It
// opens as that file, so it takes no entry, gallery or listing; it holds that
// file alone, so a second path is refused; and it keeps that file, so a delete
// is refused. Replacing the file (?replaces=, ?replaceAll=1) is the one
// content change it takes, which is how a sent link survives an edit.

// textShareRefusal answers the 409 an upload of rel into v earns for being a
// second file of a text share, or nil. replacing is true when the request
// carries ?replaces= or ?replaceAll=1, which hands the old file's place to
// the new one.
//
// v.Files holds at most one entry for a text share (every admission path
// enforces it); the condition names that invariant directly rather than
// looping to discover it: more than one file already means the share is
// wider than it should be, and exactly one means rel must be that file.
func textShareRefusal(v shareView, rel string, replacing bool) error {
	if !v.Text || replacing {
		return nil
	}
	if len(v.Files) > 1 || (len(v.Files) == 1 && v.Files[0].Path != rel) {
		return refuse(http.StatusConflict, "text-share", "a text share holds one file: replace it rather than adding "+rel)
	}
	return nil
}

// textShareReplacing reports whether ?replaces=/?replaceAll=1 actually
// replaces content already in v, which is the only way either one earns an
// exemption from the one-file rule above. replaceAll always qualifies: it
// collapses the share to whatever this upload commits, which is a valid
// answer whether the share already held a file or not. replaces qualifies
// only when the share currently holds that exact path; a replaces naming a
// path the share does not hold names nothing to replace, so the caller must
// weigh the upload against the ordinary one-file rule instead of skipping
// it, or the upload commits as a second file that ReplaceEntry then fails
// to place, orphaned because a text share's delete route is itself refused.
func textShareReplacing(v shareView, replaces string, replaceAll bool) bool {
	if replaceAll {
		return true
	}
	if replaces == "" {
		return false
	}
	_, ok := v.FileByPath(replaces)
	return ok
}

// textReadMaxBytes is the largest note GET /api/shares/{id}/text answers:
// the in-place edit limit every app holds (core/judge.TextEditMaxBytes,
// 256 KiB), so a note the editor can open is a note this route reads.
const textReadMaxBytes int64 = 256 * 1024

// shareText answers GET /api/shares/{id}/text: the owner's text share's one
// file as {"name","text"}, name being the file's relpath, so the web client's
// note editor opens with the current words. The text is wrapped in JSON
// rather than served as the file: on the app origin it is data the page
// reads, never a document the browser renders. Owner only (anyone else, an
// admin included, gets the 404 an unknown share gets); a share that is not
// a text share is 409 not-text-share, a text share holding no file yet 404,
// its file still uploading 409 file-pending, over textReadMaxBytes 413
// text-too-large, and bytes that are not UTF-8 409 text-not-utf8.
func (h *handler) shareText(w http.ResponseWriter, r *http.Request) {
	v, _, ok := h.ownedShare(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if !v.Text {
		writeErrorCode(w, http.StatusConflict, "not-text-share", "this share is not a text share")
		return
	}
	if len(v.Files) != 1 {
		writeErrorCode(w, http.StatusNotFound, "not-found", "the text share holds no text yet")
		return
	}
	f := v.Files[0]
	if f.Pending {
		writeErrorCode(w, http.StatusConflict, "file-pending", "the text is still uploading")
		return
	}
	tooLarge := func() {
		writeErrorCode(w, http.StatusRequestEntityTooLarge, "text-too-large",
			fmt.Sprintf("the text is over %d KiB", textReadMaxBytes/1024))
	}
	if f.Size > textReadMaxBytes {
		tooLarge()
		return
	}
	file, _, f, err := h.openEntry(v, f)
	if err != nil {
		writeErrorCode(w, http.StatusNotFound, "not-found", "the text share's file is missing")
		return
	}
	defer file.Close()
	b, err := io.ReadAll(io.LimitReader(file, textReadMaxBytes+1))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "reading the text failed")
		return
	}
	if int64(len(b)) > textReadMaxBytes {
		tooLarge()
		return
	}
	if !utf8.Valid(b) {
		writeErrorCode(w, http.StatusConflict, "text-not-utf8", "the text is not UTF-8")
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Name string `json:"name"`
		Text string `json:"text"`
	}{f.Path, string(b)})
}
