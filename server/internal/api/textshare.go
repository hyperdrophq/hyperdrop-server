package api

import "net/http"

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
