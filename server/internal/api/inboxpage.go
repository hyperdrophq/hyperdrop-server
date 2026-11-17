package api

import (
	"fmt"
	"strings"

	"hyperdrop/server/internal/metadb"
)

// inboxData is what the /receive/{id} upload page renders: page copy only,
// never the inbox's content. The uploader sees their own session's
// progress and nothing anyone else sent (blind share).
type inboxData struct {
	ID     string
	Name   string
	Note   string
	Closed bool
	// Full is an open inbox holding as many files as it takes: the page
	// says so rather than offer a drop zone every upload of which is refused.
	Full bool
	// The link's caps, for the page to refuse a file that could never fit
	// before a byte moves and to name the limit when an upload fails.
	MaxBytes int64
	MaxFiles int
	// Limits reads like "5 files, 20 MB in all"; empty for an uncapped link.
	Limits string
}

// inboxFileLimit is the file cap an inbox reports: its own maxFiles, or the
// server's bound (metadb.InboxMaxFiles) where that is lower than what the
// inbox stored, or once the inbox holds that many files and the bound is
// what refuses the next one. 0 stays the "server's bound" it means while
// the bound is not reached.
func inboxFileLimit(maxFiles, committed int) int {
	limit := metadb.InboxFileCap(maxFiles)
	if maxFiles > limit || committed >= limit {
		return limit
	}
	return maxFiles
}

// inboxFull reports whether an inbox holds as many files as it takes.
func inboxFull(maxFiles, committed int) bool {
	return committed >= metadb.InboxFileCap(maxFiles)
}

// inboxLimits words a link's caps for its upload page.
func inboxLimits(maxFiles int, maxBytes int64) string {
	var parts []string
	if maxFiles > 0 {
		parts = append(parts, fmt.Sprintf("%d files", maxFiles))
	}
	if maxBytes > 0 {
		parts = append(parts, fmt.Sprintf("%d MB in all", (maxBytes+(1<<20)-1)>>20))
	}
	return strings.Join(parts, ", ")
}

// inboxTmpl is the public upload page: inline CSS and vanilla JS like
// every other public page (no assets on disk, no external resources).
// Uploads are sequential XHR PUTs, XHR because fetch exposes no upload
// progress. The PUT URL is built absolute from the inbox id: the page
// URL /receive/{id} has no trailing slash, so a relative "files/x" would
// resolve outside the inbox.
var inboxTmpl = page("receive", "inbox.html")
