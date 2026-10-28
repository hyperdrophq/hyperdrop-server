package api

import (
	"net/http"
)

// The "it's coming" page: served on /view, /download and /zip while the
// requested content is still uploading. Self-contained like the listing page,
// plus a small poller against /share/{id}/status that live-updates the
// progress bar and reloads the page the moment the content is ready (the
// reload then serves the real view/download/zip).
var waitingTmpl = page("waiting", "waiting.html")

type waitingData struct {
	ID    string
	Slug  string // "" = whole-share mode (/zip)
	Title string
	// Waiting tells the visitor what happens when the upload finishes:
	// the file appearing right here (view) vs a download starting.
	Waiting string
	// Gone is shown when the share 404s mid-wait: it existed when this page
	// was served, so it was canceled/removed on the sender's side.
	Gone string
}

// renderWaiting serves the still-uploading page. f selects single-file mode
// (progress for that slug; reload serves the file); nil means whole-share
// (progress across all files; the reload of /share opens whatever the
// share opens as, the reload of /zip starts the zip). willView says the
// finished reload renders content in the browser (a /view of a viewable
// file, the share page), as opposed to starting a download.
func (h *handler) renderWaiting(w http.ResponseWriter, v shareView, f *fileView, willView bool) {
	d := waitingData{ID: v.ID}
	switch {
	case f != nil && willView:
		d.Waiting = "Still uploading: the file will appear right here the moment it's ready."
	case f != nil:
		d.Waiting = "Still uploading: your download will start automatically the moment it's ready."
	case willView:
		d.Waiting = "Still uploading: the share will open right here the moment all files are ready."
	default:
		d.Waiting = "Still uploading: your download will start automatically when all files are ready."
	}
	if f != nil {
		d.Gone = "The upload was canceled or the share was removed on the sender's side, so the file isn't coming. Ask the sender to share it again."
	} else {
		d.Gone = "The upload was canceled or the share was removed on the sender's side, so the files aren't coming. Ask the sender to share them again."
	}
	if f != nil {
		d.Slug = f.Slug
		d.Title = f.Path
	} else {
		d.Title = v.Name
		if d.Title == "" {
			d.Title = "Files"
		}
	}
	h.renderPage(w, framable, 0, true, waitingTmpl, d)
}
