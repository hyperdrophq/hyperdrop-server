package api

import (
	"net/http"
	"path"
)

// The "it's coming" page: served on /view, /download and /zip, and on a file
// link, while the requested content is still uploading. Self-contained like
// the listing page, plus a small poller that live-updates the progress bar
// and reloads the page the moment the content is ready (the reload then
// serves the real view/download/zip). A share's page polls
// /share/{id}/status; a file link's polls the address it is given.
var waitingTmpl = page("waiting", "waiting.html")

type waitingData struct {
	ID    string
	Slug  string // "" = whole-share mode (/zip), and on a file link
	Title string
	// StatusURL is the poll a file link's page reads (/f/{fileKey}/status);
	// "" means the share's own /share/{id}/status.
	StatusURL string
	// OneFile says the page waits on one file rather than the whole share.
	OneFile bool
	// Waiting tells the visitor what happens when the upload finishes:
	// the file appearing right here (view) vs a download starting.
	Waiting string
	// Gone is shown when the poll answers 404 mid-wait: the share or the
	// file link existed when this page was served, so it was canceled or
	// removed on the sender's side.
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
		d.Waiting = waitingFileView
	case f != nil:
		d.Waiting = waitingFileDownload
	case willView:
		d.Waiting = "Still uploading: the share will open right here the moment all files are ready."
	default:
		d.Waiting = "Still uploading: your download will start automatically when all files are ready."
	}
	if f != nil {
		d.Gone = waitingFileGone
	} else {
		d.Gone = "The upload was canceled or the share was removed on the sender's side, so the files aren't coming. Ask the sender to share them again."
	}
	if f != nil {
		d.Slug = f.Slug
		d.OneFile = true
		d.Title = f.Path
	} else {
		d.Title = v.Name
		if d.Title == "" {
			d.Title = "Files"
		}
	}
	h.renderPage(w, framable, 0, true, waitingTmpl, d)
}

// The waiting page's one-file sentences, on a share's /view and /download and
// on a file link.
const (
	waitingFileView     = "Still uploading: the file will appear right here the moment it's ready."
	waitingFileDownload = "Still uploading: your download will start automatically the moment it's ready."
	waitingFileGone     = "The upload was canceled or the share was removed on the sender's side, so the file isn't coming. Ask the sender to share it again."
)

// renderFileLinkWaiting is the still-uploading page of a file link: the
// share's waiting page in its one-file mode, titled by the file's base name
// and polling /f/{fileKey}/status. It is built from the key and the file
// alone, so it carries no share id, no slug, no folder and no other file.
// willView says the finished reload renders the file in the browser rather
// than downloading it.
func (h *handler) renderFileLinkWaiting(w http.ResponseWriter, key string, f fileView, willView bool) {
	d := waitingData{Title: path.Base(f.Path), Waiting: waitingFileDownload, Gone: waitingFileGone,
		StatusURL: "/f/" + key + "/status", OneFile: true}
	if willView {
		d.Waiting = waitingFileView
	}
	h.renderPage(w, framable, 0, true, waitingTmpl, d)
}
