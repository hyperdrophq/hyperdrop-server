// The owner-facing routes for live shares (server/internal/liveshare),
// created, watched with a job long-poll, and relayed byte-for-byte through
// the owner's own connected client. Nothing here touches the disk: the
// registry is in-memory and the bytes never land on this server at all.

package api

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"

	"hyperdrop/server/internal/liveshare"
	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/shareid"
)

// liveSharePark is how long a job poll holds before answering "nothing yet".
// Shorter than the watch route's 50 s: a live share is latency-sensitive in a
// way the mount is not, and 180 requests/hour per share is nothing.
const liveSharePark = 20 * time.Second

// liveShareFailBodyLimit bounds the /error body: a JSON object holding one short
// code string ("network-lost", "file-vanished", ...), never anything bigger.
// Every JSON handler in this package caps its body one way or another.
const liveShareFailBodyLimit = 4 << 10

// newLiveShareID wraps a raw id minter so it never hands out an id the
// database already holds (see newHandler in api.go for why that collision
// would make the live share permanently unreachable). Factored out as a
// function of mint/exists, rather than inlined as a closure over *metadb.DB,
// purely so the loop itself is unit-testable without forcing a real
// shareid.NewID collision, which crypto/rand gives no hook to do.
func newLiveShareID(mint func() string, exists func(string) bool) func() string {
	return func() string {
		for {
			id := mint()
			if !exists(id) {
				return id
			}
		}
	}
}

// defaultLiveShareGrace is how long a live share outlives its sharer's
// connection when Deployment.LiveShareGrace does not say otherwise.
const defaultLiveShareGrace = 5 * time.Minute

// liveShareView converts a live record into the view every public route
// consumes. CommittedAt carries the manifest mtime: the strong ETag is built
// from it, and "when the bytes landed" is the source file's own mtime for a
// share that stores nothing.
func liveShareView(rec liveshare.Record) shareView {
	v := shareView{Share: metadb.Share{
		ID: rec.ID, Name: rec.Name, Owner: rec.Owner, Folder: rec.Folder,
		CreatedAt: rec.CreatedAt, PasswordHash: rec.PasswordHash,
		PasswordGen: rec.PasswordGen, Listing: rec.Listing, Media: rec.Media,
		Entry: rec.Entry, ExpiresAt: rec.ExpiresAt, Visitors: rec.Visitors,
	}, LiveShare: true}
	for _, f := range rec.Files {
		mt := f.MTime
		v.Files = append(v.Files, fileView{File: metadb.File{
			Path: f.Path, Size: f.Size, Slug: f.Slug, Mime: f.Mime, CommittedAt: &mt}})
		v.TotalBytes += f.Size
	}
	v.FileCount = len(v.Files)
	return v
}

// liveShareAnswer is the owner's answer for a live record: the share as
// every route shapes it, with each file's direct-link key, paired with its
// file by slug, so the answer's order never decides which key a file gets.
func liveShareAnswer(rec liveshare.Record) shareOut {
	so := toShareOut(liveShareView(rec))
	keys := make(map[string]string, len(rec.Files))
	for _, f := range rec.Files {
		keys[f.Slug] = f.Key
	}
	for i := range so.Files {
		so.Files[i].FileKey = keys[so.Files[i].Slug]
	}
	return so
}

// createLiveShare mints a relay-only share: nothing is written to disk, and
// the registry mints the ID and every file's public slug the same way a
// stored share's manifest does.
func (h *handler) createLiveShare(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Resume   string `json:"resume"`
		Name     string `json:"name"`
		Folder   bool   `json:"folder"`
		Password string `json:"password"`
		ZipSize  int64  `json:"zipSize"`
		Listing  bool   `json:"listing"`
		// Entry: the relpath /share/{id} opens as a web page, one of the
		// manifest's files. The manifest is complete at creation, so an
		// entry naming no file is refused here rather than resolved later.
		Entry string               `json:"entry"`
		Files []liveShareFileInput `json:"files"`
	}
	body, ok := readLiveShareBody(w, r)
	if !ok {
		return
	}
	if len(body) > 0 {
		if err := decodeRequest(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, badJSONMessage(err))
			return
		}
	}
	if len(req.Files) == 0 {
		writeError(w, http.StatusBadRequest, "a live share needs at least one file")
		return
	}
	seen, err := liveShareManifestRefusal(req.Files)
	if err != nil {
		writeRefusal(w, err)
		return
	}
	req.Entry = relPath(req.Entry)
	if req.Name != "" {
		clean, err := cleanShareName(req.Name)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		req.Name = clean
	}
	if req.Entry != "" && !seen[req.Entry] {
		writeRefusal(w, errLiveShareEntry)
		return
	}
	if err := (linkOpens{Listing: req.Listing, Entry: req.Entry != ""}).refuse(); err != nil {
		writeRefusal(w, err)
		return
	}
	u := reqUser(r)
	rec := liveshare.Record{Name: req.Name, Owner: u.Username, Folder: req.Folder, ZipSize: req.ZipSize,
		Listing: req.Listing, Entry: req.Entry}
	rec.Files = toLiveFiles(req.Files)
	if req.Resume != "" {
		if !shareid.ValidID(req.Resume) {
			writeError(w, http.StatusBadRequest, "invalid live share id")
			return
		}
		resumed, err := h.liveShareReg.Resume(req.Resume, rec)
		switch err {
		case nil:
			writeJSON(w, http.StatusOK, liveShareAnswer(resumed))
		case liveshare.ErrResumeMismatch:
			writeErrorCode(w, http.StatusConflict, "live-share-resume-mismatch",
				"the local files changed since this live share stopped")
		default:
			writeErrorCode(w, http.StatusNotFound, "live-share-ended",
				"this live share can no longer be resumed")
		}
		return
	}
	// A fresh live share draws on the same per-account creation budget as a
	// stored one; a resume above re-registers a share the account already
	// had and costs nothing.
	if !h.allowCreate(w, u) {
		return
	}
	hash, ok := hashPassword(w, req.Password)
	if !ok {
		return
	}
	rec.PasswordHash = hash
	rec, err = h.liveShareReg.Create(rec)
	if err == liveshare.ErrTooMany {
		writeErrorCode(w, http.StatusTooManyRequests, "too-many-live-shares",
			"this account already has as many live shares open as it may, stop one first")
		return
	}
	if err != nil {
		writeRefusal(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, liveShareAnswer(rec))
}

// liveSharePark is overridable in tests, like watchTimeout.
func (h *handler) liveSharePark() time.Duration {
	if h.liveSharePollPark > 0 {
		return h.liveSharePollPark
	}
	return liveSharePark
}

// liveSharePollJobs is the sharer's long-poll for work: it parks until a visitor's
// request has minted a job or the park elapses, then hands back every
// unclaimed offer at once.
func (h *handler) liveSharePollJobs(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !shareid.ValidID(id) {
		http.NotFound(w, r)
		return
	}
	offers, err := h.liveShareReg.Poll(r.Context(), id, reqUser(r).Username, h.liveSharePark())
	if errors.Is(err, liveshare.ErrNoShare) {
		http.NotFound(w, r)
		return
	}
	if err != nil { // context ended; the client is gone, any answer is unread
		return
	}
	if offers == nil {
		offers = []liveshare.Offer{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"jobs": offers, "visitors": h.liveShareReg.Visitors(id)})
}

// liveShareSendJob streams the sharer's PUT/POST body straight into the waiting
// visitor's pipe: relay, not storage, nothing here ever touches disk. A
// sharer that goes silent mid-body loses the relay to the server's body
// limits (bodyDeadline in package main), which count only time spent inside
// a Read: a visitor who stops reading blocks the copy in Write and costs the
// sharer nothing.
func (h *handler) liveShareSendJob(w http.ResponseWriter, r *http.Request) {
	c, ok := h.liveShareReg.Claim(reqUser(r).Username, r.PathValue("job"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	if _, err := io.Copy(c, r.Body); err != nil {
		// The sharer's upload broke; the visitor sees the truncation.
		c.CloseWithError(err)
		writeError(w, http.StatusBadRequest, "transfer interrupted")
		return
	}
	c.Close()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// liveShareFailJob lets the sharer report a job it cannot fulfil (the local file
// vanished, went unreadable, and so on) so the parked visitor gets a real
// error instead of hanging until the claim timeout.
func (h *handler) liveShareFailJob(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if !decodeJSONBody(w, r, liveShareFailBodyLimit, &req) {
		return // decodeJSONBody already answered (bad JSON or over the limit)
	}
	if req.Code == "" {
		writeError(w, http.StatusBadRequest, "a failure needs a code")
		return
	}
	if !h.liveShareReg.Fail(reqUser(r).Username, r.PathValue("job"), req.Code) {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// deleteLiveShare ends the share and fails every job still waiting on it,
// the registry-side equivalent of metadb.DeleteShare.
func (h *handler) deleteLiveShare(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !shareid.ValidID(id) || !h.liveShareReg.Delete(id, reqUser(r).Username) {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// liveShareFileInput is the client-supplied manifest, without server-minted slugs.
type liveShareFileInput struct {
	Path  string    `json:"path"`
	Size  int64     `json:"size"`
	Mime  string    `json:"mime"`
	MTime time.Time `json:"mtime"`
}

// liveShareManifestRefusal puts every path of the files one request names
// through relPath, in place, then applies the checks create and PATCH ask
// of them, and answers the set of their paths: at most
// liveShareManifestMaxFiles of them (413 manifest-too-big), each a valid
// relpath with a size that is not negative, none named twice. They mirror
// metadb.CreateShare's own manifest checks: a negative size or a duplicate
// path is nonsense a client should never send, and for a live share it would
// otherwise feed straight into the Range and ETag math with nothing upstream
// having caught it.
func liveShareManifestRefusal(files []liveShareFileInput) (map[string]bool, error) {
	if len(files) > liveShareManifestMaxFiles {
		return nil, refuse(http.StatusRequestEntityTooLarge, "manifest-too-big",
			fmt.Sprintf("%d files; a live share describes at most %d", len(files), liveShareManifestMaxFiles))
	}
	seen := make(map[string]bool, len(files))
	for i := range files {
		files[i].Path = relPath(files[i].Path)
	}
	for _, f := range files {
		if !shareid.ValidRelPath(f.Path) {
			return nil, refuse(http.StatusBadRequest, "", "bad file path "+f.Path)
		}
		if f.Size < 0 {
			return nil, refuse(http.StatusBadRequest, "", fmt.Sprintf("negative size for %q", f.Path))
		}
		if seen[f.Path] {
			return nil, refuse(http.StatusBadRequest, "", fmt.Sprintf("duplicate manifest path %q", f.Path))
		}
		seen[f.Path] = true
	}
	return seen, nil
}

// errLiveShareEntry refuses a web page that is not one of the share's files.
var errLiveShareEntry = refuse(http.StatusBadRequest, "", "entry must name a file of the share")

// patchLiveShare updates a relay that is already running: more files, and/or
// whether /share/{id} opens the file listing. PATCH rather than a nested POST
// because `POST /api/live-share/jobs/{job}` already owns a path of the same shape,
// and the two would be ambiguous for "/api/live-share/jobs". The share keeps its id,
// so every link already sent stays valid, and each new file gets a slug of its
// own; a path the relay already serves is replaced in place and keeps its
// slug, exactly as `add` does for a stored share.
//
// The manifest checks are the ones createLiveShare applies, for the same
// reason: a bad relpath or a negative size would otherwise reach the Range and
// ETag math with nothing upstream having caught it.
func (h *handler) patchLiveShare(w http.ResponseWriter, r *http.Request) {
	var req liveShareUpdate
	body, ok := readLiveShareBody(w, r)
	if !ok {
		return
	}
	if err := decodeRequest(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, badJSONMessage(err))
		return
	}
	if !req.any() {
		writeError(w, http.StatusBadRequest, "nothing to change")
		return
	}
	if len(req.AddFiles) > 0 && len(req.ReplaceFiles) > 0 {
		writeError(w, http.StatusBadRequest, "add and replace are one question: pass one")
		return
	}
	fileSrc := req.AddFiles
	if len(req.ReplaceFiles) > 0 {
		fileSrc = req.ReplaceFiles
	}
	if _, err := liveShareManifestRefusal(fileSrc); err != nil {
		writeRefusal(w, err)
		return
	}
	if req.Name != nil {
		clean, err := cleanShareName(*req.Name)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		*req.Name = clean
	}
	if req.ExpiresInSeconds != nil && *req.ExpiresInSeconds < 0 {
		writeError(w, http.StatusBadRequest, "negative duration")
		return
	}
	if req.Entry != nil {
		entry := relPath(*req.Entry)
		req.Entry = &entry
	}
	if req.Entry != nil && *req.Entry != "" && !shareid.ValidRelPath(*req.Entry) {
		writeRefusal(w, errLiveShareEntry)
		return
	}
	// The password is hashed before the registry is touched: bcrypt is too
	// slow to run under the registry lock, and a password it refuses must
	// refuse the whole request rather than follow a change already made.
	var hash *string
	if req.Password != nil {
		hashed, ok := hashPassword(w, *req.Password)
		if !ok {
			return
		}
		hash = &hashed
	}
	edit := liveshare.Edit{ZipSize: req.ZipSize, Meta: req.meta(hash, time.Now())}
	files := toLiveFiles(fileSrc)
	if len(req.ReplaceFiles) > 0 {
		edit.Replace = files
	} else {
		edit.Add = files
	}
	// Every refusal is asked of the record the edit would leave, inside the
	// one registry update that stores it, so a refused PATCH changes nothing:
	// the opens rule on the share as it stands plus the request, the page on
	// the files this same request leaves, the gallery gate on them too.
	rec, err := h.liveShareReg.Patch(r.PathValue("id"), reqUser(r).Username, edit,
		func(current, next liveshare.Record) error {
			opens := linkOpens{Listing: current.Listing, Gallery: current.Media, Entry: current.Entry != ""}
			if err := opens.with(req.Listing, req.Media, req.Entry).refuse(); err != nil {
				return err
			}
			if req.Entry != nil && *req.Entry != "" {
				if _, ok := fileByPath(liveShareView(next), *req.Entry); !ok {
					return errLiveShareEntry
				}
			}
			if req.Media != nil && *req.Media {
				return galleryRefusal(liveShareView(next))
			}
			return nil
		})
	switch {
	case errors.Is(err, liveshare.ErrNoShare):
		writeError(w, http.StatusNotFound, "no such live share")
	case errors.Is(err, liveshare.ErrTooManyFiles):
		writeErrorCode(w, http.StatusRequestEntityTooLarge, "manifest-too-big",
			fmt.Sprintf("a live share describes at most %d files, these would make it more", liveShareManifestMaxFiles))
	case err != nil:
		writeRefusal(w, err)
	default:
		writeJSON(w, http.StatusOK, liveShareAnswer(rec))
	}
}

// liveShareUpdate is the PATCH body of a live share. The file lists change
// what the relay serves; the rest is the share's meta, with the stored
// PATCH's pointer semantics (absent = unchanged).
type liveShareUpdate struct {
	AddFiles     []liveShareFileInput `json:"addFiles"`
	ReplaceFiles []liveShareFileInput `json:"replaceFiles"`
	ZipSize      int64                `json:"zipSize"`
	Listing      *bool                `json:"listing"`
	Media        *bool                `json:"media"`
	// Entry: absent = unchanged, "" = no web page, a relpath = the page
	// the link opens, which must be a file the relay serves once the
	// files of this same request are in.
	Entry            *string `json:"entry"`
	Name             *string `json:"name"`
	Password         *string `json:"password"`
	ExpiresInSeconds *int64  `json:"expiresInSeconds"`
}

// metaSet reports whether the request changes any of the share's meta.
func (u liveShareUpdate) metaSet() bool {
	return u.Listing != nil || u.Media != nil || u.Entry != nil || u.Name != nil ||
		u.Password != nil || u.ExpiresInSeconds != nil
}

// meta is the registry's form of the request's meta change; passwordHash is
// the caller's bcrypt of Password, nil when the password stays.
func (u liveShareUpdate) meta(passwordHash *string, now time.Time) liveshare.Meta {
	m := liveshare.Meta{Listing: u.Listing, Media: u.Media, Entry: u.Entry, Name: u.Name, PasswordHash: passwordHash}
	if u.ExpiresInSeconds != nil {
		m.SetExpiry, m.ExpiresAt = true, expiryAt(now, *u.ExpiresInSeconds)
	}
	return m
}

// any reports whether the request changes anything at all.
func (u liveShareUpdate) any() bool {
	return len(u.AddFiles) > 0 || len(u.ReplaceFiles) > 0 || u.metaSet()
}

// readLiveShareBody reads a live share request body, answering 413 itself
// when it is over liveShareBodyLimit.
func readLiveShareBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, liveShareBodyLimit))
	if err != nil {
		writeErrorCode(w, http.StatusRequestEntityTooLarge, "body-too-large",
			fmt.Sprintf("live share request over %d bytes; a live share describes at most %d files",
				liveShareBodyLimit, liveShareManifestMaxFiles))
		return nil, false
	}
	return body, true
}

// toLiveFiles converts a request's file list to the registry's.
func toLiveFiles(in []liveShareFileInput) []liveshare.File {
	out := make([]liveshare.File, 0, len(in))
	for _, f := range in {
		out = append(out, liveshare.File{Path: f.Path, Size: f.Size, Mime: liveShareMime(f.Mime), MTime: f.MTime})
	}
	return out
}

// liveShareMime is the type a live file is served under. A stored file's
// type is the server's own detection; a live file's is the sharer's client's
// word, so only a type that parses cleanly is kept and anything else serves
// as a download, never as whatever a browser makes of it. An empty type
// stays empty, which serveLiveShareFile already serves as a download.
func liveShareMime(claimed string) string {
	if claimed == "" {
		return ""
	}
	if _, _, err := mime.ParseMediaType(claimed); err != nil {
		return "application/octet-stream"
	}
	return claimed
}
