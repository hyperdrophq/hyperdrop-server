package api

import (
	"errors"
	"net/http"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/mimetype"
	"hyperdrop/server/internal/shareid"
)

// A file link (/f/{fileKey}) serves ONE file of one share, and its key names
// neither. Nothing any of its answers carries, in a header or a body, names
// the share: not its id, not its name, not another file, not the file's
// folders. Every answer below is built from the key and the file alone, never
// from a share page, so a new answer owes a file-link variant of its page
// rather than a reuse of the share's.
//
// Every route resolves the same way, in this order, and every refusal before
// the password is the same 404 (JSON on the status poll), so a key reveals
// nothing about why it fails:
//
//  1. the key's shape;
//  2. the key: metadb's file_links first, then the live registry;
//  3. the share's visibility, through visibleShareID, which refuses an inbox;
//  4. the share's sources (a linked share that cannot be read answers the
//     file link's unavailable page);
//  5. the share's password, proven by the link's own cookie or ?pw=;
//  6. the slug naming a file the share still holds;
//  7. an unfurler's card, then a pending file's waiting page;
//  8. the owner's no-embed setting;
//  9. the bytes, counted as any public read of the share is.
//
// What the share opens as (its file, a listing, a page, a gallery) never
// matters here.

// resolveFileKey answers the share and slug a file key names: a stored or
// linked share's row first, then the live registry. A key of the wrong shape
// is refused before any lookup.
func (h *handler) resolveFileKey(key string) (shareID, slug string, ok bool) {
	if !shareid.ValidFileKey(key) {
		return "", "", false
	}
	shareID, slug, err := h.db.ResolveFileKey(key)
	if err == nil {
		return shareID, slug, true
	}
	if !errors.Is(err, metadb.ErrNotFound) {
		return "", "", false
	}
	rec, slug, ok := h.liveShareReg.ByFileKey(key)
	if !ok {
		return "", "", false
	}
	return rec.ID, slug, true
}

// fileLinkTarget runs the first four gates for key: it answers the share's
// file lookup and the file's slug, or ok=false for the one 404 every refusal
// shares. A linked share whose sources cannot be read comes back with
// SourceMissing set, which the caller answers.
func (h *handler) fileLinkTarget(key string) (files fileLookup, slug string, ok bool) {
	id, slug, ok := h.resolveFileKey(key)
	if !ok {
		return fileLookup{}, "", false
	}
	v, ok := h.visibleShareID(id, h.viewMeta)
	if !ok {
		return fileLookup{}, "", false
	}
	files, err := h.lookupFor(v)
	if err != nil {
		return fileLookup{}, "", false
	}
	// A linked share's lookup holds a freshly composed view, which the gate's
	// reading of the owner's setting is not part of.
	files.v.ownerNoEmbed = v.ownerNoEmbed
	return files, slug, true
}

// fileLinkHeaders are carried by every /f/ answer: no Referer, so a document
// served here cannot hand its own address to a site it links to, and no
// search index.
func fileLinkHeaders(w http.ResponseWriter) {
	w.Header().Set("Referrer-Policy", "no-referrer")
	noIndex(w)
}

// fileLinkNext is where a file link's unlock sends the visitor: exactly the
// link's View or Download address, with no query, and the View address for
// anything else.
func fileLinkNext(raw, key string) string {
	view := "/f/" + key
	if raw == view+"/download" {
		return raw
	}
	return view
}

// enforceFileAccess is enforceAccess for a file link. The share's password is
// proven by the link's own cookie (hdf_<fileKey>) or by ?pw=, never by the
// share's hd_<id>, and a visit the cookie admits renews it (admitFileAccess).
// ?pw= spends the same guess budget as the form and always unlocks unticked,
// and a top-level navigation that brought a right one is sent on to the same
// link without it, on the cookie just set. Anything else gets the link's
// password form, whose next is one of the link's two addresses and whose card
// is f's (the zero fileView when the share no longer holds the file).
func (h *handler) enforceFileAccess(w http.ResponseWriter, r *http.Request, v shareView, f fileView, key string) (shareView, bool) {
	if v.PasswordHash == "" {
		return v, true
	}
	if h.admitFileAccess(w, r, key, v.PasswordGen) {
		return v, true
	}
	next := fileLinkNext(r.URL.Path, key)
	if pw := r.URL.Query().Get("pw"); pw != "" {
		unlocked, done := h.guessSharePassword(w, r, v, pw)
		if done {
			return shareView{}, false
		}
		if unlocked {
			h.setFileAccessCookie(w, r, key, v.PasswordGen, false)
			if r.Method == http.MethodGet && r.Header.Get("Sec-Fetch-Mode") == "navigate" &&
				r.Header.Get("Sec-Fetch-Dest") == "document" {
				http.Redirect(w, r, next, http.StatusSeeOther)
				return shareView{}, false
			}
			return v, true
		}
	}
	h.renderFileLinkPassword(w, r, key, v, f, next, "", http.StatusOK)
	return shareView{}, false
}

// fileLinkView answers GET /f/{fileKey}: the file, inline when a browser
// renders its type, as /view does.
func (h *handler) fileLinkView(w http.ResponseWriter, r *http.Request) {
	h.serveFileLink(w, r, false)
}

// fileLinkDownload answers GET /f/{fileKey}/download: the file as an
// attachment, byte for byte, as /download does. There is no bearer bypass
// and no download ticket: the owner's apps read their own bytes through
// /download/{id}/{slug}.
func (h *handler) fileLinkDownload(w http.ResponseWriter, r *http.Request) {
	h.serveFileLink(w, r, true)
}

// serveFileLink answers a file link's View (download false) and Download:
// the gates of the comment at the top of this file, then the file's bytes
// through the same serving code as /view and /download. Every page it can
// answer instead (the unavailable page, the password form, the card, the
// waiting page) is the file link's own variant, built from the key and the
// file alone.
func (h *handler) serveFileLink(w http.ResponseWriter, r *http.Request, download bool) {
	fileLinkHeaders(w)
	key := r.PathValue("fileKey")
	files, slug, ok := h.fileLinkTarget(key)
	if !ok {
		http.NotFound(w, r)
		return
	}
	v := files.v
	if v.SourceMissing {
		h.renderFileLinkUnavailable(w, r)
		return
	}
	// The file is looked up before the password so the form's card can show
	// its tile; a slug the share no longer holds is still refused only after
	// the password.
	f, held := files.bySlug(slug)
	if _, ok := h.enforceFileAccess(w, r, v, f, key); !ok {
		return
	}
	// Every answer past the password, card and bytes alike, is private on a
	// protected share and revalidated on every share, so a Stop Direct Link
	// or a password added later reaches a cache that holds this answer.
	privateIfProtected(w, v)
	revalidate(w)
	if !held {
		http.NotFound(w, r)
		return
	}
	// A link unfurler gets a card instead of the bytes, under serveFile's
	// rule: a playable card's own video fetch (ogMediaParam) is the one
	// exception, and never on a live share.
	if isUnfurler(r.UserAgent()) && (v.LiveShare || r.URL.Query().Get(ogMediaParam) != "1") {
		h.renderCard(w, h.fileLinkCard(r, key, v, f))
		return
	}
	inline := !download
	if f.Pending {
		h.renderFileLinkWaiting(w, key, f, inline && mimetype.Viewable(f.MimeOrGuess()))
		return
	}
	if v.ownerNoEmbed && !h.applyFileLinkNoEmbed(w, r) {
		return
	}
	if inline && !mimetype.Viewable(f.Mime) {
		inline = false
	}
	// Counted as serveFile counts a read of the share: while the bytes move,
	// and never the owner's own fetch.
	if !h.bearerOwns(r, v) {
		defer h.dl.begin(v.ID, v.Owner)()
		if !v.LiveShare || h.liveShareReg.Online(v.ID) {
			h.recordVisit(v, h.visitorToken(r))
		}
	}
	w, clearDeadline := withStallDeadlines(w)
	defer clearDeadline()
	if v.LiveShare {
		h.serveLiveShareFile(w, r, v, f, inline)
		return
	}
	// No page icon: its address would need a second key.
	h.serveStoredFile(w, r, v, f, inline, nil, nil)
}

// applyFileLinkNoEmbed is applyNoEmbed for a file link: the same
// Cross-Origin-Resource-Policy, and an explicitly cross-site embed fetch is
// refused with 403 and no body rather than redirected, since applyNoEmbed's
// redirect names the share page. It reports false when it wrote the refusal.
func (h *handler) applyFileLinkNoEmbed(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Add("Vary", "Referer, Sec-Fetch-Site, Sec-Fetch-Dest")
	corp := "same-origin"
	if h.embeddedByOwnPage(r) {
		corp = "same-site"
	}
	w.Header().Set("Cross-Origin-Resource-Policy", corp)
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" && embedDests[r.Header.Get("Sec-Fetch-Dest")] {
		w.WriteHeader(http.StatusForbidden)
		return false
	}
	return true
}

// fileLinkUnlock answers POST /f/{fileKey}/unlock, the file link's password
// form. One guess runs on the share-password limiter, as /unlock/{id}'s does;
// a right one sets hdf_<fileKey>, of the kind the form asked for
// (keepRequested), and answers 303 to next, and a wrong one
// re-renders the form with 401. A share with no password has nothing to
// unlock: the visitor is sent on to next while the file is there.
func (h *handler) fileLinkUnlock(w http.ResponseWriter, r *http.Request) {
	fileLinkHeaders(w)
	key := r.PathValue("fileKey")
	files, slug, ok := h.fileLinkTarget(key)
	if !ok {
		http.NotFound(w, r)
		return
	}
	v := files.v
	if v.SourceMissing {
		h.renderFileLinkUnavailable(w, r)
		return
	}
	// The form is tiny; anything bigger is abuse, not a password.
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "bad form")
		return
	}
	next := fileLinkNext(r.PostFormValue("next"), key)
	f, held := files.bySlug(slug)
	if v.PasswordHash == "" {
		if !held {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	unlocked, done := h.guessSharePassword(w, r, v, r.PostFormValue("password"))
	if done {
		return
	}
	if !unlocked {
		h.renderFileLinkPassword(w, r, key, v, f, next, "Incorrect password. Try again.", http.StatusUnauthorized)
		return
	}
	h.setFileAccessCookie(w, r, key, v.PasswordGen, keepRequested(r))
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// fileLinkStatus answers GET /f/{fileKey}/status, the file link's waiting
// page poll: this one file's progress, with no path, no slug and none of the
// share's counts. Like /share/{id}/status it never renders a page: a refusal
// is a JSON 404, a missing or stale cookie a JSON 401 (?pw= is not read), and
// an unreadable source {"unavailable":true}.
func (h *handler) fileLinkStatus(w http.ResponseWriter, r *http.Request) {
	fileLinkHeaders(w)
	w.Header().Set("Cache-Control", "no-store")
	key := r.PathValue("fileKey")
	files, slug, ok := h.fileLinkTarget(key)
	if !ok {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	v := files.v
	if v.SourceMissing {
		writeJSON(w, http.StatusOK, map[string]bool{"unavailable": true})
		return
	}
	if v.PasswordHash != "" && !h.validFileAccess(r, key, v.PasswordGen) {
		writeError(w, http.StatusUnauthorized, "password required")
		return
	}
	f, ok := files.bySlug(slug)
	if !ok {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, h.fileLinkProgress(v, f))
}

// fileLinkFileStatus is the one file a file link's status answer describes.
type fileLinkFileStatus struct {
	Size     int64 `json:"size"`
	Bytes    int64 `json:"bytes"`
	Complete bool  `json:"complete"`
	// Preparing is the sender's fresh report on the pending file, absent
	// when there is none or the file has committed.
	Preparing *prepOut `json:"preparing,omitempty"`
}

// fileLinkStatusOut is a file link's status answer: whether its one file is
// complete, and that file's progress. It holds no path, no slug and none of
// the share's counts.
type fileLinkStatusOut struct {
	Complete bool               `json:"complete"`
	File     fileLinkFileStatus `json:"file"`
}

// fileLinkProgress is f's upload state. A pending stored file's received
// bytes are measured from its part; a linked or live file is never pending.
func (h *handler) fileLinkProgress(v shareView, f fileView) fileLinkStatusOut {
	st := fileLinkFileStatus{Size: f.Size, Complete: !f.Pending}
	if !f.Pending {
		st.Bytes = f.Size
		return fileLinkStatusOut{Complete: true, File: st}
	}
	if rep, ok := h.prep.get(v.ID, f.Path); ok {
		st.Preparing = &prepOut{Stage: string(rep.Stage), Fraction: rep.Fraction}
	}
	if !v.LiveShare && !f.Linked {
		// Best-effort: a racing commit reads as 0, and the next poll corrects it.
		if n, err := h.fs.PartSize(v.ID, f.Path); err == nil {
			st.Bytes = n
		}
	}
	return fileLinkStatusOut{File: st}
}
