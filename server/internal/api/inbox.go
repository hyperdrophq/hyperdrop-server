package api

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/sharefs"
	"hyperdrop/server/internal/shareid"
)

// inboxNoteLimit caps the message an inbox's upload page shows. The
// byte/file caps themselves are OPTIONAL: bytes default to unlimited, the
// owner's quota being the standing bound, and files to
// metadb.InboxMaxFiles, the bound a zero-byte file cannot slip past.
const inboxNoteLimit = 500

// inboxNoteRefusal is the 400 for a note past inboxNoteLimit characters, or
// nil. Characters, not bytes, so a note in a script of multi-byte letters
// gets the same 500 a Latin one does.
func inboxNoteRefusal(note string) error {
	if utf8.RuneCountInString(strings.TrimSpace(note)) > inboxNoteLimit {
		return refuse(http.StatusBadRequest, "", fmt.Sprintf("note too long (limit %d characters)", inboxNoteLimit))
	}
	return nil
}

// visitorTTL is how long one sender's grouping token lives: long enough for a
// slow share of many files, short enough that a shared browser does not group
// next week's sender with this one.
const visitorTTL = 12 * time.Hour

// visitorCookieName is the per-link grouping cookie. It carries NO authority:
// no gate consults it, and it is scoped to this link's upload path so it never
// reaches the file origin. "hdv_" cannot be read as the access cookie's
// "hd_" + id, share ids being 10-char base58, an alphabet with no underscore.
func visitorCookieName(id string) string { return "hdv_" + id }

// validVisitor accepts only what visitorSession mints: 22 base64url
// characters. Anything else is ignored and replaced, so nothing an uploader
// supplies is ever recorded on a file entry.
func validVisitor(v string) bool {
	if len(v) != 22 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
			c >= '0' && c <= '9' || c == '-' || c == '_'
		if !ok {
			return false
		}
	}
	return true
}

// readVisitor returns the grouping token this sender already carries, or ""
// when it carries none. The UPLOAD reads and never mints: minting there would
// hand a cookieless client (curl, a browser refusing cookies) a fresh token
// per file, turning one person's share into one group per file, which is the
// opposite of what the token is for.
func readVisitor(r *http.Request, id string) string {
	if c, err := r.Cookie(visitorCookieName(id)); err == nil && validVisitor(c.Value) {
		return c.Value
	}
	return ""
}

// visitorSession returns this sender's grouping token, minting one when the
// browser carries none. It is what turns "these six files" into "these six
// files from ONE person". Only the upload PAGE mints, because that is the one
// request a browser makes before any file moves.
func (h *handler) visitorSession(w http.ResponseWriter, r *http.Request, id string) string {
	if v := readVisitor(r, id); v != "" {
		return v
	}
	return h.setGroupingCookie(w, r, visitorCookieName(id), "/receive/"+id, "", visitorTTL)
}

// displayableName refuses what a stranger's file name could use to mislead
// the owner where it is shown (the push banner, the CLI's terminal, a
// listing, Content-Disposition): invalid UTF-8, C0 and C1 controls (a
// terminal escape) and the bidirectional formatting characters that make
// "invoice\u202efdp.exe" read as "invoiceexe.pdf".
func displayableName(name string) bool {
	if !utf8.ValidString(name) {
		return false
	}
	for _, c := range name {
		switch {
		case c < 0x20, c >= 0x7f && c <= 0x9f,
			c == 0x061c, c == 0x200e, c == 0x200f,
			c >= 0x202a && c <= 0x202e, c >= 0x2066 && c <= 0x2069:
			return false
		}
	}
	return true
}

// inboxPage serves GET /receive/{id}: the public upload page. A protected
// inbox shows the shared password form first (same cookie, same lockout);
// a closed inbox renders the page in its closed state rather than 404,
// so a sender with the link learns the state instead of suspecting a typo.
func (h *handler) inboxPage(w http.ResponseWriter, r *http.Request) {
	v, ok := h.visibleInbox(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	v, ok = h.enforceAccess(w, r, v)
	if !ok {
		return
	}
	// A link unfurler gets an Open Graph card, so a pasted inbox link
	// shows a real preview in chat apps. Only the page copy the sender
	// would see anyway (name and note), never received content; a
	// protected inbox never reaches here for a bot (the password form
	// above carries the generic protected card).
	if isUnfurler(r.UserAgent()) {
		desc := v.Note
		if desc == "" {
			desc = "Upload files to this Receive Inbox from your browser"
		}
		h.renderCard(w, h.newCard(r, v.Name, desc+" · "+cardFooter, "/receive/"+v.ID))
		return
	}
	// The sender's grouping token rides the uploads below automatically, so
	// the page's JS never handles an identity of its own.
	_ = h.visitorSession(w, r, v.ID)
	h.recordVisit(v, h.mintVisitor(w, r))
	maxFiles := inboxFileLimit(v.MaxFiles, v.Committed)
	h.renderPage(w, framable, 0, false, inboxTmpl, inboxData{ID: v.ID, Name: v.Name,
		Note: v.Note, Closed: v.Closed, Full: !v.Closed && inboxFull(v.MaxFiles, v.Committed),
		MaxBytes: v.MaxBytes, MaxFiles: maxFiles,
		Limits: inboxLimits(maxFiles, v.MaxBytes)})
}

// writeInboxRefusal answers a stranger's refused upload as writeRefusal
// does, except that a quota refusal, wherever it arises (the check before
// the body, or the commit's), says the same words and names nothing of the
// account.
func writeInboxRefusal(w http.ResponseWriter, err error) {
	if errors.Is(err, metadb.ErrQuota) {
		writeErrorCode(w, http.StatusInsufficientStorage, "quota", "this file does not fit the inbox owner's storage")
		return
	}
	writeRefusal(w, err)
}

// inboxUpload serves PUT /receive/{id}/files/{name}: the anonymous upload.
// Gate order: inbox exists (404) -> password cookie (401 JSON, the page
// re-establishes it) -> open (403) -> name valid -> caps -> the owner's
// quota (507) -> a slot among the uploads in flight (429) -> the name
// claim -> disk room -> the row, which charges the bytes to the inbox's
// OWNER and enforces the link's own caps inside its transaction. The body
// is read under an idle deadline.
func (h *handler) inboxUpload(w http.ResponseWriter, r *http.Request) {
	v, ok := h.visibleInbox(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if v.PasswordHash != "" && !h.validAccess(r, v.ID, v.PasswordGen) {
		writeError(w, http.StatusUnauthorized, "password required")
		return
	}
	if v.Closed {
		writeErrorCode(w, http.StatusForbidden, "closed", "this inbox is no longer accepting files")
		return
	}
	// One path segment, through relPath like every relpath. The wildcard
	// is {name}, but ServeMux hands it the percent-DECODED value, so a %2F
	// arrives as a slash and must be refused here.
	name := relPath(r.PathValue("name"))
	if name == "" || strings.Contains(name, "/") || !shareid.ValidRelPath(name) || !displayableName(name) {
		writeError(w, http.StatusBadRequest, "bad file name")
		return
	}
	// The caps must be checkable before the first byte, so the length is
	// required and the body arrives uncompressed (browsers do both).
	if r.Header.Get("Content-Encoding") != "" {
		writeError(w, http.StatusBadRequest, "no transport compression on inbox uploads")
		return
	}
	if r.ContentLength < 0 {
		writeError(w, http.StatusLengthRequired, "Content-Length required")
		return
	}
	// Pending declarations describe uploads in flight, not occupied slots
	// or committed bytes. A stalled sender must not reserve either cap.
	if v.Committed >= metadb.InboxFileCap(v.MaxFiles) {
		writeErrorCode(w, http.StatusRequestEntityTooLarge, "receive-full",
			"this inbox is not accepting more files")
		return
	}
	if v.MaxBytes > 0 && r.ContentLength > v.MaxBytes-v.Bytes {
		writeErrorCode(w, http.StatusRequestEntityTooLarge, "receive-full",
			"this file does not fit what the inbox accepts")
		return
	}
	// The owner's quota is checked before a slot, a claim, a hold or a row
	// is taken: an upload the account cannot hold costs nothing. A
	// colliding name is renamed rather than overwritten, so the upload
	// replaces no file's bytes. The refusal tells a stranger nothing of
	// what the account holds.
	owner, err := h.db.User(v.Owner)
	if err == nil {
		err = h.ownerRoom(owner, v.ID, "", r.ContentLength)
	}
	if err != nil {
		writeInboxRefusal(w, err)
		return
	}
	// Keyed like the lockouts: a host holding an IPv6 /64 holds 2^64
	// addresses, and one per upload would take every slot.
	releaseSlot, ok := h.inboxSlots.take(v.ID, addrKey(clientIP(r)))
	if !ok {
		w.Header().Set("Retry-After", "10")
		writeErrorCode(w, http.StatusTooManyRequests, "rate-limited",
			"too many uploads to this inbox at once, try again in a moment")
		return
	}
	defer releaseSlot()
	src := &sourceBody{r: idleBody{r: r.Body, rc: http.NewResponseController(w)}}
	body := requestBody{r: src, src: src}
	// The claim renames a colliding basename (blind share: a second sender
	// must never overwrite the first) and keeps concurrent same-name
	// uploads off one staging .part.
	by := readVisitor(r, v.ID)
	// A row at a path holds it whatever its state: a committed file, or a
	// pending one the owner declared, compared under shareid.FoldPath on a
	// volume that folds case (metadb.PathsHeld). A read that fails holds
	// every candidate it was asked about.
	held := func(candidates []string) map[string]bool {
		taken, err := h.db.PathsHeld(v.ID, candidates)
		if err != nil {
			taken = map[string]bool{}
			for _, c := range candidates {
				taken[c] = true
			}
		}
		return taken
	}
	up, ok := h.claims.claim(v.ID, v.Owner, name, held, r.ContentLength, by)
	if !ok {
		writeErrorCode(w, http.StatusRequestEntityTooLarge, "receive-full",
			"this inbox holds too many files with this name")
		return
	}
	defer up.Release()
	chosen := up.Name
	hold, err := h.fs.AdmitAnonymousWrite(v.ID, r.ContentLength)
	if err != nil {
		writeInboxRefusal(w, err)
		return
	}
	defer hold.Release()
	if _, err := h.db.DeclareFile(v.ID, chosen, r.ContentLength); err != nil {
		writeInboxRefusal(w, err)
		return
	}
	n, err := h.fs.Write(v.ID, chosen, up.Reader(hold.Reader(http.MaxBytesReader(w, io.NopCloser(body), r.ContentLength))))
	if err == nil && n != r.ContentLength {
		err = fmt.Errorf("%w: body shorter than Content-Length", sharefs.ErrBadRequest)
	}
	// The upload leaves the owner's incoming list before its last journal
	// write, the commit or the withdrawal below, so the row that write
	// resolves never shows it still arriving.
	up.Finish()
	if err != nil {
		h.fs.Discard(v.ID, chosen)
		_ = h.db.RemovePending(v.ID, chosen)
		writeInboxRefusal(w, err)
		return
	}
	// The caps above are advisory: two admitted uploads can race past them
	// together. CommitFile is where the link's byte and file caps, and the
	// owner's quota, are decided, inside the writing transaction.
	f, err := h.commitUpload(metadb.CommitInput{ShareID: v.ID, Path: chosen, UploadSession: by, Anonymous: true}, r.ContentLength)
	if err != nil {
		// A one-shot body has no resume state: whatever stayed staged goes
		// with the row, or it would sit outside every cap and sweep.
		h.fs.Discard(v.ID, chosen)
		_ = h.db.RemovePending(v.ID, chosen)
		writeInboxRefusal(w, err)
		return
	}
	// No slug, no links: an uploader gets nothing it could fetch back.
	writeJSON(w, http.StatusCreated, map[string]any{"name": f.Path, "size": f.Size})
}
