package api

import (
	"errors"
	"fmt"
	"hyperdrop/server/internal/linked"
	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/shareid"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Manifest bounds for share creation. maxManifestFiles is how many entries
// one create request may declare, and createBodyLimit is the budget it is
// sized against: an entry costs about 90 bytes on the wire, so 10,000 of
// them is under a megabyte and the 4 MB body holds a full manifest with
// room for the rest of the request. Past that count a create stops
// describing a share anybody is going to watch land.
const (
	maxManifestFiles = 10000
	createBodyLimit  = 4 << 20
)

// kindInbox is the ?kind= value that scopes a listing to inboxes.
const kindInbox = "receive"

// Bounds for a STREAM share's manifest, which is the whole share: every file
// the relay will ever serve is described in the create (or addFiles) request,
// with mime and mtime beside path and size, and nothing arrives later. The
// stored caps above size an OPTIONAL early-links manifest a client skips for
// a big folder; a stream client cannot skip it, and an ordinary project
// folder (node_modules, .git) runs to tens of thousands of files. What bounds
// a stream manifest is the registry's memory (about 250 B an entry for the
// life of the relay, so ~25 MB at the cap, times the per-owner share cap) and
// the listing page rendered from it (about 330 B a row); the byte bound
// leaves room for the long paths a dependency tree has.
const (
	liveShareManifestMaxFiles = 100000
	liveShareBodyLimit        = 64 << 20
)

// createShareRequest is the body of POST /api/shares. The steps that judge it
// take it by pointer: a step that admits a field also stores the form the
// share keeps (the cleaned name, the trimmed note, the clamped file cap, the
// folder flag the sources imply).
type createShareRequest struct {
	Name   string `json:"name"`
	Folder bool   `json:"folder"`
	// Entry: the relpath /share/{id} opens instead of the listing. Set at
	// creation, when the manifest's files are all still pending, so it
	// is validated as a path and resolved against the files at serve
	// time.
	Entry            string `json:"entry"`
	Password         string `json:"password"`
	ExpiresInSeconds int64  `json:"expiresInSeconds"`
	// ReserveBytes: the client's total upload size, admission-checked
	// against free space minus other uploads' live reservations, so two
	// clients can't both start into space that fits only one.
	ReserveBytes int64 `json:"reserveBytes"`
	// Files: optional manifest. Each entry becomes a pending file row
	// with a pre-minted slug, so links exist before the upload starts.
	Files []struct {
		Path string `json:"path"`
		Size int64  `json:"size"`
	} `json:"files"`
	// Media creates a GALLERY: /share/{id} renders the pictures instead
	// of the file listing. Declared here and nowhere else, because the
	// client acts on it before the first byte is uploaded.
	Media bool `json:"media"`
	// Listing forces the file listing on a share of ONE file, which
	// /share/{id} otherwise redirects straight to.
	Listing bool `json:"listing"`
	// Inbox creates an INBOX: a container strangers fill through the
	// public /receive/{id} page. Note is the page's message; the caps bound
	// what the request accepts in total (defaults when 0).
	Inbox bool `json:"receive"`
	// Text creates a TEXT share: one text file, opened as that file.
	Text     bool   `json:"text"`
	Note     string `json:"note"`
	MaxBytes int64  `json:"maxBytes"`
	MaxFiles int    `json:"maxFiles"`
	// Source creates a LINKED share of a folder or file already on the
	// server's disk: no manifest, no receive flag and no reservation,
	// because there is nothing to upload.
	Source string `json:"source"`
	// Sources makes ONE linked share of several picks at once; each
	// lists under its own name. Exclusive with Source.
	Sources []string `json:"sources"`
	// LinksOff creates the share with its public links already off;
	// absent or false, they are on. Refused on an inbox.
	LinksOff *bool `json:"linksOff,omitempty"`
}

// linksOff reports whether the request creates the share with its public
// links off.
func (req *createShareRequest) linksOff() bool {
	return req.LinksOff != nil && *req.LinksOff
}

// createShare judges the request in a fixed order, and a request wrong in
// several ways is answered by the first step that refuses it: its paths and
// name, what its View link opens, its sources, its inbox fields, the
// creation limiter, its password, the store's own rules, and last the checks
// only a created share can answer.
func (h *handler) createShare(w http.ResponseWriter, r *http.Request) {
	req, ok := readCreateRequest(w, r)
	if !ok {
		return
	}
	u := reqUser(r)
	sources, err := h.createRefusal(u, &req)
	if err != nil {
		writeRefusal(w, err)
		return
	}
	// Quotas cap how much a guest can STORE; this caps how fast they can
	// create.
	if !h.allowCreate(w, u) {
		return
	}
	opts := req.options(u.Username, sources)
	hash, ok := hashPassword(w, req.Password)
	if !ok {
		return
	}
	opts.PasswordHash = hash
	if req.Password != "" {
		plain := req.Password
		opts.SealPassword = func(id string) ([]byte, error) { return h.sealPassword(id, hash, plain) }
	}
	opts.ExpiresAt = expiryAt(time.Now(), req.ExpiresInSeconds)
	d, err := h.db.CreateShare(opts)
	if err != nil {
		writeRefusal(w, err)
		return
	}
	v, err := h.admitCreated(u, d, &req, sources)
	if err != nil {
		writeRefusal(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, h.resolvedRow(v))
}

// readCreateRequest reads and decodes the create body and spells its paths
// in NFC, or answers the refusal itself and reports false. An empty body is
// a share with every field at its zero value.
func readCreateRequest(w http.ResponseWriter, r *http.Request) (createShareRequest, bool) {
	var req createShareRequest
	// An oversized manifest is answered as a size, never as a JSON syntax
	// error: readCapped reads through http.MaxBytesReader, not a truncating
	// reader.
	body, ok := readCapped(w, r, createBodyLimit, func(w http.ResponseWriter) {
		writeErrorCode(w, http.StatusRequestEntityTooLarge, "body-too-large",
			fmt.Sprintf("share request too large (limit %d bytes): send at most %d files in the manifest",
				createBodyLimit, maxManifestFiles))
	})
	if !ok {
		return req, false
	}
	if len(body) > 0 {
		if err := decodeRequest(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, badJSONMessage(err))
			return req, false
		}
	}
	req.Entry = relPath(req.Entry)
	for i := range req.Files {
		req.Files[i].Path = relPath(req.Files[i].Path)
	}
	return req, true
}

// createRefusal runs every check a create request answers before the share
// exists, in the order a request wrong twice is answered by, and answers the
// share's sources (Source or Sources, as one list) or the first refusal.
func (h *handler) createRefusal(u metadb.User, req *createShareRequest) ([]string, error) {
	if err := req.pathsRefusal(); err != nil {
		return nil, err
	}
	if err := req.cleanName(); err != nil {
		return nil, err
	}
	if err := req.opensRefusal(); err != nil {
		return nil, err
	}
	sources, err := h.createSourcesRefusal(u, req)
	if err != nil {
		return nil, err
	}
	if err := req.inboxRefusal(); err != nil {
		return nil, err
	}
	return sources, nil
}

// pathsRefusal judges the paths a request names: the manifest's size, each
// manifest path's depth and the entry page's path.
func (req *createShareRequest) pathsRefusal() error {
	if len(req.Files) > maxManifestFiles {
		return refuse(http.StatusRequestEntityTooLarge, "manifest-too-big",
			fmt.Sprintf("manifest has %d files, the limit is %d: create the share without a manifest and upload into it",
				len(req.Files), maxManifestFiles))
	}
	for _, f := range req.Files {
		if tooDeep(f.Path) {
			return errPathTooDeep
		}
	}
	if req.Entry != "" && !shareid.ValidRelPath(req.Entry) {
		return refuse(http.StatusBadRequest, "", "entry must be a relative path inside the share")
	}
	return nil
}

// cleanName refuses an unusable name and stores the cleaned one. A name is
// optional at creation (a client may simply not send one), but one that
// arrives must be usable: the same rule the rename path applies.
func (req *createShareRequest) cleanName() error {
	if req.Name == "" {
		return nil
	}
	clean, err := cleanShareName(req.Name)
	if err != nil {
		return refuse(http.StatusBadRequest, "", err.Error())
	}
	req.Name = clean
	return nil
}

// opensRefusal is the one question a share's View link answers, asked of the
// kinds the request combines: a gallery is a published page, an inbox is
// never served publicly at all, an entry names some other page as the
// landing one, and a text share opens as its one file. The rest of a text
// share's rule (one file, no source) is the store's, asked at CreateShare.
func (req *createShareRequest) opensRefusal() error {
	return linkOpens{Listing: req.Listing, Entry: req.Entry != "",
		Gallery: req.Media, Inbox: req.Inbox, Text: req.Text}.refuse()
}

// createSourcesRefusal judges a LINKED share's sources and answers them as
// one list (the request's sources as sent, empty for a share with none; an
// empty non-nil slice comes back unchanged): Source and Sources are
// exclusive, an inbox takes none, every source passes both boundaries and
// resolves, and no
// manifest path lists on top of an entry a source serves. A share of several
// sources, of a folder, or of a source beside uploads is stored as a folder.
func (h *handler) createSourcesRefusal(u metadb.User, req *createShareRequest) ([]string, error) {
	if req.Source != "" && len(req.Sources) > 0 {
		return nil, refuse(http.StatusBadRequest, "bad-source", "give source or sources, not both")
	}
	sources := req.Sources
	if req.Source != "" {
		sources = []string{req.Source}
	}
	if len(sources) == 0 {
		return sources, nil
	}
	if req.Inbox {
		return nil, refuse(http.StatusBadRequest, "source-exclusive",
			"an inbox takes no sources")
	}
	anyDir, err := h.sourceListRefusal(u, sources)
	if err != nil {
		return nil, err
	}
	// A share of several sources, or of a source beside uploads, is a
	// folder: it lists more than one thing.
	req.Folder = req.Folder || anyDir || len(sources) > 1 || len(req.Files) > 0
	specs := make([]linked.SourceSpec, 0, len(sources))
	for _, src := range sources {
		specs = append(specs, linked.SourceSpec{Path: src})
	}
	for _, f := range req.Files {
		if err := h.sourceSpecNameRefusal(specs, f.Path); err != nil {
			return nil, err
		}
	}
	return sources, nil
}

// inboxRefusal judges the fields that belong to an INBOX: an inbox carries
// them and none of a share's publish-side fields, and any other share
// carries none of them. It stores the trimmed note and the file cap clamped
// to the server's bound.
func (req *createShareRequest) inboxRefusal() error {
	if !req.Inbox {
		if req.Note != "" || req.MaxBytes != 0 || req.MaxFiles != 0 {
			return refuse(http.StatusBadRequest, "", "note and caps apply to Receive Inboxes only")
		}
		return nil
	}
	// A request carries none of a share's publish-side machinery: no
	// manifest (nothing is known up front), no entry page (its content
	// is never served publicly), no expiry (close is the off switch),
	// no reservation (the owner is not about to upload), and no links
	// off (it has no public links to turn off).
	if len(req.Files) > 0 || req.Entry != "" || req.ExpiresInSeconds != 0 || req.ReserveBytes != 0 || req.linksOff() {
		return refuse(http.StatusBadRequest, "", "an inbox takes no manifest, entry, expiry, reservation or links off")
	}
	// The name titles the upload page, so unlike a share there is no
	// filename to fall back on.
	if req.Name == "" {
		return refuse(http.StatusBadRequest, "", "an inbox needs a name")
	}
	req.Note = strings.TrimSpace(req.Note)
	if err := inboxNoteRefusal(req.Note); err != nil {
		return err
	}
	// The caps are opt-in: 0 stays 0 (unlimited), the owner's quota
	// being the standing bound. A file cap above the server's bound is
	// stored as that bound, the most any inbox takes.
	if req.MaxBytes < 0 || req.MaxFiles < 0 {
		return refuse(http.StatusBadRequest, "", "negative cap")
	}
	req.MaxFiles = min(req.MaxFiles, metadb.InboxMaxFiles)
	return nil
}

// options is the share the admitted request describes, owned by owner, with
// a pending file row for each manifest entry. The password and the expiry
// are the handler's to add.
func (req *createShareRequest) options(owner string, sources []string) metadb.CreateOptions {
	opts := metadb.CreateOptions{Name: req.Name, Owner: owner, Folder: req.Folder,
		Entry:   req.Entry,
		Media:   req.Media,
		Listing: req.Listing,
		Inbox:   req.Inbox, Text: req.Text, Note: req.Note,
		MaxBytes: req.MaxBytes, MaxFiles: req.MaxFiles,
		Sources: sources, LinksOff: req.linksOff()}
	for _, f := range req.Files {
		opts.Files = append(opts.Files, metadb.PendingFile{Path: f.Path, Size: f.Size})
	}
	return opts
}

// admitCreated runs the checks only a created share can answer and answers
// its view, or deletes the share and answers the refusal: the sources still
// granted, a linked share's first walk and its gallery gate, then the
// reservation.
func (h *handler) admitCreated(u metadb.User, d metadb.Share, req *createShareRequest, sources []string) (shareView, error) {
	// The sources were admitted against the allowlist this request carried;
	// asked again now the share exists, a narrowing that committed in
	// between refuses the create as the admission would have (ungranted).
	if lost, err := h.ungranted(u.Username, sources); err != nil || len(lost) > 0 {
		_ = h.db.DeleteShare(d.ID)
		if err == nil {
			err = refuse(http.StatusForbidden, "source-forbidden", "this account may not share from "+lost[0])
		}
		return shareView{}, err
	}
	v := h.viewFrom(d)
	if d.Linked() {
		// The create response carries the first walk of the source, the
		// same as any later read: a client that lists what it just made
		// must see the files without a second round trip. A share the
		// server just created but cannot read back is an error: a later
		// GET would 500 the same way.
		if v.SourceMissing {
			_ = h.db.DeleteShare(d.ID)
			return shareView{}, refuse(http.StatusInternalServerError, "", "source is unreadable")
		}
		// linkOpens.refuse only checks the exclusivity of Entry/Listing/
		// Gallery/Inbox; a linked share's files are only known after this walk,
		// so gallery playability is gated here instead, exactly as PATCH
		// gates it against an ordinary share's already-uploaded files.
		if req.Media {
			if err := galleryRefusal(v); err != nil {
				_ = h.db.DeleteShare(d.ID)
				return shareView{}, err
			}
		}
	}
	if req.ReserveBytes > 0 {
		err := h.ownerRoom(u, d.ID, "", req.ReserveBytes)
		if err == nil {
			err = h.fs.Reserve(d.ID, u.Username, req.ReserveBytes)
		}
		if err != nil {
			_ = h.db.DeleteShare(d.ID)
			if errors.Is(err, metadb.ErrQuota) {
				return shareView{}, refuse(http.StatusInsufficientStorage, "quota", err.Error())
			}
			// The one upload failure a server OWNER can act on, so it
			// carries a code the app can name a remedy for.
			return shareView{}, refuse(http.StatusInsufficientStorage, "no-space",
				spaceMessage(err, u.IsAdmin()))
		}
	}
	return v, nil
}

// getShare returns one share by ID, the single-share read the client uses
// after a replace/edit, so it doesn't fetch the whole listing for one entry.
// It is the one route that answers `password`, to the owner's bearer only
// (ownedShare refuses anyone else, an admin included) and under no-store; a
// copy that does not open leaves it out and the share reads as set.
func (h *handler) getShare(w http.ResponseWriter, r *http.Request) {
	v, _, ok := h.ownedShare(w, r)
	if !ok {
		return
	}
	out := h.resolvedRow(v)
	if pw := h.readablePassword(v.Share); pw != "" {
		out.Password = pw
		w.Header().Set("Cache-Control", "no-store")
	}
	writeJSON(w, http.StatusOK, out)
}

// Listing page bounds: an absent/invalid limit gets metadb.DefaultListLimit;
// nothing can ask for more than metadb.MaxListLimit rows in one response.
// Clients page with offset until they have total.
//
// File bounds on a listing. Rows bound the page in SHARES; these bound it in
// FILES. Without them, 500 rows over 20,000-file shares would build ten
// million file entries for one response, about 4 GB, reachable from the
// app's ordinary Shares screen.
//
// Two ceilings, because neither covers the other. The per-share cap stops one
// fat share; the page budget stops many medium ones (metadb.MaxListLimit rows
// at the per-share cap is still 200,000 entries). A row past the cap reports
// its true fileCount and totalSize with filesTruncated set, and clients fetch
// the whole record with GET /api/shares/{id}, which is never capped.
//
// Vars, not consts, only so tests can shrink them; nothing on the request path
// writes them.
var (
	listMaxFilesPerShare = metadb.DefaultMaxFilesPerShare
	listMaxFilesPerPage  = metadb.DefaultMaxFilesPerPage
)

// listShares returns one page of the caller's own shares, newest first, every
// role scoped the same way, an admin included. Response: {shares, total,
// offset, totalBytes} - total counts everything the query matches (so
// clients know how far the pages go), and totalBytes is the committed bytes
// of those same matches.
func (h *handler) listShares(w http.ResponseWriter, r *http.Request) {
	u := reqUser(r)
	query := r.URL.Query()
	q := metadb.ListQuery{Name: query.Get("q"), Limit: metadb.DefaultListLimit,
		MaxFiles: listMaxFilesPerShare, MaxPageFiles: listMaxFilesPerPage,
		After: query.Get("after")}
	// The default listing is ordinary shares only; inboxes are their own
	// scope (?kind=receive), so no existing consumer ever sees them.
	switch kind := query.Get("kind"); kind {
	case "", kindInbox:
		q.Kind = kind
	default:
		writeError(w, http.StatusBadRequest, "kind takes receive")
		return
	}
	q.Owner = u.Username
	if v, err := strconv.Atoi(query.Get("offset")); err == nil && v > 0 {
		q.Offset = v
	}
	if v, err := strconv.Atoi(query.Get("limit")); err == nil && v > 0 {
		q.Limit = min(v, metadb.MaxListLimit)
	}
	page, err := h.db.List(q)
	if errors.Is(err, metadb.ErrBadRequest) {
		writeError(w, http.StatusBadRequest, "invalid cursor")
		return
	}
	if err != nil {
		writeRefusal(w, err)
		return
	}
	out := make([]shareOut, 0, len(page.Shares))
	for _, d := range page.Shares {
		out = append(out, h.resolvedRow(h.viewFrom(d)))
	}
	resp := map[string]any{
		"shares": out, "total": page.Total, "offset": q.Offset, "totalBytes": page.TotalBytes,
	}
	if page.NextCursor != "" {
		resp["nextCursor"] = page.NextCursor
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *handler) deleteShare(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := h.ownedShareMeta(w, r); !ok {
		return
	}
	if err := h.copySourceRefusal(r.PathValue("id")); err != nil {
		writeRefusal(w, err)
		return
	}
	if err := h.removeShare(r.PathValue("id")); err != nil {
		writeRefusal(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
