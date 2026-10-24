package api

import (
	"log"
	"net/http"
	"sort"
	"time"

	"golang.org/x/crypto/bcrypt"

	"hyperdrop/server/internal/linked"
	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/shareid"
)

// The pieces every share-mutating handler needs. createShare, updateShare and
// patchLiveShare use one copy: three copies is how the opens rule ends up
// spelled three times with three different levels of completeness.

// linkOpens is the state of the ONE question a share's View link answers: the
// file itself, the file listing, a page in the share, or a gallery. An inbox
// link settles it too, its content never being served publicly at all.
//
// Asked of the RESULTING state rather than of what is stored, so one request
// can move a web page straight to a gallery.
type linkOpens struct {
	Listing bool
	Entry   bool
	Gallery bool
	// Inbox applies at creation only: a share never becomes an inbox
	// afterwards.
	Inbox bool
	// Text applies at creation only, like Inbox: a share never becomes a text share afterwards.
	Text bool
}

// refuse answers the 400 naming the pair of answers that cannot both be
// given, or nil when at most one was.
//
// The wording is per PAIR on purpose. "a gallery is not a file listing" tells
// the caller which two of the fields it sent collided; a single "pass one"
// would leave them to work out which.
func (o linkOpens) refuse() error {
	msg := ""
	switch {
	case o.Text && o.Inbox:
		msg = "a share is a text share or an inbox, never both"
	case o.Text && (o.Gallery || o.Entry || o.Listing):
		msg = "a text share opens as its file and takes no entry, gallery or listing"
	case o.Gallery && o.Inbox:
		msg = "a share is a gallery or an inbox, never both"
	case o.Listing && o.Inbox:
		msg = "an inbox has no file listing: its content is never served publicly"
	case o.Entry && o.Inbox:
		msg = "an inbox has no entry page: its content is never served publicly"
	case o.Gallery && o.Entry:
		msg = "a gallery has no entry page: the gallery is the page"
	case o.Listing && o.Gallery:
		msg = "a gallery is not a file listing"
	case o.Listing && o.Entry:
		msg = "a page is not a file listing"
	default:
		return nil
	}
	return refuse(http.StatusBadRequest, "", msg)
}

// with answers the state an edit leaves: each field the request sends
// (non-nil) replaces the stored answer, the rest stay. Stored and live
// shares both fold their PATCH through it, so the opens rule is asked of
// the RESULTING state and one request can move a web page straight to a
// gallery.
func (o linkOpens) with(listing, media *bool, entry *string) linkOpens {
	if listing != nil {
		o.Listing = *listing
	}
	if media != nil {
		o.Gallery = *media
	}
	if entry != nil {
		o.Entry = *entry != ""
	}
	return o
}

// sharePasswordHash bcrypts a share password. An empty password hashes to ""
// rather than to a hash of nothing: "" is what every caller stores to mean
// "no password".
func sharePasswordHash(password string) (string, error) {
	if password == "" {
		return "", nil
	}
	b, err := bcrypt.GenerateFromPassword([]byte(password), metadb.BcryptCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// hashPassword is sharePasswordHash for a handler holding the writer: it
// answers the refusal itself and reports whether the caller should carry on.
// A share password longer than bcrypt reads is 400 password-too-long, the
// account passwords' bound and code; a share password has no minimum.
func hashPassword(w http.ResponseWriter, password string) (string, bool) {
	if len(password) > maxPasswordBytes {
		writeErrorCode(w, http.StatusBadRequest, "password-too-long",
			"a share password can be at most 72 bytes long")
		return "", false
	}
	hash, err := sharePasswordHash(password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "hashing password")
		return "", false
	}
	return hash, true
}

// applyEdit validates one edit against the share it names and applies it,
// answering the share as it stands afterwards, or the refusal (a *refusal
// or a metadb error, both answered by writeRefusal). PATCH and the batch edit share it,
// so one share and a thousand answer the same refusals in the same order.
//
// passwordHash is the caller's bcrypt of req.Password, an argument rather
// than a computation here because a batch hashes ONE password for every share
// it edits.
func (h *handler) applyEdit(v shareView, u metadb.User, req shareUpdate,
	passwordHash string) (shareView, error) {
	if !req.any() {
		return shareView{}, refuse(http.StatusBadRequest, "", "nothing to change")
	}
	// A text share's View answer is its file. Asked before the opens rule, so
	// the caller learns the kind that refused rather than a pair that did.
	if v.Text && (req.Entry != nil || req.Media != nil || req.Listing != nil) {
		return shareView{}, refuse(http.StatusConflict, "text-share", "a text share opens as its file: entry, media and listing cannot change")
	}
	if v.Text && (len(req.Linked) > 0 || req.Sources != nil) {
		return shareView{}, refuse(http.StatusConflict, "text-share", "a text share is one text file: it takes no server folder")
	}
	opens := linkOpens{Listing: v.Listing, Entry: v.Entry != "", Gallery: v.Media}
	if err := opens.with(req.Listing, req.Media, req.Entry).refuse(); err != nil {
		return shareView{}, err
	}
	if v.Inbox && (len(req.Linked) > 0 || req.Sources != nil) {
		return shareView{}, refuse(http.StatusBadRequest, "source-exclusive", "an inbox takes no sources")
	}
	// anyDir settles the folder flag below: a share that points at a folder
	// reads as one, whatever it was created from.
	var sourcesHoldAFolder bool
	if req.Sources != nil {
		anyDir, err := h.sourceListRefusal(u, *req.Sources)
		if err != nil {
			return shareView{}, err
		}
		sourcesHoldAFolder = anyDir
	}
	if v.Inbox {
		// A request's content is never published, so the publish-side fields
		// cannot apply: no entry page, no expiry, and nothing schedulable
		// (open/closed takes effect the moment it is set).
		if req.publishOnly() {
			return shareView{}, refuse(http.StatusBadRequest, "",
				"an inbox takes no entry, gallery, listing, expiry, pin or scheduled change")
		}
	} else if req.inboxOnly() {
		return shareView{}, refuse(http.StatusBadRequest, "",
			"closed, note, notify and seenAt apply to Receive Inboxes only")
	}
	// After the inbox refusal above, so an inbox is turned away for
	// being one rather than for having no pictures to show.
	if req.Media != nil && *req.Media && !v.Media {
		if err := galleryRefusal(v); err != nil {
			return shareView{}, err
		}
	}
	if req.Note != nil {
		if err := inboxNoteRefusal(*req.Note); err != nil {
			return shareView{}, err
		}
	}
	if req.Entry != nil {
		entry := relPath(*req.Entry)
		req.Entry = &entry
	}
	if req.Entry != nil && *req.Entry != "" && !shareid.ValidRelPath(*req.Entry) {
		return shareView{}, refuse(http.StatusBadRequest, "", "entry must be a relative path inside the share")
	}
	if req.ApplyInSeconds < 0 || (req.ExpiresInSeconds != nil && *req.ExpiresInSeconds < 0) {
		return shareView{}, refuse(http.StatusBadRequest, "", "negative duration")
	}
	var newName string
	if req.Name != nil {
		clean, err := cleanShareName(*req.Name)
		if err != nil {
			return shareView{}, refuse(http.StatusBadRequest, "", err.Error())
		}
		newName = clean
	}
	switch req.CancelPending {
	case "", metadb.ScheduledPassword, metadb.ScheduledExpiry, "all":
	default:
		return shareView{}, refuse(http.StatusBadRequest, "", "cancelPending must be password, expiry, or all")
	}
	// The filters are composed before anything is written, so a source the
	// request cannot fix refuses the whole edit rather than half of it.
	var filters []metadb.FilterEdit
	if len(req.Linked) > 0 {
		sources := v.SourceList()
		if req.Sources != nil {
			sources = *req.Sources
		}
		revoked := map[string]bool{}
		for _, src := range v.Sources {
			revoked[src.Path] = src.Revoked()
		}
		var err error
		if filters, err = h.filterEdits(sources, revoked, req.Linked); err != nil {
			return shareView{}, err
		}
	}
	// A manifest created before attaching fixed sources must get the same
	// collision gate as a create carrying sources. Committed uploads retain
	// their existing shadowing behavior when sources are added later.
	if req.Sources != nil && len(filters) > 0 {
		specs := make([]linked.SourceSpec, 0, len(*req.Sources))
		existing, err := h.dbSpecs(v.Share)
		if err != nil {
			return shareView{}, err
		}
		for _, source := range *req.Sources {
			spec := linked.SourceSpec{Path: source}
			for _, old := range existing {
				if old.Path == source {
					spec = old
				}
			}
			specs = append(specs, spec)
		}
		for _, f := range v.StoredFiles() {
			if f.Pending {
				if err := h.sourceSpecNameRefusal(specs, len(specs) > 1, f.Path); err != nil {
					return shareView{}, err
				}
			}
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	opts, actions := req.options(newName, passwordHash, now)
	// A batch bcrypts once and seals per share here, each copy bound to its
	// share's id and to the hash written beside it.
	if req.Password != nil && *req.Password != "" {
		sealed, err := h.sealPassword(v.ID, passwordHash, *req.Password)
		if err != nil {
			return shareView{}, err
		}
		opts.PasswordSealed = sealed
		for i := range actions {
			if actions[i].Kind == metadb.ScheduledPassword {
				actions[i].PasswordSealed = sealed
			}
		}
	}
	// The flag says how a listing page draws the share: a folder mark for a
	// share that holds a tree, a file mark for one file. Sources that hold a
	// folder, several sources (each listing under its own name) and an
	// upload beside them each make it a tree. It never goes back: a share
	// that has held several files is not one file again.
	if req.Sources != nil {
		folder := v.Folder || sourcesHoldAFolder || len(*req.Sources) > 1 || len(v.StoredFiles()) > 0
		opts.SetFolder, opts.Folder = folder != v.Folder, folder
	}
	if req.CancelPending != "" {
		if _, err := h.db.CancelScheduled(v.ID, req.CancelPending); err != nil {
			return shareView{}, err
		}
	}
	// Sources first, so a source added in the same request is one the
	// filters below can name. The slug map moves onto the names the new
	// list produces in the same transaction that changes the rows, so a link
	// already copied keeps pointing at its file. A removed source's tiles go
	// after the commit, rows first: a crash between leaves a stray tile no
	// slug names, the documented worst case.
	if req.Sources != nil {
		rekey := h.realignSlugs(v.SourceList(), *req.Sources)
		_, removed, err := h.db.SetSources(v.ID, *req.Sources, rekey, filters)
		if err != nil {
			return shareView{}, err
		}
		for _, slug := range removed {
			h.fs.RemoveThumb(v.ID, slug)
		}
		had := make(map[string]bool, len(v.Sources))
		for _, src := range v.Sources {
			had[src.Path] = true
		}
		var added []string
		for _, src := range *req.Sources {
			if !had[src] {
				added = append(added, src)
			}
		}
		// The sources are committed; the second look is logged when it
		// fails rather than failing an edit that has already applied.
		if err := h.revokeUngranted(v.ID, v.Owner, added); err != nil {
			log.Printf("share %s: revoking ungranted sources: %v", v.ID, err)
		}
	}
	if !opts.Empty() {
		if _, err := h.db.UpdateShare(v.ID, opts); err != nil {
			return shareView{}, err
		}
	}
	if req.Sources == nil && len(filters) > 0 {
		if _, err := h.db.EditFilter(v.ID, filters); err != nil {
			return shareView{}, err
		}
	}
	// One write for both schedulable fields, so a combined password and
	// expiry edit cannot half-persist.
	if len(actions) > 0 {
		if _, err := h.db.Schedule(v.ID, actions...); err != nil {
			return shareView{}, err
		}
	}
	return h.view(v.ID)
}

// filterEdits turns the PATCH `linked` map into the edits the rows take,
// walking a source the request FIXES so the stored list is what the folder
// holds right now. Sorted by source, so two edits in one request apply the
// same way twice and a refusal names the same one.
//
// A revoked source is never fixed (409 source-revoked): fixing walks the
// folder, and the owner's allowlist no longer covers it, so the walk would
// read a folder the account may not share and its answer would say whether
// the folder exists and how big it is.
func (h *handler) filterEdits(sources []string, revoked map[string]bool,
	edits map[string]linkedSourceEdit) ([]metadb.FilterEdit, error) {
	held := make(map[string]bool, len(sources))
	for _, s := range sources {
		held[s] = true
	}
	out := make([]metadb.FilterEdit, 0, len(edits))
	for source, e := range edits {
		out = append(out, e.edit(source))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Source < out[j].Source })
	for i := range out {
		if !held[out[i].Source] {
			return nil, refuse(http.StatusBadRequest, "not-a-source",
				"not one of this share's sources: "+out[i].Source)
		}
		// A hidden path is held to what the listing can show
		// (linked.ValidHide), so a row the listing could never match is
		// never stored and a listed name is never refused. A show only
		// deletes a row, so it names any.
		for _, rel := range out[i].Hide {
			if !linked.ValidHide(rel) {
				return nil, refuse(http.StatusBadRequest, "bad-source", "hide must name a clean relative path: "+rel)
			}
		}
		if !out[i].SetFixed || !out[i].Fixed {
			continue
		}
		if revoked[out[i].Source] {
			return nil, refuse(http.StatusConflict, "source-revoked",
				"this account may no longer share from "+out[i].Source)
		}
		rels, err := h.walkSource(out[i].Source)
		if err != nil {
			return nil, err
		}
		out[i].FixedList = rels
	}
	return out, nil
}

// walkSource lists what one source holds right now, for the `linked` edit
// that FIXES it to that list. A folder whose walk does not fit is refused
// rather than pinned to a window of itself, which would hide the rest of it
// without saying so.
func (h *handler) walkSource(source string) ([]string, error) {
	l, readable := linked.Compose(h.roots, []linked.SourceSpec{{Path: source}}, linked.MaxWalk)
	if !readable {
		return nil, refuse(http.StatusNotFound, "source-missing", "no such file or folder on the server: "+source)
	}
	if l.Truncated {
		return nil, refuse(http.StatusBadRequest, "source-too-big-to-fix",
			"the folder holds too many files to share as a fixed list")
	}
	rels := make([]string, 0, len(l.Entries))
	for _, e := range l.Entries {
		rels = append(rels, e.Rel)
	}
	return rels, nil
}

// removeFiles removes rows first, then the bytes and tiles they named. A
// crash between leaves files nothing serves, which the boot pass does not
// walk for; that is the documented worst case, and the alternative order
// would serve rows whose bytes are gone.
func (h *handler) removeFiles(id string, paths []string) (metadb.Share, error) {
	d, slugs, err := h.db.RemoveFiles(id, paths)
	if err != nil {
		return metadb.Share{}, err
	}
	for i, p := range paths {
		_ = h.fs.RemoveFile(id, p)
		h.prep.forgetFile(id, p)
		if s := slugs[i]; s != "" {
			h.fs.RemoveThumb(id, s)
		}
	}
	return d, nil
}

// removeShare deletes a share: the rows first, then the directory. Once the
// rows are gone the share is gone; a directory left behind is the boot
// orphan pass's to remove, so a failure there is logged, not returned.
func (h *handler) removeShare(id string) error {
	if err := h.db.DeleteShare(id); err != nil {
		return err
	}
	h.prep.forgetShare(id)
	if err := h.fs.RemoveShare(id); err != nil {
		log.Printf("delete %s: removing directory: %v", id, err)
	}
	return nil
}

// contentEdit names a change to the entries a share holds, for
// contentEditRefusal.
type contentEdit int

const (
	editDeleteFile contentEdit = iota
	editMove
	editAddFolder
	editDeleteFolder
)

// contentEditRefusal answers the 409 a share's KIND gives an edit of its
// entries, or nil when the kind takes it. An inbox holds what strangers sent,
// flat: its files are removable and nothing else. A text share holds its one
// file, which a replace changes and nothing else does. Every content route
// asks here once, right after the ownership gate, so a new kind or a new
// route is one place.
func (v shareView) contentEditRefusal(e contentEdit) error {
	switch {
	case v.Inbox && e == editMove:
		return refuse(http.StatusConflict, "receive", "an inbox's files cannot be moved")
	case v.Inbox && (e == editAddFolder || e == editDeleteFolder):
		return refuse(http.StatusConflict, "receive", "an inbox holds no folders")
	case v.Text && e == editDeleteFile:
		return refuse(http.StatusConflict, "text-share", "a text share keeps its one file: replace it instead of removing it")
	case v.Text && e == editMove:
		return refuse(http.StatusConflict, "text-share", "a text share's one file cannot be moved: replace it under the new name instead")
	case v.Text:
		return refuse(http.StatusConflict, "text-share", "a text share holds one file and takes no folders")
	}
	return nil
}

// expiryAt is the moment an expiry of secs seconds from now lands, to the
// second and in UTC, or nil for none (secs <= 0). Every route that takes
// expiresInSeconds answers through it, so a stored share, a scheduled
// expiry and a live share expire on the same clock.
func expiryAt(now time.Time, secs int64) *time.Time {
	if secs <= 0 {
		return nil
	}
	exp := afterSeconds(now, secs).UTC().Truncate(time.Second)
	return &exp
}

// maxRequestSeconds bounds a span a request gives in seconds (an expiry, a
// scheduled change): a century, past any share's life. A larger count would
// overflow time.Duration and land in the past, expiring a share, or
// applying a scheduled change, at once.
const maxRequestSeconds = 100 * 365 * 24 * 60 * 60

// afterSeconds is the moment secs seconds after now, secs capped at
// maxRequestSeconds.
func afterSeconds(now time.Time, secs int64) time.Time {
	return now.Add(time.Duration(min(secs, maxRequestSeconds)) * time.Second)
}
