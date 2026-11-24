package api

import (
	"errors"
	"log"
	"net/http"
	"sort"
	"strings"
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
// A share password set here is a chosen password under the accounts' rule
// (checkChosenPassword: 8 to 72 bytes, not among the most common; 400
// password-too-short, password-too-long, or the too-common message), since
// the share's lanes slow a guesser down but cannot save a four-digit PIN. An
// empty password removes the password and is not judged; a password already
// stored is never measured, so a share set before the rule still opens.
func hashPassword(w http.ResponseWriter, password string) (string, bool) {
	if password != "" {
		if err := checkChosenPassword(password); err != nil {
			writeRefusal(w, err)
			return "", false
		}
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
	plan, err := h.planEdit(v, u, &req)
	if err != nil {
		return shareView{}, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	opts, actions := req.options(plan.name, passwordHash, now)
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
		folder := v.Folder || plan.sourcesHoldAFolder || len(*req.Sources) > 1 || len(v.StoredFiles()) > 0
		opts.SetFolder, opts.Folder = folder != v.Folder, folder
	}
	if req.CancelPending != "" {
		if _, err := h.db.CancelScheduled(v.ID, req.CancelPending); err != nil {
			return shareView{}, err
		}
	}
	// Sources first, so a source added in the same request is one the
	// filters below can name.
	if req.Sources != nil {
		if err := h.replaceSources(v, *req.Sources, plan.filters); err != nil {
			return shareView{}, err
		}
	}
	if !opts.Empty() {
		if _, err := h.db.UpdateShare(v.ID, opts); err != nil {
			return shareView{}, err
		}
	}
	if req.Sources == nil && len(plan.filters) > 0 {
		if _, err := h.db.EditFilter(v.ID, plan.filters); err != nil {
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

// editPlan is what an edit's checks settle before anything is written: the
// cleaned name, whether the new sources hold a folder, and the filter edits
// the `linked` map composes.
type editPlan struct {
	name               string
	sourcesHoldAFolder bool
	filters            []metadb.FilterEdit
}

// planEdit runs every check of an edit against v, in the order that decides
// which refusal a request wrong in several ways gets: what the share's kind
// refuses, the new sources, the fields, then the filters and the names a
// fixed source would take. It writes nothing; it spells req.Entry as a
// relpath for the options built from req afterwards.
func (h *handler) planEdit(v shareView, u metadb.User, req *shareUpdate) (editPlan, error) {
	if err := req.kindRefusal(v); err != nil {
		return editPlan{}, err
	}
	var plan editPlan
	// anyDir settles the folder flag: a share that points at a folder reads
	// as one, whatever it was created from.
	if req.Sources != nil {
		anyDir, err := h.sourceListRefusal(u, *req.Sources)
		if err != nil {
			return editPlan{}, err
		}
		plan.sourcesHoldAFolder = anyDir
	}
	name, err := req.fieldsRefusal(v)
	if err != nil {
		return editPlan{}, err
	}
	plan.name = name
	if plan.filters, err = h.editFilters(v, *req); err != nil {
		return editPlan{}, err
	}
	return plan, nil
}

// kindRefusal is what the share's kind refuses of the request: an empty
// request, a text share's opens and sources, an opens pair in the resulting
// state, and an inbox's sources.
func (req shareUpdate) kindRefusal(v shareView) error {
	if !req.any() {
		return refuse(http.StatusBadRequest, "", "nothing to change")
	}
	// A text share's View answer is its file. Asked before the opens rule, so
	// the caller learns the kind that refused rather than a pair that did.
	if v.Text && (req.Entry != nil || req.Media != nil || req.Listing != nil) {
		return refuse(http.StatusConflict, "text-share", "a text share opens as its file: entry, media and listing cannot change")
	}
	if v.Text && (len(req.Linked) > 0 || req.Sources != nil) {
		return refuse(http.StatusConflict, "text-share", "a text share is one text file: it takes no server folder")
	}
	opens := linkOpens{Listing: v.Listing, Entry: v.Entry != "", Gallery: v.Media}
	if err := opens.with(req.Listing, req.Media, req.Entry).refuse(); err != nil {
		return err
	}
	if v.Inbox && (len(req.Linked) > 0 || req.Sources != nil) {
		return refuse(http.StatusBadRequest, "source-exclusive", "an inbox takes no sources")
	}
	return nil
}

// fieldsRefusal checks the request's fields against v and answers the
// cleaned name (empty when the request names none): the fields of the other
// kind of share, a gallery the files cannot make, the caps, the note, the
// entry (spelled as a relpath in req), the durations, the name and
// cancelPending.
func (req *shareUpdate) fieldsRefusal(v shareView) (string, error) {
	if v.Inbox {
		// A request's content is never published, so the publish-side fields
		// cannot apply: no entry page, no expiry, and nothing schedulable
		// (open/closed takes effect the moment it is set).
		if req.publishOnly() {
			return "", refuse(http.StatusBadRequest, "",
				"an inbox takes no entry, gallery, listing, expiry, pin, links off or scheduled change")
		}
	} else if req.inboxOnly() {
		return "", refuse(http.StatusBadRequest, "",
			"closed, note, notify, seenAt, maxBytes and maxFiles apply to Receive Inboxes only")
	}
	// After the inbox refusal above, so an inbox is turned away for
	// being one rather than for having no pictures to show.
	if req.Media != nil && *req.Media && !v.Media {
		if err := galleryRefusal(v); err != nil {
			return "", err
		}
	}
	if (req.MaxBytes != nil && *req.MaxBytes < 0) || (req.MaxFiles != nil && *req.MaxFiles < 0) {
		return "", refuse(http.StatusBadRequest, "", "negative cap")
	}
	if req.Note != nil {
		if err := inboxNoteRefusal(*req.Note); err != nil {
			return "", err
		}
	}
	if req.Entry != nil {
		entry := relPath(*req.Entry)
		req.Entry = &entry
	}
	if req.Entry != nil && *req.Entry != "" && !shareid.ValidRelPath(*req.Entry) {
		return "", refuse(http.StatusBadRequest, "", "entry must be a relative path inside the share")
	}
	if req.ApplyInSeconds < 0 || (req.ExpiresInSeconds != nil && *req.ExpiresInSeconds < 0) {
		return "", refuse(http.StatusBadRequest, "", "negative duration")
	}
	var newName string
	if req.Name != nil {
		clean, err := cleanShareName(*req.Name)
		if err != nil {
			return "", refuse(http.StatusBadRequest, "", err.Error())
		}
		newName = clean
	}
	switch req.CancelPending {
	case "", metadb.ScheduledPassword, metadb.ScheduledExpiry, "all":
	default:
		return "", refuse(http.StatusBadRequest, "", "cancelPending must be password, expiry, or all")
	}
	return newName, nil
}

// editFilters composes the request's `linked` map into filter edits before
// anything is written, so a source the request cannot fix refuses the whole
// edit rather than half of it. A request that sets the sources and edits
// their filters holds the share's pending uploads to the collision gate a
// create carrying sources applies; committed uploads keep their shadowing
// when sources are added later.
func (h *handler) editFilters(v shareView, req shareUpdate) ([]metadb.FilterEdit, error) {
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
			return nil, err
		}
	}
	if req.Sources != nil && len(filters) > 0 {
		specs := make([]linked.SourceSpec, 0, len(*req.Sources))
		existing, err := h.dbSpecs(v.Share)
		if err != nil {
			return nil, err
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
				if err := h.sourceSpecNameRefusal(specs, f.Path); err != nil {
					return nil, err
				}
			}
		}
	}
	return filters, nil
}

// replaceSources sets the share's sources to sources, with filters applied
// in the same write. The slug map moves onto the names the new list
// produces in the same transaction that changes the rows, so a link already
// copied keeps pointing at its file. A removed source's tiles go after the
// commit, rows first: a crash between leaves a stray tile no slug names,
// the documented worst case. The sources added are then checked against the
// owner's allowlist once more; that look is logged when it fails rather
// than failing an edit that has already applied.
func (h *handler) replaceSources(v shareView, sources []string, filters []metadb.FilterEdit) error {
	rekey := h.realignSlugs(v.SourceList(), sources)
	_, removed, err := h.db.SetSources(v.ID, sources, rekey, filters)
	if err != nil {
		return err
	}
	for _, slug := range removed {
		h.fs.RemoveThumb(v.ID, slug)
	}
	had := make(map[string]bool, len(v.Sources))
	for _, src := range v.Sources {
		had[src.Path] = true
	}
	var added []string
	for _, src := range sources {
		if !had[src] {
			added = append(added, src)
		}
	}
	if err := h.revokeUngranted(v.ID, v.Owner, added); err != nil {
		log.Printf("share %s: revoking ungranted sources: %v", v.ID, err)
	}
	return nil
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
		// A hidden path is held to what the listing can show (a valid
		// relpath, linked.ValidRel), so a row the listing could never match
		// is never stored and a listed name is never refused. A show only
		// deletes a row, so it names any.
		for _, rel := range out[i].Hide {
			if !linked.ValidRel(rel) {
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
// would serve rows whose bytes are gone. The bytes go only where no row
// names the path once its lock is held (removeUnnamed).
func (h *handler) removeFiles(id string, paths []string) (metadb.Share, error) {
	d, slugs, err := h.db.RemoveFiles(id, paths)
	if err != nil {
		return metadb.Share{}, err
	}
	if h.rowsRemoved != nil {
		h.rowsRemoved(id, paths)
	}
	for i, p := range paths {
		h.removeUnnamed(id, p)
		h.prep.forgetFile(id, p)
		if s := slugs[i]; s != "" {
			h.fs.RemoveThumb(id, s)
		}
	}
	return d, nil
}

// removeUnnamed removes the bytes at rel whose row a removal took, under
// rel's path lock, and only when no row (committed or pending, looked up
// under the share's spelling, as the volume compares names) names rel by
// then: a publish commit or an upload of rel between the row's removal and
// the lock wrote a row naming bytes there, which stay. A lookup that fails
// keeps the bytes; bytes no row names are the worst case, never a row
// naming no bytes.
func (h *handler) removeUnnamed(id, rel string) {
	_, _ = h.fs.RemoveFileIf(id, rel, func() bool {
		spelled, err := h.db.Spelling(id, rel, "")
		if err != nil {
			return false
		}
		_, err = h.db.File(id, spelled)
		return errors.Is(err, metadb.ErrNotFound)
	})
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

// shareUpdate is the PATCH /api/shares/{id} body. A named type rather than an
// anonymous struct so the questions asked of it (is anything set? which fields
// belong to an inbox?) can be methods beside the fields they read,
// instead of three long conjunctions inside the handler.
type shareUpdate struct {
	// Pointer semantics: absent = leave unchanged. "" removes the
	// password; expiresInSeconds 0 removes the expiry.
	Password         *string `json:"password"`
	ExpiresInSeconds *int64  `json:"expiresInSeconds"`
	// ApplyInSeconds > 0 schedules the change(s) instead of applying now.
	ApplyInSeconds int64 `json:"applyInSeconds"`
	// CancelPending: "password" | "expiry" | "all".
	CancelPending string `json:"cancelPending"`
	// Name: absent = unchanged. Unlike Password, "" is NOT "remove": a
	// share has to have a name, so an empty one is a 400.
	Name *string `json:"name"`
	// Entry: absent = unchanged, "" = back to the file listing, a relpath
	// = the page /share opens. Not checked against the file list, which may
	// legitimately be empty when this is set: /share resolves it at serve time.
	Entry *string `json:"entry"`
	// Closed/Note mutate an inbox (refused on ordinary shares):
	// closed stops the /receive page accepting uploads, note is its message.
	Closed *bool   `json:"closed"`
	Note   *string `json:"note"`
	// Notify/SeenAt are inbox fields like Closed and Note.
	Notify *bool      `json:"notify"`
	SeenAt *time.Time `json:"seenAt"`
	// MaxBytes/MaxFiles set an inbox's own caps: absent = unchanged, 0 = no
	// cap of its own, negative = refused. A file cap above the server's bound
	// is stored as the bound. Lowering a cap below what the inbox holds
	// deletes nothing; the inbox reads full.
	MaxBytes *int64 `json:"maxBytes"`
	MaxFiles *int   `json:"maxFiles"`
	// Sources replaces the share's sources, validated exactly like create.
	// Refused on an inbox. An empty list is a share with no sources.
	Sources *[]string `json:"sources"`
	// Linked edits what each named source SHOWS of what its walk finds,
	// applied per source and merged with what the share holds: a client that
	// knows one source's change need not know the others'. Applied after
	// Sources, so a source added in the same request can be fixed in it.
	// Refused on an inbox, like Sources.
	Linked map[string]linkedSourceEdit `json:"linked"`
	// Media turns the share into a GALLERY, or back into a file listing.
	// Asymmetric on purpose: false is always allowed, because a listing
	// renders anything, while true is gated on every file that would be
	// TILED being one a browser plays (see galleryRefusal).
	Media *bool `json:"media"`
	// Listing makes a one-file share open its file listing rather than
	// the file. Symmetric, unlike Media: a listing renders anything, so
	// both directions are always allowed.
	Listing *bool `json:"listing"`
	// Pinned pins the share to the top of the owner's list, or unpins it.
	// Pinning an already pinned share keeps its pin time. Refused on an
	// inbox, and never moves modifiedAt: the order of the owner's own list
	// is not a change to the share.
	Pinned *bool `json:"pinned"`
	// LinksOff turns the share's public links off (true) or back on (false).
	// Refused on an inbox, whose content is never served, and never moves
	// modifiedAt: the content did not change.
	LinksOff *bool `json:"linksOff,omitempty"`
	// pinAt is the pin time a new pin takes, set by a batch so every share
	// it pins shares one time and keeps its place among the others; zero
	// takes the edit's own time.
	pinAt time.Time
}

// linkedSourceEdit is one source's instruction under shareUpdate.Linked.
// Fixed true snapshots the source now (the server walks it and records what
// it found), false returns it to live, absent leaves that alone. Hide takes
// relpaths (source-relative) out of what the source shows; Show is the undo.
type linkedSourceEdit struct {
	Fixed *bool    `json:"fixed"`
	Hide  []string `json:"hide"`
	Show  []string `json:"show"`
}

func (e linkedSourceEdit) edit(source string) metadb.FilterEdit {
	out := metadb.FilterEdit{Source: source, Hide: relPaths(e.Hide), Show: relPaths(e.Show)}
	if e.Fixed != nil {
		out.SetFixed, out.Fixed = true, *e.Fixed
	}
	return out
}

// any reports whether the request asks for anything at all. Every field is a
// pointer or a zero-meaning-absent scalar, so "nothing to change" is a real
// state a client can send by accident.
func (u shareUpdate) any() bool {
	return u.Password != nil || u.ExpiresInSeconds != nil || u.CancelPending != "" ||
		u.Name != nil || u.Entry != nil || u.Closed != nil || u.Note != nil ||
		u.Notify != nil || u.SeenAt != nil || u.Media != nil || u.Listing != nil ||
		u.Sources != nil || len(u.Linked) > 0 || u.Pinned != nil ||
		u.MaxBytes != nil || u.MaxFiles != nil || u.LinksOff != nil
}

// inboxOnly reports whether the request touches a field that exists only on
// an inbox.
func (u shareUpdate) inboxOnly() bool {
	return u.Closed != nil || u.Note != nil || u.Notify != nil || u.SeenAt != nil ||
		u.MaxBytes != nil || u.MaxFiles != nil
}

// publishOnly reports whether the request touches a field that only a
// PUBLISHED share has. An inbox's content is never served, so none of
// these can apply to one.
func (u shareUpdate) publishOnly() bool {
	return u.Entry != nil || u.Media != nil || u.Listing != nil ||
		u.ExpiresInSeconds != nil || u.ApplyInSeconds > 0 || u.Pinned != nil ||
		u.LinksOff != nil
}

// options turns the request into the row edit, plus the changes it asks to
// be applied later.
//
// A name ALWAYS applies immediately, even beside a scheduled password or
// expiry change: scheduling exists because an access decision has a "let it
// lapse later" story, and a name has none. The same goes for what the link
// opens. Only the password and the expiry are schedulable, which is why they
// are the only two read under ApplyInSeconds == 0 here and answered as
// scheduled changes when it is not.
func (u shareUpdate) options(name, passwordHash string,
	now time.Time) (metadb.UpdateOptions, []metadb.Scheduled) {
	var o metadb.UpdateOptions
	if u.Name != nil {
		o.SetName, o.Name = true, name
	}
	if u.Entry != nil {
		o.SetEntry, o.Entry = true, *u.Entry
	}
	if u.Media != nil {
		o.SetMedia, o.Media = true, *u.Media
	}
	if u.Listing != nil {
		o.SetListing, o.Listing = true, *u.Listing
	}
	if u.Closed != nil {
		o.SetClosed, o.Closed = true, *u.Closed
	}
	if u.Note != nil {
		o.SetNote, o.Note = true, strings.TrimSpace(*u.Note)
	}
	if u.Notify != nil {
		o.SetNotify, o.Notify = true, *u.Notify
	}
	if u.SeenAt != nil {
		o.SeenAt = u.SeenAt
	}
	if u.MaxBytes != nil {
		o.SetMaxBytes, o.MaxBytes = true, *u.MaxBytes
	}
	if u.MaxFiles != nil {
		o.SetMaxFiles, o.MaxFiles = true, min(*u.MaxFiles, metadb.InboxMaxFiles)
	}
	if u.Pinned != nil {
		o.SetPinned, o.Pinned, o.PinnedAt = true, *u.Pinned, u.pinAt
	}
	if u.LinksOff != nil {
		o.SetLinksOff, o.LinksOff = true, *u.LinksOff
	}
	if u.ApplyInSeconds <= 0 {
		if u.Password != nil {
			o.SetPassword, o.PasswordHash = true, passwordHash
		}
		if u.ExpiresInSeconds != nil {
			o.SetExpiry, o.ExpiresAt = true, expiryAt(now, *u.ExpiresInSeconds)
		}
		return o, nil
	}
	applyAt := afterSeconds(now, u.ApplyInSeconds)
	var actions []metadb.Scheduled
	if u.Password != nil {
		actions = append(actions, metadb.Scheduled{Kind: metadb.ScheduledPassword,
			ApplyAt: applyAt, Clear: *u.Password == "", PasswordHash: passwordHash})
	}
	if u.ExpiresInSeconds != nil {
		actions = append(actions, metadb.Scheduled{Kind: metadb.ScheduledExpiry, ApplyAt: applyAt,
			Clear: *u.ExpiresInSeconds == 0, ExpiresAt: expiryAt(applyAt, *u.ExpiresInSeconds)})
	}
	return o, actions
}

// updateShare edits an existing share's password/expiry, immediately or
// scheduled via applyInSeconds (the server applies it later; the client can
// be offline). Editing an already-expired-but-unswept share is allowed and
// can rescue it by setting a new expiry.
func (h *handler) updateShare(w http.ResponseWriter, r *http.Request) {
	v, caller, ok := h.ownedShare(w, r)
	if !ok {
		return
	}
	var req shareUpdate
	if !decodeJSONBody(w, r, 1<<20, &req) {
		return
	}
	var hash string
	if req.Password != nil {
		if hash, ok = hashPassword(w, *req.Password); !ok {
			return
		}
	}
	edited, err := h.applyEdit(v, caller, req, hash)
	if err != nil {
		writeRefusal(w, err)
		return
	}
	// The full resolved row, not the bare DTO: clients persist this response
	// into their replicas as a whole-row overwrite, so a missing hasPoster or
	// incoming here would erase state the listing had already delivered.
	writeJSON(w, http.StatusOK, h.resolvedRow(edited))
}
