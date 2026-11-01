package api

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"hyperdrop/server/internal/linked"
	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/mimetype"
	"hyperdrop/server/internal/sharefs"
)

// fileLookup finds one file of a share that passed a public gate, at the cost
// of the file asked about rather than of the share. A stored share's files are
// rows, so a lookup is one indexed read and its view never carries the file
// list. A linked or live share's files exist only in its composed view (the
// walk of its sources, the relay's manifest), so a lookup searches that view.
type fileLookup struct {
	v  shareView
	db *metadb.DB // set when the share's files are rows
}

// lookupFor answers the lookup for v, the row-only view a gate read
// (viewMeta). A linked share is composed first: its entries exist nowhere
// but the walk, which is also what says whether any source can be read at
// all, so the view the lookup answers carries SourceMissing. err means the
// share could not be read again.
func (h *handler) lookupFor(v shareView) (fileLookup, error) {
	switch {
	case v.LiveShare:
		return fileLookup{v: v}, nil
	case v.Linked():
		full, err := h.publicView(v.ID)
		return fileLookup{v: full}, err
	}
	return fileLookup{v: v, db: h.db}, nil
}

// bySlug maps a public URL slug to its file entry. Public links carry only
// the slug (UUIDv4), never the original filename; the name comes back via
// Content-Disposition when the file is served. The empty slug names nothing.
func (l fileLookup) bySlug(slug string) (fileView, bool) {
	if l.db == nil {
		return l.v.FileBySlug(slug)
	}
	if slug == "" {
		return fileView{}, false
	}
	f, err := l.db.ResolveSlug(l.v.ID, slug)
	return fileView{File: f}, err == nil
}

// byPath finds an entry by its relative path, refusing what fileByPath
// refuses (metadb.File applies the same ValidRelPath).
func (l fileLookup) byPath(rel string) (fileView, bool) {
	if l.db == nil {
		return fileByPath(l.v, rel)
	}
	f, err := l.db.File(l.v.ID, rel)
	return fileView{File: f}, err == nil
}

// anyPending reports whether a file of the share is still uploading. A stored
// share answers from its counters: files counts every row and committed the
// landed ones, both kept by the files triggers in the statement that writes
// the row.
func (l fileLookup) anyPending() bool {
	if l.db == nil {
		return l.v.AnyPending()
	}
	return l.v.FileCount > l.v.Committed
}

// whole is the share with every file it holds, for an answer about the whole
// share rather than one file of it: an unfurler's card, whose picture says
// whether the share holds a video anywhere. A lookup answering from rows reads
// them all here; the others already hold them.
func (l fileLookup) whole() shareView {
	if l.db == nil {
		return l.v
	}
	if d, err := l.db.Share(l.v.ID); err == nil {
		return viewOf(d)
	}
	return l.v
}

// resolution is what a route's resolver made of the request path: a file, a
// redirect to a different one, or nothing.
type resolution struct {
	file     fileView
	ok       bool
	redirect string
	// waitForAll gates a web page file on the complete share. An index.html
	// that landed first must not open a broken site while its assets are still
	// uploading.
	waitForAll bool
}

// fileRoute describes how one public payload route addresses a file and what
// it may serve. Everything AFTER resolution is shared between /view,
// /download and /site, deliberately: a file addressed by relpath has to be
// indistinguishable from the same file addressed by slug, down to the sandbox
// header and the ETag. The one difference is the icon link a page may be
// given, which names the icon by the route's own address.
type fileRoute struct {
	// inline serves the bytes for the browser to render rather than save.
	inline bool
	// allowBearer lets the share's owner past the password gate with a
	// token. The DOWNLOAD route only.
	allowBearer bool
	// noEmbed applies the owner's no-embed setting (applyNoEmbed): every
	// payload route.
	noEmbed bool
	// siteExempt lifts noEmbed for a share that opens as a page (a set
	// Entry): /site. A site's own pages run in the sandbox's opaque origin,
	// so every asset they load arrives as a cross-site embed,
	// indistinguishable from another site's. Any other share's file keeps
	// the setting on /site exactly as on /view, or a path would be the way
	// around it.
	siteExempt bool
	// gate, when set, decides a protected share's access in place of the
	// cookie gate below. /site takes it (siteGate): page addresses stay
	// copyable, and a sandboxed page's subresource requests prove access
	// with the grant in their address. It answers proven when the request
	// already holds that proof, and done when it wrote the response itself.
	// Proven covers non-page files only (grantServes): serveFile sends a
	// page, and the whole-share waiting page, through the cookie gate
	// regardless.
	gate    func(w http.ResponseWriter, r *http.Request, v shareView) (proven, done bool)
	resolve func(*http.Request, fileLookup) resolution
	// iconAddr addresses a share's icon file through this route, for the
	// link a page that names no icon of its own is given (pageicon.go).
	// Unset on a route that serves no page.
	iconAddr func(v shareView, icon fileView) string
}

// slugResolve addresses a file by its public slug: /view and /download.
func slugResolve(r *http.Request, files fileLookup) resolution {
	f, ok := files.bySlug(r.PathValue("path"))
	return resolution{file: f, ok: ok}
}

// openEntry opens one file's bytes: a stored file through the share's root,
// a linked entry through its source's root. It answers the entry the bytes
// belong to, which for a stored file is its row read again beside the open
// (openStored): serve that, never the f a lookup resolved earlier.
func (h *handler) openEntry(v shareView, f fileView) (io.ReadSeekCloser, os.FileInfo, fileView, error) {
	o := h.entryOpener(v)
	defer o.Close()
	return o.open(f)
}

// openStored reads a stored file's row and opens its bytes under the share's
// swap lock held shared, so a publish's commit, which writes its rows and
// renames its bytes under that lock held exclusively, lands wholly before
// or wholly after the pair: the type, hash and size answered always name the
// bytes opened. The lock covers the read and the open only; the descriptor
// keeps the bytes it opened through a later rename, so the transfer runs
// unlocked. A row that is gone or still pending opens nothing, and neither
// do bytes whose size is not the row's: a row is never served over bytes
// it does not name (a rename that failed left the file it was to replace).
// slug is the one the caller resolved: a row at rel under another slug is
// another file that has taken the path since, and opens nothing either. A
// replace, a publish's included, keeps the slug and opens.
func (h *handler) openStored(id, rel, slug string) (*os.File, os.FileInfo, fileView, error) {
	var (
		file *os.File
		fi   os.FileInfo
		row  metadb.File
	)
	err := h.fs.ReadSwapped(id, func() error {
		var err error
		if row, err = h.db.File(id, rel); err != nil {
			return err
		}
		if row.Pending || row.Slug != slug {
			return sharefs.ErrNotFound
		}
		file, fi, err = h.fs.Open(id, row.Path)
		if err == nil && fi.Size() != row.Size {
			file.Close()
			return sharefs.ErrNotFound
		}
		return err
	})
	if err != nil {
		return nil, nil, fileView{}, err
	}
	return file, fi, fileView{File: row}, nil
}

// entryOpener opens many files of one share, for a route that reads more
// than one (a zip): a linked share's specs are read once and each source's
// root opened once, rather than once per entry. The caller closes each file
// it is handed, then the opener.
type entryOpener struct {
	h      *handler
	v      shareView
	linked *linked.Opener // nil until a linked entry is opened
}

func (h *handler) entryOpener(v shareView) *entryOpener {
	return &entryOpener{h: h, v: v}
}

// open opens f's bytes and answers the entry they belong to: a stored
// file's row as openStored read it, a linked entry as f names it.
func (o *entryOpener) open(f fileView) (io.ReadSeekCloser, os.FileInfo, fileView, error) {
	if !f.Linked {
		file, fi, row, err := o.h.openStored(o.v.ID, f.Path, f.Slug)
		if err != nil {
			return nil, nil, fileView{}, err
		}
		return file, fi, row, nil
	}
	if o.linked == nil {
		specs, err := o.h.dbSpecs(o.v.Share)
		if err != nil {
			return nil, nil, fileView{}, err
		}
		o.linked = linked.NewOpener(o.h.roots, specs, o.v.Prefixed())
	}
	file, fi, err := o.linked.Open(f.Path)
	if err != nil {
		return nil, nil, fileView{}, err
	}
	return file, fi, f, nil
}

// Close closes the source roots the opener opened. A file it handed out
// stays readable: it holds its own descriptor.
func (o *entryOpener) Close() {
	if o.linked != nil {
		o.linked.Close()
	}
}

// serveFile resolves the request path against the share metadata, then
// streams the file from disk (with Range support). View (inline=true) lets
// the browser render what it can; types a browser can't render are served as
// attachment outright: clients don't offer View links for them, but stale or
// hand-built /view URLs still degrade into a clean download.
//
// The gate reads the share's row alone (viewMeta): existence, expiry, the
// owner, the kind and the password are all columns, so a refused request
// costs no file list and no source walk. What the admitted request then
// asks of the files goes through fileLookup, bounded by the one file it
// names.
func (h *handler) serveFile(w http.ResponseWriter, r *http.Request, rt fileRoute) {
	noIndex(w)
	inline := rt.inline
	v, ok := h.visibleShareAnyVia(r, h.viewMeta)
	if !ok {
		http.NotFound(w, r)
		return
	}
	noEmbed := rt.noEmbed && v.ownerNoEmbed && !(rt.siteExempt && v.Entry != "")
	ownerFetch := h.bearerOwnsOnce(r, v)
	if rt.allowBearer {
		// A download ticket (the web client's single-use stand-in for a
		// bearer on this origin) opens exactly what the owner's bearer does.
		bearer := ownerFetch
		var done, owns bool
		ownerFetch = func() bool {
			if !done {
				owns, done = bearer() || h.ticketOwns(r, v), true
			}
			return owns
		}
	}
	// An inbox is invisible on every public read. The ONE exception
	// is its owner's own bearer fetch on the download route (Quick Look,
	// `hyperdrop fetch`): that read is authenticated, not public, and without
	// it the owner could receive files they can never open.
	if v.Inbox && !(rt.allowBearer && ownerFetch()) {
		http.NotFound(w, r)
		return
	}
	proven := false
	if rt.gate != nil {
		var done bool
		if proven, done = rt.gate(w, r, v); done {
			return
		}
	}
	// The owner's own client may fetch through the password gate on the
	// DOWNLOAD route only (`hyperdrop fetch`, the Finder mount): no cookie is
	// minted, /view stays exactly as public as it was, and an uploaded sandboxed
	// page cannot ride this, since it never holds a token.
	if !proven && !(rt.allowBearer && v.PasswordHash != "" && ownerFetch()) {
		// A refused ticket is the owner's download, not a visitor's, so it
		// gets the ticket's refusal rather than the password form; a share
		// access cookie still opens the file.
		if rt.allowBearer && v.PasswordHash != "" && hasTicket(r) && !h.validAccess(r, v.ID, v.PasswordGen) {
			http.NotFound(w, r)
			return
		}
		if v, ok = h.enforceAccess(w, r, v); !ok {
			return
		}
	}
	files, err := h.lookupFor(v)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	v = files.v
	if v.SourceMissing {
		// The owner's own client gets an ERROR, never the page: a bearer
		// fetch saves what it is handed, so an HTML page answered with 200
		// would land on their disk under the file's own name.
		if rt.allowBearer && ownerFetch() {
			writeErrorCode(w, http.StatusNotFound, "source-missing", "the folder behind this share is not available")
			return
		}
		h.renderUnavailable(w, r, v)
		return
	}
	res := rt.resolve(r, files)
	// A gate's proof (a /site grant) opens assets, never a page. The file's
	// own type decides, not the request's Sec-Fetch-Dest, which any client
	// can write: a page, or the waiting page standing in for the whole
	// share, goes through the cookie gate like any other request.
	if proven && (res.waitForAll || res.ok && !grantServes(res.file.MimeOrGuess())) {
		if _, ok := h.enforceAccess(w, r, v); !ok {
			return
		}
	}
	if res.waitForAll {
		h.renderWaiting(w, v, nil, true)
		return
	}
	if res.redirect != "" {
		http.Redirect(w, r, res.redirect, http.StatusMovedPermanently)
		return
	}
	if !res.ok {
		http.NotFound(w, r)
		return
	}
	f := res.file
	// A link unfurler gets a metadata card instead of the bytes: it wants a
	// preview, not the file. Ahead of the pending branch so early links
	// preview from the moment they exist, and ahead of applyNoEmbed, which
	// has nothing to guard when no content is served.
	//
	// …unless this IS the card's own video fetch (ogMediaParam): a playable
	// card points og:video at this same URL, and the chat app fetches it with
	// the same bot User-Agent, so without the escape hatch we would answer our
	// own preview with HTML and the video would never play. The parameter
	// grants nothing a human with the link doesn't already have.
	//
	// A live share never honors it, whatever the query string says: fileCard
	// (preview.go) never emits og:video for a live share, so no legitimate
	// fetch of this parameter can exist for one, and letting it through here
	// would be the one way a bot UA could still pull real bytes off the
	// sharer's own uplink and cause a job, the exact thing this whole branch
	// exists to prevent.
	if isUnfurler(r.UserAgent()) && (v.LiveShare || r.URL.Query().Get(ogMediaParam) != "1") {
		h.renderCard(w, h.fileCard(r, files.whole(), f))
		return
	}
	if f.Pending {
		// The mime is an extension guess while pending, good enough to
		// predict whether the finished reload shows the file or downloads it.
		h.renderWaiting(w, v, &f, inline && mimetype.Viewable(f.MimeOrGuess()))
		return
	}
	if noEmbed && !h.applyNoEmbed(w, r, v.ID) {
		return
	}
	if inline && !mimetype.Viewable(f.Mime) {
		inline = false
	}
	privateIfProtected(w, v)
	// Bytes are about to move for this share: count the request while it runs,
	// so its owner can be told someone is pulling it right now. Counted here
	// rather than at the top of the route, because a refusal, a redirect and
	// the waiting page are not downloads, and the owner's own fetch is not a
	// stranger pulling their share.
	if !ownerFetch() {
		defer h.dl.begin(v.ID, v.Owner)()
		// A live share whose sharer is offline answers 503 below, which is a
		// refusal rather than a read.
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
	var icon func() string
	if rt.iconAddr != nil {
		icon = func() string {
			ic, ok := pageIcon(files, f.Path)
			if !ok {
				return ""
			}
			return rt.iconAddr(v, ic) + "?v=" + iconVersion(ic)
		}
	}
	var admit func(fileView) bool
	if proven && grantServes(f.MimeOrGuess()) {
		admit = func(opened fileView) bool {
			if grantServes(opened.MimeOrGuess()) {
				return true
			}
			_, ok := h.enforceAccess(w, r, v)
			return ok
		}
	}
	h.serveStoredFile(w, r, v, f, inline, icon, admit)
}

// embedDests are the Sec-Fetch-Dest values of subresource loads: the ways a
// third-party page pulls a file INTO itself, as opposed to navigating to it.
var embedDests = map[string]bool{"image": true, "video": true, "audio": true,
	"iframe": true, "embed": true, "object": true}

// applyNoEmbed enforces the owner's no-embed setting on a file response:
// Cross-Origin-Resource-Policy makes compliant browsers refuse the bytes as
// another origin's subresource, and an explicitly cross-site embed fetch is
// redirected to the share page instead of served. Direct opens (navigations,
// same-origin previews, curl) are untouched. Returns false when it wrote the
// redirect.
//
// The policy is same-origin except for this server's own pages: the gallery
// renders on the app origin and points every picture at the file origin, so
// a load it makes is answered same-site. Same-site alone would also admit
// every other server under the same registrable domain (each free name is a
// sibling under hyperdrop.link), so the Referer has to name the app origin,
// and a page that suppresses its Referer gets same-origin. The answer
// depends on those request headers, so it varies by them.
func (h *handler) applyNoEmbed(w http.ResponseWriter, r *http.Request, shareID string) bool {
	w.Header().Add("Vary", "Referer, Sec-Fetch-Site, Sec-Fetch-Dest")
	corp := "same-origin"
	if h.embeddedByOwnPage(r) {
		corp = "same-site"
	}
	w.Header().Set("Cross-Origin-Resource-Policy", corp)
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" && embedDests[r.Header.Get("Sec-Fetch-Dest")] {
		http.Redirect(w, r, "/share/"+shareID, http.StatusFound)
		return false
	}
	return true
}

// embeddedByOwnPage reports whether a request is a same-site load whose
// Referer is a page on this server's app origin.
func (h *handler) embeddedByOwnPage(r *http.Request) bool {
	o := h.origins()
	if !o.Split() || r.Header.Get("Sec-Fetch-Site") != "same-site" {
		return false
	}
	ref, err := url.Parse(r.Referer())
	return err == nil && ref.Scheme == "https" && strings.EqualFold(ref.Hostname(), o.App)
}

// bearerOwns reports whether the request carries a bearer token for the
// share's owner: the authenticated client fetching its own bytes (the
// Finder mount, Quick Look, a drag out of the app's own list, `hyperdrop
// fetch`). A missing or invalid token is simply "no": the request then walks
// the ordinary anonymous path.
//
// The owner's own reads are not counted as downloads or visits, or a client
// warns an owner about themselves the moment they go to delete what they
// just previewed. Any other bearer counts like an anonymous visitor: the
// question the count answers is "is anyone pulling this right now", and no
// token but the owner's is the owner. An admin's token unlocks no other
// account's protected share, so it reaches only what any visitor reaches.
// A web session is never an owner here: its value is no bearer token
// (UserByToken never matches it), and these routes read no session cookie,
// since the web client reads no bytes with one. A bearer that owes a second
// factor (twoFactorRestricted) is no owner either, so it reaches only what
// any visitor reaches, as on every route h.auth refuses it.
func (h *handler) bearerOwns(r *http.Request, v shareView) bool {
	tok := bearerToken(r)
	if tok == "" {
		return false
	}
	u, err := h.db.UserByToken(tok, metadb.ClientInfo{})
	if err != nil || u.Username != v.Owner {
		return false
	}
	return !h.twoFactorRestricted(u, tokenNamed(u, metadb.TokenHash(tok)))
}

// bearerOwnsOnce is bearerOwns resolved lazily and at most once, for a
// handler that asks the question from several branches.
func (h *handler) bearerOwnsOnce(r *http.Request, v shareView) func() bool {
	var done, owns bool
	return func() bool {
		if !done {
			owns, done = h.bearerOwns(r, v), true
		}
		return owns
	}
}

func (h *handler) viewFile(w http.ResponseWriter, r *http.Request) {
	h.serveFile(w, r, fileRoute{inline: true, noEmbed: true, resolve: slugResolve,
		iconAddr: func(v shareView, icon fileView) string { return "/view/" + v.ID + "/" + icon.Slug }})
}

func (h *handler) downloadFile(w http.ResponseWriter, r *http.Request) {
	h.serveFile(w, r, fileRoute{allowBearer: true, noEmbed: true, resolve: slugResolve})
}
