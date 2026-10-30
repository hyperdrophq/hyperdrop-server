package api

import (
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"golang.org/x/text/unicode/norm"

	"hyperdrop/server/internal/shareid"
)

// A public file link is /view/{id}/{slug}, and a slug is a UUIDv4. So a
// browser showing an uploaded index.html resolves href="style.css" to
// /view/{id}/style.css, which names nothing: every relative reference in a
// shared page is dead, and a folder of HTML renders unstyled with its
// internal links broken.
//
// /site/{id}/{relpath} is the second way to address the same bytes. It
// changes which URL resolves and nothing else: the sandbox, the origin split,
// the access gate and the byte-serving path are all the ones /view already
// uses, so a file reached this way is indistinguishable from the same file
// reached by slug.
//
// It is NOT gated on Share.Entry. That value decides what /share opens; this
// route has to answer for any share, because it cannot know which of a
// share's files a visitor will click View on. The cost is that a share's
// filenames are routable once its ID is known, which gives away nothing:
// /share already lists every filename in plain text to anyone holding the
// link.

// indexName is the file a directory request resolves to. The comparison is
// exact and case-sensitive, so Index.html is not an index: the server stores
// on Linux and serves back what it was sent.
const indexName = "index.html"

// siteCtx is one /site request after the gate: the relative path to
// resolve and the address prefix every redirect keeps, "/site/{id}/" or
// "/site/{id}/{grant}/". A redirect that dropped the grant would send a
// protected page's relative references to addresses the gate refuses.
type siteCtx struct {
	rel  string
	base string
}

// siteResolve addresses a file by its relative path, with directory requests
// resolving to their index.
func siteResolve(files fileLookup, sc siteCtx) resolution {
	waitForAll := files.v.Entry != "" && files.anyPending()
	for _, rel := range siteSpellings(sc.rel) {
		if res, ok := siteFind(files, sc.base, rel, waitForAll); ok {
			return res
		}
	}
	return siteRescue(files, sc.base, sc.rel, waitForAll)
}

// siteSpellings is rel as the request spelled it, then composed (NFC), then
// decomposed (NFD), each spelling once. Every relpath the server records is
// NFC (relPath), a linked entry keeps the server filesystem's bytes, which a
// folder copied from a Mac often holds decomposed, and a browser sends
// whatever the page's author typed: two spellings of café.css would
// otherwise be two different files to this lookup.
func siteSpellings(rel string) []string {
	out := []string{rel}
	for _, s := range []string{norm.NFC.String(rel), norm.NFD.String(rel)} {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// siteFind looks rel up spelled exactly as given: a directory request (the
// share root, or any path ending in a slash) serves its index, a file is
// served, and a directory that holds an index is redirected to its
// trailing-slash form rather than served here: without the slash, a
// relative href inside that page resolves against its PARENT, so every
// asset would be looked up one directory too high.
func siteFind(files fileLookup, base, rel string, waitForAll bool) (resolution, bool) {
	if rel == "" || strings.HasSuffix(rel, "/") {
		if f, ok := files.byPath(rel + indexName); ok {
			return resolution{file: f, ok: true, waitForAll: waitForAll}, true
		}
		return resolution{}, false
	}
	if f, ok := files.byPath(rel); ok {
		return resolution{file: f, ok: true, waitForAll: waitForAll}, true
	}
	if _, ok := files.byPath(rel + "/" + indexName); ok {
		return resolution{redirect: siteAddr(base, rel+"/"), waitForAll: waitForAll}, true
	}
	return resolution{}, false
}

// siteRescue answers an address whose percent-encoding was applied twice.
// Chrome keeps a space and any reserved character a page pre-encoded (an href
// built with encodeURIComponent writes $ as %24) encoded in the address bar
// while it shows Unicode decoded; pasting that mixed address into a chat
// client encodes the % again, so %24 arrives as %2524 and the one decoding the
// server does leaves a name no share holds.
//
// It runs only after the exact lookup above has failed, so a file whose NAME
// contains a literal %XX always wins, and it decodes exactly ONCE: a third
// layer is not rescued. A rescued request is never served in place. It
// redirects to the canonical address (a directory to its trailing-slash form),
// so the visitor's address bar, and every relative href resolved against it,
// hold the address the share's own links use.
func siteRescue(files fileLookup, base, rel string, waitForAll bool) resolution {
	if !hasPercentEscape(rel) {
		return resolution{}
	}
	dec, err := url.PathUnescape(rel)
	if err != nil || dec == rel {
		return resolution{}
	}
	for _, s := range siteSpellings(dec) {
		res, ok := siteFind(files, base, s, waitForAll)
		if !ok {
			continue
		}
		if res.redirect == "" {
			res = resolution{redirect: siteAddr(base, s), waitForAll: waitForAll}
		}
		return res
	}
	return resolution{}
}

// hasPercentEscape reports whether the path still holds a % followed by two
// hex digits, which is the only shape a second decoding can change.
func hasPercentEscape(rel string) bool {
	for i := 0; i+2 < len(rel); i++ {
		if rel[i] == '%' && isHexDigit(rel[i+1]) && isHexDigit(rel[i+2]) {
			return true
		}
	}
	return false
}

func isHexDigit(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// fileByPath finds a committed-or-pending entry by its stored relative path.
// Matching against the stored list IS the traversal defence: a path the share
// does not contain cannot be served however it was spelled, so "../etc/passwd"
// simply fails to match. ValidRelPath is kept anyway so a planted file name
// cannot introduce a path the rest of the server would refuse.
func fileByPath(v shareView, rel string) (fileView, bool) {
	if !shareid.ValidRelPath(rel) {
		return fileView{}, false
	}
	return v.FileByPath(rel)
}

// sitePath builds a /site URL path, escaping each segment: rel arrives
// decoded and may hold spaces, #, ? or non-ASCII.
func sitePath(id, rel string) string {
	return siteAddr(siteBase(id, ""), rel)
}

// siteBase is the prefix a share's /site addresses share: with a grant once
// the visitor of a protected share has proven access, so every relative
// reference inside a page resolves to a granted address, and bare
// otherwise.
func siteBase(id, grant string) string {
	if grant == "" {
		return "/site/" + id + "/"
	}
	return "/site/" + id + "/" + grant + "/"
}

// siteAddr appends a relative path to a site base, escaping it.
func siteAddr(base, rel string) string {
	u := url.URL{Path: base + rel}
	return u.String()
}

// siteRedirect is a /site address with the request's own query kept: a
// static site reads its query string, so the redirect that puts a page
// under a grant must not drop it. `pw` is left behind, spent on the cookie
// this redirect follows.
func siteRedirect(id, grant, rest, rawQuery string) string {
	addr := siteAddr(siteBase(id, grant), rest)
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return addr
	}
	q.Del("pw")
	if len(q) == 0 {
		return addr
	}
	return addr + "?" + q.Encode()
}

// A grant is a proof carried in the address instead of in a cookie:
// "<expUnix>.<hex HMAC>", bound to the share, its password generation and a
// 12 h expiry by signGrant. It has the access cookie's shape but is signed
// over its own message, so a grant presented as the hd_<id> cookie verifies
// as nothing, and a cookie value in the address is not a grant. A protected
// site needs it because
// its pages run in the sandbox's opaque origin, and a subresource request
// from such a page arrives with NEITHER the cookie NOR a Referer to stand
// in for it (measured in Chrome: Sec-Fetch-Site: cross-site, no Cookie
// header, no Referer, under every Referrer-Policy the page can set). The
// grant rides the page's own address, which every relative reference
// inherits, and it is the only proof a stylesheet, script, font or picture
// of a protected site can carry. Changing the password bumps the generation
// and revokes every grant with it, exactly as it revokes every cookie.
//
// What it is NOT is a way into a PAGE, and two locks keep it that way:
//
//   - siteGate admits a grant alone only for a subresource destination
//     (siteGrantDest), so a navigation to a copied address goes through the
//     cookie gate and asks the next visitor for the password.
//   - The header is the client's to write, so the FILE decides as well:
//     serveFile sends every page-rendering file (grantServes) back through
//     the cookie gate when the grant was the only proof, whatever
//     Sec-Fetch-Dest the request claimed.
//
// So a granted address pasted elsewhere, or replayed with a forged header,
// reaches the share's non-page files by path until it expires, and never a
// page, the listing, /view, /download or /zip.

// splitGrant separates a leading grant segment from the rest of a /site
// path. Recognition is by shape alone; whether it VERIFIES is the gate's
// question. A share file whose top-level folder is spelled like a grant is
// not addressable through /site, which nothing real is named.
func splitGrant(path string) (grant, rest string) {
	seg, tail, found := strings.Cut(path, "/")
	if !isGrantShaped(seg) {
		return "", path
	}
	if !found {
		return seg, ""
	}
	return seg, tail
}

// isGrantShaped reports whether seg is "<digits>.<64 hex>", the shape
// signGrant emits.
func isGrantShaped(seg string) bool {
	dot := strings.IndexByte(seg, '.')
	if dot < 1 || len(seg)-dot-1 != 64 {
		return false
	}
	for _, c := range seg[:dot] {
		if c < '0' || c > '9' {
			return false
		}
	}
	for i := dot + 1; i < len(seg); i++ {
		if !isHexDigit(seg[i]) || seg[i] >= 'A' && seg[i] <= 'F' {
			return false
		}
	}
	return true
}

// grantTTL is how long a site grant verifies. It is shorter than either
// access cookie's lifetime because an address leaks more easily than a
// cookie, and a page mints fresh grants each time it loads.
const grantTTL = 12 * time.Hour

// grantFor mints a fresh grant for a protected share, or "" for an open
// one, whose site addresses carry none.
func (h *handler) grantFor(v shareView) string {
	if v.PasswordHash == "" {
		return ""
	}
	return h.signGrant(v.ID, v.PasswordGen, time.Now().Add(grantTTL))
}

// grantServes reports whether a file may be served on a grant alone: any
// file a browser would not turn into a document. HTML, XHTML and the XML
// family (isDocumentType) are pages, and a page of a protected share opens through the
// cookie gate only. SVG is a document type too (it is sandboxed like one),
// but a site loads it as a picture through <img>, so it is served as the
// asset it is; a navigation to it arrives as a document and never reaches
// the grant.
func grantServes(mimeType string) bool {
	mt, _, err := mime.ParseMediaType(mimeType)
	if err != nil {
		return false
	}
	return !isDocumentType(mt) || mt == "image/svg+xml"
}

// siteGate is /site's password gate, in place of the cookie gate serveFile
// applies to the slug routes. It answers with the request's site context,
// whether access is already proven (a verified grant), and whether it wrote
// the response itself.
//
//   - An open share resolves the path as given. A grant-shaped segment on it
//     is a stale address from before the password was removed, redirected to
//     the plain form of the same page.
//   - A protected share's SUBRESOURCES (stylesheet, script, font, picture,
//     media) are proven by a verified grant in the path, which is the only
//     proof they can carry: the page asking for them is sandboxed into an
//     opaque origin, whose requests bring no cookie and no Referer. That
//     proof covers non-page files only: serveFile sends a file that fails
//     grantServes back through enforceAccess.
//   - A protected share's PAGE is never opened by a grant alone: a document
//     goes through the cookie gate (enforceAccess: cookie, ?pw=, or the
//     password form), which is what keeps a copied /site address asking the
//     next visitor for the password.
//   - An admitted visitor is served in place when the address already
//     carries a live grant, and redirected to a freshly granted address
//     otherwise, since a page's relative references resolve against its own
//     address and that is where their proof has to be.
func (h *handler) siteGate(w http.ResponseWriter, r *http.Request, v shareView) (sc siteCtx, proven, done bool) {
	grant, rest := splitGrant(r.PathValue("path"))
	if v.PasswordHash == "" {
		if grant != "" {
			http.Redirect(w, r, sitePath(v.ID, rest), http.StatusMovedPermanently)
			return sc, false, true
		}
		return siteCtx{rel: rest, base: siteBase(v.ID, "")}, false, false
	}
	granted := grant != "" && h.grantValid(grant, v.ID, v.PasswordGen)
	if granted && siteGrantDest(r.Header.Get("Sec-Fetch-Dest")) {
		w.Header().Set("Referrer-Policy", "no-referrer")
		return siteCtx{rel: rest, base: siteBase(v.ID, grant)}, true, false
	}
	if _, ok := h.enforceAccess(w, r, v); !ok {
		return sc, false, true
	}
	// Serving the granted address in place is also what stops a redirect
	// loop: a fresh grant differs from a live one only by its expiry, so a
	// gate that always redirected would never stop minting.
	if granted {
		w.Header().Set("Referrer-Policy", "no-referrer")
		return siteCtx{rel: rest, base: siteBase(v.ID, grant)}, false, false
	}
	http.Redirect(w, r, siteRedirect(v.ID, h.grantFor(v), rest, r.URL.RawQuery), http.StatusFound)
	return sc, false, true
}

func siteAssetDest(dest string) bool {
	return dest == "style" || dest == "script" || dest == "font"
}

func siteGrantDest(dest string) bool {
	return siteAssetDest(dest) || openDests[dest]
}

// siteEntry is the /site path /share/{id} opens instead of its listing, or
// "" when this share has no site to open. Two conditions, each for its own
// reason:
//
//   - Entry is set. Empty is every share that never asked for anything else.
//   - It names a file the share actually holds, looked up by its path
//     (publicShare.hasFile) wherever it sorts. The value is stored without
//     being checked against the file list (it is set at creation, when a
//     manifest's files are all still pending), so this is where it is
//     resolved. Pending counts, but the site stays on the whole-share waiting
//     page until every asset is committed.
//
// A password is not a condition: it decides who may open the link, never
// what it opens. The path carries no grant, so it is a copyable address.
func (p *publicShare) siteEntry() (string, error) {
	if p.v.Entry == "" {
		return "", nil
	}
	has, err := p.hasFile(p.v.Entry)
	if err != nil || !has {
		return "", err
	}
	return siteAddr(siteBase(p.v.ID, ""), p.v.Entry), nil
}

// viewURL is a file's View link on the listing page. HTML is addressed by
// RELPATH, because that is the only address a relative href inside it can
// resolve against; everything else keeps the slug, which is the identity a
// content replacement donates. Protected pages use the same copyable
// relpath address as open ones: the access cookie, not a grant in the path,
// is what lets the owner open them.
func viewURL(v shareView, f fileView, grant string) string {
	if isHTML(f.Mime) {
		return siteAddr(siteBase(v.ID, grant), f.Path)
	}
	return "/view/" + v.ID + "/" + f.Slug
}

// downloadURL is a file's Download link: by slug, always, since saving a
// file needs no relative reference to resolve.
func downloadURL(v shareView, f fileView) string {
	return "/download/" + v.ID + "/" + f.Slug
}

// isHTML reports whether this entry is a page whose relative references need
// to resolve. Deliberately narrower than isDocumentType (serve.go): an SVG or
// an XML file is sandboxed for the same reason but is not something a person
// browses between.
func isHTML(mimeType string) bool {
	mt, _, err := mime.ParseMediaType(mimeType)
	if err != nil {
		return false
	}
	return mt == "text/html" || mt == "application/xhtml+xml"
}

// siteFile serves a share's file by relative path. A protected share is
// gated by siteGate rather than by serveFile's cookie gate: page addresses
// stay copyable, and the subresource requests of a sandboxed page prove
// access with the grant in their address, for non-page files only.
//
// A live share's pages come the same way, relayed off the sharer's Mac
// through serveFile's stream twin: the sandbox, the origin split and the
// access cookie are the route's, whatever holds the bytes.
func (h *handler) siteFile(w http.ResponseWriter, r *http.Request) {
	var sc siteCtx
	h.serveFile(w, r, fileRoute{inline: true, noEmbed: true, siteExempt: true,
		gate: func(w http.ResponseWriter, r *http.Request, v shareView) (proven, done bool) {
			sc, proven, done = h.siteGate(w, r, v)
			return proven, done
		},
		resolve:  func(_ *http.Request, files fileLookup) resolution { return siteResolve(files, sc) },
		iconAddr: func(_ shareView, icon fileView) string { return siteAddr(sc.base, icon.Path) },
	})
}

// siteRoot redirects /site/{id} to /site/{id}/. Same reason as the directory
// redirect above: relative references in the index need the trailing slash to
// resolve inside the share rather than beside it.
func (h *handler) siteRoot(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !shareid.ValidID(id) {
		http.NotFound(w, r)
		return
	}
	// The redirect mints the cookie so the page it leads to counts under it;
	// it resolves no share and counts nothing itself.
	h.mintVisitor(w, r)
	http.Redirect(w, r, sitePath(id, ""), http.StatusMovedPermanently)
}
