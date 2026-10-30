package api

import (
	"fmt"
	"io"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"

	"hyperdrop/server/internal/hevctag"
	"hyperdrop/server/internal/mimetype"
)

// serveStoredFile streams from disk with correct MIME + disposition and full
// Range support. The caller has already resolved the entry against the share;
// what is served is the entry openEntry answers with the bytes it opened (a
// stored file's row read again under the share's swap lock), so the type,
// hash and length always describe the same version even when a publish
// commits between the resolve and the open. The entry carries its
// commit-time mime; sniffing is only the fallback for an entry with none.
// The content hash becomes a strong ETag so a Range-resumed download
// can't splice old and new bytes across a content replacement (If-Range).
//
// admit, when set, is asked about the opened entry before anything is
// written, and answers false when it wrote the response itself: a /site
// grant proves access for the type the request was resolved as, and an
// entry that became a page meanwhile goes through the cookie gate.
//
// A linked entry opens through its source's root rather than the share's
// (openEntry), which is the only difference between serving a folder the
// server already held and serving uploaded bytes.
//
// Every answer is revalidated (Cache-Control: no-cache): a browser may keep
// the bytes but asks again before reusing them, so a password added or an
// expiry reached after the first fetch meets the gate, and a conditional
// request still costs a 304 without a body. A protected share's answer is
// also private. An HTML page is revalidated for one more reason: what it is
// sent as depends on the share's icon as well as its own bytes. icon, when set, answers the address of the share's icon
// for that page, or "" for none; a page that declares no icon of its own is
// sent with a link to it (pageicon.go). Such a rewritten page is its own
// representation: its own length, an entity tag naming the link, no
// Last-Modified (the page's date cannot see the icon change), and Range
// answered from the rewritten bytes.
func (h *handler) serveStoredFile(w http.ResponseWriter, r *http.Request, v shareView, f fileView, inline bool, icon func() string, admit func(fileView) bool) {
	rs, fi, f, err := h.openEntry(v, f)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer rs.Close()
	if admit != nil && !admit(f) {
		return
	}
	name := path.Base(f.Path)
	mimeType, sha256 := f.Mime, f.SHA256
	switch {
	case mimeType == "":
		mimeType = mimetype.Detect(rs, name)
	case f.Linked:
		// A linked entry's type is its name's, never sniffed by the walk;
		// the bytes are open here, so an XML or JSON name over binary
		// content is caught before it is served inline as one.
		mimeType = mimetype.Confirm(rs, mimeType)
	}
	// The viewable verdict the caller made is the resolved entry's; the
	// opened one's type decides too.
	inline = inline && mimetype.Viewable(mimeType)
	sandboxDocument(w, mimeType)
	// An `hev1` HEVC movie is rewritten to `hvc1` on the way out of the
	// INLINE route, which is the one a browser plays: the same bitstream
	// under the name every decoder accepts (server/internal/hevctag).
	// /download is deliberately left alone, so what a visitor SAVES is the
	// file the owner put there, byte for byte.
	var body io.ReadSeeker = rs
	retagged := false
	if inline && hevctag.Applies(name) {
		if offs := h.hevcOffsets(v, f.Path, sha256, fi, rs); len(offs) > 0 {
			body, retagged = hevctag.Reader(rs, offs), true
		}
	}
	modTime := fi.ModTime()
	iconLink := ""
	revalidate(w)
	if inline && isHTML(mimeType) {
		if icon != nil && rewritablePage(mimeType) {
			if href := icon(); href != "" {
				if page, link, ok := withPageIcon(rs, fi.Size(), href); ok {
					body, iconLink, modTime = page, link, time.Time{}
				}
			}
		}
	}
	negotiable := canNegotiateFile(r, mimeType, inline)
	enc := ""
	if negotiable {
		enc = negotiateEncoding(r.Header.Get("Accept-Encoding"))
	}
	if iconLink != "" && sha256 == "" {
		// A linked page has no content hash; its size and date name the
		// bytes the link is spliced into.
		sha256 = fmt.Sprintf("%x-%x", fi.Size(), fi.ModTime().UnixNano())
	}
	if sha256 != "" {
		tag := sha256
		if iconLink != "" {
			tag += iconLinkTag(iconLink)
		}
		if retagged {
			// A rewritten body is a DIFFERENT representation from the stored
			// file and owes a different entity tag, for the reason the
			// encodings below owe one: /view and /download must never
			// validate against each other's cached bytes.
			tag += "-hvc1"
		}
		if enc != "" {
			// A content-coded response is a DIFFERENT representation and owes a
			// different entity tag. Sharing one would let a cache holding the
			// compressed body validate a Range request against it, and a Range
			// request is always answered with identity bytes, so the two would
			// splice.
			tag += "-" + enc
		}
		w.Header().Set("ETag", `"`+tag+`"`)
	}
	w.Header().Set("Content-Type", mimeType)
	w.Header().Set("Content-Disposition", dispositionHeader(inline, name))
	if enc == "" {
		if negotiable {
			// This client took identity, but the response still varies: a
			// shared cache must not hand these bytes to a client that would
			// have been sent zstd.
			w.Header().Add("Vary", "Accept-Encoding")
		}
		http.ServeContent(w, r, "", modTime, body)
		return
	}
	cw := &compressingWriter{ResponseWriter: w, encoding: enc}
	defer cw.finish()
	http.ServeContent(cw, r, "", modTime, body)
}

// revalidate makes a response cacheable only on revalidation, keeping a
// "private" a protected share's response already carries. A response
// already marked no-cache is left as it is.
func revalidate(w http.ResponseWriter) {
	cc := w.Header().Get("Cache-Control")
	if strings.Contains(cc, "no-cache") {
		return
	}
	if cc != "" {
		w.Header().Set("Cache-Control", cc+", no-cache")
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
}

// sandboxCSP puts an uploaded page in an opaque origin. It keeps the things
// a shared page legitimately does (running its own script, submitting a
// form, opening a link) and drops the one thing that makes uploads dangerous
// to each other: being same-origin with files.<domain>. allow-same-origin
// hands that straight back, and allow-popups-to-escape-sandbox launders it
// through a new window, so neither may ever appear here.
const sandboxCSP = "sandbox allow-scripts allow-forms allow-popups allow-modals allow-downloads"

// documentTypes are the uploaded MIME types a browser will turn into a
// scriptable document, beside the +xml family isDocumentType adds. Anything
// else (an image, a video, a PDF, a download) has no way to read another
// response, so sandboxing it would cost it its own origin for nothing.
var documentTypes = map[string]bool{
	"text/html": true, "application/xhtml+xml": true, "image/svg+xml": true,
	"text/xml": true, "application/xml": true, "text/xsl": true,
}

// isDocumentType reports whether a parsed, lowercased media type is one a
// browser may render as a scriptable document: documentTypes, and every
// +xml type (RSS, Atom, XSLT, MathML, a vendor's own), which Firefox and
// Safari render as XML, where an XHTML element runs its script. It is the
// rule mimetype.Viewable uses to call a +xml type viewable, so whatever
// /view serves inline as XML is sandboxed. A stored file's type comes from
// the system's mime table and a live file's from the sharer's client, so
// neither list can be known in advance.
func isDocumentType(mt string) bool {
	return documentTypes[mt] || strings.HasSuffix(mt, "+xml")
}

// sandboxDocument applies the sandbox to uploaded content that could run as a
// page. The origin split (origins.go) already keeps that page off the app's
// hostname; this keeps it away from every OTHER upload, which the split alone
// does not, since all uploads share the one file origin. It is set on
// /download as well as /view: a disposition is a request, not a guarantee.
//
// It fails closed: a type that does not parse cleanly is sandboxed too,
// because a browser parses Content-Type more leniently than Go and renders
// "text/html; x" as a page.
func sandboxDocument(w http.ResponseWriter, mimeType string) {
	mt, _, err := mime.ParseMediaType(mimeType)
	if err == nil && !isDocumentType(mt) {
		return
	}
	w.Header().Set("Content-Security-Policy", sandboxCSP)
}

// canNegotiateFile reports whether this file response may carry a content
// encoding. Three conditions, each load-bearing:
//
//   - inline: the VIEW route only. /download and /zip stay byte-exact by
//     design: a download's progress bar needs the real Content-Length, and a
//     zip is already compressed. (inline is also false for a /view URL on a
//     type the browser can't render, which degrades to a download.)
//   - no Range: resume semantics count ORIGINAL bytes, so a ranged response is
//     always identity.
//   - a compressible type: see mimetype.Compressible.
func canNegotiateFile(r *http.Request, mimeType string, inline bool) bool {
	return inline && r.Header.Get("Range") == "" && mimetype.Compressible(mimeType)
}

func dispositionHeader(inline bool, name string) string {
	disp := "attachment"
	if inline {
		disp = "inline"
	}
	return mime.FormatMediaType(disp, map[string]string{"filename": name})
}
