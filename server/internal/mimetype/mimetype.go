// Package mimetype resolves stored files' MIME types (extension first,
// content sniff fallback) and decides whether a browser renders a type
// inline, the basis of the per-file "viewable" flag in API responses.
package mimetype

import (
	"bytes"
	"io"
	"mime"
	"net/http"
	"path"
	"strings"
	"unicode/utf8"
)

// Detect resolves by extension first, sniffing content only as fallback.
// An extension that names a structured text type is confirmed against the
// content (Confirm). The reader's position is restored to the start.
func Detect(f io.ReadSeeker, name string) string {
	if ct := mime.TypeByExtension(path.Ext(name)); ct != "" {
		return Confirm(f, ct)
	}
	buf := make([]byte, sniffLen)
	n, _ := io.ReadFull(f, buf)
	f.Seek(0, io.SeekStart)
	ct := http.DetectContentType(buf[:n])
	if strings.HasPrefix(ct, "text/plain") {
		return "text/plain; charset=utf-8"
	}
	return ct
}

// sniffLen is how much of a file the content checks read, the prefix
// http.DetectContentType considers.
const sniffLen = 512

// Confirm answers mimeType, or application/octet-stream when mimeType is an
// XML or JSON type (application/xml, application/json, text/xml, any +xml or
// +json) and the file's first 512 bytes are not text. A name alone decides
// those types, and a mime table can map an extension that also names a binary
// format to one of them (Debian's maps .pkg, a macOS installer, to
// application/vnd.apple.installer+xml): served inline, such a file is an XML
// parse error where a download was meant. Text is UTF-8 (ASCII included)
// with no NUL byte, or anything after a UTF-16 byte order mark. Every other
// type is answered unread. The reader's position is restored to the start.
func Confirm(f io.ReadSeeker, mimeType string) string {
	if !structuredText(mimeType) {
		return mimeType
	}
	buf := make([]byte, sniffLen)
	n, _ := io.ReadFull(f, buf)
	f.Seek(0, io.SeekStart)
	if !looksLikeText(buf[:n], n == sniffLen) {
		return "application/octet-stream"
	}
	return mimeType
}

// structuredText reports whether a type is one Confirm checks.
func structuredText(mimeType string) bool {
	mt := BaseType(mimeType)
	switch mt {
	case "application/xml", "application/json", "text/xml":
		return true
	}
	return strings.HasSuffix(mt, "+xml") || strings.HasSuffix(mt, "+json")
}

// looksLikeText is Confirm's test of a file's first bytes. cut says the
// prefix may end inside a multi-byte character, which is then not held
// against it.
func looksLikeText(b []byte, cut bool) bool {
	if len(b) >= 2 && (b[0] == 0xFE && b[1] == 0xFF || b[0] == 0xFF && b[1] == 0xFE) {
		return true
	}
	if bytes.IndexByte(b, 0) >= 0 {
		return false
	}
	if cut {
		// Drop an incomplete last character, at most three bytes long.
		last := len(b) - 1
		for last > 0 && len(b)-last < utf8.UTFMax && !utf8.RuneStart(b[last]) {
			last--
		}
		if !utf8.FullRune(b[last:]) {
			b = b[:last]
		}
	}
	return utf8.Valid(b)
}

// ByName guesses a MIME type from the filename's extension alone, for
// pending (declared-but-not-uploaded) manifest entries where no bytes
// exist yet. Empty for unknown extensions; the commit-time Detect verdict
// overwrites it either way.
func ByName(name string) string {
	return mime.TypeByExtension(path.Ext(name))
}

// BaseType strips the parameters and lowercases what is left. Deliberately not
// mime.ParseMediaType: that allocates a params map unconditionally and no
// caller reads the params, so at the listing ceiling (500 rows x 100 files,
// via toFileOut) it would be 50,000 throwaway maps per GET /api/shares.
// Anything without a "/" is not a media type and reads as empty, which every
// caller treats as "no".
func BaseType(mimeType string) string {
	mt, _, _ := strings.Cut(mimeType, ";")
	mt = strings.ToLower(strings.TrimSpace(mt))
	if !strings.Contains(mt, "/") {
		return ""
	}
	return mt
}

// Viewable reports whether browsers render this MIME type inline. Anything
// else downloads either way, so a View link would be meaningless. Empty or
// unparseable MIME is not viewable.
func Viewable(mimeType string) bool {
	mt := BaseType(mimeType)
	switch {
	case strings.HasPrefix(mt, "image/"),
		strings.HasPrefix(mt, "video/"),
		strings.HasPrefix(mt, "audio/"),
		strings.HasPrefix(mt, "text/"):
		return true
	}
	switch mt {
	case "application/pdf", "application/json", "application/xml":
		return true
	}
	return strings.HasSuffix(mt, "+xml") || strings.HasSuffix(mt, "+json")
}

// galleryPlayable are the types a gallery can TILE: what every current
// browser decodes on its own, with no plugin and no conversion.
//
// An allowlist, and deliberately narrower than Viewable, which passes any
// image/* and so calls a HEIC viewable when no browser shows one. It is also
// narrower than the gallery's own mediaKind, which buckets a HEIC as a photo
// on purpose so a phone's camera roll lays out correctly. Laying a file out
// as a picture and being able to show it are different claims, and this is
// the one that gates turning an existing share into a gallery: being wrong
// the permissive way publishes a grid of broken tiles.
var galleryPlayable = map[string]bool{
	"image/jpeg": true,
	"image/png":  true,
	"image/gif":  true,
	"image/webp": true,
	"image/avif": true,
	"video/mp4":  true,
	"video/webm": true,
	"audio/mpeg": true,
	"audio/mp4":  true,
	"audio/aac":  true,
	"audio/wav":  true,
	"audio/ogg":  true,
	"audio/flac": true,
	// Aliases for those same containers. A distribution's mime table and a
	// content sniffer each answer with their own spelling, and refusing one
	// of them would refuse a file every browser plays: .m4v is an MP4, and
	// audio/wave is the same RIFF bytes as audio/wav.
	"video/x-m4v":  true,
	"audio/x-wav":  true,
	"audio/wave":   true,
	"audio/x-m4a":  true,
	"audio/x-flac": true,
}

// GalleryPlayable reports whether a browser plays this type unaided.
//
// The check is CONTAINER level, which is as far as a stored MIME type goes:
// an .mp4 carrying HEVC passes here and will not play in Chrome. The app
// avoids that at creation by converting before it uploads, which is exactly
// what cannot be done for bytes already on the server. Empty (a pending entry
// with nothing sniffed yet) is not playable, so a share still uploading
// refuses rather than guesses.
func GalleryPlayable(mimeType string) bool {
	return galleryPlayable[BaseType(mimeType)]
}

// textish are the non-text/* types whose bytes are still markup, source or
// data. An allowlist, deliberately: a denylist would compress every new
// binary type someone invents, and being wrong that way costs CPU on both
// ends for nothing.
var textish = map[string]bool{
	"application/json":                  true,
	"application/xml":                   true,
	"application/javascript":            true,
	"application/x-javascript":          true,
	"application/ecmascript":            true,
	"application/x-ndjson":              true,
	"application/ld+json":               true,
	"application/manifest+json":         true,
	"application/x-sh":                  true,
	"application/x-www-form-urlencoded": true,
	"image/svg+xml":                     true,
}

// Compressible reports whether serving this MIME type through a response
// encoding is worth it. True only for content that is genuinely text
// underneath: media and archives carry their own compression, so re-encoding
// them spends CPU on both ends to make the payload very slightly larger, and
// it costs the exact Content-Length that download progress depends on.
//
// PDF is deliberately absent even though it is Viewable, because its streams are
// already deflated.
func Compressible(mimeType string) bool {
	mt := BaseType(mimeType)
	if strings.HasPrefix(mt, "text/") || textish[mt] {
		return true
	}
	return strings.HasSuffix(mt, "+json") || strings.HasSuffix(mt, "+xml")
}
