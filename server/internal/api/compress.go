package api

import (
	"compress/gzip"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// Response compression for the TEXT routes: the share listing, the waiting
// page's status poll, and the JSON reads. A big folder's listing is ~215 bytes
// of HTML per file (2.1 MiB at 10k files) and the status poll repeats a
// per-file JSON payload for the whole upload; both compress roughly 10:1, which
// matters enormously to a recipient on a distant link.
//
// Deliberately route-scoped rather than global middleware: `/view`,
// `/download` and `/zip` serve file bytes with an exact Content-Length and
// Range support, and compressing those would break both (besides
// re-compressing already-compressed payloads). Wrapping only text handlers
// keeps that hazard out of reach.
//
// zstd when the client advertises it (Chrome 123+, Firefox 126+), gzip
// otherwise, since Safari doesn't do zstd and it's a first-class client here.

var gzipPool = sync.Pool{New: func() any { return gzip.NewWriter(io.Discard) }}

var zstdPool = sync.Pool{New: func() any {
	// SpeedFastest: these are one-shot responses on the request path, not
	// archives: latency saved on the wire is the point, not the last 5%.
	enc, _ := zstd.NewWriter(io.Discard, zstd.WithEncoderLevel(zstd.SpeedFastest))
	return enc
}}

// negotiateEncoding picks the response encoding from Accept-Encoding. "" = send
// it uncompressed. A coding offered with q=0 is a refusal of it, and is never
// picked.
func negotiateEncoding(accept string) string {
	// One pass over the header: this runs on every text route and every
	// negotiated /view. zstd wins outright when both are offered.
	var gzipOK bool
	for rest := strings.ToLower(accept); rest != ""; {
		var part string
		part, rest, _ = strings.Cut(rest, ",")
		name, params, _ := strings.Cut(part, ";")
		if refused(params) {
			continue
		}
		switch strings.TrimSpace(name) {
		case "zstd":
			return "zstd"
		case "gzip":
			gzipOK = true
		}
	}
	if gzipOK {
		return "gzip"
	}
	return ""
}

// refused reports whether a coding's parameters carry q=0. A weight that
// does not parse is not a refusal: the coding is taken as offered.
func refused(params string) bool {
	for params != "" {
		var p string
		p, params, _ = strings.Cut(params, ";")
		k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
		if !ok || strings.TrimSpace(k) != "q" {
			continue
		}
		q, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		return err == nil && q == 0
	}
	return false
}

// compressingWriter defers compression until the first Write, so a handler that
// only sets a status (304, an error) is untouched.
type compressingWriter struct {
	http.ResponseWriter
	encoding string
	w        io.Writer // the compressor, once started
	close    func()
	started  bool
	code     int
}

func (c *compressingWriter) WriteHeader(code int) {
	c.code = code
	// Range/partial responses carry byte offsets into the ORIGINAL bytes;
	// compressing them would be a lie. 304 has no body at all.
	if code == http.StatusPartialContent || code == http.StatusNotModified {
		c.encoding = ""
	}
	if c.encoding != "" {
		c.Header().Set("Content-Encoding", c.encoding)
		// The length does not describe what's on the wire, and the body is
		// encoding-dependent.
		c.Header().Del("Content-Length")
		// Nor can the client ask for a byte range of a stream whose framing it
		// hasn't got: ServeContent advertises ranges on the file routes, and
		// offering them here would invite a request we answer with identity.
		c.Header().Del("Accept-Ranges")
		c.Header().Add("Vary", "Accept-Encoding")
	}
	c.ResponseWriter.WriteHeader(code)
}

func (c *compressingWriter) Write(p []byte) (int, error) {
	if !c.started {
		c.started = true
		if c.code == 0 {
			c.WriteHeader(http.StatusOK)
		}
		switch c.encoding {
		case "gzip":
			gz := gzipPool.Get().(*gzip.Writer)
			gz.Reset(c.ResponseWriter)
			c.w, c.close = gz, func() { gz.Close(); gzipPool.Put(gz) }
		case "zstd":
			enc := zstdPool.Get().(*zstd.Encoder)
			enc.Reset(c.ResponseWriter)
			c.w, c.close = enc, func() { enc.Close(); zstdPool.Put(enc) }
		default:
			c.w = c.ResponseWriter
		}
	}
	return c.w.Write(p)
}

// Flush keeps streamed responses (the listing renders as it walks the tree)
// flowing through the compressor.
func (c *compressingWriter) Flush() {
	if f, ok := c.w.(interface{ Flush() error }); ok {
		_ = f.Flush()
	}
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (c *compressingWriter) finish() {
	if c.close != nil {
		c.close()
	}
}

// compressText wraps a text-producing handler with negotiated compression.
func compressText(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		enc := negotiateEncoding(r.Header.Get("Accept-Encoding"))
		if enc == "" || r.Header.Get("Range") != "" {
			next(w, r)
			return
		}
		cw := &compressingWriter{ResponseWriter: w, encoding: enc}
		defer cw.finish()
		next(cw, r)
	}
}
