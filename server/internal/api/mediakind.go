package api

import (
	"net/http"
	"path"
	"strings"

	"hyperdrop/server/internal/mimetype"
)

// The four buckets a gallery sorts its files into. Three of them are things a
// browser plays; the fourth is everything else, which the gallery lists
// rather than tiles.
const (
	kindPhoto = "photo"
	kindVideo = "video"
	kindAudio = "audio"
	kindFile  = "file"
)

// mediaKind classifies one stored file for the gallery.
//
// The MIME sniffed at commit answers first, because it describes
// what the browser will actually be handed. The extension is the fallback for
// a PENDING manifest entry, whose bytes have not landed yet, and for the
// container formats a bare Linux box's mime table does not know: heic, mov,
// mkv and their neighbours resolve to "" through mime.TypeByExtension there,
// which would put a phone's whole camera roll in the file list.
func mediaKind(mimeType, name string) string {
	switch mt := mimetype.BaseType(mimeType); mt {
	case "image/svg+xml":
		// An SVG is a document that happens to carry an image type: it is
		// sandboxed for the reason an uploaded page is, and a photo tile is
		// not where arbitrary vector content belongs.
		return kindFile
	case "":
		// Nothing sniffed. Fall through to the extension.
	default:
		if k := kindOfBaseType(mt); k != "" {
			return k
		}
		return kindFile
	}
	ext := strings.ToLower(strings.TrimPrefix(path.Ext(path.Base(name)), "."))
	if ext == "" {
		return kindFile
	}
	switch {
	case photoExtensions[ext]:
		return kindPhoto
	case videoExtensions[ext]:
		return kindVideo
	case audioExtensions[ext]:
		return kindAudio
	}
	return kindFile
}

// kindOfBaseType maps a parameter-free lowercase media type to a bucket, or
// "" when it names none of the three.
func kindOfBaseType(mt string) string {
	switch {
	case strings.HasPrefix(mt, "image/"):
		return kindPhoto
	case strings.HasPrefix(mt, "video/"):
		return kindVideo
	case strings.HasPrefix(mt, "audio/"):
		return kindAudio
	}
	return ""
}

// The extension fallbacks. Deliberately generous on the photo side: a camera
// raw is a picture even though no browser opens one, and the app converts it
// to JPEG on the way into a media share, so what lands here IS viewable. A
// raw that reached the server untouched (a terminal share) tiles as a broken
// image, which still reads better than hiding it among the PDFs.
var (
	photoExtensions = set(
		"jpg", "jpeg", "jpe", "png", "gif", "webp", "avif", "bmp", "ico",
		"heic", "heif", "heics", "heifs", "tif", "tiff",
		"dng", "cr2", "cr3", "nef", "nrw", "arw", "srf", "sr2", "raf",
		"rw2", "orf", "pef", "raw", "3fr", "erf", "mos", "x3f",
	)
	videoExtensions = set(
		"mp4", "m4v", "mov", "qt", "mkv", "webm", "avi", "mpg", "mpeg",
		"m2ts", "mts", "ts", "wmv", "flv", "3gp", "3g2", "ogv",
	)
	audioExtensions = set(
		"mp3", "m4a", "m4b", "aac", "wav", "wave", "flac", "ogg", "oga",
		"opus", "aiff", "aif", "aifc", "wma", "amr", "caf", "ape", "wv",
	)
)

func set(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, it := range items {
		m[it] = true
	}
	return m
}

// galleryRefusal answers the 400 a share that cannot BECOME a gallery earns,
// or nil when it can.
//
// Only the entering direction is gated. A file listing renders anything, so
// leaving a gallery can never produce a broken page; entering one publishes a
// grid, and a tile a browser cannot decode is a broken picture in public.
//
// The rule is per file and follows what the page would DO with it: a file the
// gallery would tile (photo, video, audio) has to be playable, while one that
// lands in the gallery's own file list (a PDF, a README) is welcome and
// unconstrained, exactly as it is when a gallery is created.
func galleryRefusal(v shareView) error {
	for _, f := range v.Files {
		// A pending entry's bytes have not landed, so nothing has been
		// sniffed and nothing can be said about it. Refusing beats guessing
		// from the extension, which would turn a share into a gallery on a
		// promise the upload might not keep.
		if f.Pending {
			return refuse(http.StatusBadRequest, "share-incomplete", "this share is still uploading")
		}
	}
	tiled := 0
	for _, f := range v.Files {
		if !wouldBeTiled(f) {
			continue
		}
		tiled++
		if !mimetype.GalleryPlayable(f.Mime) {
			return refuse(http.StatusBadRequest, "not-gallery-playable",
				"no browser can show "+path.Base(f.Path)+" without converting it first")
		}
	}
	// A gallery with nothing to lay out is a page of file rows under a grid
	// that never appears. An empty share and a share of documents are the
	// same refusal: there are no pictures.
	if tiled == 0 {
		return refuse(http.StatusBadRequest, "no-pictures", "this share has no pictures, video or audio to show")
	}
	return nil
}

// wouldBeTiled reports whether the gallery would treat this file as a
// picture rather than list it, asked of BOTH readings of the file.
//
// The name has to be consulted even when a MIME type was sniffed, because a
// bare Linux box's mime table does not know heic, mov or mkv: a real HEIC
// sniffs as octet-stream there, which mediaKind reads as an ordinary file. On
// such a box a camera roll would convert "successfully" into a gallery with
// no pictures in it and thirteen rows in its file list. Refusing names the
// actual problem instead.
func wouldBeTiled(f fileView) bool {
	return mediaKind(f.Mime, f.Path) != kindFile || mediaKind("", f.Path) != kindFile
}
