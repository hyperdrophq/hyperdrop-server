package api

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	"hyperdrop/server/internal/linked"
	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/sharefs"
	"hyperdrop/server/internal/shareid"
)

// thumbMaxBytes caps one gallery thumbnail. A 512 px JPEG at q0.72 is around
// 40 KB, so this is roomy; it exists because a thumbnail is a sidecar, not a
// file entry, and is therefore invisible to the usage index that bounds
// everything else a client can write.
const thumbMaxBytes = 512 << 10

// galleryMetaMaxBytes caps the gallery sidecar body. Four small numbers per
// file over the manifest ceiling is well inside this.
const galleryMetaMaxBytes = 4 << 20

// setThumb stores one file's gallery thumbnail:
// PUT /api/shares/{id}/thumbs/{slug} with the raw JPEG as the body.
//
// The slug must name a file this share actually holds, which is what bounds
// the number of thumbnails a share can accumulate: without it a client could
// mint slugs forever and fill the directory with bytes no quota counts.
//
// The body must DECODE as a JPEG. The file layer is handed client-supplied
// bytes it will later serve to strangers, and "it is a JPEG because the route
// says so" is not a check.
func (h *handler) setThumb(w http.ResponseWriter, r *http.Request) {
	v, _, ok := h.ownedShareMeta(w, r)
	if !ok {
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, thumbMaxBytes+1))
	if err != nil || len(data) > thumbMaxBytes {
		writeErrorCode(w, http.StatusRequestEntityTooLarge, "thumb-too-large",
			"thumbnail too large (limit 512 KB)")
		return
	}
	// The file layer checks the slug's shape and that the bytes decode as a
	// JPEG, because three writers reach the same file and a check in a route
	// body is a check the other two skip, and asks whether the slug names a
	// file of the share under the lock a delete's tile removal takes.
	slug := r.PathValue("slug")
	switch err := h.fs.SetThumb(v.ID, v.Owner, slug, data, func() (int64, bool) { return h.shareFileSize(v, slug) }); {
	case errors.Is(err, sharefs.ErrTooLarge):
		writeErrorCode(w, http.StatusRequestEntityTooLarge, "thumb-too-large", err.Error())
	case errors.Is(err, sharefs.ErrNotFound):
		writeErrorCode(w, http.StatusNotFound, "not-found", "no such file in this share")
	case errors.Is(err, sharefs.ErrBadRequest):
		writeError(w, http.StatusBadRequest, "a thumbnail must be a non-empty JPEG")
	case err != nil:
		writeRefusal(w, err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// shareFileSize answers the size of the file a slug names and whether this
// share holds it. The file rows answer first and answer for a share of any
// size, the view's own list second: a LINKED entry's slug is minted beside the
// walk rather than stored as a file row, so the walk is the only place that
// names it.
func (h *handler) shareFileSize(v shareView, slug string) (int64, bool) {
	if f, err := h.db.ResolveSlug(v.ID, slug); err == nil {
		return f.Size, true
	}
	if f, ok := v.FileBySlug(slug); ok {
		return f.Size, true
	}
	return 0, false
}

// galleryMetaIn is one item as a client sends it. Field names are spelled out
// here, unlike the short keys the page reads, because this is the API a
// client writes against.
type galleryMetaIn struct {
	Slug       string     `json:"slug"`
	Width      int        `json:"w"`
	Height     int        `json:"h"`
	DurationMS int        `json:"durationMs"`
	TakenAt    *time.Time `json:"takenAt"`
}

// setGallery records a share's gallery metadata: PUT /api/shares/{id}/gallery.
//
// The write MERGES by slug (metadb.SetGallery): files join a gallery a batch at
// a time, and a client knows only the batch it just measured, so a wholesale
// write would erase the dimensions and dates of everything already there. A
// row is pruned where its entry leaves the share or hands its slug on, never
// here.
//
// Items naming a slug this share does not hold are DROPPED rather than
// refused, and the response reports how many: a client that uploads metadata
// for a file whose upload failed should not lose the metadata for every file
// that worked. Nothing the client sent is stored verbatim; the map is rebuilt
// from validated fields, because the gallery page renders it.
func (h *handler) setGallery(w http.ResponseWriter, r *http.Request) {
	v, _, ok := h.ownedShare(w, r)
	if !ok {
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, galleryMetaMaxBytes+1))
	if err != nil || len(body) > galleryMetaMaxBytes {
		writeErrorCode(w, http.StatusRequestEntityTooLarge, "body-too-large",
			"gallery metadata too large (limit 4 MB)")
		return
	}
	var req struct {
		Items []galleryMetaIn `json:"items"`
	}
	if err := decodeRequest(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, badJSONMessage(err))
		return
	}
	held := make(map[string]bool, len(v.Files))
	for _, f := range v.Files {
		held[f.Slug] = true
	}
	items := make(map[string]metadb.GalleryItem, len(req.Items))
	dropped := 0
	for _, in := range req.Items {
		if !shareid.ValidSlug(in.Slug) || !held[in.Slug] {
			dropped++
			continue
		}
		items[in.Slug] = metadb.GalleryItem{
			Width:      clampDimension(in.Width),
			Height:     clampDimension(in.Height),
			DurationMS: clampDuration(in.DurationMS),
			TakenAt:    in.TakenAt,
		}
	}
	if err := h.db.SetGallery(v.ID, items); err != nil {
		writeRefusal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"items": len(items), "dropped": dropped})
}

// Bounds on the two numbers that reach CSS. They only ever describe a real
// file's pixels and running time, and a nonsense value would be laid out as
// one, so out-of-range reads as "unknown" rather than as an error: the tile
// falls back to square, which is the same thing an absent value does.
const (
	maxPixelDimension = 1 << 17 // 131072, past any sensor or codec
	maxDurationMS     = 1000 * 60 * 60 * 24
)

func clampDimension(v int) int {
	if v <= 0 || v > maxPixelDimension {
		return 0
	}
	return v
}

func clampDuration(v int) int {
	if v <= 0 || v > maxDurationMS {
		return 0
	}
	return v
}

// thumbForOwner serves one gallery tile to the share's owner:
// GET /api/shares/{id}/thumbs/{slug}. Authenticated and owner-scoped, so a
// protected gallery's tiles reach the owner's other devices without the
// password, while the public /thumb keeps its gate.
func (h *handler) thumbForOwner(w http.ResponseWriter, r *http.Request) {
	v, _, ok := h.ownedShareMeta(w, r)
	if !ok {
		return
	}
	data, err := h.fs.Thumb(v.ID, r.PathValue("slug"))
	if err != nil {
		writeErrorCode(w, http.StatusNotFound, "not-found", "no tile for that file")
		return
	}
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Cache-Control", "private, max-age=3600")
	w.Write(data)
}

// thumbImage serves one gallery thumbnail: GET /thumb/{id}/{slug}.
//
// The gate is /view's, not /card's: a thumbnail is a view of the share's
// CONTENT, so a protected share's thumbnails are behind its password, and
// visibleShareVia keeps an expired share, a suspended owner and an inbox
// answering 404 here as everywhere else.
func (h *handler) thumbImage(w http.ResponseWriter, r *http.Request) {
	// The META read, not the whole share: a gallery fires one of these per
	// file, and nothing here needs the file list or a linked share's walk.
	// sharefs.ValidSlug (inside Thumb) is what bounds the path, and a stored
	// file's tile is deleted with the file, so its slug does not have to be
	// re-checked against the share on every read. A linked entry's tile
	// outlives a revoke and a hide (its slug is kept so a restore or a show
	// brings the link back), so linkedTileShown asks that question here.
	v, ok := h.loadPublicShareVia(w, r, h.viewMeta)
	if !ok {
		return
	}
	if v.Linked() && !h.linkedTileShown(v, r.PathValue("slug")) {
		http.NotFound(w, r)
		return
	}
	// The tile is read without the share's swap lock: a stored share's tile
	// resolves no row here (its slug alone names the sidecar), and no
	// publish's commit touches a tile under that lock, so there is no row
	// and no rename for the read to straddle. A deleted file's tile is
	// removed after the commit, and a read meanwhile answers the tile or 404.
	data, err := h.fs.Thumb(v.ID, r.PathValue("slug"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/jpeg")
	noIndex(w)
	// A tile is revalidated like every payload answer, so a password added
	// later meets the gate; a protected share's is also private, so no
	// shared cache answers the next request without the cookie.
	if v.PasswordHash != "" {
		w.Header().Set("Cache-Control", "private, no-cache")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	sum := sha256.Sum256(data)
	w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:16])+`"`)
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(data))
}

// linkedTileShown reports whether a linked share's listing names the entry a
// tile's slug was minted for, without walking a source: a stored file of the
// slug answers yes, a linked entry answers what linked.Shown makes of its
// relpath (its source revoked, the entry hidden or outside a fixed list all
// answer no), and a linked entry a stored file of the same relpath shadows
// answers no, because the listing names that path as the upload. A source
// that cannot be read right now says nothing about a tile, the rule viewMeta
// keeps for every sidecar.
func (h *handler) linkedTileShown(v shareView, slug string) bool {
	if _, err := h.db.ResolveSlug(v.ID, slug); err == nil {
		return true
	}
	rel, err := h.db.LinkedRel(v.ID, slug)
	if err != nil {
		return false
	}
	if _, err := h.db.File(v.ID, rel); err == nil {
		return false
	}
	specs, err := h.dbSpecs(v.Share)
	return err == nil && linked.Shown(specs, v.Prefixed(), rel)
}

// Batched sidecars: a whole gallery's tiles in ONE request as a tar.
//
// One request per tile costs a request, a meta read and a notification each,
// which a 1,500-photo gallery pays 1,500 times over after the share has
// already committed. Reading the share ONCE and writing N tiles pays it once.
//
// It is the same trade `/batch` makes for small files, and deliberately not a
// replacement for the per-slug PUT: adding one file to an existing gallery
// wants one request, not a tar of one.
const (
	// sidecarBatchMaxFiles bounds entries per request so one caller cannot
	// hold a connection indefinitely, matching batchMaxFiles.
	sidecarBatchMaxFiles = 2000
	// sidecarBatchMaxBytes bounds the whole stream. thumbMaxBytes still
	// bounds each entry.
	sidecarBatchMaxBytes = 256 << 20
)

// sidecarBatchResult reports what landed. Refused entries (a name that is
// not a tile's, a tile naming no file in this share, bytes that are not a
// JPEG) are SKIPPED and named rather than failing the request: a
// gallery's tiles are decoration, and losing every good one because of a
// single bad entry would be the wrong trade.
type sidecarBatchResult struct {
	Stored  int      `json:"stored"`
	Skipped []string `json:"skipped,omitempty"`
	Error   string   `json:"error,omitempty"`
}

// readSidecarTar unpacks a tar of gallery tiles into one share, naming each
// entry's slug with `slug`, so the route decides how an archive name maps to
// a tile.
// An entry whose name yields no slug is skipped, so a caller that sends a
// name this route does not understand loses that entry and nothing else.
//
// `holds` answers whether a slug names one of this share's files and how big
// that file is, which bounds both the number of tiles a share can accumulate
// and the size of each: without it a client could mint slugs forever and fill
// the directory with bytes no quota counts. `owner` is the account whose room
// above the disk reserve each tile is admitted against.
// A free function taking the file layer rather than a handler method: the
// file layer is all it needs.
func readSidecarTar(fs *sharefs.FS, w http.ResponseWriter, r *http.Request, shareID, owner string,
	holds func(slug string) (int64, bool), slug func(hdr *tar.Header) string) {
	body, cleanup, _, err := decodeBody(w, r)
	if err != nil {
		return // decodeBody has already answered
	}
	defer cleanup()

	var res sidecarBatchResult
	// A stream past the limit is refused whatever the tar reader makes of
	// the cut: an end inside an entry reads as a broken stream, and one in
	// an entry's padding as a clean end, so the limit itself is checked
	// rather than the reader's error.
	limited := &io.LimitedReader{R: body, N: sidecarBatchMaxBytes + 1}
	overLimit := func() bool {
		if limited.N > 0 {
			return false
		}
		res.Error = "more bytes than the per-request limit"
		writeJSON(w, http.StatusRequestEntityTooLarge, res)
		return true
	}
	tr := tar.NewReader(limited)
	seen := 0
	// One buffer for the whole stream, reassigned so the growth is kept:
	// a 2,000-tile batch must not allocate 2,000 times.
	var entry bytes.Buffer
	for {
		hdr, err := tr.Next()
		if err != nil && overLimit() {
			return
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			res.Error = "sidecar stream ended early: " + err.Error()
			writeJSON(w, http.StatusBadRequest, res)
			return
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		seen++
		if seen > sidecarBatchMaxFiles {
			res.Error = "more entries than the per-request limit"
			writeJSON(w, http.StatusRequestEntityTooLarge, res)
			return
		}
		// The header's size is checked BEFORE the body is read, so an
		// oversized entry is skipped without ever being buffered.
		if hdr.Size > thumbMaxBytes {
			res.Skipped = append(res.Skipped, hdr.Name)
			// #nosec G110 -- the whole stream is read through a LimitReader of sidecarBatchMaxBytes
			if _, derr := io.Copy(io.Discard, tr); derr != nil {
				if overLimit() {
					return
				}
				res.Error = "sidecar stream ended early: " + derr.Error()
				writeJSON(w, http.StatusBadRequest, res)
				return
			}
			continue
		}
		entry.Reset()
		if _, rerr := entry.ReadFrom(io.LimitReader(tr, thumbMaxBytes+1)); rerr != nil {
			if overLimit() {
				return
			}
			res.Error = "sidecar stream ended early: " + rerr.Error()
			writeJSON(w, http.StatusBadRequest, res)
			return
		}
		name := slug(hdr)
		if name == "" || int64(entry.Len()) > thumbMaxBytes ||
			fs.SetThumb(shareID, owner, name, entry.Bytes(), func() (int64, bool) { return holds(name) }) != nil {
			res.Skipped = append(res.Skipped, hdr.Name)
			continue
		}
		res.Stored++
	}
	writeJSON(w, http.StatusOK, res)
}

// setThumbBatch takes a tar of <slug>.jpg entries.
func (h *handler) setThumbBatch(w http.ResponseWriter, r *http.Request) {
	v, _, ok := h.ownedShareMeta(w, r)
	if !ok {
		return
	}
	readSidecarTar(h.fs, w, r, v.ID, v.Owner, func(slug string) (int64, bool) { return h.shareFileSize(v, slug) },
		func(hdr *tar.Header) string { return strings.TrimSuffix(path.Base(hdr.Name), ".jpg") })
}
