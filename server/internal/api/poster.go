package api

import (
	"errors"
	"io"
	"net/http"
	"path"
	"strings"

	"hyperdrop/server/internal/mimetype"
	"hyperdrop/server/internal/sharefs"
)

// CardImage is which picture a link preview shows. Chat apps and LinkedIn all
// render og:image, and only some of them render og:video, so this is the one
// thing that decides whether a shared video looks like anything at all.
type CardImage int

const (
	// CardBrand is the static HyperDrop mark: the default for everything that
	// is not a video, and the fallback whenever a poster is not available.
	CardBrand CardImage = iota
	// CardVideoGeneric is a static play-button tile. It says "there is a video
	// behind this link" WITHOUT showing a frame of it.
	CardVideoGeneric
	// CardPoster is a real frame from the video.
	CardPoster
)

// posterMaxBytes caps the uploaded poster. A 1280x720 JPEG is around 150 KB;
// this leaves generous room while keeping a stray upload from filling a share
// directory with something no quota accounts for.
const posterMaxBytes = 4 << 20

// pickCardImage decides which image a share's card carries.
//
// The rule that matters most is the first one. **A protected share NEVER shows
// a frame of its own video**: the whole point of the password is that the
// content is not public, and og:image is fetched by anonymous bots that carry
// no cookies and cannot be gated. Worse, chat providers CACHE what they fetch,
// so a frame that leaked once outlives deleting the share. A protected video
// gets the generic play tile instead, which tells the recipient there is a
// video to unlock and nothing about what is in it.
//
// That tile does disclose one bit ("this protected share is a video"), which
// `protectedCard` otherwise withholds. Accepted deliberately: a link that
// unfurls as a blank card reads as broken, and knowing a locked thing is a
// video is not the secret the password protects.
//
// A Receive Inbox is the exception to that exception: its content is never
// public, so whatever it holds, protected or not, its card is the brand mark.
func pickCardImage(v shareView, hasVideo, hasPoster bool) CardImage {
	if v.Inbox {
		return CardBrand
	}
	if v.PasswordHash != "" {
		if hasVideo {
			return CardVideoGeneric
		}
		return CardBrand
	}
	if hasPoster {
		return CardPoster
	}
	if hasVideo {
		return CardVideoGeneric
	}
	return CardBrand
}

// path returns the URL path for the chosen image, relative to the canonical
// base. The poster is per share; the other two are static and identical
// everywhere, so they carry no share information at all.
func (c CardImage) path(shareID string) string {
	switch c {
	case CardPoster:
		return "/card/" + shareID + "/poster.jpg"
	case CardVideoGeneric:
		return "/card-video.png"
	default:
		return "/card.png"
	}
}

// shareHasVideo reports whether any committed file in the share is a video,
// which is what makes the generic play tile the right fallback. Pending files
// count: an early link previews before the bytes land, and the card a chat app
// caches first is the one it keeps.
func shareHasVideo(v shareView) bool {
	for _, f := range v.Files {
		if isVideoMime(f.Mime) || isVideoExt(f.Path) {
			return true
		}
	}
	return false
}

func isVideoMime(mime string) bool {
	return strings.HasPrefix(mimetype.BaseType(mime), "video/")
}

// isVideoExt catches a pending entry, whose Mime is only an extension guess
// and may be empty until the bytes commit. The gallery's list decides.
func isVideoExt(name string) bool {
	return videoExtensions[strings.ToLower(strings.TrimPrefix(path.Ext(name), "."))]
}

// setPoster stores the share's link-preview image: PUT /api/shares/{id}/poster
// with the raw JPEG as the body. Owner-scoped like every other share write.
//
// A separate route rather than a file upload, because the poster is not one of
// the user's files: it takes no slug, never appears in a listing or a zip, and
// is not counted against the quota.
func (h *handler) setPoster(w http.ResponseWriter, r *http.Request) {
	v, _, ok := h.ownedShareMeta(w, r)
	if !ok {
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, posterMaxBytes+1))
	var tooBig *http.MaxBytesError
	switch {
	case errors.As(err, &tooBig), err == nil && len(data) > posterMaxBytes:
		writeError(w, http.StatusRequestEntityTooLarge, "poster too large or empty")
		return
	case err != nil:
		// The body stopped arriving (a client that hung up mid-send): that
		// is the request failing, not the poster being refused, and saying
		// "too large" would send the caller looking for a smaller picture.
		writeError(w, http.StatusBadRequest, "reading the request body: "+err.Error())
		return
	}
	if len(data) == 0 {
		writeError(w, http.StatusRequestEntityTooLarge, "poster too large or empty")
		return
	}
	// The file layer stores the image and the note naming the entry it is
	// taken from as one change, and refuses bytes that do not decode as a
	// JPEG: the poster is served to strangers as image/jpeg on every host, the
	// app origin included.
	switch err := h.fs.SetPoster(v.ID, posterSourceSlug(v), data); {
	case errors.Is(err, sharefs.ErrNotFound):
		writeError(w, http.StatusNotFound, "share not found")
	case errors.Is(err, sharefs.ErrBadRequest):
		writeError(w, http.StatusBadRequest, "a poster must be a JPEG")
	case err != nil:
		writeRefusal(w, err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// clearPoster removes the share's link-preview image: DELETE
// /api/shares/{id}/poster. Owner-scoped, and 204 whether or not a poster was
// stored. The public card reads the file, so it falls back to its brand or
// generic image at once.
func (h *handler) clearPoster(w http.ResponseWriter, r *http.Request) {
	v, _, ok := h.ownedShareMeta(w, r)
	if !ok {
		return
	}
	if err := h.fs.RemovePoster(v.ID); err != nil {
		writeRefusal(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// posterSourceSlug names the entry a poster set now is taken from: the
// share's one entry when it holds exactly one, which is the only selection
// a client makes a poster for. A share of several entries, or none, or a
// live share (whose entries are the sharer's, not rows) answers "": the
// poster names no entry.
func posterSourceSlug(v shareView) string {
	if v.LiveShare {
		return ""
	}
	if n, _ := v.Totals(); n != 1 || len(v.Files) != 1 {
		return ""
	}
	return v.Files[0].Slug
}

// posterShown reports whether a share's stored poster may go on its public
// card, which is what an anonymous bot fetches and a chat provider caches.
// Never once a linked source is revoked: a poster that names no entry cannot
// be told apart from a frame of the revoked folder. And never once the entry
// it names stops being shown: a stored file deleted, a linked entry hidden by
// the source's filter, outside its fixed list, under a revoked source or
// shadowed by an upload (linkedTileShown, the rule a gallery tile follows; a
// source that cannot be read right now says nothing, as for a tile). A note
// that cannot be read withholds it too.
func (h *handler) posterShown(v shareView) bool {
	for _, s := range v.Sources {
		if s.Revoked() {
			return false
		}
	}
	slug, err := h.fs.PosterSource(v.ID)
	switch {
	case err != nil:
		return false
	case slug == "":
		return true
	case v.Linked():
		return h.linkedTileShown(v, slug)
	}
	_, err = h.db.ResolveSlug(v.ID, slug)
	return err == nil
}

// shownPoster reads a share's stored poster when posterShown lets it go on
// the public card, and ErrNoPoster when it does not. For a share with no
// linked source the check (the entry the poster names still resolving to a
// row) and the read of the image run together under the share's swap lock
// held shared, so a publish's commit that deletes that entry lands wholly
// before or wholly after them: a frame of a file the commit removed is never
// served. A linked share's check, which asks its source folder about the
// entry (linkedTileShown), runs outside the lock.
func (h *handler) shownPoster(v shareView) ([]byte, error) {
	if v.Linked() {
		if !h.posterShown(v) {
			return nil, sharefs.ErrNoPoster
		}
		return h.fs.Poster(v.ID)
	}
	var data []byte
	err := h.fs.ReadSwapped(v.ID, func() error {
		if !h.posterShown(v) {
			return sharefs.ErrNoPoster
		}
		var err error
		data, err = h.fs.Poster(v.ID)
		return err
	})
	return data, err
}

// posterForOwner serves the share's stored preview to its authenticated
// owner: GET /api/shares/{id}/poster. Unlike the public card route below, a
// password on the share does not withhold the image here: the caller has
// proven they own the share, and this is the thumbnail their own app shows
// beside it. Cache-Control is private so no shared cache ever holds it.
func (h *handler) posterForOwner(w http.ResponseWriter, r *http.Request) {
	v, _, ok := h.ownedShareMeta(w, r)
	if !ok {
		return
	}
	data, err := h.fs.Poster(v.ID)
	if err != nil {
		writeErrorCode(w, http.StatusNotFound, "not-found", "share has no poster")
		return
	}
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Cache-Control", "private, max-age=3600")
	w.Write(data)
}

// posterImage serves a share's preview frame: GET /card/{id}/poster.jpg.
//
// The id is its own path segment because ServeMux wildcards must be whole
// segments, and the trailing .jpg is kept because some crawlers still sniff
// the extension before the Content-Type.
//
// Unauthenticated by necessity, since the unfurler bots that fetch og:image
// carry no cookies and no token. That is exactly why the gate below is a
// REFUSAL rather than a redirect: a protected share, a Receive Inbox or an
// expired share answers 404 and shows nothing. Anything else would put a frame of
// someone's video into chat providers' preview caches, which outlive deleting
// the share.
func (h *handler) posterImage(w http.ResponseWriter, r *http.Request) {
	// visibleShareVia is the canonical public gate: it already answers 404 for an
	// expired share and for a suspended or expired OWNER, so a poster cannot
	// outlive the link it previews. The META read, for the reason thumbImage
	// takes it: the image is a sidecar, so no file list and no source walk is
	// needed to answer. visibleShareVia rather than loadPublicShare, because a
	// protected share is REFUSED here rather than shown the password form.
	v, ok := h.visibleShareVia(r, h.viewMeta)
	if !ok || v.PasswordHash != "" {
		http.NotFound(w, r)
		return
	}
	data, err := h.shownPoster(v)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("X-Robots-Tag", "noindex")
	// Short, unlike the immutable static tiles: a replaced file should not
	// leave a stale frame on a CDN for a week.
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Write(data)
}
