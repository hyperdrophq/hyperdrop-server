// Link previews: the Open Graph cards chat apps show when a share link is
// pasted. Cards carry metadata only (a name, a type, a size) and never a
// byte of file content, so no crawler ever decodes an untrusted file and no
// unauthenticated endpoint serves one.
//
// Single-file links point at /view and /download, which return the file
// itself, so there is no HTML for a crawler to read. Requests whose
// User-Agent names a known link unfurler get the card instead of the bytes;
// everyone else is untouched. That also stops a bot fetch of a /download or
// /zip link from costing a full transfer or a zip build.
package api

import (
	"bytes"
	"html/template"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"log"
	"net/http"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"

	"hyperdrop/server/internal/mimetype"
	"hyperdrop/server/internal/sharefs"
)

// unfurlerUAs are substrings identifying link-preview crawlers, matched
// case-insensitively. The list rots as apps rename their bots, and that
// failure is deliberately mild: an unrecognized crawler gets the raw
// response and no preview. It can never leak anything and never breaks a
// human's download.
//
// Spoofable, also deliberately: a forged bot User-Agent yields the card
// instead of the file, which is strictly less than the honest request would
// have returned.
var unfurlerUAs = []string{
	"telegrambot", "slackbot", "discordbot", "facebookexternalhit", "twitterbot",
	"whatsapp", "linkedinbot", "skypeuripreview", "iframely", "redditbot",
	"vkshare", "mastodon", "bluesky", "cardyb", "embedly",
	// Pinterest's crawlers, never bare "pinterest": its in-app browser adds
	// [Pinterest/iOS] or [Pinterest/Android] to an ordinary browser's agent,
	// and a person opening a link there must get the file, not the card.
	"pinterestbot", "pinterest/0.",
	"google-pagerenderer", "applebot", "signal-desktop", "nuzzel", "quora link preview",
}

func isUnfurler(ua string) bool {
	ua = strings.ToLower(ua)
	return slices.ContainsFunc(unfurlerUAs, func(bot string) bool { return strings.Contains(ua, bot) })
}

// ogCard is everything a preview shows. Nothing here may be transient:
// preview caches freeze whatever they see first, so a card reading
// "uploading… 40%" would read that forever.
type ogCard struct {
	Title       string
	Description string
	URL         string
	Image       string
	// Video, when set, makes the card a PLAYABLE one: chat apps that support
	// og:video fetch this URL and play the clip inline instead of showing a
	// still card. It is the file's own /view link.
	//
	// This is the one place a preview hands over file CONTENT rather than
	// metadata, so it is deliberately narrow: see videoCardFields for every
	// condition. The unfurler downloads the whole clip and caches a copy that
	// outlives deleting the share.
	Video       string
	VideoType   string
	VideoWidth  int
	VideoHeight int
}

// HasVideo drives the template: og:type and the player tags only appear for
// a card that really has a playable video. Exported because html/template
// can only call exported methods.
func (c ogCard) HasVideo() bool { return c.Video != "" }

// ogMediaParam marks a fetch as the card's own video request, so the
// unfurler branch hands over the bytes instead of the HTML card it would
// otherwise answer its own og:video URL with (see serveFile).
const ogMediaParam = "ogmedia"

// ogVideoMaxBytes caps what we advertise as inline-playable. Chat apps refuse
// to inline anything much larger anyway (Telegram's preview fetch gives up in
// this range), so past it the card would cost a full upload of the file for a
// preview that still falls back to the static image. Screen recordings out of
// HyperDrop's own encoder land far below it.
const ogVideoMaxBytes = 20 << 20

// videoCardFields decides whether a file may be advertised as a playable
// video, and returns the tag values when it may. Every condition exists for a
// reason a comment can name:
//
//   - MP4 only: it is the container/codec combination every unfurler and
//     browser plays, and the only one our own encoder produces. A raw .mov
//     shared from Finder would be fetched and then fail to play.
//   - committed only: a pending (early-link) file's /view serves a waiting
//     page. Preview caches freeze whatever they see first, so advertising a
//     video that isn't there yet would cache "broken" forever.
//   - size-capped: see ogVideoMaxBytes.
//
// Password-protected shares never reach here: they get protectedCard, whose
// whole point is revealing nothing.
//
// open hands the stored bytes over, through the file layer's open; a file it
// cannot open is a playable card without its header facts.
func videoCardFields(f fileView, open func() (*os.File, error)) (mime string, info mp4Info, ok bool) {
	if mimetype.BaseType(f.Mime) != "video/mp4" || f.Pending || f.Size <= 0 || f.Size > ogVideoMaxBytes {
		return "", mp4Info{}, false
	}
	if file, err := open(); err == nil {
		info = readMP4Info(file)
		file.Close()
	}
	return "video/mp4", info, true
}

const cardFooter = "Shared via HyperDrop"

// ogTagsTmpl renders the meta tags shared by the standalone card page and
// every public HTML page. noindex rides along: capability URLs are
// unguessable, but a leaked link that gets *indexed* is permanent in a way
// an unguessable one is not.
var ogTagsTmpl = page("ogtags", "ogtags.html")

// tags renders the card as meta tags for embedding in a page head. The
// result is template.HTML because the values are escaped here, once.
func (c ogCard) tags() template.HTML {
	var buf bytes.Buffer
	if err := ogTagsTmpl.Execute(&buf, c); err != nil {
		log.Printf("og tags: %v", err)
		return ""
	}
	return template.HTML(buf.String()) // #nosec G203 -- ogTagsTmpl is html/template, which escaped every value above
}

// cardTmpl is the standalone page served in place of file bytes. Crawlers
// read only the head; the body exists for the rare human who arrives with a
// spoofed User-Agent and would otherwise get a blank page.
var cardTmpl = page("card", "card.html")

// canonicalBase is the server's own public origin: the configured custom
// domain, else the public IP, else the request Host (plain-HTTP LAN mode,
// where the server has no canonical identity). Preferring the server's own
// identity keeps the attacker-controlled Host header out of links we mint.
func (h *handler) canonicalBase(r *http.Request) string {
	if id := h.dom.Identity(); id != "" {
		return "https://" + id
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func (h *handler) newCard(r *http.Request, title, desc, urlPath string) ogCard {
	base := h.canonicalBase(r)
	return ogCard{Title: title, Description: desc, URL: base + urlPath, Image: base + "/card.png"}
}

// withImage picks the card picture for a share: a real frame when there is one
// and the share is open, a generic play tile when it is video, the brand mark
// otherwise. See pickCardImage for why a protected share never gets a frame.
func (h *handler) withImage(c ogCard, r *http.Request, v shareView) ogCard {
	img := pickCardImage(v, shareHasVideo(v), h.fs.HasPoster(v.ID) && h.posterShown(v))
	c.Image = h.canonicalBase(r) + img.path(v.ID)
	return c
}

// fileLinkCard is the card a file link unfurls as: fileCard's words for the
// file (its base name, its kind, a video's duration, its size) at the link's
// own address /f/{fileKey}, with og:video at that address for a playable MP4
// as fileCard offers it. Its picture is fileLinkImage's. It reads nothing of
// the share but the file and the share's kind, so it names neither the share
// nor another file.
func (h *handler) fileLinkCard(r *http.Request, key string, v shareView, f fileView) ogCard {
	card := h.newCard(r, path.Base(f.Path), typeLabel(f.Mime, f.Path)+" · "+humanSize(f.Size)+" · "+cardFooter, "/f/"+key)
	card.Image = h.fileLinkImage(r, v, f)
	return h.withVideo(card, v, f)
}

// protectedFileLinkCard is what a file link of a password-protected share
// reveals, on its password form and to an unfurler: protectedCard's bare
// "Password-protected" at the link's own address, on fileLinkImage's picture.
// f is the zero fileView when the share no longer holds the file.
func (h *handler) protectedFileLinkCard(r *http.Request, key string, v shareView, f fileView) ogCard {
	card := h.newCard(r, "Password-protected", cardFooter, "/f/"+key)
	card.Image = h.fileLinkImage(r, v, f)
	return card
}

// fileLinkImage is a file link's card picture: pickCardImage's choice with no
// poster, which is the play tile for a video and the brand mark otherwise.
// The poster is the share's, and its address names the share, so the choice
// is composed with no share id at all.
func (h *handler) fileLinkImage(r *http.Request, v shareView, f fileView) string {
	return h.canonicalBase(r) + pickCardImage(v, isVideoMime(f.Mime) || isVideoExt(f.Path), false).path("")
}

// renderCard writes the standalone card page in place of a file or zip.
func (h *handler) renderCard(w http.ResponseWriter, c ogCard) {
	h.renderPage(w, framable, 0, false, cardTmpl, map[string]any{
		"Title": c.Title, "Description": c.Description, "URL": c.URL, "Tags": c.tags(),
	})
}

// fileCard describes one file: its name, what kind of thing it is, and how
// big. Pending (declared-but-not-uploaded) files use their manifest size, so
// an early link previews correctly from the moment it is created.
func (h *handler) fileCard(r *http.Request, v shareView, f fileView) ogCard {
	name := path.Base(f.Path)
	view := "/view/" + v.ID + "/" + f.Slug
	card := h.withImage(
		h.newCard(r, name, typeLabel(f.Mime, f.Path)+" · "+humanSize(f.Size)+" · "+cardFooter, view),
		r, v)
	return h.withVideo(card, v, f)
}

// withVideo adds an MP4's facts to its card: the duration in the description
// and, when the file qualifies (videoCardFields), og:video at the card's own
// URL with ogMediaParam, which the unfurler branch answers with the bytes.
func (h *handler) withVideo(card ogCard, v shareView, f fileView) ogCard {
	// A live share has no local file to read a frame or duration from, and a
	// linked entry's bytes live under its source folder rather than in the
	// share, which is where entryPath can name a file. Reading a live share's
	// frame this way would also hand an anonymous bot a URL that pulls real
	// bytes off the sharer's own uplink and caches them: the same
	// job-creation an unfurler must never cause anywhere else. The static
	// tile stands in for both, exactly as it does for an oversized or
	// still-pending video.
	if v.LiveShare || f.Linked {
		return card
	}
	// An MP4 gets a playable card: the clip plays inside the chat message
	// instead of a static tile. The duration goes in the description whether
	// or not the video qualifies for inline play: it is header metadata, the
	// same class of fact as the size.
	mime, info, ok := videoCardFields(f, func() (*os.File, error) {
		// The header facts describe the bytes of the row the card reads: a
		// file a publish committed meanwhile opens as another version, and
		// the card goes without them.
		file, _, opened, err := h.openStored(v.ID, f.Path, f.Slug)
		if err == nil && opened.SHA256 != f.SHA256 {
			file.Close()
			return nil, sharefs.ErrNotFound
		}
		return file, err
	})
	if info.Duration > 0 {
		card.Description = typeLabel(f.Mime, f.Path) + " · " + humanDuration(info.Duration) +
			" · " + humanSize(f.Size) + " · " + cardFooter
	}
	if !ok {
		return card
	}
	card.Video = card.URL + "?" + ogMediaParam + "=1"
	card.VideoType = mime
	card.VideoWidth, card.VideoHeight = info.Width, info.Height
	return card
}

// humanDuration renders a clip length the way a player does: "0:23", "4:07",
// "1:02:11".
func humanDuration(seconds int) string {
	if seconds < 0 {
		seconds = 0
	}
	h, m, s := seconds/3600, (seconds%3600)/60, seconds%60
	if h > 0 {
		return strconv.Itoa(h) + ":" + twoDigits(m) + ":" + twoDigits(s)
	}
	return strconv.Itoa(m) + ":" + twoDigits(s)
}

func twoDigits(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

// shareCard describes a whole share: the card for a folder listing or a
// zip link.
func (h *handler) shareCard(r *http.Request, v shareView) ogCard {
	n, total := v.Totals()
	count := fileCount(n)
	title := shareTitle(v)
	return h.withImage(h.newCard(r, title, count+" · "+humanSize(total)+" · "+cardFooter, "/share/"+v.ID),
		r, v)
}

// shareTitle is what a page or a card calls a share: its name, or how many
// files it holds when it has none.
func shareTitle(v shareView) string {
	if v.Name != "" {
		return v.Name
	}
	n, _ := v.Totals()
	return fileCount(n)
}

// fileCount is "1 file", "2 files".
func fileCount(n int) string {
	if n == 1 {
		return "1 file"
	}
	return strconv.Itoa(n) + " files"
}

// protectedCard is what a password-protected share reveals: that it exists
// and needs a password. The name stays behind the password, where the
// sharer put it.
//
// A Receive Inbox reveals exactly that and nothing about what it has
// received: the brand picture, and its own upload page as the address, its
// /share/ address answering 404. The card is built from the row alone, so
// no file of the inbox is read for it.
func (h *handler) protectedCard(r *http.Request, sh shareView) ogCard {
	if sh.Inbox {
		return h.newCard(r, "Password-protected", cardFooter, "/receive/"+sh.ID)
	}
	card := h.newCard(r, "Password-protected", cardFooter, "/share/"+sh.ID)
	// A locked VIDEO gets the generic play tile, so the link unfurls as
	// something rather than a blank card. Never a real frame: pickCardImage
	// refuses one for a protected share, and this reads the share only to
	// learn whether it holds video at all, which the windowed read answers
	// without walking a 200,000-file share for a tile nobody sees.
	if v, err := h.publicViewCapped(sh.ID); err == nil {
		card = h.withImage(card, r, v)
	}
	return card
}

// typeLabel names a file's kind for a card: its extension when it has a
// usable one ("PDF", "MP4"), else a class from the MIME type, else "File".
func typeLabel(mimeType, name string) string {
	if ext := strings.TrimPrefix(path.Ext(name), "."); ext != "" && len(ext) <= 5 {
		if isAlnum(ext) {
			return strings.ToUpper(ext)
		}
	}
	switch mt := mimetype.BaseType(mimeType); {
	case strings.HasPrefix(mt, "image/"):
		return "Image"
	case strings.HasPrefix(mt, "video/"):
		return "Video"
	case strings.HasPrefix(mt, "audio/"):
		return "Audio"
	case strings.HasPrefix(mt, "text/"):
		return "Text"
	}
	return "File"
}

func isAlnum(s string) bool {
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return false
		}
	}
	return true
}

// noIndex marks a public route as not for search engines.
func noIndex(w http.ResponseWriter) { w.Header().Set("X-Robots-Tag", "noindex") }

// ogImage serves the card image: one static picture, identical on every
// server and for every share, so it carries no share information and is safe
// to serve unauthenticated.
func (h *handler) ogImage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=604800, immutable")
	w.Write(ogPNG())
}

// ogPNG draws the card image once, on first use: the brand gradient with the
// white HyperDrop mark centred. Drawn rather than embedded as a binary blob:
// it is pure geometry (the same path as the inline SVG logo, scaled), and
// a reviewable diff beats an opaque PNG in git. No text, so no font.
var ogPNG = sync.OnceValue(func() []byte {
	const w, h = 1200, 630
	// The mark in the 64-unit viewBox of the inline SVG logo: an arrow, a
	// triangle head over a rectangular stem.
	const scale, cx, cy = 9.0, 600.0, 315.0
	at := func(x, y float64) (float64, float64) {
		return cx + (x-32)*scale, cy + (y-30)*scale
	}
	ax, ay := at(32, 14)
	bx, by := at(46, 31)
	cx3, cy3 := at(18, 31)
	rx0, ry0 := at(26, 31)
	rx1, ry1 := at(38, 46)
	inMark := func(x, y float64) bool {
		if x >= rx0 && x <= rx1 && y >= ry0 && y <= ry1 {
			return true
		}
		return inTriangle(x, y, ax, ay, bx, by, cx3, cy3)
	}

	top := [3]float64{0x6B, 0x52, 0xF2} // indigo
	bot := [3]float64{0x1C, 0xAD, 0xF8} // sky
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		t := float64(y) / float64(h-1)
		var bg [3]float64
		for i := range bg {
			bg[i] = top[i] + (bot[i]-top[i])*t
		}
		for x := 0; x < w; x++ {
			// 3x3 supersample so the arrow's diagonals aren't jagged.
			hits := 0
			for sy := 0; sy < 3; sy++ {
				for sx := 0; sx < 3; sx++ {
					px := float64(x) + (float64(sx)+0.5)/3
					py := float64(y) + (float64(sy)+0.5)/3
					if inMark(px, py) {
						hits++
					}
				}
			}
			cov := float64(hits) / 9
			var px [3]uint8
			for i := range px {
				px[i] = uint8(bg[i] + (255-bg[i])*cov + 0.5)
			}
			img.SetRGBA(x, y, color.RGBA{px[0], px[1], px[2], 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		log.Printf("og image: %v", err)
	}
	return buf.Bytes()
})

// inTriangle reports whether (px,py) lies inside the triangle abc, using the
// sign of the three edge cross-products.
func inTriangle(px, py, ax, ay, bx, by, cx, cy float64) bool {
	edge := func(x0, y0, x1, y1 float64) float64 {
		return (px-x0)*(y1-y0) - (py-y0)*(x1-x0)
	}
	d1, d2, d3 := edge(ax, ay, bx, by), edge(bx, by, cx, cy), edge(cx, cy, ax, ay)
	neg := d1 < 0 || d2 < 0 || d3 < 0
	pos := d1 > 0 || d2 > 0 || d3 > 0
	return !(neg && pos)
}

// ogVideoImage serves the generic video tile: the brand card with a play
// button over it. Static and identical for every share, like /card.png, so it
// carries no share information and is safe to serve unauthenticated.
//
// It exists for PROTECTED video shares, which must never expose a real frame
// (see pickCardImage), and for open ones whose poster has not landed yet.
func (h *handler) ogVideoImage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=604800, immutable")
	w.Write(ogVideoPNG())
}

// ogVideoPNG is ogPNG with a play triangle in a translucent disc, drawn the
// same way and for the same reason: pure geometry beats an opaque binary blob
// in git, and it needs no font.
var ogVideoPNG = sync.OnceValue(func() []byte {
	base := ogPNG()
	img, err := png.Decode(bytes.NewReader(base))
	if err != nil {
		return base
	}
	b := img.Bounds()
	dst := image.NewRGBA(b)
	draw.Draw(dst, b, img, b.Min, draw.Src)

	cx, cy := float64(b.Dx())/2, float64(b.Dy())/2
	const rOuter = 132.0
	white := color.RGBA{255, 255, 255, 255}
	disc := color.RGBA{0, 0, 0, 110}
	// Triangle pointing right, centred on the disc and optically balanced by
	// nudging it off the geometric centre.
	tri := [3][2]float64{{cx - 40, cy - 58}, {cx - 40, cy + 58}, {cx + 62, cy}}
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			fx, fy := float64(x)+0.5, float64(y)+0.5
			dx, dy := fx-cx, fy-cy
			if dx*dx+dy*dy > rOuter*rOuter {
				continue
			}
			if inTriangle(fx, fy, tri[0][0], tri[0][1], tri[1][0], tri[1][1], tri[2][0], tri[2][1]) {
				dst.Set(x, y, white)
			} else {
				dst.Set(x, y, blend(dst.RGBAAt(x, y), disc))
			}
		}
	}
	var out bytes.Buffer
	if err := png.Encode(&out, dst); err != nil {
		return base
	}
	return out.Bytes()
})

// blend puts src over dst (src alpha only; both are opaque-background here).
func blend(dst color.RGBA, src color.RGBA) color.RGBA {
	a := float64(src.A) / 255
	mix := func(s, d uint8) uint8 { return uint8(float64(s)*a + float64(d)*(1-a)) }
	return color.RGBA{mix(src.R, dst.R), mix(src.G, dst.G), mix(src.B, dst.B), 255}
}
