package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"io"
	"mime"
	"net/http"
	"path"
	"strings"

	nethtml "golang.org/x/net/html"
)

// A share's page that names no tab icon of its own makes the browser ask
// for /favicon.ico at the file origin's root, which is HyperDrop's mark. So
// a page served as a page (/site and /view, inline) whose first bytes
// declare no icon link is given one, pointing at the share's own icon file
// through the route the page came by: the same origin, the same sandbox and
// the same gate as any other file of the share. A share holding no icon file
// gets no icon link, and the tab keeps HyperDrop's.
//
// iOS takes a page's lock-screen artwork, while it plays sound, from the
// icon links in its head, touch icons first, and with none stretches the
// 48 px /favicon.ico. The site author's icon always wins: a page that
// declares any icon of its own (an icon link or a touch icon) is given no
// touch icon. A page that declares none is given the share's
// apple-touch-icon.png nearest it, addressed and versioned like the tab
// icon; failing that, when the share holds no icon file at all on the
// page's path (no favicon.* and no apple-touch-icon.png in the page's
// folder or any folder above it), the server's 512 px mark on the page's
// own origin. A share holding only a favicon.* on that path gets its tab
// icon link alone.
//
// Only a top-level document load is rewritten (documentLoad): the tab icon
// and the lock-screen artwork are both read from the main frame. A page a
// site's own script fetches and inserts, or loads in a frame, is served
// byte for byte under the stored file's entity tag, so a fragment keeps its
// one root element and a script comparing the text sees the file. The two
// answers differ, so a page that could be rewritten varies by
// Sec-Fetch-Dest.

// pageIconNames are the files that count as a share's icon, in the order
// one folder is searched.
var pageIconNames = []string{"favicon.ico", "favicon.svg", "favicon.png"}

// pageTouchIconNames are the files that count as a share's touch icon.
var pageTouchIconNames = []string{"apple-touch-icon.png"}

// serverTouchIcon is the server's own touch icon (icon.go), which answers
// on either origin.
const serverTouchIcon = "/apple-touch-icon.png"

// pageIcons are the addresses of a share's icon files nearest one page, ""
// for a kind the share does not hold.
type pageIcons struct{ icon, touch string }

// pageIconsFor finds both icons nearest a page and addresses each through
// addr, versioned by its state.
func pageIconsFor(files fileLookup, page string, addr func(fileView) string) pageIcons {
	var out pageIcons
	if f, ok := pageIcon(files, page, pageIconNames); ok {
		out.icon = addr(f) + "?v=" + iconVersion(f)
	}
	if f, ok := pageIcon(files, page, pageTouchIconNames); ok {
		out.touch = addr(f) + "?v=" + iconVersion(f)
	}
	return out
}

// pageHeadWindow bounds how much of a page is read to find its head. A page
// whose head is not over within it is served unmodified: an icon link may
// still come after.
const pageHeadWindow = 64 << 10

// pageIcon finds the icon nearest a page, one of names: its own folder
// first, then each folder above it up to the share's root. The names match
// exactly and case-sensitively, like indexName; a file still uploading is
// not an icon.
func pageIcon(files fileLookup, page string, names []string) (fileView, bool) {
	dir := path.Dir(page)
	for {
		prefix := ""
		if dir != "." {
			prefix = dir + "/"
		}
		for _, name := range names {
			if f, ok := files.byPath(prefix + name); ok && !f.Pending {
				return f, true
			}
		}
		if dir == "." {
			return fileView{}, false
		}
		dir = path.Dir(dir)
	}
}

// iconVersion names one state of an icon file, so a new or changed icon is
// a new address and a cached old one is never shown in its place: a stored
// file's content hash, a linked entry's size and modification time.
func iconVersion(f fileView) string {
	if len(f.SHA256) >= 16 {
		return f.SHA256[:16]
	}
	var at int64
	if f.CommittedAt != nil {
		at = f.CommittedAt.UnixNano()
	}
	sum := sha256.Sum256(fmt.Appendf(nil, "%d:%d", f.Size, at))
	return hex.EncodeToString(sum[:8])
}

// pageIconLink is the element inserted into a page for an icon address.
func pageIconLink(href string) string {
	return `<link rel="icon" href="` + html.EscapeString(href) + `">`
}

// pageTouchLink is the element inserted into a page for a touch icon
// address. Every touch icon it names is declared at the 512 px square iOS
// scores best; a share's own is taken at its word.
func pageTouchLink(href string) string {
	return `<link rel="apple-touch-icon" sizes="512x512" href="` + html.EscapeString(href) + `">`
}

// pageIconLinks is the markup given to a page that declares declared: the
// share's tab icon unless the page names one; and, only when the page
// declares no icon of any kind, the share's touch icon, or the server's when
// icons holds no icon file of either kind. "" when the page is given nothing.
func pageIconLinks(declared pageDeclares, icons pageIcons) string {
	links := ""
	if !declared.icon && icons.icon != "" {
		links += pageIconLink(icons.icon)
	}
	if declared.icon || declared.touch {
		return links
	}
	switch {
	case icons.touch != "":
		links += pageTouchLink(icons.touch)
	case icons.icon == "":
		links += pageTouchLink(serverTouchIcon)
	}
	return links
}

// documentLoad reports whether a request loads a page as the top-level
// document, the one load a page's icon links serve. A request with no
// Sec-Fetch-Dest (an older browser, curl) counts as one.
func documentLoad(r *http.Request) bool {
	dest := r.Header.Get("Sec-Fetch-Dest")
	return dest == "" || dest == "document"
}

// addVary adds header to a response's Vary unless it already names it.
func addVary(w http.ResponseWriter, header string) {
	for _, v := range w.Header().Values("Vary") {
		for _, name := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(name), header) {
				return
			}
		}
	}
	w.Header().Add("Vary", header)
}

// iconLinkTag is the entity-tag suffix of a page sent with link, so the
// same page with other icon markup is another representation.
func iconLinkTag(link string) string {
	sum := sha256.Sum256([]byte(link))
	return "-i" + hex.EncodeToString(sum[:8])
}

// rewritablePage reports whether a served type is an HTML page the link can
// be spliced into: text/html in UTF-8 or with no charset named. XHTML is an
// XML document a stray element would break, and a page in a UTF-16 encoding
// cannot take ASCII bytes.
func rewritablePage(mimeType string) bool {
	mt, params, err := mime.ParseMediaType(mimeType)
	if err != nil || mt != "text/html" {
		return false
	}
	cs := strings.ToLower(params["charset"])
	return cs == "" || cs == "utf-8" || cs == "utf8"
}

// headOnlyTags are the elements a head may hold. Any other start tag, or
// text that is not whitespace, ends the head the way a browser's parser
// ends it.
var headOnlyTags = map[string]bool{
	"html": true, "head": true, "base": true, "basefont": true, "bgsound": true,
	"link": true, "meta": true, "title": true, "style": true, "script": true,
	"noscript": true, "noframes": true, "template": true,
}

// rawTextTags are the elements whose content the tokenizer hands back as
// text, so a <link> written inside one is not an element.
var rawTextTags = map[string]bool{
	"title": true, "style": true, "script": true, "noscript": true, "noframes": true,
	"textarea": true, "xmp": true, "iframe": true, "noembed": true, "plaintext": true,
}

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// pageDeclares says which icons a page names itself.
type pageDeclares struct {
	// icon: a <link> whose rel holds the token "icon", in any case (which
	// "shortcut icon" holds too; apple-touch-icon and mask-icon do not set
	// the tab's icon), anywhere in the window, a link in the body included,
	// since a browser honours that one too.
	icon bool
	// touch: a <link> whose rel holds apple-touch-icon or
	// apple-touch-icon-precomposed, anywhere in the window like icon.
	touch bool
}

// pageIconInsert answers the offset in a page's first bytes where icon links
// belong and the icons the page declares, or false when nothing may be
// inserted: the bytes are a UTF-16 document, or the window ends before the
// head does. complete says b is the whole page.
//
// The links go right after <head ...>. A page with no head tag takes it
// after <html ...>, or after its doctype, or at its start (after a byte
// order mark): a browser places a <link> met before the body in the head it
// implies, and inserting ahead of a doctype would drop the page into quirks
// mode.
func pageIconInsert(b []byte, complete bool) (int, pageDeclares, bool) {
	var declared pageDeclares
	if len(b) >= 2 && (b[0] == 0xFE && b[1] == 0xFF || b[0] == 0xFF && b[1] == 0xFE) {
		return 0, declared, false
	}
	base := 0
	if bytes.HasPrefix(b, utf8BOM) {
		base = len(utf8BOM)
	}
	z := nethtml.NewTokenizer(bytes.NewReader(b[base:]))
	at, off := base, base
	inHead, headTag := true, false
	raw, template := "", 0
	for {
		tt := z.Next()
		off += len(z.Raw())
		if tt == nethtml.ErrorToken {
			if !errors.Is(z.Err(), io.EOF) {
				return 0, declared, false
			}
			break
		}
		// A token reaching the window's edge may be cut short: it decides
		// nothing.
		if !complete && off >= len(b) {
			break
		}
		switch tt {
		case nethtml.DoctypeToken:
			if inHead && !headTag {
				at = off
			}
		case nethtml.TextToken:
			if raw == "" && template == 0 && len(bytes.TrimSpace(z.Raw())) > 0 {
				inHead = false
			}
		case nethtml.StartTagToken, nethtml.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			tag := string(name)
			if tag == "link" && hasAttr {
				icon, touch := linkRels(z)
				declared.icon = declared.icon || icon
				declared.touch = declared.touch || touch
			}
			if template > 0 {
				if tag == "template" {
					template++
				}
				continue
			}
			switch {
			case tag == "template" && tt == nethtml.StartTagToken:
				template++
			case tag == "html" && inHead && !headTag:
				at = off
			case tag == "head" && inHead && !headTag:
				at, headTag = off, true
			case !headOnlyTags[tag]:
				inHead = false
			}
			if rawTextTags[tag] && tt == nethtml.StartTagToken {
				raw = tag
			}
		case nethtml.EndTagToken:
			name, _ := z.TagName()
			tag := string(name)
			switch {
			case tag == raw:
				raw = ""
			case tag == "template" && template > 0:
				template--
			case tag == "head" && template == 0:
				inHead = false
			}
		}
	}
	if inHead && !complete {
		return 0, declared, false
	}
	return at, declared, true
}

// linkRels reports whether the current <link> tag's rel holds the token
// "icon", and whether it holds a touch icon's.
func linkRels(z *nethtml.Tokenizer) (icon, touch bool) {
	for {
		key, val, more := z.TagAttr()
		if string(key) == "rel" {
			for _, tok := range strings.Fields(strings.ToLower(string(val))) {
				switch tok {
				case "icon":
					icon = true
				case "apple-touch-icon", "apple-touch-icon-precomposed":
					touch = true
				}
			}
		}
		if !more {
			return icon, touch
		}
	}
}

// withPageIcon splices icon links into a page whose bytes rs holds (size
// long, positioned at its start), answering the rewritten page and the
// markup it carries, or false when the page is served as it is. Only the
// window is read here; the rest streams from rs.
func withPageIcon(rs io.ReadSeeker, size int64, icons pageIcons) (io.ReadSeeker, string, bool) {
	buf := make([]byte, min(size, pageHeadWindow))
	n, err := io.ReadFull(rs, buf)
	if _, serr := rs.Seek(0, io.SeekStart); serr != nil {
		return nil, "", false
	}
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, "", false
	}
	buf = buf[:n]
	at, declared, ok := pageIconInsert(buf, int64(n) >= size)
	if !ok {
		return nil, "", false
	}
	link := pageIconLinks(declared, icons)
	if link == "" {
		return nil, "", false
	}
	head := make([]byte, 0, n+len(link))
	head = append(head, buf[:at]...)
	head = append(head, link...)
	head = append(head, buf[at:]...)
	return &splicedPage{head: head, rest: rs, restAt: int64(n), size: size + int64(len(link)), restPos: -1}, link, true
}

// splicedPage is a page read as its rewritten first bytes followed by the
// rest of the file, seekable so http.ServeContent can size it and answer a
// Range from it.
type splicedPage struct {
	head    []byte
	rest    io.ReadSeeker
	restAt  int64 // where the rest begins in the file
	size    int64 // the rewritten page's length
	pos     int64
	restPos int64 // rest's offset in the file, -1 when unknown
}

func (p *splicedPage) Read(b []byte) (int, error) {
	if p.pos >= p.size {
		return 0, io.EOF
	}
	if h := int64(len(p.head)); p.pos < h {
		n := copy(b, p.head[p.pos:])
		p.pos += int64(n)
		return n, nil
	}
	want := p.restAt + p.pos - int64(len(p.head))
	if p.restPos != want {
		if _, err := p.rest.Seek(want, io.SeekStart); err != nil {
			p.restPos = -1
			return 0, err
		}
		p.restPos = want
	}
	if left := p.size - p.pos; int64(len(b)) > left {
		b = b[:left]
	}
	n, err := p.rest.Read(b)
	p.pos += int64(n)
	p.restPos += int64(n)
	if errors.Is(err, io.EOF) && p.pos < p.size {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

func (p *splicedPage) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		offset += p.pos
	case io.SeekEnd:
		offset += p.size
	default:
		return 0, errors.New("splicedPage: bad whence")
	}
	if offset < 0 {
		return 0, errors.New("splicedPage: negative position")
	}
	p.pos = offset
	return offset, nil
}
