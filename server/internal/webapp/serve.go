package webapp

import (
	"bytes"
	"embed"
	"errors"
	"html/template"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

// State is whether /app serves the installed bundle.
type State int

const (
	// StateOn serves the current install.
	StateOn State = iota
	// StateOff is the administrator's switch turned off.
	StateOff
	// StateMissing is no bundle installed.
	StateMissing
	// StateUpdating is an installed bundle this server no longer serves
	// (webbundle.Serves), waiting for the fetch of one it does.
	StateUpdating
)

// unavailableCSSPath is the stylesheet of the page answered in every state but
// on. The CSP allows no inline style, so the page links it, and it is
// answered whatever the state.
const unavailableCSSPath = "/app/.hyperdrop/unavailable.css"

//go:embed pages/unavailable.html pages/unavailable.css
var pageFS embed.FS

var (
	unavailablePage = template.Must(template.ParseFS(pageFS, "pages/unavailable.html"))
	unavailableCSS  = mustRead("pages/unavailable.css")
	// pageTime is the stylesheet's modification time: the binary's start.
	pageTime = time.Now()
)

func mustRead(name string) []byte {
	b, err := pageFS.ReadFile(name)
	if err != nil {
		panic(err)
	}
	return b
}

var stateText = map[State]struct{ Title, Note string }{
	StateOff: {
		"The administrator turned off the web version",
		"Use a HyperDrop app to reach this server, or ask its administrator to turn the web version back on.",
	},
	StateMissing: {
		"The web version isn't installed on this server yet",
		"Use a HyperDrop app to reach this server for now.",
	},
	StateUpdating: {
		"The web version is being updated",
		"This server has a newer version than the web version installed on it. Try again in a few minutes.",
	},
}

// contentTypes are the types a bundle's files are served as. Every
// stylesheet and script must carry its type, since nosniff makes the browser
// refuse one that does not, and a bare Linux box's own mime table can lack
// most of these.
var contentTypes = map[string]string{
	".html":        "text/html; charset=utf-8",
	".js":          "text/javascript; charset=utf-8",
	".mjs":         "text/javascript; charset=utf-8",
	".css":         "text/css; charset=utf-8",
	".wasm":        "application/wasm",
	".json":        "application/json",
	".map":         "application/json",
	".webmanifest": "application/manifest+json",
	".svg":         "image/svg+xml",
	".png":         "image/png",
	".ico":         "image/x-icon",
	".webp":        "image/webp",
	".woff2":       "font/woff2",
	".woff":        "font/woff",
	".txt":         "text/plain; charset=utf-8",
}

func contentType(name string) string {
	ext := strings.ToLower(path.Ext(name))
	if t, ok := contentTypes[ext]; ok {
		return t
	}
	if t := mime.TypeByExtension(ext); t != "" {
		return t
	}
	return "application/octet-stream"
}

// Handler serves /app and /app/... from st's current bundle while state says
// on, and the server's own unavailable page otherwise. csp is read on every
// answer, which all carry SecurityHeaders.
//
// A path naming a file answers it (its .gz sibling when the browser takes
// gzip); a path with no extension that names no file answers index.html, the
// client router's; anything else is 404. Nothing is listed, and every read
// goes through os.Root, so no link leads outside the install.
func Handler(st *Store, state func() State, csp func() string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SecurityHeaders(w.Header(), csp())
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path == "/app" {
			target := "/app/"
			if r.URL.RawQuery != "" {
				target += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, target, http.StatusPermanentRedirect)
			return
		}
		if r.URL.Path == unavailableCSSPath {
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
			w.Header().Set("Cache-Control", "no-cache")
			http.ServeContent(w, r, "unavailable.css", pageTime, bytes.NewReader(unavailableCSS))
			return
		}
		s := state()
		inst, ok := st.Current()
		if s == StateOn && !ok {
			s = StateMissing
		}
		if s != StateOn {
			unavailable(w, s)
			return
		}
		serveFile(w, r, inst.Dir, strings.TrimPrefix(r.URL.Path, "/app/"))
	})
}

func unavailable(w http.ResponseWriter, s State) {
	text, ok := stateText[s]
	if !ok {
		text = stateText[StateMissing]
	}
	var buf bytes.Buffer
	if err := unavailablePage.Execute(&buf, struct{ Title, Note, Stylesheet string }{text.Title, text.Note, unavailableCSSPath}); err != nil {
		http.Error(w, "the web version is unavailable", http.StatusServiceUnavailable)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Length", strconv.Itoa(buf.Len()))
	w.WriteHeader(http.StatusServiceUnavailable)
	w.Write(buf.Bytes())
}

func notFound(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "404 page not found", http.StatusNotFound)
}

func serveFile(w http.ResponseWriter, r *http.Request, dir, rel string) {
	name := "index.html"
	if rel != "" {
		name = path.Clean(rel)
	}
	if !fs.ValidPath(name) || name == "." || name == metaName {
		notFound(w)
		return
	}
	// An install whose directory or index.html cannot be opened has nothing
	// to serve: the answer is the missing page, as for no install at all.
	root, err := os.OpenRoot(dir)
	if err != nil {
		unavailable(w, StateMissing)
		return
	}
	defer root.Close()

	f, fi, err := openRegular(root, name)
	if err != nil && path.Ext(name) == "" {
		name = "index.html"
		f, fi, err = openRegular(root, name)
	}
	if err != nil && name == "index.html" {
		unavailable(w, StateMissing)
		return
	}
	if err != nil {
		notFound(w)
		return
	}
	defer f.Close()

	h := w.Header()
	h.Set("Content-Type", contentType(name))
	switch {
	case name == "index.html":
		h.Set("Cache-Control", "no-store")
	case strings.HasPrefix(name, "assets/"):
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
	default:
		h.Set("Cache-Control", "no-cache")
	}
	if gz, gzi, err := openRegular(root, name+".gz"); err == nil {
		defer gz.Close()
		h.Set("Vary", "Accept-Encoding")
		if acceptsGzip(r.Header.Values("Accept-Encoding")) {
			h.Set("Content-Encoding", "gzip")
			http.ServeContent(w, r, name, gzi.ModTime(), gz)
			return
		}
	}
	http.ServeContent(w, r, name, fi.ModTime(), f)
}

// openRegular opens name under root when it is a regular file.
func openRegular(root *os.Root, name string) (*os.File, os.FileInfo, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err == nil && !fi.Mode().IsRegular() {
		err = errors.New("not a regular file")
	}
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, fi, nil
}

// acceptsGzip reads Accept-Encoding: gzip listed with a nonzero quality.
func acceptsGzip(values []string) bool {
	for _, v := range values {
		for part := range strings.SplitSeq(v, ",") {
			coding, params, _ := strings.Cut(part, ";")
			if !strings.EqualFold(strings.TrimSpace(coding), "gzip") {
				continue
			}
			q := 1.0
			for p := range strings.SplitSeq(params, ";") {
				k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
				if ok && strings.EqualFold(strings.TrimSpace(k), "q") {
					if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
						q = f
					}
				}
			}
			return q > 0
		}
	}
	return false
}
