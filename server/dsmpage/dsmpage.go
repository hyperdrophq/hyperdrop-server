// Package dsmpage is HyperDrop's page in DSM's main menu: a CGI program
// (`hyperdrop-server dsmpage`, run by the package's ui/index.cgi) that DSM's
// own web server runs once per request on DSM's origin, as the package user
// (DSM 6 runs it as root and it becomes the package user first, root.go). It
// serves the page and a small JSON API to DSM administrators.
//
// The process is short-lived and serves one request: it opens no data
// volume itself, binds nothing and reads no HYPERDROP_DATA. What it needs
// from the volume it asks the server binary's own subcommands for.
package dsmpage

import (
	"cmp"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/cgi"
	"os"
	"slices"
	"strings"
)

//go:embed assets
var assets embed.FS

// assetTypes are the files under /assets/ and their content types. The
// page itself (assets/index.html) is served only at "/".
var assetTypes = map[string]string{
	"page.js":  "text/javascript; charset=utf-8",
	"page.css": "text/css; charset=utf-8",
}

// csp allows the page its own scripts, styles, images and API calls and
// nothing else: no inline code, no other origin, no framing by another site.
const csp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; " +
	"connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'"

// Deps are the DSM programs the page runs. A nil field takes the real one.
type Deps struct {
	// Environ is the CGI request's environment (os.Environ).
	Environ func() []string
	// Authenticate answers the DSM user signed in to the request whose
	// environment it is given, or "" for none: on DSM 7 authenticate.cgi,
	// on DSM 6 DSM's web API on loopback (webapi.go).
	Authenticate func(ctx context.Context, env []string) (string, error)
	// Groups answers the DSM groups a user belongs to (id -Gn).
	Groups func(ctx context.Context, user string) ([]string, error)
	// ConfPath is the package's hyperdrop.conf, StatusPath the server's
	// status file, SharesDir the folder holding the shared-folder links the
	// data folder is reached through, ProcRoot the process table and
	// ServerBinary the program a running server executes (and the one the
	// worker and the admin rescue's subcommands run).
	ConfPath, StatusPath, SharesDir, ProcRoot, ServerBinary string
	// VarDir is the package's var directory, which holds the worker's lock,
	// its job, last-change.json, address-request and the admin rescue's
	// password seed. Script is the package's start-stop-status.
	VarDir, Script string
	// Major is the DSM generation, 6 or 7; 0 reads it from VersionFile
	// (/etc.defaults/VERSION). Target is the package's target link, which
	// on DSM 6 names the volume VarDir is on.
	Major               int
	VersionFile, Target string
	// Service stops, starts and checks the server (start-stop-status).
	Service Service
	// StartWorker starts the worker on the job file (a Save, an admin
	// rescue or the wait after a storage move), handing it the lock, and
	// returns without waiting for it.
	StartWorker func(job string, lock *os.File) error
}

const (
	packageVar    = "/var/packages/hyperdrop/var"
	packageTarget = "/var/packages/hyperdrop/target"
)

// apiHandler serves one API route for the DSM administrator user.
type apiHandler func(w http.ResponseWriter, r *http.Request, user string)

// apiRoute is a route's handler for each method it answers.
type apiRoute map[string]apiHandler

type page struct {
	deps Deps
	api  map[string]apiRoute
}

// New returns the page's handler, routing on the request's URL path, which
// is the CGI's PATH_INFO ("/" for the page itself).
func New(d Deps) http.Handler {
	return newPage(d)
}

// newPage fills d's defaults.
func newPage(d Deps) *page {
	if d.Environ == nil {
		d.Environ = os.Environ
	}
	d.VersionFile = cmp.Or(d.VersionFile, versionFile)
	if d.Major == 0 {
		d.Major = readMajor(d.VersionFile)
	}
	if d.Authenticate == nil {
		if d.Major == 6 {
			d.Authenticate = webAPIAuthenticate
		} else {
			d.Authenticate = func(ctx context.Context, env []string) (string, error) {
				return runAuthenticate(ctx, authenticateCGI, env)
			}
		}
	}
	if d.Groups == nil {
		d.Groups = func(ctx context.Context, user string) ([]string, error) {
			return runGroups(ctx, idProgram(), user)
		}
	}
	d.Target = cmp.Or(d.Target, packageTarget)
	if d.Major == 6 {
		// A target under no volume leaves VarDir empty: every route then
		// answers its locked or empty shape, and nothing reads a path under
		// /var/packages.
		d.VarDir = cmp.Or(d.VarDir, dsm6VarDir(d.Target))
	} else {
		d.VarDir = cmp.Or(d.VarDir, packageVar)
	}
	if d.VarDir != "" {
		d.ConfPath = cmp.Or(d.ConfPath, d.VarDir+"/hyperdrop.conf")
		d.StatusPath = cmp.Or(d.StatusPath, d.VarDir+"/status.json")
	}
	d.SharesDir = cmp.Or(d.SharesDir, "/var/packages/hyperdrop/shares")
	d.ProcRoot = cmp.Or(d.ProcRoot, "/proc")
	d.ServerBinary = cmp.Or(d.ServerBinary, packageTarget+"/bin/hyperdrop-server")
	d.Script = cmp.Or(d.Script, "/var/packages/hyperdrop/scripts/start-stop-status")
	if d.StartWorker == nil {
		bin := d.ServerBinary
		d.StartWorker = func(job string, lock *os.File) error { return startWorker(bin, job, lock) }
	}
	p := &page{deps: d}
	if p.deps.Service == nil {
		p.deps.Service = newScriptService(p)
	}
	p.api = map[string]apiRoute{
		"/api/state":               {http.MethodGet: p.serveState},
		"/api/settings":            {http.MethodPost: p.serveSettings},
		"/api/rescue":              {http.MethodGet: p.serveAdmins, http.MethodPost: p.serveRescue},
		"/api/storage":             {http.MethodGet: p.serveStorage},
		"/api/storage/stop":        {http.MethodPost: p.serveStopForMove},
		"/api/storage/stop-failed": {http.MethodPost: p.serveStopFailed},
		"/api/storage/start":       {http.MethodPost: p.serveStartAfterMove},
	}
	return p
}

// Serve answers the one CGI request in this process's environment and
// returns the exit code. A process that starts as root (DSM 6) first runs
// the root step (root.go), which leaves it the package user; when that
// refuses, every request gets its sentence and nothing else runs.
func Serve() int {
	h := http.Handler(nil)
	if err := realRootStep().run(); err != nil {
		h = serveRefusal(err)
	} else {
		h = New(Deps{})
	}
	if err := cgi.Serve(onPathInfo(h, os.Getenv)); err != nil {
		fmt.Fprintf(os.Stderr, "dsmpage: %v\n", err)
		return 1
	}
	return 0
}

// onPathInfo routes a CGI request on PATH_INFO, the part of the address
// after the CGI's own, which net/http/cgi leaves inside the full URL path.
func onPathInfo(h http.Handler, getenv func(string) string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r2 := r.Clone(r.Context())
		r2.URL.Path = getenv("PATH_INFO")
		if r2.URL.Path == "" {
			r2.URL.Path = "/"
		}
		r2.URL.RawPath = ""
		h.ServeHTTP(w, r2)
	})
}

// ServeHTTP serves the page and its assets to anyone, since they carry no
// data and the browser loads them without DSM's token header, and every
// /api/ route only after requireDSMAdmin, which runs before the route or
// method is even looked at.
func (p *page) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	setHeaders(h)

	path := r.URL.Path
	if strings.HasPrefix(path, "/api/") {
		user, code, err := p.requireDSMAdmin(r)
		if err != nil {
			writeError(w, code, err.Error())
			return
		}
		rt, ok := p.api[path]
		if !ok {
			writeError(w, http.StatusNotFound, "No such request.")
			return
		}
		serve, ok := rt[r.Method]
		if !ok {
			h.Set("Allow", strings.Join(slices.Sorted(maps.Keys(rt)), ", "))
			writeError(w, http.StatusMethodNotAllowed, "Wrong method for this request.")
			return
		}
		serve(w, r, user)
		return
	}
	serveStatic(w, r)
}

// setHeaders sets the headers every answer of the CGI carries.
func setHeaders(h http.Header) {
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", csp)
	h.Set("Referrer-Policy", "no-referrer")
}

// serveStatic serves the page ("/") and its assets, which hold no data.
func serveStatic(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	path := r.URL.Path
	name, ctype := "", ""
	switch {
	case path == "/":
		name, ctype = "index.html", "text/html; charset=utf-8"
	case strings.HasPrefix(path, "/assets/"):
		name = strings.TrimPrefix(path, "/assets/")
		ctype = assetTypes[name]
	}
	if ctype == "" {
		http.Error(w, "Not found.", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.Set("Allow", "GET, HEAD")
		http.Error(w, "Method not allowed.", http.StatusMethodNotAllowed)
		return
	}
	body, err := assets.ReadFile("assets/" + name)
	if err != nil {
		http.Error(w, "Not found.", http.StatusNotFound)
		return
	}
	h.Set("Content-Type", ctype)
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		w.Write(body)
	}
}

// writeJSON answers v as JSON with the status code.
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// dsmReplaces are the statuses whose body DSM's web server replaces with its
// own error page when a package's CGI answers them (error_page with
// scgi_intercept_errors in DSM's nginx), on DSM 6 and DSM 7.
var dsmReplaces = map[int]bool{
	http.StatusForbidden: true, http.StatusNotFound: true, http.StatusInternalServerError: true,
	http.StatusBadGateway: true, http.StatusServiceUnavailable: true, http.StatusGatewayTimeout: true,
}

// writeError answers {"error": msg}, msg being one sentence the page shows.
// A status DSM would replace travels as 200 with the status beside the
// sentence ({"error", "status"}), or the sentence would never reach the
// page; the page's script reads both forms.
func writeError(w http.ResponseWriter, code int, msg string) {
	if dsmReplaces[code] {
		writeJSON(w, http.StatusOK, map[string]any{"error": msg, "status": code})
		return
	}
	writeJSON(w, code, map[string]string{"error": msg})
}
