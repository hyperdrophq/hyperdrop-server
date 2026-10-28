// Package dsmpage is HyperDrop's page in DSM 7's main menu: a CGI program
// (`hyperdrop-server dsmpage`, run by the package's ui/index.cgi) that DSM's
// own web server runs once per request, as the package user, on DSM's
// origin. It serves the page and a small JSON API to DSM administrators.
//
// The process is short-lived and serves one request: it opens no data
// volume itself, binds nothing and reads no HYPERDROP_DATA. What it needs
// from the volume it asks the server binary's own subcommands for.
package dsmpage

import (
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

// ScriptPath is the address DSM serves the CGI at, the url in the package's
// ui/config. The page loads its assets and calls its API under it.
const ScriptPath = "/webman/3rdparty/hyperdrop/index.cgi"

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
	// environment it is given (authenticate.cgi), or "" for none.
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

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

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
	if d.Authenticate == nil {
		d.Authenticate = func(ctx context.Context, env []string) (string, error) {
			return runAuthenticate(ctx, authenticateCGI, env)
		}
	}
	if d.Groups == nil {
		d.Groups = func(ctx context.Context, user string) ([]string, error) {
			return runGroups(ctx, idProgram(), user)
		}
	}
	d.VarDir = orDefault(d.VarDir, packageVar)
	d.ConfPath = orDefault(d.ConfPath, d.VarDir+"/hyperdrop.conf")
	d.StatusPath = orDefault(d.StatusPath, d.VarDir+"/status.json")
	d.SharesDir = orDefault(d.SharesDir, "/var/packages/hyperdrop/shares")
	d.ProcRoot = orDefault(d.ProcRoot, "/proc")
	d.ServerBinary = orDefault(d.ServerBinary, packageTarget+"/bin/hyperdrop-server")
	d.Script = orDefault(d.Script, "/var/packages/hyperdrop/scripts/start-stop-status")
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
// returns the exit code.
func Serve() int {
	if err := cgi.Serve(onPathInfo(New(Deps{}), os.Getenv)); err != nil {
		fmt.Fprintf(os.Stderr, "dsmpage: %v\n", err)
		return 1
	}
	return 0
}

// onPathInfo routes a CGI request on PATH_INFO, the part of the address
// after ScriptPath, which net/http/cgi leaves inside the full URL path.
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
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", csp)
	h.Set("Referrer-Policy", "no-referrer")

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

// writeError answers {"error": msg}, msg being one sentence the page shows.
func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
