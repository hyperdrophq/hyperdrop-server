package dsmpage

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeDSM stands in for authenticate.cgi and id: it answers user for the
// session and groups for each user, and counts how often each one ran.
type fakeDSM struct {
	user    string
	authErr error
	groups  map[string][]string

	authCalls, groupCalls int
	env                   []string
	authDeadline          time.Duration
	groupDeadline         time.Duration
}

var cgiEnv = []string{"HTTP_X_SYNO_TOKEN=tok", "HTTP_COOKIE=id=session", "REMOTE_ADDR=192.0.2.7"}

func (f *fakeDSM) handler() http.Handler {
	return New(Deps{
		Environ: func() []string { return slices.Clone(cgiEnv) },
		Authenticate: func(ctx context.Context, env []string) (string, error) {
			f.authCalls++
			f.env = env
			if dl, ok := ctx.Deadline(); ok {
				f.authDeadline = time.Until(dl)
			}
			return f.user, f.authErr
		},
		Groups: func(ctx context.Context, user string) ([]string, error) {
			f.groupCalls++
			if dl, ok := ctx.Deadline(); ok {
				f.groupDeadline = time.Until(dl)
			}
			return f.groups[user], nil
		},
	})
}

var apiRoutes = []struct{ method, path string }{
	{"GET", "/api/state"},
	{"POST", "/api/settings"},
	{"GET", "/api/rescue"},
	{"POST", "/api/rescue"},
	{"GET", "/api/storage"},
	{"POST", "/api/storage/stop"},
	{"POST", "/api/storage/stop-failed"},
	{"POST", "/api/storage/start"},
}

func call(t *testing.T, h http.Handler, method, path string, token bool) *httptest.ResponseRecorder {
	t.Helper()
	var body *strings.Reader
	if method == "POST" {
		body = strings.NewReader("{}")
	} else {
		body = strings.NewReader("")
	}
	r := httptest.NewRequest(method, path, body)
	if token {
		r.Header.Set("X-SYNO-TOKEN", "tok")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func errorText(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type %q, want JSON (body %q)", ct, w.Body.String())
	}
	var v struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("body %q: %v", w.Body.String(), err)
	}
	return v.Error
}

func TestAPIWithoutATokenAnswers401AndRunsNothing(t *testing.T) {
	f := &fakeDSM{user: "alice", groups: map[string][]string{"alice": {"administrators"}}}
	h := f.handler()
	for _, rt := range apiRoutes {
		w := call(t, h, rt.method, rt.path, false)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s: %d, want 401", rt.method, rt.path, w.Code)
		}
		if got := errorText(t, w); got != "Sign in to DSM again." {
			t.Errorf("%s %s: error %q", rt.method, rt.path, got)
		}
	}
	if f.authCalls != 0 || f.groupCalls != 0 {
		t.Errorf("ran authenticate %d times and id %d times without a token", f.authCalls, f.groupCalls)
	}
}

func TestAPIWithoutAValidDSMUserAnswers401(t *testing.T) {
	for _, tc := range []struct {
		name string
		user string
		err  error
	}{
		{"empty", "", nil},
		{"spaces only", "  \n", nil},
		{"a space inside", "bob smith", nil},
		{"a slash", "a/b", nil},
		{"a second line", "alice\nroot", nil},
		{"too long", strings.Repeat("a", 65), nil},
		{"authenticate failed", "alice", errors.New("exit status 1")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeDSM{user: tc.user, authErr: tc.err,
				groups: map[string][]string{tc.user: {"administrators"}, "alice": {"administrators"}}}
			h := f.handler()
			for _, rt := range apiRoutes {
				w := call(t, h, rt.method, rt.path, true)
				if w.Code != http.StatusUnauthorized {
					t.Errorf("%s %s: %d, want 401", rt.method, rt.path, w.Code)
				}
				if got := errorText(t, w); got != "Sign in to DSM again." {
					t.Errorf("%s %s: error %q", rt.method, rt.path, got)
				}
			}
			if f.groupCalls != 0 {
				t.Errorf("ran id %d times for user %q", f.groupCalls, tc.user)
			}
		})
	}
}

func TestAPIForANonAdministratorAnswers403OnEveryRoute(t *testing.T) {
	for _, groups := range [][]string{nil, {"users"}, {"users", "administrators2"}, {"Administrators"}} {
		f := &fakeDSM{user: "bob", groups: map[string][]string{"bob": groups}}
		h := f.handler()
		for _, rt := range apiRoutes {
			w := call(t, h, rt.method, rt.path, true)
			if w.Code != http.StatusForbidden {
				t.Errorf("groups %q, %s %s: %d, want 403", groups, rt.method, rt.path, w.Code)
			}
			if got := errorText(t, w); got != "Only DSM administrators can use this page." {
				t.Errorf("%s %s: error %q", rt.method, rt.path, got)
			}
		}
	}
}

func TestAuthenticateGetsTheCGIEnvironmentAndBothChecksATimeout(t *testing.T) {
	f := &fakeDSM{user: "alice", groups: map[string][]string{"alice": {"administrators"}}}
	call(t, f.handler(), "GET", "/api/state", true)
	if !slices.Equal(f.env, cgiEnv) {
		t.Errorf("authenticate got env %q, want the CGI's %q", f.env, cgiEnv)
	}
	for name, d := range map[string]time.Duration{"authenticate": f.authDeadline, "id": f.groupDeadline} {
		if d <= 0 || d > commandTimeout {
			t.Errorf("%s ran with %v left, want a deadline within %v", name, d, commandTimeout)
		}
	}
}

func TestAPIRoutesCheckTheSessionBeforeTheMethodOrThePath(t *testing.T) {
	f := &fakeDSM{user: "alice", groups: map[string][]string{"alice": {"administrators"}}}
	h := f.handler()
	if w := call(t, h, "GET", "/api/nope", false); w.Code != http.StatusUnauthorized {
		t.Errorf("unknown route without a token: %d, want 401", w.Code)
	}
	if w := call(t, h, "GET", "/api/settings", false); w.Code != http.StatusUnauthorized {
		t.Errorf("wrong method without a token: %d, want 401", w.Code)
	}
	w := call(t, h, "GET", "/api/nope", true)
	if w.Code != http.StatusNotFound {
		t.Errorf("unknown route: %d, want 404", w.Code)
	}
	errorText(t, w)
	w = call(t, h, "GET", "/api/settings", true)
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "POST" {
		t.Errorf("GET settings: %d Allow %q, want 405 Allow POST", w.Code, w.Header().Get("Allow"))
	}
	errorText(t, w)
}

func TestThePageAndItsAssetsNeedNoSession(t *testing.T) {
	f := &fakeDSM{}
	h := f.handler()
	for path, ctype := range map[string]string{
		"/":                "text/html; charset=utf-8",
		"/assets/page.js":  "text/javascript; charset=utf-8",
		"/assets/page.css": "text/css; charset=utf-8",
	} {
		w := call(t, h, "GET", path, false)
		if w.Code != http.StatusOK {
			t.Errorf("GET %s: %d, want 200", path, w.Code)
		}
		if got := w.Header().Get("Content-Type"); got != ctype {
			t.Errorf("GET %s: Content-Type %q, want %q", path, got, ctype)
		}
		if w.Body.Len() == 0 {
			t.Errorf("GET %s: empty body", path)
		}
	}
	if f.authCalls != 0 {
		t.Errorf("the page ran authenticate %d times", f.authCalls)
	}
	for _, path := range []string{"/assets/index.html", "/assets/", "/assets/../api/state", "/index.html", "/nope"} {
		if w := call(t, h, "GET", path, false); w.Code != http.StatusNotFound {
			t.Errorf("GET %s: %d, want 404", path, w.Code)
		}
	}
	if w := call(t, h, "POST", "/", false); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /: %d, want 405", w.Code)
	}
}

func TestEveryResponseCarriesTheHeaders(t *testing.T) {
	f := &fakeDSM{user: "alice", groups: map[string][]string{"alice": {"administrators"}}}
	h := f.handler()
	for _, tc := range []struct {
		method, path string
		token        bool
	}{
		{"GET", "/", false}, {"GET", "/assets/page.js", false}, {"GET", "/nope", false},
		{"GET", "/api/state", false}, {"GET", "/api/state", true}, {"POST", "/api/settings", true},
	} {
		w := call(t, h, tc.method, tc.path, tc.token)
		hd := w.Header()
		if hd.Get("Cache-Control") != "no-store" || hd.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s %s: Cache-Control %q, X-Content-Type-Options %q", tc.method, tc.path,
				hd.Get("Cache-Control"), hd.Get("X-Content-Type-Options"))
		}
		csp := hd.Get("Content-Security-Policy")
		for _, want := range []string{"default-src 'none'", "script-src 'self'", "style-src 'self'", "connect-src 'self'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("%s %s: CSP %q lacks %s", tc.method, tc.path, csp, want)
			}
		}
		if strings.Contains(csp, "unsafe-") {
			t.Errorf("%s %s: CSP %q allows unsafe sources", tc.method, tc.path, csp)
		}
	}
}

// The page is served at the address ui/config names, so every asset and API
// call it makes is absolute under ScriptPath.
func TestThePageReferencesItsOwnAddress(t *testing.T) {
	h := (&fakeDSM{}).handler()
	page := call(t, h, "GET", "/", false).Body.String()
	for _, want := range []string{ScriptPath + "/assets/page.js", ScriptPath + "/assets/page.css"} {
		if !strings.Contains(page, want) {
			t.Errorf("index.html does not load %s", want)
		}
	}
	if inline := regexp.MustCompile(`<script>|<style|style=|\son[a-z]+=`).FindString(page); inline != "" {
		t.Errorf("index.html carries inline script or style (%s), which the CSP refuses", inline)
	}
	js := call(t, h, "GET", "/assets/page.js", false).Body.String()
	for _, want := range []string{ScriptPath, "/webman/login.cgi", "SynoToken", "X-SYNO-TOKEN",
		"Sign in to DSM again.", "same-origin"} {
		if !strings.Contains(js, want) {
			t.Errorf("page.js does not mention %s", want)
		}
	}
}

// A move's stop and start go through DSM's own package control, as Package
// Center's do, with the administrator's session: only that clears DSM's
// running state for the folder edit and refreshes the folder's link.
func TestThePageHasDSMStopAndStartThePackageForAMove(t *testing.T) {
	js := call(t, (&fakeDSM{}).handler(), "GET", "/assets/page.js", false).Body.String()
	for _, want := range []string{"/webapi/entry.cgi", "SYNO.Core.Package.Control", "'hyperdrop'",
		"'stop'", "'start'", "/api/storage/stop", "/api/storage/stop-failed", "/api/storage/start"} {
		if !strings.Contains(js, want) {
			t.Errorf("page.js does not mention %s", want)
		}
	}
}

func TestCGIRoutesOnPathInfo(t *testing.T) {
	var seen string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen = r.URL.Path })
	for pathInfo, want := range map[string]string{"/api/state": "/api/state", "": "/", "/": "/"} {
		h := onPathInfo(inner, func(k string) string {
			if k == "PATH_INFO" {
				return pathInfo
			}
			return ""
		})
		r := httptest.NewRequest("GET", ScriptPath+pathInfo, nil)
		h.ServeHTTP(httptest.NewRecorder(), r)
		if seen != want {
			t.Errorf("PATH_INFO %q routed as %q, want %q", pathInfo, seen, want)
		}
	}
}

func writeScript(t *testing.T, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the DSM commands are POSIX programs")
	}
	p := filepath.Join(t.TempDir(), "prog")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunAuthenticatePassesTheEnvironmentAndTrimsTheUser(t *testing.T) {
	prog := writeScript(t, `[ -n "$HTTP_X_SYNO_TOKEN" ] && printf '  %s\n' "$HD_USER"`+"\n")
	user, err := runAuthenticate(context.Background(), prog, []string{"HTTP_X_SYNO_TOKEN=tok", "HD_USER=alice"})
	if err != nil || user != "alice" {
		t.Errorf("got %q, %v; want alice", user, err)
	}
	user, err = runAuthenticate(context.Background(), prog, []string{"HD_USER=alice"})
	if user != "" {
		t.Errorf("without the token header got %q, %v; want no user", user, err)
	}
}

func TestRunAuthenticateStopsAtTheDeadline(t *testing.T) {
	prog := writeScript(t, "sleep 30\necho alice\n")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	user, err := runAuthenticate(ctx, prog, nil)
	if err == nil || user != "" {
		t.Errorf("got %q, %v; want an error", user, err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("returned after %v", d)
	}
}

func TestRunGroupsReadsIDsWords(t *testing.T) {
	prog := writeScript(t, `[ "$1 $2 $3" = "-Gn -- alice" ] && echo "users administrators"`+"\n")
	groups, err := runGroups(context.Background(), prog, "alice")
	if err != nil || !slices.Equal(groups, []string{"users", "administrators"}) {
		t.Errorf("got %q, %v", groups, err)
	}
	if _, err := runGroups(context.Background(), prog, "bob"); err == nil {
		t.Error("a failing id gave no error")
	}
}
