package webapp

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testCSP = "default-src 'none'"

func gzipped(t *testing.T, s string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(s))
	zw.Close()
	return buf.String()
}

// served installs a typical bundle and answers its handler in state.
func served(t *testing.T, state *State) http.Handler {
	t.Helper()
	s := newSigner(t)
	st := openStore(t, t.TempDir(), s)
	install(t, st, s, "1.0.0", 1, map[string]string{
		"index.html":               "<!doctype html><title>app</title>",
		"assets/app-1234.js":       "console.log(1)",
		"assets/app-1234.js.gz":    gzipped(t, "console.log(1)"),
		"assets/style-99.css":      "body{}",
		"hyperdrop.wasm":           "\x00asm",
		"robots.txt":               "User-agent: *",
		"manifest.webmanifest":     "{}",
		"assets/fonts/inter.woff2": "font",
	})
	return Handler(st, func() State { return *state }, func() string { return testCSP })
}

func get(t *testing.T, h http.Handler, path string, header ...string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Result()
}

func body(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestHandlerSPAFallback(t *testing.T) {
	on := StateOn
	h := served(t, &on)

	resp := get(t, h, "/app")
	if resp.StatusCode != http.StatusPermanentRedirect || resp.Header.Get("Location") != "/app/" {
		t.Fatalf("/app answered %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	for _, p := range []string{"/app/", "/app/index.html", "/app/shares", "/app/shares/abc/", "/app/inboxes/x", "/app/assets"} {
		resp := get(t, h, p)
		if resp.StatusCode != http.StatusOK || !strings.Contains(body(t, resp), "<title>app</title>") {
			t.Errorf("%s answered %d, not index.html", p, resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
			t.Errorf("%s Content-Type %q", p, ct)
		}
	}
	for _, p := range []string{"/app/missing.js", "/app/assets/gone-1.css", "/app/../etc/passwd", "/app/" + metaName, "/app/assets/"} {
		resp := get(t, h, p)
		if p == "/app/assets/" {
			// A directory is never listed: with no extension it is the client
			// router's.
			if b := body(t, resp); strings.Contains(b, "app-1234.js") {
				t.Errorf("%s listed the directory: %s", p, b)
			}
			continue
		}
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s answered %d, want 404", p, resp.StatusCode)
		}
	}
	resp = get(t, h, "/app/hyperdrop.wasm")
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/wasm" {
		t.Fatalf("wasm answered %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	for p, want := range map[string]string{
		"/app/assets/style-99.css":      "text/css; charset=utf-8",
		"/app/assets/app-1234.js":       "text/javascript; charset=utf-8",
		"/app/manifest.webmanifest":     "application/manifest+json",
		"/app/assets/fonts/inter.woff2": "font/woff2",
	} {
		if ct := get(t, h, p).Header.Get("Content-Type"); ct != want {
			t.Errorf("%s Content-Type %q, want %q", p, ct, want)
		}
	}

	post := httptest.NewRecorder()
	h.ServeHTTP(post, httptest.NewRequest(http.MethodPost, "/app/", nil))
	if post.Code != http.StatusMethodNotAllowed || post.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("POST answered %d, Cache-Control %q", post.Code, post.Header().Get("Cache-Control"))
	}
}

func TestHandlerBrokenInstallAnswersMissing(t *testing.T) {
	s := newSigner(t)
	st := openStore(t, t.TempDir(), s)
	install(t, st, s, "1.0.0", 1, map[string]string{"index.html": "app", "app.js": "js"})
	inst, _ := st.Current()
	h := Handler(st, func() State { return StateOn }, func() string { return testCSP })
	missing := func(label, p string) {
		t.Helper()
		resp := get(t, h, p)
		b := body(t, resp)
		if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(b, "installed on this server yet") || resp.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s %s answered %d %q", label, p, resp.StatusCode, b)
		}
	}

	// index.html gone: the router's paths answer the missing page, a named
	// file that is still there is served, a missing one is 404.
	if err := os.Remove(filepath.Join(inst.Dir, "index.html")); err != nil {
		t.Fatal(err)
	}
	missing("no index.html", "/app/")
	missing("no index.html", "/app/shares/x")
	if resp := get(t, h, "/app/app.js"); resp.StatusCode != http.StatusOK {
		t.Errorf("app.js answered %d", resp.StatusCode)
	}
	if resp := get(t, h, "/app/gone.js"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("gone.js answered %d", resp.StatusCode)
	}

	// The whole directory gone.
	if err := os.RemoveAll(inst.Dir); err != nil {
		t.Fatal(err)
	}
	missing("no directory", "/app/")
	missing("no directory", "/app/app.js")
}

func TestHandlerRefusesSymlinkOut(t *testing.T) {
	s := newSigner(t)
	st := openStore(t, t.TempDir(), s)
	dev := t.TempDir()
	os.WriteFile(filepath.Join(dev, "index.html"), []byte("dev"), 0o644)
	outside := filepath.Join(t.TempDir(), "secret.txt")
	os.WriteFile(outside, []byte("secret"), 0o644)
	if err := os.Symlink(outside, filepath.Join(dev, "leak.txt")); err != nil {
		t.Fatal(err)
	}
	st.UseDevDir(dev)
	h := Handler(st, func() State { return StateOn }, func() string { return testCSP })
	resp := get(t, h, "/app/leak.txt")
	if b := body(t, resp); resp.StatusCode == http.StatusOK || strings.Contains(b, "secret") {
		t.Fatalf("a symlink out of the install served %d %q", resp.StatusCode, b)
	}
	if b := body(t, get(t, h, "/app/")); b != "dev" {
		t.Fatalf("dev dir served %q", b)
	}
}

func TestHandlerGzipSibling(t *testing.T) {
	on := StateOn
	h := served(t, &on)

	resp := get(t, h, "/app/assets/app-1234.js", "Accept-Encoding", "br, gzip;q=0.8")
	if resp.Header.Get("Content-Encoding") != "gzip" || resp.Header.Get("Vary") != "Accept-Encoding" {
		t.Fatalf("headers %v", resp.Header)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/javascript; charset=utf-8" {
		t.Fatalf("Content-Type %q, want the original's", ct)
	}
	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(zr); string(b) != "console.log(1)" {
		t.Fatalf("decoded %q", b)
	}

	for _, ae := range []string{"", "br", "gzip;q=0"} {
		resp := get(t, h, "/app/assets/app-1234.js", "Accept-Encoding", ae)
		if resp.Header.Get("Content-Encoding") != "" || body(t, resp) != "console.log(1)" {
			t.Errorf("Accept-Encoding %q got the gzip sibling", ae)
		}
		if resp.Header.Get("Vary") != "Accept-Encoding" {
			t.Errorf("Accept-Encoding %q: no Vary on a file with a sibling", ae)
		}
	}
	// A file without a sibling is served as itself.
	resp = get(t, h, "/app/assets/style-99.css", "Accept-Encoding", "gzip")
	if resp.Header.Get("Content-Encoding") != "" || body(t, resp) != "body{}" {
		t.Fatal("a file without a sibling was encoded")
	}
}

func TestHandlerCacheHeaders(t *testing.T) {
	on := StateOn
	h := served(t, &on)
	for p, want := range map[string]string{
		"/app/":                    "no-store",
		"/app/index.html":          "no-store",
		"/app/shares/x":            "no-store",
		"/app/assets/app-1234.js":  "public, max-age=31536000, immutable",
		"/app/assets/style-99.css": "public, max-age=31536000, immutable",
		"/app/hyperdrop.wasm":      "no-cache",
		"/app/robots.txt":          "no-cache",
	} {
		if got := get(t, h, p).Header.Get("Cache-Control"); got != want {
			t.Errorf("%s Cache-Control %q, want %q", p, got, want)
		}
	}
}

func TestHandlerSecurityHeadersOnEveryAnswer(t *testing.T) {
	state := StateOn
	h := served(t, &state)
	check := func(label string, resp *http.Response) {
		t.Helper()
		want := map[string]string{
			"Content-Security-Policy":    testCSP,
			"X-Frame-Options":            "DENY",
			"Referrer-Policy":            "no-referrer",
			"Cross-Origin-Opener-Policy": "same-origin",
			"X-Content-Type-Options":     "nosniff",
			"Permissions-Policy":         "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
		}
		for k, v := range want {
			if got := resp.Header.Get(k); got != v {
				t.Errorf("%s: %s = %q, want %q", label, k, got, v)
			}
		}
	}
	check("redirect", get(t, h, "/app"))
	check("index", get(t, h, "/app/"))
	check("asset", get(t, h, "/app/assets/app-1234.js", "Accept-Encoding", "gzip"))
	check("404", get(t, h, "/app/nope.js"))
	check("stylesheet", get(t, h, unavailableCSSPath))
	state = StateMissing
	check("503", get(t, h, "/app/"))
	check("503 stylesheet", get(t, h, unavailableCSSPath))
}

func TestHandlerStates(t *testing.T) {
	state := StateOn
	h := served(t, &state)
	for s, want := range map[State]string{
		StateOff:      "The administrator turned off the web version",
		StateMissing:  "The web version isn&#39;t installed on this server yet",
		StateUpdating: "The web version is being updated",
	} {
		state = s
		for _, p := range []string{"/app/", "/app/shares/x", "/app/assets/app-1234.js"} {
			resp := get(t, h, p)
			b := body(t, resp)
			if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(b, want) {
				t.Errorf("state %d %s answered %d %q", s, p, resp.StatusCode, b)
			}
			if resp.Header.Get("Cache-Control") != "no-store" {
				t.Errorf("state %d %s Cache-Control %q", s, p, resp.Header.Get("Cache-Control"))
			}
			if strings.Contains(b, "<style") || strings.Contains(b, "style=") || strings.Contains(b, "<script") {
				t.Errorf("state %d: the page carries inline style or script, which the CSP refuses", s)
			}
			if !strings.Contains(b, `href="`+unavailableCSSPath+`"`) {
				t.Errorf("state %d: the page does not link its stylesheet", s)
			}
		}
		css := get(t, h, unavailableCSSPath)
		if css.StatusCode != http.StatusOK || css.Header.Get("Content-Type") != "text/css; charset=utf-8" || !strings.Contains(body(t, css), "--ink") {
			t.Errorf("state %d: stylesheet answered %d", s, css.StatusCode)
		}
	}

	// A store with nothing installed answers the missing page even if the
	// caller's state says on.
	empty := openStore(t, t.TempDir(), newSigner(t))
	h = Handler(empty, func() State { return StateOn }, func() string { return testCSP })
	resp := get(t, h, "/app/")
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(body(t, resp), "installed") {
		t.Fatalf("an empty store answered %d", resp.StatusCode)
	}
}

func TestCSPWithAndWithoutSplit(t *testing.T) {
	split := "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; " +
		"img-src 'self' blob: data: https://files.example.com; media-src 'self' blob: https://files.example.com; " +
		"connect-src 'self'; font-src 'self'; manifest-src 'self'; worker-src 'self' blob:; " +
		"frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
	if got := CSP("https://files.example.com"); got != split {
		t.Fatalf("split CSP\n got %s\nwant %s", got, split)
	}
	single := "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; " +
		"img-src 'self' blob: data:; media-src 'self' blob:; " +
		"connect-src 'self'; font-src 'self'; manifest-src 'self'; worker-src 'self' blob:; " +
		"frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
	if got := CSP(""); got != single {
		t.Fatalf("single-origin CSP\n got %s\nwant %s", got, single)
	}
}
