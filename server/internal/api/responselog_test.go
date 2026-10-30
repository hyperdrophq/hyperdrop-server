package api

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// captureLog routes the standard logger into a buffer for the test's life.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

func TestRefusedResponsesAreLoggedByRoutePatternNeverByPath(t *testing.T) {
	buf := captureLog(t)
	h := newTestAPI(t)
	id := createInbox(t, h, `{"name":"drops","receive":true,"password":"pw"}`)
	// No unlock cookie: the anonymous PUT is refused, and the refusal must
	// not name the file the stranger tried to send.
	req := httptest.NewRequest("PUT", "/receive/"+id+"/files/secret-name.pdf", strings.NewReader("x"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code < 400 {
		t.Fatalf("expected a refusal without the cookie, got %d", rec.Code)
	}
	out := buf.String()
	if strings.Contains(out, "secret-name") {
		t.Fatalf("the log holds the relpath: %s", out)
	}
	if !strings.Contains(out, "route=PUT /receive/{id}/files/{name}") {
		t.Fatalf("the log lacks the route pattern: %s", out)
	}
	if !strings.Contains(out, "share="+id) {
		t.Fatalf("the log lacks the share id: %s", out)
	}
	if !strings.Contains(out, "status="+itoa(rec.Code)) {
		t.Fatalf("the log lacks the status: %s", out)
	}
}

func TestSuccessfulResponsesAreNotLogged(t *testing.T) {
	buf := captureLog(t)
	h := newTestAPI(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/health", nil))
	if rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	if buf.Len() != 0 {
		t.Fatalf("logged a 200: %s", buf.String())
	}
}

func TestARefusalCarriesItsErrorCode(t *testing.T) {
	buf := captureLog(t)
	h := newTestAPI(t)
	rec := doReq(t, h, "GET", "/api/shares/"+strings.Repeat("a", 32), testToken, "")
	if rec.Code != 404 {
		t.Fatal(rec.Code)
	}
	if !strings.Contains(buf.String(), "code=not-found") {
		t.Fatalf("no code in %s", buf.String())
	}
}

func TestAPanicAnswers500AndIsLogged(t *testing.T) {
	buf := captureLog(t)
	h := recoverPanics(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
	if rec.Code != 500 {
		t.Fatal(rec.Code)
	}
	if !strings.Contains(buf.String(), "panic: boom") {
		t.Fatalf("panic not logged: %s", buf.String())
	}
}

// fromPeer is a request from addr with user agent ua.
func fromPeer(method, path, addr, ua string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = addr
	req.Header.Set("User-Agent", ua)
	return req
}

// A request for a path the server does not have names where it came from,
// once a minute per source: a scanner's burst of hundreds is one line and a
// count, never hundreds of lines that say nothing.
func TestUnmatchedRequestsNameTheirSourceOnceAMinute(t *testing.T) {
	buf := captureLog(t)
	now := time.Date(2026, 10, 23, 8, 45, 0, 0, time.UTC)
	resetUnmatchedLog(func() time.Time { return now })
	h := newTestAPI(t)
	for _, p := range []string{"/wp-login.php", "/.env", "/admin", "/x"} {
		h.ServeHTTP(httptest.NewRecorder(), fromPeer("GET", p, "203.0.113.9:4000", "Mozilla/5.0 (scanner) \"x\""))
	}
	h.ServeHTTP(httptest.NewRecorder(), fromPeer("POST", "/cgi-bin/x", "203.0.113.9:4001", "Mozilla/5.0 (scanner)"))
	out := buf.String()
	if n := strings.Count(out, "\n"); n != 1 {
		t.Fatalf("%d lines for one source's burst, want 1:\n%s", n, out)
	}
	if !strings.Contains(out, "peer=203.0.113.9") || !strings.Contains(out, `ua="Mozilla/5.0 (scanner) 'x'"`) {
		t.Fatalf("the line does not name the source: %s", out)
	}
	if strings.Contains(out, "wp-login") {
		t.Fatalf("the line holds the path: %s", out)
	}
	now = now.Add(61 * time.Second)
	h.ServeHTTP(httptest.NewRecorder(), fromPeer("GET", "/y", "203.0.113.9:4002", "Mozilla/5.0 (scanner)"))
	if !strings.Contains(buf.String(), "suppressed=4") {
		t.Fatalf("the next minute's line does not count the burst: %s", buf.String())
	}
	h.ServeHTTP(httptest.NewRecorder(), fromPeer("GET", "/z", "198.51.100.7:4000", "curl/8"))
	if !strings.Contains(buf.String(), "peer=198.51.100.7") {
		t.Fatalf("another source is not named: %s", buf.String())
	}
}

// A refusal on a route the server has stays one line per response and
// names no address.
func TestRoutedRefusalsNameNoAddress(t *testing.T) {
	buf := captureLog(t)
	resetUnmatchedLog(time.Now)
	h := newTestAPI(t)
	for i := 0; i < 2; i++ {
		h.ServeHTTP(httptest.NewRecorder(), fromPeer("GET", "/api/shares", "203.0.113.9:4000", "x"))
	}
	if n := strings.Count(buf.String(), "route=GET /api/shares"); n != 2 || strings.Contains(buf.String(), "peer=") {
		t.Fatalf("routed refusals: %s", buf.String())
	}
}
