package dsmpage

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// answered is the status an API answer means: the HTTP status, or the one
// its body carries when it travelled as 200 because DSM would have replaced
// it.
func answered(t *testing.T, w *httptest.ResponseRecorder) int {
	t.Helper()
	if w.Code != http.StatusOK {
		return w.Code
	}
	var body struct {
		Error  *string `json:"error"`
		Status int     `json:"status"`
	}
	if json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Error == nil {
		return w.Code
	}
	return body.Status
}

// DSM's web server replaces the body of a 403, 404, 500, 502, 503 or 504 a
// package's CGI answers with its own error page, on DSM 6 and DSM 7, so the
// sentence would never reach the page. Those travel as 200 with the status
// in the body; every other status travels as itself.
func TestErrorsDSMWouldReplaceTravelInTheBody(t *testing.T) {
	for _, code := range []int{403, 404, 500, 502, 503, 504} {
		w := httptest.NewRecorder()
		writeError(w, code, "One sentence.")
		if w.Code != http.StatusOK {
			t.Errorf("%d went out as %d, which DSM replaces", code, w.Code)
		}
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body["error"] != "One sentence." || body["status"] != float64(code) {
			t.Errorf("%d: body %v", code, body)
		}
	}
	for _, code := range []int{400, 401, 405, 409} {
		w := httptest.NewRecorder()
		writeError(w, code, "One sentence.")
		if w.Code != code {
			t.Errorf("%d went out as %d", code, w.Code)
		}
		if strings.Contains(w.Body.String(), `"status"`) {
			t.Errorf("%d carries a status in its body: %s", code, w.Body)
		}
	}
}

// A CGI the root step refused still serves the page and its assets, which
// hold no data, and answers every API call with the step's sentence, so the
// administrator reads why instead of DSM's error page.
func TestARefusedCGIServesThePageAndItsSentence(t *testing.T) {
	h := serveRefusal(errUnsafeInstall)
	for _, path := range []string{"/", "/assets/page.js", "/assets/page.css"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK || w.Body.Len() == 0 {
			t.Errorf("GET %s: %d, %d bytes", path, w.Code, w.Body.Len())
		}
	}
	for _, c := range []struct{ method, path string }{{"GET", "/api/state"}, {"POST", "/api/settings"}, {"GET", "/api/nope"}} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(c.method, c.path, strings.NewReader("{}")))
		if got := answered(t, w); got != http.StatusInternalServerError {
			t.Errorf("%s %s answered %d (HTTP %d)", c.method, c.path, got, w.Code)
		}
		if !strings.Contains(w.Body.String(), errUnsafeInstall.Error()) {
			t.Errorf("%s %s: body %s", c.method, c.path, w.Body)
		}
		if w.Header().Get("Content-Security-Policy") == "" {
			t.Errorf("%s %s: no CSP on a refusal", c.method, c.path)
		}
	}
}
