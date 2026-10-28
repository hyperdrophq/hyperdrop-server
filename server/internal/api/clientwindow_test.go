package api

import (
	"hyperdrop/server/internal/metadb"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// metadbVersion is the version a request's X-HyperDrop-Client names, as auth
// reads it.
func metadbVersion(header string) string { return metadb.ParseClientHeader(header).Version }

// An authenticated request from a client outside the window is refused
// before its token is read; one inside it, or one naming no client, is not.
func TestAClientOutsideTheWindowIsRefused(t *testing.T) {
	h := &handler{version: "1.5.2"}
	ok := h.auth(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	for _, tc := range []struct {
		header, code string
		status       int
	}{
		{"1.3.9 macos", "client-outdated", http.StatusConflict},
		{"0.9.0 linux", "client-outdated", http.StatusConflict},
		{"1.7.0 macos", "server-outdated", http.StatusConflict},
		{"2.5.0 macos", "server-outdated", http.StatusConflict},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/shares", nil)
		req.Header.Set("X-HyperDrop-Client", tc.header)
		ok.ServeHTTP(rec, req)
		if rec.Code != tc.status || !strings.Contains(rec.Body.String(), `"code":"`+tc.code+`"`) {
			t.Errorf("%s: %d %s, want %d %s", tc.header, rec.Code, rec.Body, tc.status, tc.code)
		}
	}
	for _, header := range []string{"1.4.0 macos", "1.5.0 ios", "1.6.9 linux", "", "garbage"} {
		rec := httptest.NewRecorder()
		if h.refuseClientOutsideWindow(rec, httptest.NewRequest(http.MethodGet, "/api/shares", nil), metadbVersion(header)) {
			t.Errorf("%q was refused: %s", header, rec.Body)
		}
	}
}

// The routes that repair a mismatch stay reachable from outside the window:
// a client two minors ahead can still enrol a second factor, update the
// server and read its role. Driven through the real mux, so r.Pattern is
// what the router sets.
func TestTheRepairRoutesAreReachableFromOutsideTheWindow(t *testing.T) {
	h := newTestAPI(t)
	far := "9.0.0 macos"
	for _, route := range []struct{ method, path string }{
		{"GET", "/api/me"}, {"GET", "/api/me/totp"},
	} {
		rec := doReqWithBearerAndHeader(t, h, route.method, route.path, testToken, "X-HyperDrop-Client", far)
		if rec.Code == http.StatusConflict {
			t.Errorf("%s %s refused a client outside the window: %s", route.method, route.path, rec.Body)
		}
	}
	if rec := doReqWithBearerAndHeader(t, h, "GET", "/api/shares", testToken, "X-HyperDrop-Client", far); rec.Code != http.StatusConflict {
		t.Errorf("GET /api/shares from outside the window = %d, want 409", rec.Code)
	}
	src, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	for pattern := range windowExempt {
		if !strings.Contains(string(src), `mux.Handle("`+pattern+`"`) {
			t.Errorf("exempt pattern %q names no route: a renamed route lost its exemption", pattern)
		}
	}
}
