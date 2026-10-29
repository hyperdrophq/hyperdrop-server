package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The JSON this package decodes without decodeRequest, each with how many
// decodes the file holds and why none is a client's request body.
var lenientDecodes = map[string]struct {
	count int
	why   string
}{
	"connectivity.go":     {1, "the names registry's availability answer, passed through to the client"},
	"responselog.go":      {1, "this server's own response, read back for the log"},
	"pusher.go":           {1, "the pusher's own memory, read back from the database"},
	"pushupdate.go":       {1, "the server-update reminders already sent, read back from the database"},
	"pushsignin.go":       {1, "the phone sign-ins already announced, read back from the database"},
	"pushdomainchange.go": {1, "the address changes already pushed, read back from the database"},
}

// A JSON request body decoded leniently drops a field this server does not
// speak in silence, which is the one failure the version window cannot see:
// every request body goes through decodeRequest.
func TestEveryRequestBodyIsDecodedStrictly(t *testing.T) {
	decode := regexp.MustCompile(`json\.(Unmarshal|NewDecoder)\(`)
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no sources to scan: %v", err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		n := len(decode.FindAllIndex(src, -1))
		if f == "body.go" {
			if !strings.Contains(string(src), "func decodeRequest(body []byte, dst any) error {") {
				t.Fatal("body.go no longer defines decodeRequest")
			}
			n-- // decodeRequest itself
		}
		want := 0
		if lenient, ok := lenientDecodes[f]; ok {
			want = lenient.count
		}
		if n != want {
			t.Errorf("%s decodes JSON %d time(s) without decodeRequest, %d expected: decode request bodies with decodeRequest or decodeJSONBody", f, n, want)
		}
	}
}

// Every route that reads a JSON body answers a field it does not know with a
// 400 naming that field.
func TestEveryRouteNamesAnUnknownField(t *testing.T) {
	h := newTestAPI(t)
	for _, tc := range []struct{ method, path, token string }{
		{"POST", "/api/auth/login", ""},
		{"POST", "/api/users", testToken},
		{"PATCH", "/api/users/someone", testToken},
		{"POST", "/api/shares", testToken},
		{"POST", "/api/shares/edit", testToken},
		{"POST", "/api/shares/delete", testToken},
		{"POST", "/api/live-share", testToken},
		{"POST", "/api/me/totp", testToken},
		{"PATCH", "/api/me/password", testToken},
		{"PUT", "/api/me/push", testToken},
		{"PUT", "/api/me/activity", testToken},
		{"PATCH", "/api/server/settings", testToken},
		{"PUT", "/api/ddns", testToken},
		{"DELETE", "/api/ddns", testToken},
	} {
		rec := doReq(t, h, tc.method, tc.path, tc.token, `{"bogusField":1}`)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `does not know the field \"bogusField\"`) {
			t.Errorf("%s %s = %d %s, want 400 naming bogusField", tc.method, tc.path, rec.Code, rec.Body)
		}
	}
	// The routes under a share read their body once the share is the
	// caller's, and a publish's once the publish is open.
	id := createShare(t, h, "strict")
	pid := openPublish(t, h, testToken, id)
	for _, tc := range []struct{ method, path string }{
		{"POST", "/api/shares/" + id + "/publishes"},
		{"POST", "/api/shares/" + id + "/publishes/" + pid + "/commit"},
	} {
		rec := doReq(t, h, tc.method, tc.path, testToken, `{"bogusField":1}`)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `does not know the field \"bogusField\"`) {
			t.Errorf("%s %s = %d %s, want 400 naming bogusField", tc.method, tc.path, rec.Code, rec.Body)
		}
	}
}

func TestDecodeRequestRefusesUnknownFieldsAndTrailingData(t *testing.T) {
	var dst struct {
		Name string `json:"name"`
	}
	if err := decodeRequest([]byte(`{"name":"a"}`), &dst); err != nil || dst.Name != "a" {
		t.Fatalf("known field: %v %+v", err, dst)
	}
	for _, body := range []string{`{"name":"a","pinned":true}`, `{"name":"a"} {}`, ``} {
		if err := decodeRequest([]byte(body), &dst); err == nil {
			t.Errorf("decodeRequest(%q) accepted", body)
		}
	}
}

// A request body carrying a field this server does not speak is a 400 that
// names the field, not a success that ignored it.
func TestAnUnknownFieldInARequestIsA400(t *testing.T) {
	var dst struct {
		Name string `json:"name"`
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !decodeJSONBody(w, r, 1<<10, &dst) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPatch, "/api/shares/x", strings.NewReader(`{"name":"a","pinned":true}`)))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `does not know the field \"pinned\"`) {
		t.Fatalf("status = %d %s, want 400 naming the field", rec.Code, rec.Body)
	}
}
