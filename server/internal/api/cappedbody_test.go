package api

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// paddedJSON is `{}` followed by spaces, exactly n bytes long.
func paddedJSON(n int) string { return "{}" + strings.Repeat(" ", n-2) }

// A whole-body read under a cap answers 413 with the site's own code and
// message one byte over the cap, and reads the body at the cap.
func TestCappedBodyAnswers(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	cases := []struct {
		name, method, path string
		limit              int
		code, msg          string
	}{
		{"share create", "POST", "/api/shares", createBodyLimit, "body-too-large",
			fmt.Sprintf("share request too large (limit %d bytes): send at most %d files in the manifest",
				createBodyLimit, maxManifestFiles)},
		{"live share create", "POST", "/api/live-share", liveShareBodyLimit, "body-too-large",
			fmt.Sprintf("live share request over %d bytes; a live share describes at most %d files",
				liveShareBodyLimit, liveShareManifestMaxFiles)},
	}
	for _, c := range cases {
		t.Run(c.name+" over", func(t *testing.T) {
			rec := doReq(t, h, c.method, c.path, testToken, paddedJSON(c.limit+1))
			var e struct{ Error, Code string }
			unmarshal(t, rec, &e)
			if rec.Code != http.StatusRequestEntityTooLarge || e.Code != c.code || e.Error != c.msg {
				t.Fatalf("→ %d %q %q, want 413 %q %q", rec.Code, e.Code, e.Error, c.code, c.msg)
			}
		})
		t.Run(c.name+" at", func(t *testing.T) {
			rec := doReq(t, h, c.method, c.path, testToken, paddedJSON(c.limit))
			if rec.Code == http.StatusRequestEntityTooLarge {
				t.Fatalf("a body exactly at the cap was refused as too large: %s", rec.Body)
			}
			t.Logf("at the cap → %d", rec.Code)
		})
	}
}
