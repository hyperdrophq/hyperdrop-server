package api

import (
	"strings"
	"testing"
)

// The pages are embedded, so a missing or unparsable file is a build-time
// mistake. This proves each one is present, parses, and still carries the
// shared brand tokens and wordmark rather than a marker nobody expanded.
func TestEveryPageEmbedsAndKeepsItsBrand(t *testing.T) {
	for _, tc := range []struct {
		name string
		tmpl interface{ Name() string }
	}{
		{"gallery", galleryTmpl}, {"listing", listingTmpl},
		{"not-found", notFoundTmpl}, {"join", joinTmpl}, {"pw", passwordFormTmpl},
		{"locked", lockedOutTmpl}, {"card", cardTmpl},
		{"receive", inboxTmpl}, {"waiting", waitingTmpl},
		{"unavailable", unavailableTmpl}, {"ticket-refused", ticketRefusedTmpl},
	} {
		if tc.tmpl == nil || tc.tmpl.Name() != tc.name {
			t.Errorf("%s: template missing or misnamed", tc.name)
		}
	}
	// The pages whose light palette is the shared one ask for it rather than
	// carrying a copy, and none of them re-defines the wordmark. notfound.html
	// is deliberately absent: its palette genuinely differs (--paper #f7f7fa).
	for _, f := range []string{"listing.html", "waiting.html", "inbox.html", "gallery.html", "unavailable.html", "ticketrefused.html"} {
		b, err := pageFS.ReadFile("pages/" + f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if !strings.Contains(string(b), `{{template "brandTokens"}}`) {
			t.Errorf("%s does not ask for the shared tokens", f)
		}
		if strings.Contains(string(b), `--indigo:#6B52F2`) ||
			strings.Contains(string(b), `--indigo: #6B52F2`) {
			t.Errorf("%s re-declares a shared token instead of using the partial", f)
		}
		if strings.Contains(string(b), `{{define "mark"}}`) {
			t.Errorf("%s re-defines the wordmark instead of sharing it", f)
		}
	}
}

// Rendered output, not just file content: the marker has to become CSS and the
// wordmark has to become the product mark, or the pages ship a literal comment
// and a missing logo.
func TestASharedPageRendersItsBrand(t *testing.T) {
	var sb strings.Builder
	if err := waitingTmpl.Execute(&sb, waitingData{ID: "abc", Title: "x"}); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	for _, want := range []string{"--indigo: #6B52F2", "--paper: #FFFFFF"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered page is missing %q", want)
		}
	}
	// The product mark: the purple square and the white glyph from icon.svg.
	// A page that cannot reach the shared define renders neither.
	if !strings.Contains(out, `fill="#712dff"`) || !strings.Contains(out, `M416.82 187.3`) {
		t.Error("the wordmark did not render")
	}
}
