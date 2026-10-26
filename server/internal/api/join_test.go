package api

import (
	"net/http"
	"strings"
	"testing"
)

// The server's front page is the recipient's way in: an invite names the
// server, and the person who clicks it before reading the rest must land on
// a sentence and a place to read more, not on a 404. /join is the steps.
func TestTheRootAndJoinPagesTellARecipientWhatThisIs(t *testing.T) {
	h := withDomain(t, "share.example.com")
	for _, tc := range []struct {
		path        string
		wants, nots []string
	}{
		{"/", []string{
			"Files on this server are shared through the HyperDrop app",
			`href="https://gethyperdrop.com"`,
			"Powered by",
		}, []string{"Get HyperDrop", "hyperdrop://join", "hdjoin1."}},
		{"/join", []string{
			"Get HyperDrop",
			// The downloads page, not one platform's: the page speaks to
			// whoever was invited, on whatever they have.
			"https://gethyperdrop.com/downloads/",
			// The button opens the app's Join step with this server alone.
			`href="hyperdrop://join?server=https%3A%2F%2Fshare.example.com"`,
			// The server's own identity, never the request's Host header.
			`id="server">https://share.example.com<`,
			"hdjoin1.", "hdjoin2.",
			"Powered by",
		}, nil},
	} {
		t.Run(tc.path, func(t *testing.T) {
			rec := req(t, h, http.MethodGet, "share.example.com", tc.path)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			if got := rec.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
				t.Errorf("Content-Type = %q", got)
			}
			if got := rec.Header().Get("X-Robots-Tag"); got != "noindex" {
				t.Errorf("X-Robots-Tag = %q", got)
			}
			body := rec.Body.String()
			for _, want := range append(tc.wants, "prefers-color-scheme: dark") {
				if !strings.Contains(body, want) {
					t.Errorf("body is missing %q", want)
				}
			}
			for _, not := range tc.nots {
				if strings.Contains(body, not) {
					t.Errorf("body carries %q, which belongs to the other page", not)
				}
			}
			// The font stack's BlinkMacSystemFont is the one "Mac" allowed.
			if strings.Contains(strings.ReplaceAll(body, "BlinkMacSystemFont", ""), "Mac") {
				t.Error("the page names a platform; it speaks to every client")
			}
			// The page fetches nothing: a recipient's first page must not
			// depend on a second request to this or any other host.
			for _, never := range []string{"<script src", "<link rel=\"stylesheet\"", "fetch("} {
				if strings.Contains(body, never) {
					t.Errorf("body loads something: %q", never)
				}
			}
		})
	}
}

// A device link (hdjoin3) is read by the page: the title, the lead and the
// button change, and the login and password rows stay hidden.
func TestTheJoinPageOpensADeviceLink(t *testing.T) {
	h := withDomain(t, "share.example.com")
	body := req(t, h, http.MethodGet, "share.example.com", "/join").Body.String()
	for _, want := range []string{
		"'hdjoin3.'",
		"Sign in on your phone",
		"Open this page on the phone you are signing in, or scan the code with the HyperDrop app.",
		"typeof c.i !== 'string'",
		"typeof c.l !== 'string'",
		`id="row-login" hidden`,
		`id="row-password" hidden`,
		"'hyperdrop://join?code=' + encodeURIComponent(",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body is missing %q", want)
		}
	}
}

// The page names the server's canonical identity so a link copied from it
// is the one the invite carries; a Host header a proxy or an attacker set
// must not reach it.
func TestTheJoinPageNamesTheServerNotTheHostHeader(t *testing.T) {
	h := withDomain(t, "share.example.com")
	rec := req(t, h, http.MethodGet, "share.example.com", "/join")
	if body := rec.Body.String(); !strings.Contains(body, `id="server">https://share.example.com<`) {
		t.Fatalf("server line: %s", body)
	}
}

func TestTheJoinPageHeadHasNoBody(t *testing.T) {
	h := withDomain(t, "share.example.com")
	rec := req(t, h, http.MethodHead, "share.example.com", "/join")
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Fatalf("status %d, %d body bytes", rec.Code, rec.Body.Len())
	}
}

// Our own page, so the app origin only: on files.<domain> it redirects
// there the way the listing and the password form do.
func TestTheJoinPageIsPinnedToTheAppOrigin(t *testing.T) {
	h := withDomain(t, "share.example.com")
	for _, path := range []string{"/", "/join"} {
		rec := req(t, h, http.MethodGet, "files.share.example.com", path)
		if rec.Code != http.StatusPermanentRedirect {
			t.Fatalf("%s on the file origin: status = %d, want 308", path, rec.Code)
		}
		if got := rec.Header().Get("Location"); got != "https://share.example.com"+path {
			t.Fatalf("%s on the file origin: Location = %q", path, got)
		}
	}
}

// Only the root and /join are the page; every other unknown path stays the
// branded 404, so a broken share link is still reported as missing.
func TestOtherUnknownPathsStayNotFound(t *testing.T) {
	h := withDomain(t, "share.example.com")
	for _, path := range []string{"/join/", "/join/x", "/index.html", "/missing"} {
		rec := req(t, h, http.MethodGet, "share.example.com", path)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s: status = %d, want 404", path, rec.Code)
		}
	}
}
