package api

import "testing"

// Uploaded bytes are served from their own hostname, because a file a user
// uploaded is untrusted content: an .html or .svg is served inline, and on
// the app's own origin its script would run first-party, able to ride the
// hd_ access cookies and to draw a pixel-perfect copy of the password form
// under the real domain and certificate.

func TestFileOriginIsASubdomainOfTheAppOrigin(t *testing.T) {
	o := OriginsFor("share.example.com")
	if o.App != "share.example.com" {
		t.Errorf("App = %q", o.App)
	}
	if o.File != "files.share.example.com" {
		t.Errorf("File = %q, want files.share.example.com", o.File)
	}
	if !o.Split() {
		t.Error("Split() = false for a configured domain")
	}
}

// Without a domain (the development escape hatch) there is one host and
// nothing to split: every route has to keep answering on it.
func TestNoDomainMeansNoSplit(t *testing.T) {
	o := OriginsFor("")
	if o.Split() {
		t.Error("Split() = true with no domain configured")
	}
	for _, p := range []string{"/share/abc", "/view/abc/x", "/api/health"} {
		if host, ok := o.Misrouted(p, "192.0.2.1"); ok {
			t.Errorf("%s misrouted to %q with no domain configured", p, host)
		}
	}
}

func TestPayloadRoutesBelongToTheFileOrigin(t *testing.T) {
	o := OriginsFor("share.example.com")
	for _, p := range []string{"/view/abc/slug", "/download/abc/slug", "/zip/abc"} {
		if host, ok := o.Misrouted(p, o.App); !ok || host != o.File {
			t.Errorf("%s on the app origin: misrouted=%v host=%q, want true/%s", p, ok, host, o.File)
		}
		if _, ok := o.Misrouted(p, o.File); ok {
			t.Errorf("%s on the file origin was rejected", p)
		}
	}
}

// Our OWN HTML (the listing, the note decrypt page, the password form) is
// what an uploaded page would want to impersonate or read, so it is pinned to
// the app origin. The status POLL is not a page and is deliberately not
// pinned: the file-origin waiting page fetches it relatively, and a 308 is a
// wall to a fetch() (see isStatusPath).
func TestOurOwnPagesBelongToTheAppOrigin(t *testing.T) {
	o := OriginsFor("share.example.com")
	for _, p := range []string{"/share/abc", "/unlock/abc"} {
		if host, ok := o.Misrouted(p, o.File); !ok || host != o.App {
			t.Errorf("%s on the file origin: misrouted=%v host=%q, want true/%s", p, ok, host, o.App)
		}
		if _, ok := o.Misrouted(p, o.App); ok {
			t.Errorf("%s on the app origin was rejected", p)
		}
	}
	for _, host := range []string{o.App, o.File} {
		if _, ok := o.Misrouted("/share/abc/status", host); ok {
			t.Errorf("/share/abc/status on %s was rejected: the poll answers on both origins", host)
		}
	}
}

// The API is Bearer-authenticated and reads no cookie, so an uploaded page
// calling it has no more power than curl, while pinning it would break the
// client dialling the bare IP before DNS resolves (post-install login, the
// LAN shortcut).
func TestAPIAnswersOnAnyHost(t *testing.T) {
	o := OriginsFor("share.example.com")
	for _, p := range []string{"/api/health", "/api/shares", "/api/me", "/card.png"} {
		for _, host := range []string{o.App, o.File, "203.0.113.9", "anything"} {
			if _, ok := o.Misrouted(p, host); ok {
				t.Errorf("%s rejected on host %q", p, host)
			}
		}
	}
}

// A port in the Host header must not defeat the comparison (dev servers, and
// anything behind a non-443 forward).
func TestHostPortIsIgnored(t *testing.T) {
	o := OriginsFor("share.example.com")
	if _, ok := o.Misrouted("/share/abc", "share.example.com:8443"); ok {
		t.Error("a port in the Host header made the app origin unreachable")
	}
	if host, ok := o.Misrouted("/view/abc/s", "share.example.com:8443"); !ok || host != o.File {
		t.Errorf("port form not routed: ok=%v host=%q", ok, host)
	}
}

// An unrelated Host (someone pointing their own DNS at this IP, or a probe)
// gets sent to the canonical origin rather than served.
func TestUnknownHostIsRoutedToTheCanonicalOrigin(t *testing.T) {
	o := OriginsFor("share.example.com")
	if host, ok := o.Misrouted("/share/abc", "evil.test"); !ok || host != o.App {
		t.Errorf("unknown host: ok=%v host=%q, want true/%s", ok, host, o.App)
	}
	if host, ok := o.Misrouted("/download/abc/s", "evil.test"); !ok || host != o.File {
		t.Errorf("unknown host on a payload route: ok=%v host=%q", ok, host)
	}
}

// The visitor cookie has to reach both hosts, or a page view and the payload
// request it leads to would count as two visitors.
func TestVisitorCookieDomainCoversBothOrigins(t *testing.T) {
	if got := OriginsFor("share.example.com").VisitorCookieDomain(); got != "share.example.com" {
		t.Errorf("VisitorCookieDomain = %q, want share.example.com", got)
	}
	if got := OriginsFor("").VisitorCookieDomain(); got != "" {
		t.Errorf("VisitorCookieDomain with no domain = %q, want empty (host-only)", got)
	}
}

// The access hop belongs on the file origin, whose cookie it sets.
func TestTheAccessHopIsAFileOriginPath(t *testing.T) {
	o := OriginsFor("share.example.com")
	if want, mis := o.Misrouted("/access/abc", "share.example.com"); !mis || want != "files.share.example.com" {
		t.Errorf("/access on the app origin = (%q,%v), want the file origin", want, mis)
	}
	if _, mis := o.Misrouted("/access/abc", "files.share.example.com"); mis {
		t.Error("/access on the file origin is misrouted")
	}
}

// A host name is case-insensitive: a Host header spelled in capitals is the
// same origin, for the router and for every other comparison against it.
func TestHostCaseIsIgnored(t *testing.T) {
	o := OriginsFor("share.example.com")
	if _, ok := o.Misrouted("/share/abc", "Share.Example.COM"); ok {
		t.Error("a capitalised app host was treated as another origin")
	}
	if _, ok := o.Misrouted("/view/abc/s", "FILES.share.example.com:443"); ok {
		t.Error("a capitalised file host was treated as another origin")
	}
	if !isPayloadPath("/zip/abc") || isPayloadPath("/zip") {
		t.Error("isPayloadPath must match /zip/{id} and only it")
	}
}
