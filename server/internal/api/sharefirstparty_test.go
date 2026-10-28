package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The hosts of the split server these tests run on (domainAPI).
const (
	fpApp  = "share.example.com"
	fpFile = "files.share.example.com"
)

// fetchMeta is the Fetch Metadata a browser sends, and the Origin it adds to
// a POST or a cross-origin fetch. An empty field is not sent.
type fetchMeta struct {
	site, dest, mode, origin string
}

func (m fetchMeta) apply(req *http.Request) {
	for k, v := range map[string]string{
		"Sec-Fetch-Site": m.site, "Sec-Fetch-Dest": m.dest, "Sec-Fetch-Mode": m.mode, "Origin": m.origin,
	} {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
}

// Browser contexts a share-password guess can come from.
var (
	// A person typing or pasting a link, or opening a bookmark.
	metaTyped = fetchMeta{site: "none", dest: "document", mode: "navigate"}
	// The password form on the app origin posting to /unlock.
	metaAppForm = fetchMeta{site: "same-origin", dest: "document", mode: "navigate", origin: "https://" + fpApp}
	// The password form rendered on the file origin posting to the app's /unlock.
	metaFileForm = fetchMeta{site: "same-site", dest: "document", mode: "navigate", origin: "https://" + fpFile}
	// <img src="https://box/share/<id>?pw=x"> on another website.
	metaCrossImage = fetchMeta{site: "cross-site", dest: "image", mode: "no-cors"}
	// Another website navigating the tab, or a popup it opened, to a ?pw= link.
	metaCrossNav = fetchMeta{site: "cross-site", dest: "document", mode: "navigate"}
	// Another website's auto-submitting form.
	metaCrossForm = fetchMeta{site: "cross-site", dest: "document", mode: "navigate", origin: "https://evil.example"}
	// A script in a hosted /site page, which the sandbox puts in an opaque origin.
	metaSandboxFetch = fetchMeta{site: "cross-site", dest: "empty", mode: "no-cors", origin: "null"}
	// A form posting into a hidden frame.
	metaFrameForm = fetchMeta{site: "same-origin", dest: "iframe", mode: "navigate", origin: "https://" + fpApp}
	// A page on another host of the same registrable domain (another server's name).
	metaSiblingForm = fetchMeta{site: "same-site", dest: "document", mode: "navigate", origin: "https://other.example.com"}
	// Such a page navigating a popup it opened to a ?pw= link: a navigation
	// names no Origin.
	metaSiblingNav = fetchMeta{site: "same-site", dest: "document", mode: "navigate"}
	// A same-site form whose Origin is opaque or unreadable.
	metaNullOriginForm = fetchMeta{site: "same-site", dest: "document", mode: "navigate", origin: "null"}
	metaBadOriginForm  = fetchMeta{site: "same-site", dest: "document", mode: "navigate", origin: "://%zz"}
)

// sharePWFixture is a split server holding a protected share with a file and
// a protected inbox, both with the password hunter2.
type sharePWFixture struct {
	h                  http.Handler
	share, slug, inbox string
}

func newSharePWFixture(t *testing.T) sharePWFixture {
	t.Helper()
	h := domainAPI(t, fpApp)
	id, slug := protectedShareWithFile(t, h)
	inbox := createInbox(t, h, `{"name":"drop","receive":true,"password":"hunter2"}`)
	return sharePWFixture{h: h, share: id, slug: slug, inbox: inbox}
}

// guessVia is one way of guessing a share's password: it sends pw for the
// share or inbox id from addr and reports the answer.
type guessVia func(t *testing.T, f sharePWFixture, id, pw, addr string) *httptest.ResponseRecorder

// serveAs sends req from addr with meta and answers the recorder.
func serveAs(h http.Handler, req *http.Request, addr string, meta fetchMeta) *httptest.ResponseRecorder {
	req.RemoteAddr = addr
	meta.apply(req)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// formGuess posts the password form to the app origin's /unlock.
func formGuess(meta fetchMeta) guessVia {
	return func(t *testing.T, f sharePWFixture, id, pw, addr string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "https://"+fpApp+"/unlock/"+id, strings.NewReader("password="+pw))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return serveAs(f.h, req, addr, meta)
	}
}

// queryGuess asks the app origin's page of the share (or the inbox) with ?pw=.
func queryGuess(meta fetchMeta) guessVia {
	return func(t *testing.T, f sharePWFixture, id, pw, addr string) *httptest.ResponseRecorder {
		route := "/share/"
		if id == f.inbox {
			route = "/receive/"
		}
		return serveAs(f.h, httptest.NewRequest("GET", "https://"+fpApp+route+id+"?pw="+pw, nil), addr, meta)
	}
}

// fileQueryGuess asks the file origin's /view of the share's file with ?pw=.
func fileQueryGuess(meta fetchMeta) guessVia {
	return func(t *testing.T, f sharePWFixture, id, pw, addr string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "https://"+fpFile+"/view/"+id+"/"+f.slug+"?pw="+pw, nil)
		return serveAs(f.h, req, addr, meta)
	}
}

// wantWrongAnswer checks that a wrong guess was checked and answered with the
// password form: 401 from /unlock, 200 from a ?pw= route.
func wantWrongAnswer(t *testing.T, rec *httptest.ResponseRecorder, what string) {
	t.Helper()
	if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Password required") {
		t.Fatalf("%s: %d %.300s, want the password form", what, rec.Code, rec.Body)
	}
}

// wantAddressWait checks a refusal of the caller's address: 429, the
// address's wording, the first block's length, and no cookie.
func wantAddressWait(t *testing.T, rec *httptest.ResponseRecorder, what string) {
	t.Helper()
	body := rec.Body.String()
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(body, shareAddrWait) || strings.Contains(body, shareLaneWait) {
		t.Fatalf("%s: %d %.300s, want 429 with the address's wait", what, rec.Code, body)
	}
	if !strings.Contains(body, "Try again in about an hour.") {
		t.Fatalf("%s: %.300s, want the first block's hour", what, body)
	}
	if rec.Header().Get("Set-Cookie") != "" {
		t.Fatalf("%s set a cookie", what)
	}
}

// A wrong guess from another website's context is checked and counted on
// the share's lane, never on the visitor's address: ten of them, which
// would block an address, leave the address free to guess at the form, and
// the share's lane spaces the guesses after them.
func TestACrossSiteGuessNeverBlocksTheAddress(t *testing.T) {
	for _, tc := range []struct {
		name  string
		via   guessVia
		inbox bool
	}{
		{"an image tag's ?pw=", queryGuess(metaCrossImage), false},
		{"an image tag's ?pw= on the file origin", fileQueryGuess(metaCrossImage), false},
		{"a cross-site navigation's ?pw=", queryGuess(metaCrossNav), false},
		{"a sandboxed site page's fetch", queryGuess(metaSandboxFetch), false},
		{"a cross-site form", formGuess(metaCrossForm), false},
		{"a form posting into a frame", formGuess(metaFrameForm), false},
		{"a form on a sibling host", formGuess(metaSiblingForm), false},
		{"a sibling host's navigation's ?pw=", queryGuess(metaSiblingNav), false},
		{"a sibling host's navigation's ?pw= on the file origin", fileQueryGuess(metaSiblingNav), false},
		{"a same-site form with an opaque Origin", formGuess(metaNullOriginForm), false},
		{"a same-site form with an unreadable Origin", formGuess(metaBadOriginForm), false},
		{"a same-origin image's ?pw=", queryGuess(fetchMeta{site: "same-origin", dest: "image", mode: "no-cors"}), false},
		{"an image tag's ?pw= at an inbox", queryGuess(metaCrossImage), true},
		{"a cross-site form at an inbox", formGuess(metaCrossForm), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSharePWFixture(t)
			id := f.share
			if tc.inbox {
				id = f.inbox
			}
			const victim = "203.0.113.50:5000"
			for i := range pwFailLimit {
				wantWrongAnswer(t, tc.via(t, f, id, "nope", victim), fmt.Sprintf("cross-site wrong guess %d", i+1))
			}
			// The victim's own guess at the form is checked: the address
			// holds none of the ten. It is the lane's first spaced guess.
			wantWrongAnswer(t, formGuess(metaAppForm)(t, f, id, "nope", victim), "the victim's own wrong guess")
			// The lane counted all eleven, so the next guess waits on it.
			wantShareLaneWait(t, formGuess(metaAppForm)(t, f, id, "nope", "198.51.100.77:1"), "a guess past the lane")
		})
	}
}

// A guess from the server's own pages, a typed link, the file origin's hop
// or a client sending no Fetch Metadata counts on the address: the tenth
// wrong one blocks it, with the address's wording.
func TestAFirstPartyGuessBlocksTheAddress(t *testing.T) {
	for _, tc := range []struct {
		name  string
		via   guessVia
		inbox bool
	}{
		{"the app origin's form", formGuess(metaAppForm), false},
		{"the file origin's form", formGuess(metaFileForm), false},
		{"a form from a client without Fetch Metadata", formGuess(fetchMeta{}), false},
		{"a typed ?pw=", queryGuess(metaTyped), false},
		{"a typed ?pw= on the file origin", fileQueryGuess(metaTyped), false},
		{"a ?pw= without Fetch Metadata", queryGuess(fetchMeta{}), false},
		{"a typed ?pw= at an inbox", queryGuess(metaTyped), true},
		{"the inbox's form", formGuess(metaAppForm), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSharePWFixture(t)
			id := f.share
			if tc.inbox {
				id = f.inbox
			}
			const addr = "203.0.113.60:5000"
			for i := range pwFailLimit - 1 {
				wantWrongAnswer(t, tc.via(t, f, id, "nope", addr), fmt.Sprintf("first-party wrong guess %d", i+1))
			}
			wantAddressWait(t, tc.via(t, f, id, "nope", addr), "the tenth first-party wrong guess")
			wantAddressWait(t, tc.via(t, f, id, "hunter2", addr), "the right password from the blocked address")
		})
	}
}

// A ?pw= link on the app origin is sent to the file origin by the 308, and
// what arrives there is the same visitor's guess: a typed link keeps
// Sec-Fetch-Site none across the redirect, so the hop counts on the
// address like the link itself.
func TestTheFileOriginHopCountsAsFirstParty(t *testing.T) {
	f := newSharePWFixture(t)
	const addr = "203.0.113.61:5000"
	hop := func(pw string) *httptest.ResponseRecorder {
		t.Helper()
		first := serveAs(f.h, httptest.NewRequest("GET", "https://"+fpApp+"/view/"+f.share+"/"+f.slug+"?pw="+pw, nil), addr, metaTyped)
		loc := first.Header().Get("Location")
		if first.Code != http.StatusPermanentRedirect || !strings.HasPrefix(loc, "https://"+fpFile+"/view/") {
			t.Fatalf("the app origin's /view: %d to %q, want 308 to the file origin", first.Code, loc)
		}
		return serveAs(f.h, httptest.NewRequest("GET", loc, nil), addr, metaTyped)
	}
	for i := range pwFailLimit - 1 {
		wantWrongAnswer(t, hop("nope"), fmt.Sprintf("hop %d", i+1))
	}
	wantAddressWait(t, hop("nope"), "the tenth hop")
}

// An address blocked at one share guesses at another: the address's count
// is kept per share.
func TestOneSharesAddressBlockLeavesAnotherOpen(t *testing.T) {
	f := newSharePWFixture(t)
	other, _ := protectedShareWithFile(t, f.h)
	const addr = "203.0.113.62:5000"
	form := formGuess(metaAppForm)
	for range pwFailLimit - 1 {
		wantWrongAnswer(t, form(t, f, f.share, "nope", addr), "a wrong guess at the first share")
	}
	wantAddressWait(t, form(t, f, f.share, "nope", addr), "the tenth wrong guess at the first share")

	wantWrongAnswer(t, form(t, f, other, "nope", addr), "a wrong guess at the other share")
	if rec := form(t, f, other, "hunter2", addr); rec.Code != http.StatusSeeOther {
		t.Fatalf("the right password at the other share: %d %.300s, want 303", rec.Code, rec.Body)
	}
	wantAddressWait(t, form(t, f, f.share, "hunter2", addr), "the right password at the blocked share")
}

// A cross-site guess is checked, so a picture another page embeds with its
// password in the address loads.
func TestACrossSiteRightPasswordOpens(t *testing.T) {
	f := newSharePWFixture(t)
	rec := fileQueryGuess(metaCrossImage)(t, f, f.share, "hunter2", "203.0.113.63:5000")
	if rec.Code != http.StatusOK || rec.Body.String() != "data" {
		t.Fatalf("a cross-site picture with the right ?pw=: %d %.300s, want the bytes", rec.Code, rec.Body)
	}
}

// On a server with one origin (no domain), a same-site form counts on the
// address when its Origin names the host the request reached, and not when
// it names another host.
func TestWithoutADomainASameSiteFormCountsOnlyFromItsOwnHost(t *testing.T) {
	const host = "box.example.com"
	for _, tc := range []struct {
		origin  string
		counted bool
	}{
		{"https://" + host, true},
		{"https://" + host + ":8443", true},
		{"https://other.example.com", false},
		{"null", false},
	} {
		t.Run(tc.origin, func(t *testing.T) {
			h := newTestAPI(t)
			id := protectedShare(t, h)
			const addr = "203.0.113.64:5000"
			meta := fetchMeta{site: "same-site", dest: "document", mode: "navigate", origin: tc.origin}
			guess := func() *httptest.ResponseRecorder {
				req := httptest.NewRequest("POST", "http://"+host+"/unlock/"+id, strings.NewReader("password=nope"))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return serveAs(h, req, addr, meta)
			}
			for i := range pwFailLimit - 1 {
				wantWrongAnswer(t, guess(), fmt.Sprintf("same-site wrong guess %d", i+1))
			}
			if tc.counted {
				wantAddressWait(t, guess(), "the tenth same-site wrong guess from the host itself")
			} else {
				wantWrongAnswer(t, guess(), "the tenth same-site wrong guess from another host")
			}
		})
	}
}
