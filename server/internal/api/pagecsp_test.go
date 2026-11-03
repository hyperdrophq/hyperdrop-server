package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const (
	cspDomain = "share.example.com"
	cspFiles  = "files." + cspDomain
	// The policy of a page an owner may frame, on a split server.
	framablePageCSP = "base-uri 'none'; object-src 'none'; form-action 'self' https://" +
		cspDomain + " https://" + cspFiles
	// The policy of the password form and the join page there.
	unframedPageCSP = framablePageCSP + "; frame-ancestors 'none'"
)

// pageReq sends one browser request to host, with a client address and a
// User-Agent the test controls.
func pageReq(h http.Handler, method, host, path, body, ua string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Host = host
	req.RemoteAddr = "203.0.113.50:4000"
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func wantPagePolicy(t *testing.T, what string, rec *httptest.ResponseRecorder, wantCode int, csp string, unframedPage bool) {
	t.Helper()
	if rec.Code != wantCode {
		t.Fatalf("%s = %d, want %d: %.200s", what, rec.Code, wantCode, rec.Body)
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != csp {
		t.Errorf("%s CSP = %q\nwant %q", what, got, csp)
	}
	xfo := rec.Header().Get("X-Frame-Options")
	if unframedPage && xfo != "DENY" {
		t.Errorf("%s X-Frame-Options = %q, want DENY", what, xfo)
	}
	if !unframedPage && xfo != "" {
		t.Errorf("%s X-Frame-Options = %q, want none: an owner may frame this page", what, xfo)
	}
}

// Every page of ours carries the page policy: no <base>, no plugin content,
// forms posting only to this server's two origins. Only the password form
// and the join page refuse to be framed; a listing, a gallery, a Receive
// Inbox and the pages they reach stay embeddable.
func TestEveryPageCarriesThePagePolicy(t *testing.T) {
	h := domainAPI(t, cspDomain)

	listing := createShare(t, h, "two")
	uploadGetSlug(t, h, listing, "a.txt", "a")
	uploadGetSlug(t, h, listing, "b.txt", "b")
	gallery := newMediaShare(t, h, map[string]string{"beach.jpg": "photo-bytes"})
	inbox := createInbox(t, h, `{"name":"logs","receive":true}`)

	rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"name":"s","files":[{"path":"report.pdf","size":100}]}`)
	var pending struct {
		ID    string `json:"id"`
		Files []struct {
			Slug string `json:"slug"`
		} `json:"files"`
	}
	unmarshal(t, rec, &pending)
	if len(pending.Files) != 1 {
		t.Fatalf("pending share: %s", rec.Body)
	}

	for _, tc := range []struct {
		what, host, path, ua string
		code                 int
	}{
		{"listing", cspDomain, "/share/" + listing, "", 200},
		{"gallery", cspDomain, "/share/" + gallery, "", 200},
		{"receive inbox", cspDomain, "/receive/" + inbox, "", 200},
		{"link-preview card", cspDomain, "/share/" + listing, "Slackbot-LinkExpanding 1.0", 200},
		{"waiting page", cspFiles, "/view/" + pending.ID + "/" + pending.Files[0].Slug, "", 200},
		{"404 on the app origin", cspDomain, "/no-such-page", "", 404},
		{"404 on the files origin", cspFiles, "/view/nosuchshare1/x", "", 404},
	} {
		wantPagePolicy(t, tc.what, pageReq(h, "GET", tc.host, tc.path, "", tc.ua), tc.code, framablePageCSP, false)
	}

	for _, tc := range []struct{ what, path string }{
		{"front page", "/"}, {"join page", "/join"},
	} {
		wantPagePolicy(t, tc.what, pageReq(h, "GET", cspDomain, tc.path, "", ""), 200, unframedPageCSP, true)
		wantPagePolicy(t, tc.what+" HEAD", pageReq(h, "HEAD", cspDomain, tc.path, "", ""), 200, unframedPageCSP, true)
	}
}

// The password form refuses every frame on both origins it renders on, and
// on the 401 that answers a wrong password. The locked-out page that
// answers too many of them has nothing to click and stays framable.
func TestThePasswordFormRefusesFraming(t *testing.T) {
	h := domainAPI(t, cspDomain)
	id, slug := createProtectedFile(t, h, "s3cret", "a.txt", "data")

	wantPagePolicy(t, "form on the app origin",
		pageReq(h, "GET", cspDomain, "/share/"+id, "", ""), 200, unframedPageCSP, true)
	wantPagePolicy(t, "form in place of /view",
		pageReq(h, "GET", cspFiles, "/view/"+id+"/"+slug, "", ""), 200, unframedPageCSP, true)

	wrong := url.Values{"password": {"nope"}}.Encode()
	for i := 0; i < pwFailLimit-1; i++ {
		wantPagePolicy(t, "form after a wrong password",
			pageReq(h, "POST", cspDomain, "/unlock/"+id, wrong, ""), 401, unframedPageCSP, true)
	}
	wantPagePolicy(t, "locked-out page",
		pageReq(h, "POST", cspDomain, "/unlock/"+id, wrong, ""), 429, framablePageCSP, false)
}

// A browser checks form-action on every hop of a form's redirect chain, so
// each hop of an unlock must land on an origin the form's page names. A
// single-file share unlocked on the app origin is the long chain: the 303
// to /share/{id}, its redirect to /view, and the 308 onto files.<domain>.
// Each origin the chain reaches is named in the policy of the page that
// posted the form, the app origin's and the files origin's alike.
func TestTheUnlockChainStaysInsideFormAction(t *testing.T) {
	h := domainAPI(t, cspDomain)
	id, slug := createProtectedFile(t, h, "s3cret", "a.txt", "data")

	for _, tc := range []struct{ formHost, formPath, next string }{
		{cspDomain, "/share/" + id, "/share/" + id},
		{cspFiles, "/view/" + id + "/" + slug, "/view/" + id + "/" + slug},
	} {
		form := pageReq(h, "GET", tc.formHost, tc.formPath, "", "")
		allowed := formActionOrigins(t, form.Header().Get("Content-Security-Policy"), "https://"+tc.formHost)

		action := "https://" + tc.formHost + "/unlock/" + id
		if tc.formHost == cspFiles {
			action = "https://" + cspDomain + "/unlock/" + id
		}
		body := url.Values{"password": {"s3cret"}, "next": {tc.next}}.Encode()
		method, target, hops := "POST", action, 0
		var cookies []*http.Cookie
		for {
			u, err := url.Parse(target)
			if err != nil {
				t.Fatal(err)
			}
			if !allowed[u.Scheme+"://"+u.Host] {
				t.Fatalf("from %s: hop %d lands on %s, outside form-action %v", tc.formPath, hops, target, allowed)
			}
			req := httptest.NewRequest(method, u.RequestURI(), nil)
			if method == "POST" {
				req = httptest.NewRequest(method, u.RequestURI(), strings.NewReader(body))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			req.Host = u.Host
			for _, c := range cookies {
				req.AddCookie(c)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			cookies = append(cookies, rec.Result().Cookies()...)
			loc := rec.Header().Get("Location")
			if rec.Code < 300 || rec.Code > 399 || loc == "" {
				if rec.Code != 200 || u.Host != cspFiles {
					t.Fatalf("from %s: chain ends %d on %s, want 200 on the files origin", tc.formPath, rec.Code, target)
				}
				break
			}
			next, err := u.Parse(loc)
			if err != nil {
				t.Fatal(err)
			}
			method, target, hops = "GET", next.String(), hops+1
			if hops > 5 {
				t.Fatalf("from %s: redirect loop at %s", tc.formPath, target)
			}
		}
	}
}

// formActionOrigins is the set of origins a policy's form-action names, with
// 'self' read as self.
func formActionOrigins(t *testing.T, csp, self string) map[string]bool {
	t.Helper()
	for _, d := range strings.Split(csp, ";") {
		f := strings.Fields(d)
		if len(f) == 0 || f[0] != "form-action" {
			continue
		}
		out := map[string]bool{}
		for _, s := range f[1:] {
			if s == "'self'" {
				s = self
			}
			out[s] = true
		}
		return out
	}
	t.Fatalf("no form-action in %q", csp)
	return nil
}

// Uploaded content keeps its own policy: the sandbox, with no page policy
// and no framing header in its place.
func TestAnUploadedPageKeepsTheSandbox(t *testing.T) {
	h := domainAPI(t, cspDomain)
	id := createShare(t, h, "site")
	slug := uploadGetSlug(t, h, id, "page.html", "<script>alert(1)</script>")
	uploadGetSlug(t, h, id, "other.txt", "x")

	rec := pageReq(h, "GET", cspFiles, "/view/"+id+"/"+slug, "", "")
	if rec.Code != 200 {
		t.Fatalf("view = %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != sandboxCSP {
		t.Errorf("uploaded page CSP = %q, want the sandbox %q", got, sandboxCSP)
	}
	if got := rec.Header().Get("X-Frame-Options"); got != "" {
		t.Errorf("uploaded page X-Frame-Options = %q, want none", got)
	}
}

// Without a domain there is one origin, and 'self' is the whole form-action.
func TestWithoutADomainThePagePolicyNamesSelf(t *testing.T) {
	h := newTestAPI(t)
	id := createProtectedShare(t, h, "s3cret")
	wantPagePolicy(t, "form without a domain", doReq(t, h, "GET", "/share/"+id, "", ""), 200,
		"base-uri 'none'; object-src 'none'; form-action 'self'; frame-ancestors 'none'", true)
	wantPagePolicy(t, "404 without a domain", doReq(t, h, "GET", "/no-such-page", "", ""), 404,
		"base-uri 'none'; object-src 'none'; form-action 'self'", false)
}
