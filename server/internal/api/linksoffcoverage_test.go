package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/linked"
)

// What a share whose links are OFF owes each public route. The owner turned
// the links off, so nobody holding one may reach the share: every route
// answers the links-off page, a page that names nothing, or a plain 404, and
// the one read left is the owner's own bearer fetch on /download.
//
// The rule lives at the one gate every public route resolves through
// (visibleShareAnyID). Nothing but this file forces a NEW public route to go
// through it, so the walk below is over the MUX, through the same
// routeExposure table the inbox containment walk keeps
// (inboxcoverage_test.go): a route added there is walked here too.
//
// What each classification owes a links-off share:
//
//   - hidden: the links-off page (503) on a page route, a plain 404 on a
//     machine route (linksOffMachineRoutes), for an ordinary share and a
//     linked one. Each probe is first shown to SERVE the same share with its
//     links on, since a 404 from a route with nothing to serve proves nothing.
//   - inboxOwn: /unlock answers the links-off page (the gate decides before the
//     password); the /receive routes serve only an inbox, which has no links
//     to turn off, so a links-off share answers 404 there as any share does.
//   - beforeLookup: /site/{id} redirects on the id's shape alone and resolves
//     no share, so it must answer exactly what an id that never existed gets.
//   - notShareScoped: no share id, nothing to refuse.

// linksOffMachineRoutes are the hidden routes whose answer is a picture or
// JSON, never a page: a links-off share is a plain 404 there.
var linksOffMachineRoutes = map[string]bool{
	"GET /card/{id}/poster.jpg": true,
	"GET /share/{id}/status":    true,
	"GET /thumb/{id}/{slug}":    true,
	"GET /f/{fileKey}/status":   true,
}

const (
	linksOffTitle = "Link temporarily disabled"
	linksOffBody  = "The owner has temporarily disabled this link. Nothing has been deleted: " +
		"check back later, or ask the person who sent you the link."
	// linksOffName is the probes' share name: distinctive, so a body that
	// names the share cannot pass by naming something else.
	linksOffName = "ZanzibarLedger7731"
)

func setLinksOff(t *testing.T, h http.Handler, id string, off bool) {
	t.Helper()
	body := `{"linksOff":false}`
	if off {
		body = `{"linksOff":true}`
	}
	if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, body); rec.Code != 200 {
		t.Fatalf("links off=%v = %d %s", off, rec.Code, rec.Body)
	}
}

// wantLinksOffPage asserts rec is the links-off page.
func wantLinksOffPage(t *testing.T, what string, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("%s = %d, want 503 (the links-off page): %s", what, rec.Code, rec.Body)
		return
	}
	body := rec.Body.String()
	if !strings.Contains(body, "<title>"+linksOffTitle+"</title>") || !strings.Contains(body, linksOffBody) {
		t.Errorf("%s: not the links-off page: %s", what, body)
	}
	if strings.Contains(body, "og:") {
		t.Errorf("%s: the links-off page carries Open Graph tags", what)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("%s: Cache-Control %q, want no-store", what, got)
	}
	if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("%s: Referrer-Policy %q, want no-referrer", what, got)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Errorf("%s: the links-off page sets a cookie: %v", what, rec.Header().Values("Set-Cookie"))
	}
}

func TestALinksOffShareIsHiddenOnEveryPublicRoute(t *testing.T) {
	vol := seedLinkedVolume(t)
	roots, err := linked.NewRoots(nil, []string{vol}, nil)
	if err != nil {
		t.Fatal(err)
	}
	b := testBackendAt(t, t.TempDir())
	b.Roots = roots
	h := New(b, "2.0.0", testDomain(t), nil)

	type probe struct {
		kind, id, slug, key string
	}
	ordinary, ordinarySlug := publicProbeShare(t, h, false)
	linkedID, linkedSlug := publicProbeLinkedShare(t, h)
	probes := []probe{
		{"ordinary", ordinary, ordinarySlug, mintFileKey(t, h, testToken, ordinary, ordinarySlug)},
		{"linked", linkedID, linkedSlug, mintFileKey(t, h, testToken, linkedID, linkedSlug)},
	}
	const stranger = "Qx7mK2pR9v"

	tested := 0
	for _, p := range probes {
		if rec := doReq(t, h, "PATCH", "/api/shares/"+p.id, testToken, `{"name":"`+linksOffName+`"}`); rec.Code != 200 {
			t.Fatalf("rename = %d %s", rec.Code, rec.Body)
		}
		// Everything a links-off answer must never carry.
		words := []string{p.id, linksOffName, probeFileName, p.slug, p.key}

		// Links on: every hidden route serves the share, so the refusal
		// below is the gate's and not a route with nothing to serve.
		for key, exposure := range routeExposure {
			if exposure != hidden {
				continue
			}
			method, pattern, _ := strings.Cut(key, " ")
			path := inboxPath(pattern, p.id, p.slug, p.key)
			if rec := doReq(t, h, method, path, "", ""); rec.Code == 404 {
				t.Errorf("%s %s = 404 for a %s share with links ON: this probe cannot tell "+
					"a links-off refusal from a route with nothing to serve", method, path, p.kind)
			}
		}

		setLinksOff(t, h, p.id, true)
		for key, exposure := range routeExposure {
			method, pattern, _ := strings.Cut(key, " ")
			path := inboxPath(pattern, p.id, p.slug, p.key)
			what := p.kind + " " + method + " " + path
			switch exposure {
			case hidden:
				rec := doReq(t, h, method, path, "", "")
				if linksOffMachineRoutes[key] {
					if rec.Code != 404 {
						t.Errorf("%s = %d, want 404 for a links-off share", what, rec.Code)
					}
				} else {
					wantLinksOffPage(t, what, rec)
				}
				namesNothing(t, what, rec, words...)
				tested++
			case inboxOwn:
				rec := doReq(t, h, method, path, "", "")
				if key == "POST /unlock/{id}" {
					wantLinksOffPage(t, what, rec)
				} else if rec.Code != 404 {
					t.Errorf("%s = %d, want 404: only an inbox answers there", what, rec.Code)
				}
				namesNothing(t, what, rec, words...)
				tested++
			case beforeLookup:
				mine := doReq(t, h, method, path, "", "")
				none := doReq(t, h, method, inboxPath(pattern, stranger, p.slug, p.key), "", "")
				wantLocation := strings.Replace(none.Header().Get("Location"), stranger, p.id, 1)
				if mine.Code != none.Code || mine.Header().Get("Location") != wantLocation {
					t.Errorf("%s answers %d for a links-off share and %d for an id that never "+
						"existed: it is resolving the share, so it owes the links-off rule",
						what, mine.Code, none.Code)
				}
				tested++
			}
		}

		// Links back on: the same links serve again, nothing was lost.
		setLinksOff(t, h, p.id, false)
		for key, exposure := range routeExposure {
			if exposure != hidden {
				continue
			}
			method, pattern, _ := strings.Cut(key, " ")
			path := inboxPath(pattern, p.id, p.slug, p.key)
			if rec := doReq(t, h, method, path, "", ""); rec.Code == 404 || rec.Code == 503 {
				t.Errorf("%s %s = %d with the links back on", method, path, rec.Code)
			}
		}
	}
	if tested == 0 {
		t.Fatal("no routes were exercised: the table has drifted from the mux")
	}
}

// The owner's own bearer fetch on /download is the one read a links-off share
// keeps (Quick Look, `hyperdrop fetch`): authenticated, not public. Another
// account's bearer is a stranger's, and /view carries no bearer exception.
func TestTheOwnerStillDownloadsALinksOffShare(t *testing.T) {
	h := newTestAPI(t)
	id, slugs := shareWithFiles(t, h, linksOffName, map[string]string{"a.txt": "the bytes"})
	setLinksOff(t, h, id, true)

	rec := doReq(t, h, "GET", "/download/"+id+"/"+slugs["a.txt"], testToken, "")
	if rec.Code != 200 || rec.Body.String() != "the bytes" {
		t.Fatalf("the owner's download = %d %q, want 200 and the bytes", rec.Code, rec.Body)
	}
	bob := grantedUser(t, h, "bob")
	wantLinksOffPage(t, "another account's download",
		doReq(t, h, "GET", "/download/"+id+"/"+slugs["a.txt"], bob, ""))
	wantLinksOffPage(t, "an anonymous download", doReq(t, h, "GET", "/download/"+id+"/"+slugs["a.txt"], "", ""))
	wantLinksOffPage(t, "the owner's view", doReq(t, h, "GET", "/view/"+id+"/"+slugs["a.txt"], testToken, ""))
}

// Gone comes before off: an expired share whose links are also off is the
// plain 404 every expired share answers, never the links-off page, which
// would say the share still exists.
func TestAnExpiredLinksOffShareIsNotFound(t *testing.T) {
	dir := t.TempDir()
	h := New(testBackendAt(t, dir), "2.0.0", testDomain(t), nil)
	id, slugs := shareWithFiles(t, h, linksOffName, map[string]string{"a.txt": "the bytes"})
	setLinksOff(t, h, id, true)
	execRaw(t, dir, `UPDATE shares SET expires_at = ? WHERE id = ?`, time.Now().Add(-time.Hour).UnixNano(), id)
	for _, p := range []string{"/share/" + id, "/view/" + id + "/" + slugs["a.txt"], "/download/" + id + "/" + slugs["a.txt"], "/zip/" + id} {
		if rec := doReq(t, h, "GET", p, "", ""); rec.Code != 404 {
			t.Errorf("expired links-off %s = %d, want 404", p, rec.Code)
		}
	}
}

// Off comes before the password: a protected share whose links are off shows
// the links-off page, never the form, and a right password opens nothing and
// mints no cookie, by the form's POST or by ?pw=.
func TestALinksOffShareNeverShowsItsPassword(t *testing.T) {
	const password = "hunter2-share"
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"name":"`+linksOffName+`","password":"`+password+`","files":[{"path":"a.txt","size":9}]}`)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	var made struct {
		ID string `json:"id"`
	}
	unmarshal(t, rec, &made)
	id := made.ID
	slug := uploadGetSlug(t, h, id, "a.txt", "the bytes")
	setLinksOff(t, h, id, true)

	for _, p := range []string{"/share/" + id, "/view/" + id + "/" + slug, "/zip/" + id,
		"/share/" + id + "?pw=" + password, "/download/" + id + "/" + slug + "?pw=" + password} {
		rec := doReq(t, h, "GET", p, "", "")
		wantLinksOffPage(t, p, rec)
		if strings.Contains(rec.Body.String(), `type="password"`) {
			t.Errorf("%s shows the password form", p)
		}
	}
	form := url.Values{"password": {password}, "next": {"/share/" + id}}.Encode()
	rec = doReqForm(t, h, "POST", "/unlock/"+id, form)
	wantLinksOffPage(t, "a right password", rec)
	if sc := rec.Header().Values("Set-Cookie"); len(sc) != 0 {
		t.Errorf("a right password on a links-off share set %v", sc)
	}
}

// A visit to a links-off share is no visit: the page counts nobody and mints
// no visitor cookie.
func TestALinksOffShareCountsNoVisit(t *testing.T) {
	mux, h := newTestAPIParts(t)
	id, slugs := shareWithFiles(t, mux, linksOffName, map[string]string{"a.txt": "data", "b.txt": "more"})
	setLinksOff(t, mux, id, true)
	for i, addr := range []string{"10.0.0.1:1", "10.0.0.2:1"} {
		rec := get(mux, "/share/"+id, "Mozilla/5.0", addr, nil)
		wantLinksOffPage(t, "visit", rec)
		if visitorCookieOf(t, rec) != nil {
			t.Errorf("visit %d minted a visitor cookie", i)
		}
		get(mux, "/view/"+id+"/"+slugs["a.txt"], "Mozilla/5.0", addr, nil)
		get(mux, "/zip/"+id, "Mozilla/5.0", addr, nil)
	}
	if n := visitorsOf(t, h, mux, id); n != 0 {
		t.Fatalf("a links-off share counted %d visitors, want 0", n)
	}
}
