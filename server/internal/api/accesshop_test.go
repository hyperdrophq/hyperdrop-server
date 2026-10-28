package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/ddns"
	"hyperdrop/server/internal/domain"
	"hyperdrop/server/internal/shareid"
)

const (
	hopApp  = "share.example.com"
	hopFile = "files.share.example.com"
)

// splitHandler is a handler whose origin split is live, returned with the
// *handler behind it so a test can sign a token the way the server does.
func splitHandler(t *testing.T) (*handler, http.Handler) {
	t.Helper()
	dom, err := domain.Load(filepath.Join(t.TempDir(), "domain"), "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	if err := dom.Adopt(hopApp); err != nil {
		t.Fatal(err)
	}
	hh := newHandler(testBackend(t), "2.0.0", dom, nil, Deployment{})
	return hh, hh.routes()
}

// hopShare makes a password-protected share holding one file
// and returns its id and the file's slug.
func hopShare(t *testing.T, h http.Handler, password string) (string, string) {
	t.Helper()
	id := createProtectedShare(t, h, password)
	return id, uploadGetSlug(t, h, id, "a.txt", "protected bytes")
}

// browse sends one request as a browser would: to host, carrying cookies,
// marked as a top-level navigation.
func browse(t *testing.T, h http.Handler, method, host, target, form string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if form != "" {
		r = httptest.NewRequest(method, target, strings.NewReader(form))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	r.Host = host
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	r.Header.Set("Sec-Fetch-Dest", "document")
	for _, c := range cookies {
		r.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// accessCookieOf is the hd_<id> cookie a response sets, or nil.
func accessCookieOf(rec *httptest.ResponseRecorder, id string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == "hd_"+id && c.MaxAge >= 0 && c.Value != "" {
			return c
		}
	}
	return nil
}

// wantNoAccessDomain fails when any Set-Cookie line for an access cookie
// names a Domain: hd_<id> is host-only on whichever origin set it.
func wantNoAccessDomain(t *testing.T, rec *httptest.ResponseRecorder, what string) {
	t.Helper()
	for _, line := range rec.Header().Values("Set-Cookie") {
		if !strings.HasPrefix(line, "hd_") || strings.HasPrefix(line, visitorCookie+"=") {
			continue
		}
		if strings.Contains(strings.ToLower(line), "domain=") {
			t.Errorf("%s: access cookie %q carries a Domain attribute", what, line)
		}
	}
}

// hopTarget is the files-origin address an app-origin unlock sends the
// browser to, with its query parsed.
func hopTarget(t *testing.T, rec *httptest.ResponseRecorder, id string) (path string, q url.Values) {
	t.Helper()
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("unlock = %d %s, want 303", rec.Code, rec.Body)
	}
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "https" || u.Host != hopFile || u.Path != "/access/"+id {
		t.Fatalf("unlock Location = %q, want https://%s/access/%s", u, hopFile, id)
	}
	return u.RequestURI(), u.Query()
}

// The whole flow a recipient of a protected single-file share takes: the
// link opens on the file origin without a cookie and gets the password form
// there; the form posts to the app origin, which sets its own host-only
// cookie and sends the browser through the file origin's access route; that
// route sets the file origin's host-only cookie and forwards to the file.
func TestUnlockHopsThroughTheFileOriginAndServesTheFile(t *testing.T) {
	_, h := splitHandler(t)
	id, slug := hopShare(t, h, "s3cret")
	view := "/view/" + id + "/" + slug

	form := browse(t, h, "GET", hopFile, view, "")
	if !strings.Contains(form.Body.String(), "Password required") {
		t.Fatalf("file origin without a cookie = %d %.200s, want the password form", form.Code, form.Body)
	}
	if got := formAction(form.Body.String()); got != `action="https://`+hopApp+`/unlock/`+id+`"` {
		t.Fatalf("form action = %s", got)
	}

	unlock := browse(t, h, "POST", hopApp, "/unlock/"+id, "password=s3cret&next="+url.QueryEscape(view))
	wantNoAccessDomain(t, unlock, "unlock")
	if accessCookieOf(unlock, id) == nil {
		t.Fatalf("unlock set no access cookie on the app origin: %q", unlock.Header().Values("Set-Cookie"))
	}
	hop, q := hopTarget(t, unlock, id)
	if q.Get("next") != view {
		t.Fatalf("hop next = %q, want %q", q.Get("next"), view)
	}

	landed := browse(t, h, "GET", hopFile, hop, "")
	wantNoAccessDomain(t, landed, "access hop")
	fileCookie := accessCookieOf(landed, id)
	if fileCookie == nil {
		t.Fatalf("access hop = %d set no access cookie: %q", landed.Code, landed.Header().Values("Set-Cookie"))
	}
	if landed.Code != http.StatusSeeOther || landed.Header().Get("Location") != view {
		t.Fatalf("access hop = %d Location %q, want 303 to %s", landed.Code, landed.Header().Get("Location"), view)
	}
	if cc := landed.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("access hop Cache-Control = %q, want no-store", cc)
	}

	served := browse(t, h, "GET", hopFile, view, "", fileCookie)
	if served.Code != 200 || served.Body.String() != "protected bytes" {
		t.Fatalf("file with the hop's cookie = %d %.200s", served.Code, served.Body)
	}
}

// An unlock whose next is the listing forwards back to the app origin.
func TestTheAccessHopForwardsAPageBackToTheAppOrigin(t *testing.T) {
	_, h := splitHandler(t)
	id, _ := hopShare(t, h, "s3cret")
	unlock := browse(t, h, "POST", hopApp, "/unlock/"+id, "password=s3cret&next=/share/"+id)
	hop, _ := hopTarget(t, unlock, id)
	landed := browse(t, h, "GET", hopFile, hop, "")
	if want := "https://" + hopApp + "/share/" + id; landed.Header().Get("Location") != want {
		t.Fatalf("hop Location = %q, want %q", landed.Header().Get("Location"), want)
	}
	if accessCookieOf(landed, id) == nil {
		t.Fatal("hop set no file-origin cookie")
	}
}

// ?pw= opened as a page on the app origin takes the same hop, so the files
// its listing links to open on the file origin's own cookie.
func TestAPasswordInTheAddressHopsThroughTheFileOrigin(t *testing.T) {
	_, h := splitHandler(t)
	id, _ := hopShare(t, h, "s3cret")
	rec := browse(t, h, "GET", hopApp, "/share/"+id+"?pw=s3cret", "")
	wantNoAccessDomain(t, rec, "?pw= on the app origin")
	_, q := hopTarget(t, rec, id)
	if q.Get("next") != "/share/"+id {
		t.Fatalf("hop next = %q, want the listing without pw", q.Get("next"))
	}

	// On the file origin the cookie it sets is the one that origin needs.
	id2, slug := hopShare(t, h, "other")
	rec = browse(t, h, "GET", hopFile, "/view/"+id2+"/"+slug+"?pw=other", "")
	wantNoAccessDomain(t, rec, "?pw= on the file origin")
	if accessCookieOf(rec, id2) == nil {
		t.Fatalf("?pw= on the file origin set no cookie: %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/view/"+id2+"/"+slug {
		t.Fatalf("?pw= on the file origin Location = %q, want the same address without pw", loc)
	}
}

// The hop sets a cookie only for a token this server signed for THIS share,
// at its current password generation, and still unexpired.
func TestTheAccessHopRefusesABadToken(t *testing.T) {
	hh, h := splitHandler(t)
	id, _ := hopShare(t, h, "s3cret")
	other, _ := hopShare(t, h, "s3cret")
	gen := func(id string) int {
		v, err := hh.viewMeta(id)
		if err != nil {
			t.Fatal(err)
		}
		return v.PasswordGen
	}
	soon := time.Now().Add(time.Minute)
	for name, token := range map[string]string{
		"another share's token": hh.signAccessHop(other, gen(other), soon),
		"an expired token":      hh.signAccessHop(id, gen(id), time.Now().Add(-time.Second)),
		"an old generation":     hh.signAccessHop(id, gen(id)+1, soon),
		"a tampered token":      tamper(hh.signAccessHop(id, gen(id), soon)),
		"the cookie's value":    hh.signAccess(id, gen(id), soon),
		"a site grant":          hh.signGrant(id, gen(id), soon),
		"no token":              "",
	} {
		rec := browse(t, h, "GET", hopFile, "/access/"+id+"?token="+url.QueryEscape(token)+"&next=/share/"+id, "")
		if c := accessCookieOf(rec, id); c != nil {
			t.Errorf("%s: the hop set %s", name, c.Name)
		}
		if rec.Code != http.StatusSeeOther {
			t.Errorf("%s: hop = %d, want 303 onward to the password form", name, rec.Code)
		}
	}
	good := hh.signAccessHop(id, gen(id), soon)
	if rec := browse(t, h, "GET", hopFile, "/access/"+id+"?token="+url.QueryEscape(good), ""); accessCookieOf(rec, id) == nil {
		t.Fatalf("a good token set no cookie: %d", rec.Code)
	}
}

func tamper(token string) string {
	b := []byte(token)
	last := len(b) - 1
	if b[last] == '0' {
		b[last] = '1'
	} else {
		b[last] = '0'
	}
	return string(b)
}

// The onward address is one of this share's own public routes on one of
// this server's two origins, whatever next says.
func TestTheAccessHopIsNoOpenRedirect(t *testing.T) {
	hh, h := splitHandler(t)
	id, _ := hopShare(t, h, "s3cret")
	other, slug := hopShare(t, h, "s3cret")
	v, _ := hh.viewMeta(id)
	token := url.QueryEscape(hh.signAccessHop(id, v.PasswordGen, time.Now().Add(time.Minute)))
	fallback := "https://" + hopApp + "/share/" + id
	for _, next := range []string{
		"https://evil.example/", "//evil.example/", "/\\evil.example", "/\t/evil.example",
		"/view/" + other + "/" + slug, "/share/" + other, "/api/me", "/view/" + id + "/../../api/me",
		"javascript:alert(1)", "",
	} {
		rec := browse(t, h, "GET", hopFile, "/access/"+id+"?token="+token+"&next="+url.QueryEscape(next), "")
		if loc := rec.Header().Get("Location"); loc != fallback {
			t.Errorf("next %q: Location = %q, want %q", next, loc, fallback)
		}
	}
}

// A Receive Inbox never reaches the hop: its unlock stays on the app origin,
// where its page and its upload live, and the hop answers 404 for it.
func TestAnInboxUnlockTakesNoHop(t *testing.T) {
	hh, h := splitHandler(t)
	id := createInbox(t, h, `{"name":"drop","receive":true,"password":"s3cret"}`)
	unlock := browse(t, h, "POST", hopApp, "/unlock/"+id, "password=s3cret")
	wantNoAccessDomain(t, unlock, "inbox unlock")
	if unlock.Code != http.StatusSeeOther || unlock.Header().Get("Location") != "/receive/"+id {
		t.Fatalf("inbox unlock = %d Location %q, want 303 to /receive/%s", unlock.Code, unlock.Header().Get("Location"), id)
	}
	if accessCookieOf(unlock, id) == nil {
		t.Fatal("inbox unlock set no cookie")
	}
	v, err := hh.viewMeta(id)
	if err != nil {
		t.Fatal(err)
	}
	token := url.QueryEscape(hh.signAccessHop(id, v.PasswordGen, time.Now().Add(time.Minute)))
	if rec := browse(t, h, "GET", hopFile, "/access/"+id+"?token="+token, ""); rec.Code != 404 || accessCookieOf(rec, id) != nil {
		t.Fatalf("hop for an inbox = %d, want 404 and no cookie", rec.Code)
	}
}

// One host serves both halves when there is no domain, so the unlock
// redirects straight to next and the cookie it sets is host-only there.
func TestWithoutASplitTheUnlockTakesNoHop(t *testing.T) {
	h := newTestAPI(t)
	id, slug := hopShare(t, h, "s3cret")
	view := "/view/" + id + "/" + slug
	unlock := browse(t, h, "POST", "localhost:8081", "/unlock/"+id, "password=s3cret&next="+url.QueryEscape(view))
	wantNoAccessDomain(t, unlock, "single-origin unlock")
	if unlock.Code != http.StatusSeeOther || unlock.Header().Get("Location") != view {
		t.Fatalf("unlock = %d Location %q, want 303 to %s", unlock.Code, unlock.Header().Get("Location"), view)
	}
	c := accessCookieOf(unlock, id)
	if c == nil {
		t.Fatal("no cookie")
	}
	if rec := browse(t, h, "GET", "localhost:8081", view, "", c); rec.Code != 200 || rec.Body.String() != "protected bytes" {
		t.Fatalf("file = %d %.200s", rec.Code, rec.Body)
	}
}

// unlockedOnTheFileOrigin unlocks a fresh protected share on f's app origin,
// takes the hop, and answers the share's id, the file origin's access
// cookie and the attributes that cookie was set with.
func unlockedOnTheFileOrigin(t *testing.T, f webFixture) (string, *http.Cookie, []string) {
	t.Helper()
	id, slug := hopShare(t, f.h, "s3cret")
	unlock := browse(t, f.h, "POST", f.appHost, "/unlock/"+id, "password=s3cret&next=/view/"+id+"/"+slug)
	if unlock.Code != http.StatusSeeOther {
		t.Fatalf("unlock = %d", unlock.Code)
	}
	u, err := url.Parse(unlock.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	landed := browse(t, f.h, "GET", u.Host, u.RequestURI(), "")
	c := accessCookieOf(landed, id)
	if c == nil {
		t.Fatalf("the hop set no cookie: %d %q", landed.Code, landed.Header().Values("Set-Cookie"))
	}
	var attrs []string
	for _, line := range landed.Header().Values("Set-Cookie") {
		if strings.HasPrefix(line, "hd_"+id+"=") {
			for _, a := range strings.Split(line, "; ")[1:] {
				if !strings.HasPrefix(a, "Expires=") {
					attrs = append(attrs, a)
				}
			}
		}
	}
	return id, c, attrs
}

// signOutAnswer is a web sign-out's accessClear URL, "" when the answer has
// none, and the hd_clear cookie it sets, or nil.
func signOutAnswer(t *testing.T, f webFixture, edit ...func(*http.Request)) (string, *http.Cookie) {
	t.Helper()
	raw := f.signIn(t, false)
	rec := f.req(t, "DELETE", "/api/web/session", raw, "", edit...)
	var clear *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == accessClearCookie {
			clear = c
		}
	}
	if rec.Code == http.StatusNoContent {
		return "", clear
	}
	if rec.Code != 200 {
		t.Fatalf("sign out = %d %s", rec.Code, rec.Body)
	}
	var out map[string]string
	unmarshal(t, rec, &out)
	if len(out) != 1 || out["accessClear"] == "" {
		t.Fatalf("sign out answered %s, want only accessClear", rec.Body)
	}
	return out["accessClear"], clear
}

// clearOn sends what the web client's <img> sends to the clear URL target on
// the file origin, carrying cookies.
func clearOn(t *testing.T, h http.Handler, host, target string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("GET", target, nil)
	r.Host = host
	r.Header.Set("Sec-Fetch-Dest", "image")
	r.Header.Set("Sec-Fetch-Site", "same-site")
	for _, c := range cookies {
		r.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "image/gif" || !strings.HasPrefix(rec.Body.String(), "GIF89a") {
		t.Fatalf("clear = %d %q, want a 200 GIF whatever it clears", rec.Code, rec.Header().Get("Content-Type"))
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("clear Cache-Control = %q, want no-store", cc)
	}
	return rec
}

// A web sign-out on a split server hands the browser the file origin's clear
// URL and the one-minute hd_clear cookie its token is bound to; loading that
// URL clears every access cookie the file origin holds, with the attributes
// the hop set it with, and leaves the grouping cookies alone.
func TestASignOutClearsTheFileOriginsAccessCookies(t *testing.T) {
	f := newWebFixture(t, true)
	id, fileCookie, setAttrs := unlockedOnTheFileOrigin(t, f)

	clearURL, clearCookie := signOutAnswer(t, f)
	u, err := url.Parse(clearURL)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "https" || u.Host != "files."+webAppHost || u.Path != "/access/clear" || u.Query().Get("t") == "" {
		t.Fatalf("accessClear = %q, want https://files.%s/access/clear?t=…", clearURL, webAppHost)
	}
	if clearCookie == nil {
		t.Fatal("the sign-out set no hd_clear cookie")
	}
	if clearCookie.Domain != webAppHost || clearCookie.Path != "/access/clear" || clearCookie.MaxAge != 60 ||
		!clearCookie.HttpOnly || !clearCookie.Secure {
		t.Errorf("hd_clear = %+v, want Domain=%s Path=/access/clear Max-Age=60 HttpOnly Secure", clearCookie, webAppHost)
	}

	rec := clearOn(t, f.h, u.Host, u.RequestURI(), fileCookie, clearCookie,
		&http.Cookie{Name: visitorCookie, Value: "v"}, &http.Cookie{Name: visitorCookieName(id), Value: "v"},
		&http.Cookie{Name: "hd_short", Value: "v"})
	var accessClears, clearClears []string
	for _, line := range rec.Header().Values("Set-Cookie") {
		switch {
		case strings.HasPrefix(line, "hd_"+id+"=;"):
			accessClears = append(accessClears, line)
		case strings.HasPrefix(line, accessClearCookie+"=;"):
			clearClears = append(clearClears, line)
		default:
			t.Errorf("clear set %q", line)
		}
	}
	if len(accessClears) != 1 || len(clearClears) != 1 {
		t.Fatalf("clear set %q, want one clear of hd_%s and one of hd_clear", rec.Header().Values("Set-Cookie"), id)
	}
	if !strings.Contains(accessClears[0], "Max-Age=0") {
		t.Fatalf("clear %q has no Max-Age=0", accessClears[0])
	}
	// A browser drops a cookie only for a clear naming the same domain and
	// path it was set with.
	gone, err := http.ParseSetCookie(clearClears[0])
	if err != nil {
		t.Fatal(err)
	}
	if gone.Domain != clearCookie.Domain || gone.Path != clearCookie.Path || gone.MaxAge >= 0 ||
		gone.Secure != clearCookie.Secure || gone.HttpOnly != clearCookie.HttpOnly || gone.SameSite != clearCookie.SameSite {
		t.Fatalf("hd_clear clear %q, want the Domain %q, Path %q and flags of %+v with Max-Age=0",
			clearClears[0], clearCookie.Domain, clearCookie.Path, clearCookie)
	}
	var clearAttrs []string
	for _, a := range strings.Split(accessClears[0], "; ")[1:] {
		if a != "Max-Age=0" {
			clearAttrs = append(clearAttrs, a)
		}
	}
	slices.Sort(setAttrs)
	slices.Sort(clearAttrs)
	if !slices.Equal(setAttrs, clearAttrs) {
		t.Fatalf("clear attributes %q, want the hop's %q", clearAttrs, setAttrs)
	}
}

// Without the sign-out's own pair (its token in the address, its nonce in
// the hd_clear cookie, both unexpired) the clear clears nothing, so another
// site that links to it, a sibling host that loads it, or a token minted by
// someone else's sign-out signs nobody out of anything.
func TestTheAccessClearClearsNothingWithoutTheSignOutsPair(t *testing.T) {
	f := newWebFixture(t, true)
	id, fileCookie, _ := unlockedOnTheFileOrigin(t, f)
	clearURL, clearCookie := signOutAnswer(t, f)
	u, _ := url.Parse(clearURL)
	good := u.Query().Get("t")
	otherURL, otherCookie := signOutAnswer(t, f)
	o, _ := url.Parse(otherURL)
	gen := func() int {
		v, err := f.hd.viewMeta(id)
		if err != nil {
			t.Fatal(err)
		}
		return v.PasswordGen
	}()
	soon := time.Now().Add(time.Minute)
	for name, c := range map[string]struct {
		token  string
		cookie *http.Cookie
	}{
		"no token":                   {"", clearCookie},
		"no hd_clear cookie":         {good, nil},
		"another sign-out's token":   {o.Query().Get("t"), clearCookie},
		"another sign-out's cookie":  {good, otherCookie},
		"an expired token":           {f.hd.signAccessClear(clearCookie.Value, time.Now().Add(-time.Second)), clearCookie},
		"a tampered token":           {tamper(good), clearCookie},
		"a hop token":                {f.hd.signAccessHop(id, gen, soon), clearCookie},
		"the access cookie's value":  {f.hd.signAccess(id, gen, soon), clearCookie},
		"a site grant":               {f.hd.signGrant(id, gen, soon), clearCookie},
		"a token over another scope": {f.hd.signScoped(accessHopScope, clearCookie.Value, 0, soon), clearCookie},
	} {
		cookies := []*http.Cookie{fileCookie}
		if c.cookie != nil {
			cookies = append(cookies, c.cookie)
		}
		rec := clearOn(t, f.h, "files."+webAppHost, "/access/clear?t="+url.QueryEscape(c.token), cookies...)
		if lines := rec.Header().Values("Set-Cookie"); len(lines) != 0 {
			t.Errorf("%s: the clear set %q", name, lines)
		}
	}
	// A top-level navigation with the right pair still clears: the pair, not
	// the request's shape, is what the clear checks.
	rec := browse(t, f.h, "GET", "files."+webAppHost, u.RequestURI(), "", fileCookie, clearCookie)
	if len(rec.Header().Values("Set-Cookie")) != 2 {
		t.Fatalf("the sign-out's own pair cleared %q", rec.Header().Values("Set-Cookie"))
	}
}

// One host serves both halves without a domain: the sign-out's own answer
// clears every access cookie, so it hands out no clear and stays a 204.
func TestASingleOriginSignOutHandsOutNoClear(t *testing.T) {
	f := newWebFixture(t, false)
	clearURL, clearCookie := signOutAnswer(t, f)
	if clearURL != "" || clearCookie != nil {
		t.Fatalf("single-origin sign-out answered %q and %v", clearURL, clearCookie)
	}
}

// The clear follows the server's own split, not what /api/health
// advertises: a free name whose registration is still pending is no
// advertised domain, but the server already splits on it and the hop
// already set file-origin cookies there.
func TestAPendingFreeNameSignOutStillHandsOutTheClear(t *testing.T) {
	upd, _ := testDDNS(t)
	name := ddns.FQDN("pending-name")
	f := newWebFixtureOn(t, name, upd)
	if got := healthField(t, f.h, "domain"); got != nil {
		t.Fatalf("health advertises %v for a pending free name; the test needs it absent", got)
	}
	clearURL, clearCookie := signOutAnswer(t, f)
	if want := "https://files." + name + "/access/clear?t="; !strings.HasPrefix(clearURL, want) || clearCookie == nil {
		t.Fatalf("pending-name sign-out answered %q (cookie %v), want %s…", clearURL, clearCookie, want)
	}
}

// The clear is a file-origin path: on the app origin it gets the 308 every
// payload path gets, and nothing is cleared there.
func TestAccessClearIsMisroutedOnTheAppOrigin(t *testing.T) {
	_, h := splitHandler(t)
	rec := browse(t, h, "GET", hopApp, "/access/clear", "", &http.Cookie{Name: "hd_Qx7mK2pR9v", Value: "x"})
	if rec.Code != http.StatusPermanentRedirect || rec.Header().Get("Location") != "https://"+hopFile+"/access/clear" {
		t.Fatalf("clear on the app origin = %d %q, want 308 to the file origin", rec.Code, rec.Header().Get("Location"))
	}
	if lines := rec.Header().Values("Set-Cookie"); len(lines) != 0 {
		t.Fatalf("clear on the app origin set %q", lines)
	}
}

// "clear" can never be a share id, and the literal route takes precedence
// over the hop's wildcard, so the two patterns never meet.
func TestAccessClearIsNotTheHop(t *testing.T) {
	if shareid.ValidID("clear") {
		t.Fatal(`"clear" is a valid share id, so /access/clear could name a share`)
	}
	_, h := splitHandler(t)
	rec := clearOn(t, h, hopFile, "/access/clear?token=x&next=/share/x")
	if rec.Header().Get("Location") != "" {
		t.Fatalf("/access/clear redirected to %q, want the clear, not the hop", rec.Header().Get("Location"))
	}
}
