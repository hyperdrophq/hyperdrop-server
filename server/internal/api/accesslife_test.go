package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/metadb"
)

// wantLifetime fails unless c expires about want from now.
func wantLifetime(t *testing.T, what string, c *http.Cookie, want time.Duration) {
	t.Helper()
	if c == nil {
		t.Fatalf("%s: no cookie", what)
	}
	if left := time.Until(c.Expires); left < want-time.Minute || left > want+time.Minute {
		t.Errorf("%s: cookie lives %v, want %v", what, left.Round(time.Minute), want)
	}
}

// cookieAttrs is every attribute of the Set-Cookie line for name, Expires
// left out, in order.
func cookieAttrs(t *testing.T, rec *httptest.ResponseRecorder, name string) []string {
	t.Helper()
	for _, line := range rec.Header().Values("Set-Cookie") {
		if !strings.HasPrefix(line, name+"=") {
			continue
		}
		var attrs []string
		for _, a := range strings.Split(line, "; ")[1:] {
			if !strings.HasPrefix(a, "Expires=") {
				attrs = append(attrs, a)
			}
		}
		return attrs
	}
	t.Fatalf("no Set-Cookie for %s in %q", name, rec.Header().Values("Set-Cookie"))
	return nil
}

func passwordGen(t *testing.T, hh *handler, id string) int {
	t.Helper()
	v, err := hh.viewMeta(id)
	if err != nil {
		t.Fatal(err)
	}
	return v.PasswordGen
}

// unlockBothOrigins posts the share's password form on the app origin with
// the given form, takes the hop, and answers both origins' cookies and the
// attributes of each Set-Cookie line.
func unlockBothOrigins(t *testing.T, h http.Handler, id, form string) (app, file *http.Cookie, appAttrs, fileAttrs []string) {
	t.Helper()
	unlock := browse(t, h, "POST", hopApp, "/unlock/"+id, form)
	app = accessCookieOf(unlock, id)
	if app == nil {
		t.Fatalf("unlock set no app cookie: %d %q", unlock.Code, unlock.Header().Values("Set-Cookie"))
	}
	hop, _ := hopTarget(t, unlock, id)
	landed := browse(t, h, "GET", hopFile, hop, "")
	file = accessCookieOf(landed, id)
	if file == nil {
		t.Fatalf("the hop set no cookie: %d", landed.Code)
	}
	return app, file, cookieAttrs(t, unlock, "hd_"+id), cookieAttrs(t, landed, "hd_"+id)
}

// Ticking "This is my computer" keeps the share unlocked for 400 days on
// both origins; leaving it unticked, for 24 hours. The hop carries the kind.
func TestTheUnlockLifetimeFollowsTheCheckbox(t *testing.T) {
	_, h := splitHandler(t)
	id, slug := hopShare(t, h, "s3cret")
	next := "&next=" + url.QueryEscape("/view/"+id+"/"+slug)

	app, file, _, _ := unlockBothOrigins(t, h, id, "password=s3cret&keep=1"+next)
	wantLifetime(t, "ticked, app origin", app, accessKeepTTL)
	wantLifetime(t, "ticked, file origin", file, accessKeepTTL)

	app, file, _, _ = unlockBothOrigins(t, h, id, "password=s3cret"+next)
	wantLifetime(t, "unticked, app origin", app, accessTTL)
	wantLifetime(t, "unticked, file origin", file, accessTTL)

	if accessTTL != 24*time.Hour || accessKeepTTL != 400*24*time.Hour {
		t.Fatalf("lifetimes %v and %v, want 24 h and 400 days", accessTTL, accessKeepTTL)
	}
}

// A hop token is signed for its kind: a kept one sets a kept cookie on the
// file origin and an unticked one an unticked cookie, and neither verifies as
// the other.
func TestTheAccessHopCarriesTheKind(t *testing.T) {
	hh, h := splitHandler(t)
	id, _ := hopShare(t, h, "s3cret")
	gen := passwordGen(t, hh, id)
	soon := time.Now().Add(time.Minute)
	for _, keep := range []bool{false, true} {
		token := hh.signAccessHop(id, gen, soon, keep)
		got, ok := hh.accessHopValid(token, id, gen)
		if !ok || got != keep {
			t.Fatalf("hop token keep=%v reads as keep=%v ok=%v", keep, got, ok)
		}
		rec := browse(t, h, "GET", hopFile, "/access/"+id+"?token="+url.QueryEscape(token), "")
		want := accessTTL
		if keep {
			want = accessKeepTTL
		}
		wantLifetime(t, "hop keep="+strconv.FormatBool(keep), accessCookieOf(rec, id), want)
	}
}

// Every admitted visit refreshes the cookie on the origin that answered, at
// most once an hour, with a fresh expiry of its own kind and every other
// attribute as the unlock set it.
func TestAnAdmittedVisitRefreshesTheAccessCookie(t *testing.T) {
	hh, h := splitHandler(t)
	id, slug := hopShare(t, h, "s3cret")
	gen := passwordGen(t, hh, id)
	_, _, appAttrs, fileAttrs := unlockBothOrigins(t, h, id, "password=s3cret&next="+url.QueryEscape("/view/"+id+"/"+slug))
	now := time.Now()

	for _, origin := range []struct {
		host, path string
		attrs      []string
	}{
		{hopApp, "/share/" + id, appAttrs},
		{hopFile, "/view/" + id + "/" + slug, fileAttrs},
	} {
		for _, tc := range []struct {
			name    string
			value   string
			refresh bool
			want    time.Duration
		}{
			{"unticked, under an hour old", hh.signAccess(id, gen, now.Add(accessTTL-30*time.Minute), false), false, 0},
			{"unticked, older", hh.signAccess(id, gen, now.Add(accessTTL-2*time.Hour), false), true, accessTTL},
			{"kept, under an hour old", hh.signAccess(id, gen, now.Add(accessKeepTTL-30*time.Minute), true), false, 0},
			{"kept, older", hh.signAccess(id, gen, now.Add(accessKeepTTL-48*time.Hour), true), true, accessKeepTTL},
			{"the 12-hour format", hh.signScoped("", id, gen, now.Add(11*time.Hour)), true, accessTTL},
		} {
			what := origin.host + ", " + tc.name
			rec := browse(t, h, "GET", origin.host, origin.path, "", &http.Cookie{Name: "hd_" + id, Value: tc.value})
			if strings.Contains(rec.Body.String(), "Password required") {
				t.Fatalf("%s: not admitted (%d)", what, rec.Code)
			}
			c := accessCookieOf(rec, id)
			if !tc.refresh {
				if c != nil {
					t.Errorf("%s: re-issued the cookie", what)
				}
				continue
			}
			wantLifetime(t, what, c, tc.want)
			if got := cookieAttrs(t, rec, "hd_"+id); strings.Join(got, "; ") != strings.Join(origin.attrs, "; ") {
				t.Errorf("%s: refresh attributes %q, the unlock's %q", what, got, origin.attrs)
			}
			// The refreshed value is of the same kind, so it verifies under
			// that kind's lifetime and not the other's.
			keep, exp, ok := hh.accessValue(c.Value, id, gen)
			if !ok || keep != (tc.want == accessKeepTTL) || exp.Sub(now) < tc.want-time.Minute {
				t.Errorf("%s: refreshed value reads keep=%v exp=%v ok=%v", what, keep, exp, ok)
			}
		}
	}
}

// An unticked cookie cannot be made a kept one: its signature covers its
// expiry and its kind, so re-dating it refuses it, and a kept signature is
// never the unticked one's.
func TestAnUntickedCookieCannotBecomeKept(t *testing.T) {
	hh, h := splitHandler(t)
	id, _ := hopShare(t, h, "s3cret")
	gen := passwordGen(t, hh, id)
	exp := time.Now().Add(20 * time.Hour)
	unticked := hh.signAccess(id, gen, exp, false)
	kept := hh.signAccess(id, gen, exp, true)
	if unticked == kept {
		t.Fatal("the two kinds sign the same value")
	}
	_, mac, _ := strings.Cut(unticked, ".")
	redated := strconv.FormatInt(time.Now().Add(accessKeepTTL).Unix(), 10) + "." + mac
	if _, _, ok := hh.accessValue(redated, id, gen); ok {
		t.Fatal("a re-dated unticked value verifies")
	}
	rec := browse(t, h, "GET", hopApp, "/share/"+id, "", &http.Cookie{Name: "hd_" + id, Value: redated})
	if !strings.Contains(rec.Body.String(), "Password required") {
		t.Fatalf("a re-dated unticked cookie was admitted: %d", rec.Code)
	}
	if keep, _, ok := hh.accessValue(unticked, id, gen); !ok || keep {
		t.Fatalf("the unticked value reads keep=%v ok=%v", keep, ok)
	}
	if !hh.scopedValueValid(accessKeepScope, kept, id, gen) || hh.scopedValueValid(accessKeepScope, unticked, id, gen) {
		t.Fatal("the kept scope verifies the wrong value")
	}
}

// Changing the share's password signs out both kinds, on both origins.
func TestAPasswordChangeRefusesBothKinds(t *testing.T) {
	hh, h := splitHandler(t)
	id, slug := hopShare(t, h, "s3cret")
	gen := passwordGen(t, hh, id)
	exp := time.Now().Add(20 * time.Hour)
	cookies := map[string]*http.Cookie{
		"unticked": {Name: "hd_" + id, Value: hh.signAccess(id, gen, exp, false)},
		"kept":     {Name: "hd_" + id, Value: hh.signAccess(id, gen, exp.Add(300*24*time.Hour), true)},
	}
	if rec := patchShare(t, h, id, `{"password":"another"}`); rec.Code != 200 {
		t.Fatalf("change: %d %s", rec.Code, rec.Body)
	}
	for name, c := range cookies {
		for host, path := range map[string]string{hopApp: "/share/" + id, hopFile: "/view/" + id + "/" + slug} {
			rec := browse(t, h, "GET", host, path, "", c)
			if u, err := url.Parse(rec.Header().Get("Location")); rec.Code == http.StatusSeeOther && err == nil && u.Host == hopApp {
				// The file origin's re-access bounce, where the same
				// cookie meets the form on the app origin.
				rec = browse(t, h, "GET", hopApp, u.RequestURI(), "", c)
			}
			if !strings.Contains(rec.Body.String(), "Password required") || accessCookieOf(rec, id) != nil {
				t.Errorf("%s cookie on %s after the change = %d, want the password form and no cookie", name, host, rec.Code)
			}
		}
	}
}

// A ?pw= unlock is always unticked, a keep in the query included, on the app
// origin and through the hop.
func TestAPasswordQueryUnlocksUnticked(t *testing.T) {
	_, h := splitHandler(t)
	id, _ := hopShare(t, h, "s3cret")
	rec := browse(t, h, "GET", hopApp, "/share/"+id+"?pw=s3cret&keep=1", "")
	wantLifetime(t, "?pw= app origin", accessCookieOf(rec, id), accessTTL)
	hop, _ := hopTarget(t, rec, id)
	landed := browse(t, h, "GET", hopFile, hop, "")
	wantLifetime(t, "?pw= file origin", accessCookieOf(landed, id), accessTTL)
}

// A file link's own cookie follows the same rules: the checkbox picks its
// lifetime, ?pw= is unticked, an admitted visit refreshes it at most once an
// hour within its kind, and a password change refuses both kinds.
func TestAFileLinkCookieFollowsTheSameRules(t *testing.T) {
	h, hh := newTestAPIParts(t)
	id, _, key := protectedFileLink(t, h)
	name := "hdf_" + key

	ticked := doReqForm(t, h, "POST", "/f/"+key+"/unlock", url.Values{"password": {"hunter2"}, "keep": {"1"}}.Encode())
	wantLifetime(t, "ticked", cookieNamed(ticked, name), accessKeepTTL)
	unticked := fileLinkUnlock(t, h, key, "hunter2", "")
	wantLifetime(t, "unticked", cookieNamed(unticked, name), accessTTL)
	attrs := cookieAttrs(t, unticked, name)
	if got := cookieAttrs(t, ticked, name); strings.Join(got, "; ") != strings.Join(attrs, "; ") {
		t.Errorf("ticked attributes %q, unticked %q", got, attrs)
	}
	nav := map[string]string{"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}
	pw := fileLinkReq(t, h, "GET", "/f/"+key+"?pw=hunter2&keep=1", nav)
	wantLifetime(t, "?pw=", cookieNamed(pw, name), accessTTL)

	gen := passwordGen(t, hh, id)
	now := time.Now()
	for _, tc := range []struct {
		name    string
		value   string
		refresh bool
		want    time.Duration
	}{
		{"unticked, under an hour old", hh.signFileAccess(key, gen, now.Add(accessTTL-30*time.Minute), false), false, 0},
		{"unticked, older", hh.signFileAccess(key, gen, now.Add(accessTTL-2*time.Hour), false), true, accessTTL},
		{"kept, under an hour old", hh.signFileAccess(key, gen, now.Add(accessKeepTTL-30*time.Minute), true), false, 0},
		{"kept, older", hh.signFileAccess(key, gen, now.Add(accessKeepTTL-48*time.Hour), true), true, accessKeepTTL},
		{"the 12-hour format", hh.signScoped(fileLinkScope, key, gen, now.Add(11*time.Hour)), true, accessTTL},
	} {
		rec := fileLinkReq(t, h, "GET", "/f/"+key, nil, &http.Cookie{Name: name, Value: tc.value})
		if rec.Body.String() != "data" {
			t.Fatalf("%s: not admitted (%d)", tc.name, rec.Code)
		}
		c := cookieNamed(rec, name)
		if !tc.refresh {
			if c != nil {
				t.Errorf("%s: re-issued the cookie", tc.name)
			}
			continue
		}
		wantLifetime(t, tc.name, c, tc.want)
		if got := cookieAttrs(t, rec, name); strings.Join(got, "; ") != strings.Join(attrs, "; ") {
			t.Errorf("%s: refresh attributes %q, the unlock's %q", tc.name, got, attrs)
		}
	}

	_, mac, _ := strings.Cut(hh.signFileAccess(key, gen, now.Add(20*time.Hour), false), ".")
	redated := &http.Cookie{Name: name, Value: strconv.FormatInt(now.Add(accessKeepTTL).Unix(), 10) + "." + mac}
	if rec := fileLinkReq(t, h, "GET", "/f/"+key, nil, redated); rec.Body.String() == "data" {
		t.Fatal("a re-dated unticked file-link cookie was admitted")
	}

	kept := &http.Cookie{Name: name, Value: hh.signFileAccess(key, gen, now.Add(300*24*time.Hour), true)}
	if rec := patchShare(t, h, id, `{"password":"another"}`); rec.Code != 200 {
		t.Fatalf("change: %d %s", rec.Code, rec.Body)
	}
	if rec := fileLinkReq(t, h, "GET", "/f/"+key, nil, kept); rec.Body.String() == "data" || cookieNamed(rec, name) != nil {
		t.Fatal("a kept file-link cookie outlived a password change")
	}
}

// A site grant lives 12 hours whichever kind of cookie the page was opened
// with: an address leaks more easily than a cookie.
func TestASiteGrantExpiresAfter12Hours(t *testing.T) {
	hh, h := splitHandler(t)
	id, _ := hopShare(t, h, "s3cret")
	v, err := hh.viewMeta(id)
	if err != nil {
		t.Fatal(err)
	}
	grant := hh.grantFor(v)
	expRaw, _, _ := strings.Cut(grant, ".")
	expUnix, err := strconv.ParseInt(expRaw, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if left := time.Until(time.Unix(expUnix, 0)); left < 12*time.Hour-time.Minute || left > 12*time.Hour+time.Minute {
		t.Fatalf("grant lives %v, want 12 h", left.Round(time.Minute))
	}
	if grantTTL != 12*time.Hour {
		t.Fatalf("grantTTL = %v", grantTTL)
	}
}

// Every password page carries the "This is my computer" checkbox, unticked.
func TestEveryPasswordFormOffersThisIsMyComputer(t *testing.T) {
	_, h := splitHandler(t)
	id, slug := hopShare(t, h, "s3cret")
	inbox := createInbox(t, h, `{"name":"drop","receive":true,"password":"s3cret"}`)
	key := mintFileKey(t, h, testToken, id, slug)
	for what, req := range map[string][2]string{
		"share, app origin":  {hopApp, "/share/" + id},
		"share, file origin": {hopFile, "/view/" + id + "/" + slug + "?" + reaccessMark + "=1"},
		"file link":          {hopFile, "/f/" + key},
		"inbox":              {hopApp, "/receive/" + inbox},
	} {
		body := browse(t, h, "GET", req[0], req[1], "").Body.String()
		if !strings.Contains(body, "Password required") {
			t.Fatalf("%s: no password form: %.200s", what, body)
		}
		for _, want := range []string{
			`<input type="checkbox" name="keep" value="1">`,
			"This is my computer",
			"Stay unlocked on this browser. Leave this unticked on a shared computer.",
		} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: the form lacks %q", what, want)
			}
		}
		if strings.Contains(body, "checked") {
			t.Errorf("%s: the checkbox is ticked by default", what)
		}
	}
}

// navigate is the header set of a person opening an address in a tab.
var navigate = map[string]string{"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}

// hdSetCookies is every Set-Cookie line an answer carries for name.
func hdSetCookies(rec *httptest.ResponseRecorder, name string) []string {
	var out []string
	for _, line := range rec.Header().Values("Set-Cookie") {
		if strings.HasPrefix(line, name+"=") {
			out = append(out, line)
		}
	}
	return out
}

// A visitor whose files-origin copy has lapsed while the app origin's stays
// live reaches the file with no password form: the file origin sends the
// navigation through the app origin's re-access route, which hops back with
// a fresh copy of the app cookie's own kind.
func TestALapsedFileOriginCopyIsRestoredFromTheAppOrigin(t *testing.T) {
	hh, h := splitHandler(t)
	id, slug := hopShare(t, h, "s3cret")
	gen := passwordGen(t, hh, id)
	view := "/view/" + id + "/" + slug
	app := &http.Cookie{Name: "hd_" + id, Value: hh.signAccess(id, gen, time.Now().Add(300*24*time.Hour), true)}
	stale := &http.Cookie{Name: "hd_" + id, Value: hh.signAccess(id, gen, time.Now().Add(-time.Minute), false)}

	for name, fileCookies := range map[string][]*http.Cookie{"absent": nil, "expired": {stale}} {
		bounce := browse(t, h, "GET", hopFile, view, "", fileCookies...)
		if bounce.Code != http.StatusSeeOther || strings.Contains(bounce.Body.String(), "Password required") {
			t.Fatalf("%s copy: file origin = %d %.120s, want 303 to the app origin", name, bounce.Code, bounce.Body)
		}
		u, err := url.Parse(bounce.Header().Get("Location"))
		if err != nil || u.Scheme != "https" || u.Host != hopApp || u.Path != reaccessPrefix+id {
			t.Fatalf("%s copy: bounce Location = %q", name, bounce.Header().Get("Location"))
		}
		rehop := browse(t, h, "GET", hopApp, u.RequestURI(), "", app)
		hop, _ := hopTarget(t, rehop, id)
		landed := browse(t, h, "GET", hopFile, hop, "")
		fileCopy := accessCookieOf(landed, id)
		wantLifetime(t, name+" copy: the restored file-origin copy", fileCopy, accessKeepTTL)
		next, err := url.Parse(landed.Header().Get("Location"))
		if err != nil || next.Path != view {
			t.Fatalf("%s copy: hop Location = %q, want %s", name, landed.Header().Get("Location"), view)
		}
		got := browse(t, h, "GET", hopFile, next.RequestURI(), "", fileCopy)
		if got.Code != 200 || got.Body.String() != "protected bytes" {
			t.Fatalf("%s copy: the file = %d %.120s", name, got.Code, got.Body)
		}
	}
}

// The re-access marker stops a second bounce: a navigation that already came
// back through the app origin and still holds no copy gets the password form.
// A subresource load is never bounced.
func TestTheReaccessBounceHappensOnce(t *testing.T) {
	_, h := splitHandler(t)
	id, slug := hopShare(t, h, "s3cret")
	view := "/view/" + id + "/" + slug
	first := browse(t, h, "GET", hopFile, view, "")
	u, err := url.Parse(first.Header().Get("Location"))
	if err != nil || first.Code != http.StatusSeeOther {
		t.Fatalf("first visit = %d %q", first.Code, first.Header().Get("Location"))
	}
	if u.Query().Get("next") != view {
		t.Fatalf("bounce next %q, want %s", u.Query().Get("next"), view)
	}
	again := browse(t, h, "GET", hopFile, view+"?"+reaccessMark+"=1", "")
	if again.Code != 200 || !strings.Contains(again.Body.String(), "Password required") {
		t.Fatalf("marked visit = %d %q, want the password form", again.Code, again.Header().Get("Location"))
	}
	img := fileLinkReq(t, h, "GET", "https://"+hopFile+view, map[string]string{"Sec-Fetch-Dest": "image", "Sec-Fetch-Mode": "no-cors"})
	if img.Code == http.StatusSeeOther {
		t.Fatal("an image load was bounced")
	}
	// The app origin without its own cookie shows the form there, carrying
	// the marked address on.
	form := browse(t, h, "GET", hopApp, u.RequestURI(), "")
	if !strings.Contains(form.Body.String(), "Password required") || !strings.Contains(form.Body.String(), reaccessMark) {
		t.Fatalf("re-access without a cookie = %d %.200s", form.Code, form.Body)
	}
}

// The re-access route forwards only to this share's own file-origin
// addresses; anything else lands on the share's page.
func TestTheReaccessRouteIsNoOpenRedirect(t *testing.T) {
	hh, h := splitHandler(t)
	id, slug := hopShare(t, h, "s3cret")
	other, otherSlug := hopShare(t, h, "s3cret")
	app := &http.Cookie{Name: "hd_" + id, Value: hh.signAccess(id, passwordGen(t, hh, id), time.Now().Add(20*time.Hour), false)}
	for _, next := range []string{"https://evil.example/x", "//evil.example/view/" + id + "/" + slug,
		"/view/" + other + "/" + otherSlug, "/share/" + id + "/status", "/unlock/" + id, ""} {
		rec := browse(t, h, "GET", hopApp, reaccessPrefix+id+"?next="+url.QueryEscape(next), "", app)
		_, q := hopTarget(t, rec, id)
		if q.Get("next") != "/share/"+id {
			t.Errorf("next %q forwards to %q, want /share/%s", next, q.Get("next"), id)
		}
	}
	rec := browse(t, h, "GET", hopApp, reaccessPrefix+id+"?next="+url.QueryEscape("/download/"+id+"/"+slug), "", app)
	if _, q := hopTarget(t, rec, id); q.Get("next") != "/download/"+id+"/"+slug+"?"+reaccessMark+"=1" {
		t.Errorf("an own download address forwards to %q", q.Get("next"))
	}
}

// Every other kind of signed value is refused as hd_<id>, and an hd_ value
// is refused as hdf_<fileKey>.
func TestNoOtherSignedValueOpensAShareOrAFileLink(t *testing.T) {
	h, hh := newTestAPIParts(t)
	id, slug, key := protectedFileLink(t, h)
	other := createProtectedShare(t, h, "hunter2")
	gen := passwordGen(t, hh, id)
	exp := time.Now().Add(20 * time.Hour)
	for name, value := range map[string]string{
		"an unticked hop token":    hh.signAccessHop(id, gen, exp, false),
		"a kept hop token":         hh.signAccessHop(id, gen, exp, true),
		"an unticked hdf_ value":   hh.signFileAccess(id, gen, exp, false),
		"a kept hdf_ value":        hh.signFileAccess(id, gen, exp, true),
		"another share's kept hd_": hh.signAccess(other, passwordGen(t, hh, other), exp, true),
		"a site grant":             hh.signGrant(id, gen, exp),
		"the file key's kept hd_":  hh.signAccess(key, gen, exp, true),
	} {
		rec := fileLinkReq(t, h, "GET", "/view/"+id+"/"+slug, nil, &http.Cookie{Name: "hd_" + id, Value: value})
		if rec.Body.String() == "data" || accessCookieOf(rec, id) != nil {
			t.Errorf("%s opened the share as hd_<id>", name)
		}
	}
	for name, value := range map[string]string{
		"a kept hd_ value":          hh.signAccess(id, gen, exp, true),
		"an unticked hd_ value":     hh.signAccess(id, gen, exp, false),
		"a kept hd_ over the key":   hh.signAccess(key, gen, exp, true),
		"a kept hop token over key": hh.signAccessHop(key, gen, exp, true),
	} {
		rec := fileLinkReq(t, h, "GET", "/f/"+key, nil, &http.Cookie{Name: "hdf_" + key, Value: value})
		if rec.Body.String() == "data" || cookieNamed(rec, "hdf_"+key) != nil {
			t.Errorf("%s opened the file link as hdf_<key>", name)
		}
	}
}

// The routes that only read the cookie set none, even when it is due.
func TestTheReadOnlyRoutesRenewNothing(t *testing.T) {
	h, hh := newTestAPIParts(t)
	id, _, key := protectedFileLink(t, h)
	gen := passwordGen(t, hh, id)
	due := time.Now().Add(2 * time.Hour)
	hd := &http.Cookie{Name: "hd_" + id, Value: hh.signAccess(id, gen, due, false)}
	hdf := &http.Cookie{Name: "hdf_" + key, Value: hh.signFileAccess(key, gen, due, false)}
	if rec := fileLinkReq(t, h, "GET", "/share/"+id+"/status", nil, hd); rec.Code != 200 || len(rec.Header().Values("Set-Cookie")) != 0 {
		t.Errorf("share status = %d, Set-Cookie %q", rec.Code, rec.Header().Values("Set-Cookie"))
	}
	if rec := fileLinkReq(t, h, "GET", "/f/"+key+"/status", nil, hdf); rec.Code != 200 || len(rec.Header().Values("Set-Cookie")) != 0 {
		t.Errorf("file link status = %d, Set-Cookie %q", rec.Code, rec.Header().Values("Set-Cookie"))
	}
	inbox := createInbox(t, h, `{"name":"drop","receive":true,"password":"s3cret"}`)
	ic := &http.Cookie{Name: "hd_" + inbox, Value: hh.signAccess(inbox, passwordGen(t, hh, inbox), due, false)}
	req := httptest.NewRequest("PUT", "/receive/"+inbox+"/files/note.txt", strings.NewReader("hello"))
	req.AddCookie(ic)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 201 || len(hdSetCookies(rec, "hd_"+inbox)) != 0 {
		t.Errorf("inbox upload = %d, Set-Cookie %q", rec.Code, rec.Header().Values("Set-Cookie"))
	}
}

// An admitted answer is private whatever it turns out to be, so a renewal
// never rides an answer a shared cache keeps: a missing file's 404 too.
func TestAnAdmittedAnswerIsPrivate(t *testing.T) {
	h, hh := newTestAPIParts(t)
	id, _, key := protectedFileLink(t, h)
	gen := passwordGen(t, hh, id)
	due := time.Now().Add(2 * time.Hour)
	rec := fileLinkReq(t, h, "GET", "/view/"+id+"/nosuchslug", nil, &http.Cookie{Name: "hd_" + id, Value: hh.signAccess(id, gen, due, false)})
	if rec.Code != 404 || len(hdSetCookies(rec, "hd_"+id)) != 1 || !sharedCacheRefuses(rec) {
		t.Errorf("admitted 404 = %d, Cache-Control %q, Set-Cookie %q", rec.Code, rec.Header().Get("Cache-Control"), rec.Header().Values("Set-Cookie"))
	}
	rec = fileLinkReq(t, h, "GET", "/f/"+key, nil, &http.Cookie{Name: "hdf_" + key, Value: hh.signFileAccess(key, gen, due, false)})
	if len(hdSetCookies(rec, "hdf_"+key)) != 1 || !sharedCacheRefuses(rec) {
		t.Errorf("admitted file link: Cache-Control %q, Set-Cookie %q", rec.Header().Get("Cache-Control"), rec.Header().Values("Set-Cookie"))
	}

	// A site folder's address without its slash is a 301, which a shared
	// cache keeps unless it is told otherwise.
	sh, sp := splitHandler(t)
	site := protectedSite(t, sp, "s3cret")
	grant, _ := liveGrant(t, sp, site, "s3cret")
	cookie := &http.Cookie{Name: "hd_" + site, Value: sh.signAccess(site, passwordGen(t, sh, site), due, false)}
	rec = fileGetWith(t, sp, "/site/"+site+"/"+grant+"/docs", navigate, []*http.Cookie{cookie})
	if rec.Code != http.StatusMovedPermanently || len(hdSetCookies(rec, "hd_"+site)) != 1 || !sharedCacheRefuses(rec) {
		t.Errorf("admitted 301 = %d, Cache-Control %q, Set-Cookie %q", rec.Code, rec.Header().Get("Cache-Control"), rec.Header().Values("Set-Cookie"))
	}
}

// sharedCacheRefuses reports whether an answer's Cache-Control keeps it out
// of every shared cache.
func sharedCacheRefuses(rec *httptest.ResponseRecorder) bool {
	cc := rec.Header().Get("Cache-Control")
	return strings.Contains(cc, "private") || strings.Contains(cc, "no-store")
}

// An embed from another site never keeps the unlock alive: a cross-site one,
// and a same-site one that is not this server's own page. This server's own
// page loading the file does.
func TestAnEmbedFromAnotherSiteRenewsNothing(t *testing.T) {
	hh, h := splitHandler(t)
	id, slug := hopShare(t, h, "s3cret")
	due := &http.Cookie{Name: "hd_" + id, Value: hh.signAccess(id, passwordGen(t, hh, id), time.Now().Add(2*time.Hour), false)}
	view := "https://" + hopFile + "/view/" + id + "/" + slug
	for name, tc := range map[string]struct {
		headers map[string]string
		renews  bool
	}{
		"cross-site image":           {map[string]string{"Sec-Fetch-Dest": "image", "Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "no-cors"}, false},
		"a sibling site's image":     {map[string]string{"Sec-Fetch-Dest": "image", "Sec-Fetch-Site": "same-site", "Sec-Fetch-Mode": "no-cors", "Referer": "https://other.example.com/"}, false},
		"this server's page's image": {map[string]string{"Sec-Fetch-Dest": "image", "Sec-Fetch-Site": "same-site", "Sec-Fetch-Mode": "no-cors", "Referer": "https://" + hopApp + "/share/" + id}, true},
		"a navigation":               {navigate, true},
	} {
		rec := fileLinkReq(t, h, "GET", view, tc.headers, due)
		if got := len(hdSetCookies(rec, "hd_"+id)) == 1; got != tc.renews {
			t.Errorf("%s: renewed=%v, want %v (%d %q)", name, got, tc.renews, rec.Code, rec.Header().Values("Set-Cookie"))
		}
	}
}

// A request renews its cookie once, however many gates admit it: a /site
// page under a live grant passes siteGate and serveFile.
func TestARequestRenewsOnce(t *testing.T) {
	hh, h := splitHandler(t)
	id := protectedSite(t, h, "s3cret")
	grant, _ := liveGrant(t, h, id, "s3cret")
	due := &http.Cookie{Name: "hd_" + id, Value: hh.signAccess(id, passwordGen(t, hh, id), time.Now().Add(2*time.Hour), false)}
	rec := fileGetWith(t, h, "/site/"+id+"/"+grant+"/index.html", navigate, []*http.Cookie{due})
	if rec.Code != 200 {
		t.Fatalf("page under a live grant = %d %.120s", rec.Code, rec.Body)
	}
	if lines := hdSetCookies(rec, "hd_"+id); len(lines) != 1 {
		t.Fatalf("renewal lines %q, want exactly one", lines)
	}
}

// The re-access route hands the file origin a copy of the app cookie's own
// kind: an unticked app cookie never yields a kept copy. An open share is sent
// straight on with no cookie, and an expired share answers 404.
func TestTheReaccessRouteKeepsTheKindAndTheShareRules(t *testing.T) {
	hh, h := splitHandler(t)
	id, slug := hopShare(t, h, "s3cret")
	view := "/view/" + id + "/" + slug
	unticked := &http.Cookie{Name: "hd_" + id, Value: hh.signAccess(id, passwordGen(t, hh, id), time.Now().Add(20*time.Hour), false)}
	rehop := browse(t, h, "GET", hopApp, reaccessPrefix+id+"?next="+url.QueryEscape(view), "", unticked)
	hop, q := hopTarget(t, rehop, id)
	if keep, ok := hh.accessHopValid(q.Get("token"), id, passwordGen(t, hh, id)); !ok || keep {
		t.Fatalf("the hop token from an unticked app cookie reads keep=%v ok=%v", keep, ok)
	}
	landed := browse(t, h, "GET", hopFile, hop, "")
	fileCopy := accessCookieOf(landed, id)
	wantLifetime(t, "files-origin copy from an unticked app cookie", fileCopy, accessTTL)
	if keep, _, ok := hh.accessValue(fileCopy.Value, id, passwordGen(t, hh, id)); !ok || keep {
		t.Fatalf("the files-origin copy reads keep=%v ok=%v", keep, ok)
	}

	open := createShareBody(t, h, `{"name":"open"}`)
	openSlug := uploadGetSlug(t, h, open, "a.txt", "open bytes")
	openView := "/view/" + open + "/" + openSlug
	rec := browse(t, h, "GET", hopApp, reaccessPrefix+open+"?next="+url.QueryEscape(openView), "")
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "https://"+hopFile+openView+"?"+reaccessMark+"=1" {
		t.Fatalf("open share re-access = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if accessCookieOf(rec, open) != nil {
		t.Fatalf("open share re-access set %q", rec.Header().Values("Set-Cookie"))
	}

	past := time.Now().Add(-time.Hour).UTC()
	expired, err := hh.db.CreateShare(metadb.CreateOptions{Name: "gone", Owner: metadb.DefaultAdminName, ExpiresAt: &past})
	if err != nil {
		t.Fatal(err)
	}
	if rec := browse(t, h, "GET", hopApp, reaccessPrefix+expired.ID+"?next=/share/"+expired.ID, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("expired share re-access = %d, want 404", rec.Code)
	}
}
