package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The share-password page's wording for a share's lane and for an address.
const (
	shareLaneWait = "Password entry for this share is paused."
	shareAddrWait = "Password entry from your address is paused."
)

var (
	wrongSharePW = url.Values{"password": {"nope"}}.Encode()
	rightSharePW = url.Values{"password": {"hunter2"}}.Encode()
)

// wrongUnlock is one wrong POST /unlock/{id} from addr, answered with the
// form again.
func wrongUnlock(t *testing.T, h http.Handler, id, addr string) {
	t.Helper()
	if rec := doReqFormFrom(t, h, "/unlock/"+id, wrongSharePW, addr); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong unlock of %s from %s: %d, want 401", id, addr, rec.Code)
	}
}

// wantShareLaneWait checks a refusal on a share's lane: 429 and the share's
// wording, never the address's.
func wantShareLaneWait(t *testing.T, rec *httptest.ResponseRecorder, what string) {
	t.Helper()
	body := rec.Body.String()
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(body, shareLaneWait) || strings.Contains(body, shareAddrWait) {
		t.Fatalf("%s: %d %s, want 429 with the share's wait", what, rec.Code, body)
	}
	if rec.Header().Get("Set-Cookie") != "" {
		t.Fatalf("%s set a cookie", what)
	}
}

// throttleShare spends id's lane: its free guesses and the next spaced one,
// each from its own address, then checks that the next guess waits.
func throttleShare(t *testing.T, h http.Handler, id string, next func() string) {
	t.Helper()
	for range laneFree + 1 {
		wrongUnlock(t, h, id, next())
	}
	wantShareLaneWait(t, doReqFormFrom(t, h, "/unlock/"+id, wrongSharePW, next()), "a wrong unlock past the lane")
}

func TestAShareLaneSlowsDistributedGuesses(t *testing.T) {
	h := newTestAPI(t)
	id := protectedShare(t, h)
	next := laneAddrs(0)
	for range laneFree {
		wrongUnlock(t, h, id, next())
	}
	// The first guess past the free ones is admitted and answers the form.
	wrongUnlock(t, h, id, next())
	wantShareLaneWait(t, doReqFormFrom(t, h, "/unlock/"+id, wrongSharePW, next()), "the twelfth wrong unlock")
	wantShareLaneWait(t, doReqFormFrom(t, h, "/unlock/"+id, rightSharePW, next()), "the right password inside the spacing")
}

func TestAShareLaneDoesNotSlowAnotherShare(t *testing.T) {
	h := newTestAPI(t)
	slowed := protectedShare(t, h)
	other := protectedShare(t, h)
	next := laneAddrs(0)
	throttleShare(t, h, slowed, next)

	wrongUnlock(t, h, other, next())
	if rec := doReqFormFrom(t, h, "/unlock/"+other, rightSharePW, next()); rec.Code != http.StatusSeeOther {
		t.Fatalf("the right password at another share: %d %s, want 303", rec.Code, rec.Body)
	}
}

func TestTheQueryPasswordUsesTheSameLane(t *testing.T) {
	h := newTestAPI(t)
	id := protectedShare(t, h)
	next := laneAddrs(0)
	query := func(pw, addr string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/share/"+id+"?pw="+pw, nil)
		req.RemoteAddr = addr
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	for i := range 6 {
		if rec := query("nope", next()); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "password") {
			t.Fatalf("wrong ?pw= %d: %d, want the form", i+1, rec.Code)
		}
	}
	for range laneFree - 6 + 1 {
		wrongUnlock(t, h, id, next())
	}
	wantShareLaneWait(t, query("nope", next()), "a wrong ?pw= past the lane")
	wantShareLaneWait(t, query("hunter2", next()), "the right ?pw= inside the spacing")
	wantShareLaneWait(t, doReqFormFrom(t, h, "/unlock/"+id, rightSharePW, next()), "the right form password inside the spacing")
}

func TestAnAddressBlockStillNamesTheAddress(t *testing.T) {
	h := newTestAPI(t)
	const addr = "203.0.113.9:4321"
	id := protectedShare(t, h)
	for range pwFailLimit - 1 {
		wrongUnlock(t, h, id, addr)
	}
	// The tenth wrong guess fills the share's lane's free guesses too; the
	// address's block is what answers.
	rec := doReqFormFrom(t, h, "/unlock/"+id, wrongSharePW, addr)
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), shareAddrWait) {
		t.Fatalf("the tenth wrong unlock from one address: %d %s, want 429 with the address's wait", rec.Code, rec.Body)
	}
	rec = doReqFormFrom(t, h, "/unlock/"+id, rightSharePW, addr)
	body := rec.Body.String()
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(body, shareAddrWait) || strings.Contains(body, shareLaneWait) {
		t.Fatalf("the next unlock from a blocked address: %d %s, want 429 with the address's wait", rec.Code, body)
	}
}

func TestTheOwnerAndAnUnlockedVisitorAreNeverSlowed(t *testing.T) {
	h := newTestAPI(t)
	id, slug := protectedShareWithFile(t, h)
	next := laneAddrs(0)
	unlock := doReqFormFrom(t, h, "/unlock/"+id, rightSharePW, next())
	if unlock.Code != http.StatusSeeOther {
		t.Fatalf("unlock: %d %s, want 303", unlock.Code, unlock.Body)
	}
	cookies := unlock.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("unlock set no access cookie")
	}
	throttleShare(t, h, id, next)

	if got := doReq(t, h, "GET", "/download/"+id+"/"+slug, testToken, ""); got.Code != 200 || got.Body.String() != "data" {
		t.Fatalf("the owner's bearer download while the lane waits: %d %q", got.Code, got.Body)
	}
	req := httptest.NewRequest("GET", "/download/"+id+"/"+slug, nil)
	req.RemoteAddr = next()
	for _, c := range cookies {
		req.AddCookie(c)
	}
	got := httptest.NewRecorder()
	h.ServeHTTP(got, req)
	if got.Code != 200 || got.Body.String() != "data" {
		t.Fatalf("an unlocked visitor's download while the lane waits: %d %q", got.Code, got.Body)
	}
}

// crossSiteGuess is one ?pw= guess at share id that another website's
// picture makes a browser send from addr.
func crossSiteGuess(h http.Handler, id, pw, addr string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "/share/"+id+"?pw="+pw, nil)
	req.RemoteAddr = addr
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Sec-Fetch-Dest", "image")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestCrossSiteGuessesNeverPauseTheSharePage(t *testing.T) {
	h := newTestAPI(t)
	id := protectedShare(t, h)
	next := laneAddrs(0)
	for range laneFree + 1 {
		crossSiteGuess(h, id, "nope", next())
	}
	wantShareLaneWait(t, crossSiteGuess(h, id, "nope", next()), "a cross-site guess past its lane")

	wrongUnlock(t, h, id, next())
	if rec := doReqFormFrom(t, h, "/unlock/"+id, rightSharePW, next()); rec.Code != http.StatusSeeOther {
		t.Fatalf("the right password from the share page: %d %s, want 303", rec.Code, rec.Body)
	}
}

func TestCrossSiteGuessesAreStillSpaced(t *testing.T) {
	h := newTestAPI(t)
	id := protectedShare(t, h)
	next := laneAddrs(0)
	for range laneFree + 1 {
		crossSiteGuess(h, id, "nope", next())
	}
	wantShareLaneWait(t, crossSiteGuess(h, id, "hunter2", next()), "the right cross-site guess inside the spacing")
}

func TestFirstPartyGuessesKeepTheShareLane(t *testing.T) {
	h := newTestAPI(t)
	id := protectedShare(t, h)
	next := laneAddrs(0)
	throttleShare(t, h, id, next)
	wantShareLaneWait(t, doReqFormFrom(t, h, "/unlock/"+id, rightSharePW, next()), "the right password inside the spacing")
	if rec := crossSiteGuess(h, id, "nope", next()); rec.Code == http.StatusTooManyRequests {
		t.Fatalf("a cross-site guess while only the share's lane waits: %d, want admitted", rec.Code)
	}
}
