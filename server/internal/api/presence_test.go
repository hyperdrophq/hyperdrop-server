package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// asComputer serves a request from a client naming platform in its
// X-HyperDrop-Client, which the token records.
func asComputer(t *testing.T, h http.Handler, method, path, token, platform, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-HyperDrop-Client", "2.0.0 "+platform)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

type presenceAnswer struct {
	Presence []struct {
		At       int64  `json:"at"`
		Presence string `json:"presence"`
	} `json:"presence"`
}

// presencePath is GET /api/me/presence asking about each of times.
func presencePath(times ...time.Time) string {
	q := make([]string, len(times))
	for i, at := range times {
		q[i] = fmt.Sprintf("at=%d", at.Unix())
	}
	return "/api/me/presence?" + strings.Join(q, "&")
}

func TestPresenceAnswersEachTimeInOrder(t *testing.T) {
	h, hd := newTestAPIParts(t)
	mac := seedUser(t, hd.db, "bob")
	pc, err := hd.db.MintToken("bob", "pc")
	if err != nil {
		t.Fatal(err)
	}
	// Both computers name their platform; only the Mac's owner is at it.
	if rec := asComputer(t, h, "PUT", "/api/me/activity", pc, "windows", `{"onConsole":false,"idleSeconds":0}`); rec.Code != 204 {
		t.Fatalf("the PC's report = %d %s", rec.Code, rec.Body)
	}
	if rec := asComputer(t, h, "PUT", "/api/me/activity", mac, "macos", `{"onConsole":true,"idleSeconds":30}`); rec.Code != 204 {
		t.Fatalf("the Mac's report = %d %s", rec.Code, rec.Body)
	}
	now := time.Now()
	times := []time.Time{now, now.Add(-time.Hour), now.Add(-10 * time.Second)}
	for _, c := range []struct {
		token, platform string
		want            []string
	}{
		{mac, "macos", []string{"self", "none", "self"}},
		{pc, "windows", []string{"other", "none", "other"}},
	} {
		rec := asComputer(t, h, "GET", presencePath(times...), c.token, c.platform, "")
		if rec.Code != 200 {
			t.Fatalf("GET presence as %s = %d %s", c.platform, rec.Code, rec.Body)
		}
		var got presenceAnswer
		unmarshal(t, rec, &got)
		if len(got.Presence) != len(times) {
			t.Fatalf("as %s: %d answers, want %d: %s", c.platform, len(got.Presence), len(times), rec.Body)
		}
		for i, p := range got.Presence {
			if p.At != times[i].Unix() || p.Presence != c.want[i] {
				t.Errorf("as %s, answer %d = %+v, want at %d %s", c.platform, i, p, times[i].Unix(), c.want[i])
			}
		}
	}
	// The report's bound is the limit: 119 seconds idle records a span, 120
	// records none. Each read asks about a second taken after the report,
	// which the span from the input it last saw until now covers.
	for _, c := range []struct {
		idle int
		want string
	}{{119, "self"}, {120, "none"}} {
		tok := seedUser(t, hd.db, fmt.Sprintf("idle%d", c.idle))
		body := fmt.Sprintf(`{"onConsole":true,"idleSeconds":%d}`, c.idle)
		if rec := asComputer(t, h, "PUT", "/api/me/activity", tok, "macos", body); rec.Code != 204 {
			t.Fatalf("idle %d s: the report = %d %s", c.idle, rec.Code, rec.Body)
		}
		after := time.Now()
		var got presenceAnswer
		unmarshal(t, asComputer(t, h, "GET", presencePath(after, after.Add(-110*time.Second)), tok, "macos", ""), &got)
		if len(got.Presence) != 2 || got.Presence[0].Presence != c.want || got.Presence[1].Presence != c.want {
			t.Fatalf("idle %d s: the Mac reads as %+v, want %s", c.idle, got, c.want)
		}
	}
}

func TestPresenceRefusesMoreThan32Times(t *testing.T) {
	h, hd := newTestAPIParts(t)
	tok := seedUser(t, hd.db, "bob")
	now := time.Now()
	many := make([]time.Time, 33)
	for i := range many {
		many[i] = now.Add(-time.Duration(i) * time.Minute)
	}
	if rec := doReq(t, h, "GET", presencePath(many[:32]...), tok, ""); rec.Code != 200 {
		t.Fatalf("32 times = %d %s, want 200", rec.Code, rec.Body)
	}
	for what, path := range map[string]string{
		"33 times":     presencePath(many...),
		"no time":      "/api/me/presence",
		"an empty at":  "/api/me/presence?at=",
		"not a number": "/api/me/presence?at=yesterday",
		"a fraction":   "/api/me/presence?at=1.5",
		"negative":     "/api/me/presence?at=-1",
		"far future":   "/api/me/presence?at=99999999999999",
	} {
		rec := doReq(t, h, "GET", path, tok, "")
		if rec.Code != 400 || errCode(t, rec.Body.String()) != "invalid" {
			t.Errorf("%s = %d %s, want 400 invalid", what, rec.Code, rec.Body)
		}
	}
}

func TestPresenceIsCookieReachableAndOpenToARestrictedAccount(t *testing.T) {
	if cookieRoutes["GET /api/me/presence"] != cookieJSON {
		t.Fatal("GET /api/me/presence is not a cookie-reachable JSON read")
	}
	f := newWebFixture(t, true)
	raw := f.signIn(t, false)
	rec := f.req(t, "GET", presencePath(time.Now()), raw, "")
	if rec.Code != 200 {
		t.Fatalf("GET presence with a web session = %d %s", rec.Code, rec.Body)
	}
	var got presenceAnswer
	unmarshal(t, rec, &got)
	if len(got.Presence) != 1 || got.Presence[0].Presence != "none" {
		t.Fatalf("the web session reads %+v", got)
	}

	h, _ := restrictedAdminAPI(t)
	rec = doReq(t, h, "GET", presencePath(time.Now()), testToken, "")
	if setupRequired(rec) || rec.Code != 200 {
		t.Fatalf("GET presence as an admin owing a second factor = %d %s, want 200", rec.Code, rec.Body)
	}
}
