package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// doReqHeaders sends a request carrying several headers.
func doReqHeaders(t *testing.T, h http.Handler, method, path string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// unlockCookie unlocks a protected share and returns the access cookie as a
// Cookie header value.
func unlockCookie(t *testing.T, h http.Handler, id, pw string) string {
	t.Helper()
	body := url.Values{"password": {pw}, "next": {"/share/" + id}}.Encode()
	sub := doReqForm(t, h, "POST", "/unlock/"+id, body)
	if sub.Code != 303 {
		t.Fatalf("unlock = %d", sub.Code)
	}
	return strings.SplitN(sub.Header().Get("Set-Cookie"), ";", 2)[0]
}

func TestEveryPayloadAnswerIsRevalidated(t *testing.T) {
	h := newTestAPI(t)
	check := func(label, id, slug, cookie, want string) {
		t.Helper()
		paths := []string{
			"/view/" + id + "/" + slug, "/download/" + id + "/" + slug, "/zip/" + id,
		}
		for _, p := range paths {
			for _, m := range []string{"GET", "HEAD"} {
				got := doReqHeaders(t, h, m, p, map[string]string{"Cookie": cookie})
				if got.Code != 200 {
					t.Fatalf("%s %s %s: %d", label, m, p, got.Code)
				}
				if cc := got.Header().Get("Cache-Control"); cc != want {
					t.Errorf("%s %s %s: Cache-Control = %q, want %q", label, m, p, cc, want)
				}
			}
		}
		site := doReqHeaders(t, h, "GET", "/site/"+id+"/a.png", map[string]string{"Cookie": cookie})
		if site.Code == http.StatusSeeOther || site.Code == http.StatusFound || site.Code == http.StatusTemporaryRedirect {
			site = doReqHeaders(t, h, "GET", site.Header().Get("Location"),
				map[string]string{"Cookie": cookie, "Sec-Fetch-Dest": "image"})
		}
		if site.Code != 200 || site.Header().Get("Cache-Control") != want {
			t.Errorf("%s /site asset: %d, Cache-Control = %q, want %q", label, site.Code, site.Header().Get("Cache-Control"), want)
		}
		for _, m := range []string{"GET", "HEAD"} {
			th := doReqHeaders(t, h, m, "/thumb/"+id+"/"+slug, map[string]string{"Cookie": cookie})
			if th.Code != 200 || th.Header().Get("Cache-Control") != want {
				t.Errorf("%s %s /thumb: %d, Cache-Control = %q, want %q", label, m, th.Code, th.Header().Get("Cache-Control"), want)
			}
		}
	}
	setup := func(body string) (string, string) {
		rec := doReq(t, h, "POST", "/api/shares", testToken, body)
		var cr struct{ ID string }
		unmarshal(t, rec, &cr)
		slug := uploadGetSlug(t, h, cr.ID, "a.png", "data")
		doReq(t, h, "PUT", "/api/shares/"+cr.ID+"/thumbs/"+slug, testToken, string(aJPEG(t, 8, 8)))
		return cr.ID, slug
	}
	id, slug := setup(`{"name":"open","media":true}`)
	check("open", id, slug, "", "no-cache")
	pid, pslug := setup(`{"name":"secret","media":true,"password":"hunter2"}`)
	check("protected", pid, pslug, unlockCookie(t, h, pid, "hunter2"), "private, no-cache")
}

func TestALapsedCookieMeetsTheFormNotACachedFile(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"secret","password":"hunter2"}`)
	var cr struct{ ID string }
	unmarshal(t, rec, &cr)
	slug := uploadGetSlug(t, h, cr.ID, "a.txt", "data")
	p := "/view/" + cr.ID + "/" + slug
	first := doReqHeaders(t, h, "GET", p, map[string]string{"Cookie": unlockCookie(t, h, cr.ID, "hunter2")})
	etag := first.Header().Get("ETag")
	if first.Code != 200 || etag == "" {
		t.Fatalf("first: %d etag %q", first.Code, etag)
	}
	got := doReqHeaders(t, h, "GET", p, map[string]string{"If-None-Match": etag})
	if got.Code != 200 || !strings.Contains(got.Body.String(), "<form") || got.Body.String() == "data" {
		t.Fatalf("uncookied conditional: %d %q", got.Code, got.Body.String())
	}
}

func TestAPasswordAddedLaterReachesARevalidatingCache(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "open")
	slug := uploadGetSlug(t, h, id, "a.txt", "data")
	p := "/view/" + id + "/" + slug
	etag := doReq(t, h, "GET", p, "", "").Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag")
	}
	if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"password":"hunter2"}`); rec.Code != 200 {
		t.Fatalf("patch = %d %s", rec.Code, rec.Body)
	}
	got := doReqHeaders(t, h, "GET", p, map[string]string{"If-None-Match": etag})
	if got.Code != 200 || !strings.Contains(got.Body.String(), "<form") {
		t.Fatalf("after password: %d %q", got.Code, got.Body.String())
	}
}

func TestAnUnchangedFileStillRevalidatesWithA304(t *testing.T) {
	h := newTestAPI(t)
	for _, protected := range []bool{false, true} {
		body, cookie := `{"name":"s"}`, ""
		if protected {
			body = `{"name":"s","password":"hunter2"}`
		}
		rec := doReq(t, h, "POST", "/api/shares", testToken, body)
		var cr struct{ ID string }
		unmarshal(t, rec, &cr)
		slug := uploadGetSlug(t, h, cr.ID, "a.txt", "0123456789")
		if protected {
			cookie = unlockCookie(t, h, cr.ID, "hunter2")
		}
		p := "/view/" + cr.ID + "/" + slug
		etag := doReqHeaders(t, h, "GET", p, map[string]string{"Cookie": cookie}).Header().Get("ETag")
		got := doReqHeaders(t, h, "GET", p, map[string]string{"Cookie": cookie, "If-None-Match": etag})
		if got.Code != 304 || got.Body.Len() != 0 {
			t.Errorf("protected=%v conditional: %d, %d body bytes", protected, got.Code, got.Body.Len())
		}
		rng := doReqHeaders(t, h, "GET", p, map[string]string{"Cookie": cookie, "Range": "bytes=2-5", "If-Range": etag})
		if rng.Code != 206 || rng.Body.String() != "2345" {
			t.Errorf("protected=%v range: %d %q", protected, rng.Code, rng.Body.String())
		}
	}
}

func TestTheThumbnailOfAProtectedShareIsNotKeptAfterTheCookie(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"Trip","media":true,"password":"letmein"}`)
	var cr struct{ ID string }
	unmarshal(t, rec, &cr)
	slug := uploadGetSlug(t, h, cr.ID, "a.jpg", "photo")
	doReq(t, h, "PUT", "/api/shares/"+cr.ID+"/thumbs/"+slug, testToken, string(aJPEG(t, 8, 8)))
	got := doReqHeaders(t, h, "GET", "/thumb/"+cr.ID+"/"+slug, map[string]string{"Cookie": unlockCookie(t, h, cr.ID, "letmein")})
	cc := got.Header().Get("Cache-Control")
	if got.Code != 200 || cc != "private, no-cache" || strings.Contains(cc, "max-age") {
		t.Fatalf("thumb: %d Cache-Control = %q", got.Code, cc)
	}
}

func TestTheUnfurlerPosterKeepsItsHour(t *testing.T) {
	h := newTestAPI(t)
	id, _ := mediaShareWithFile(t, h, "a.jpg", "pretend-photo")
	rec := doReq(t, h, "PUT", "/api/shares/"+id+"/poster", testToken, string(aJPEG(t, 8, 8)))
	if rec.Code/100 != 2 {
		t.Fatalf("poster upload = %d %s", rec.Code, rec.Body)
	}
	got := doReq(t, h, "GET", "/card/"+id+"/poster.jpg", "", "")
	if got.Code != 200 || got.Header().Get("Cache-Control") != "public, max-age=3600" {
		t.Fatalf("poster: %d Cache-Control = %q", got.Code, got.Header().Get("Cache-Control"))
	}
}
