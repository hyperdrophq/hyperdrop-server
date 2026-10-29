package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// doReqFormFrom is doReqForm with a controllable client address: the lockout
// is per-IP, so tests need to speak as different clients.
func doReqFormFrom(t *testing.T, h http.Handler, path, body, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func protectedShare(t *testing.T, h http.Handler) string {
	t.Helper()
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"secret","password":"hunter2"}`)
	var cr struct{ ID string }
	unmarshal(t, rec, &cr)
	uploadGetSlug(t, h, cr.ID, "a.txt", "data")
	return cr.ID
}

func TestPasswordLockoutBlocksTenthFailure(t *testing.T) {
	h := newTestAPI(t)
	id := protectedShare(t, h)
	wrong := url.Values{"password": {"nope"}}.Encode()

	for i := 0; i < pwFailLimit-1; i++ {
		rec := doReqFormFrom(t, h, "/unlock/"+id, wrong, "203.0.113.9:4321")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d, want 401", i+1, rec.Code)
		}
	}
	// The 10th wrong guess trips the block.
	rec := doReqFormFrom(t, h, "/unlock/"+id, wrong, "203.0.113.9:4321")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt %d = %d, want 429", pwFailLimit, rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Too many") {
		t.Fatalf("blocked page missing explanation: %s", rec.Body)
	}

	// Even the CORRECT password is refused while blocked.
	right := url.Values{"password": {"hunter2"}}.Encode()
	rec = doReqFormFrom(t, h, "/unlock/"+id, right, "203.0.113.9:9999")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("correct password while blocked = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Set-Cookie") != "" {
		t.Fatal("blocked submit set an access cookie")
	}

	// A different client is unaffected.
	rec = doReqFormFrom(t, h, "/unlock/"+id, right, "198.51.100.4:1111")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("other IP = %d, want 303", rec.Code)
	}
}

func TestPasswordSuccessResetsLockoutCounter(t *testing.T) {
	h := newTestAPI(t)
	id := protectedShare(t, h)
	wrong := url.Values{"password": {"nope"}}.Encode()
	right := url.Values{"password": {"hunter2"}}.Encode()

	for i := 0; i < pwFailLimit-1; i++ {
		doReqFormFrom(t, h, "/unlock/"+id, wrong, "203.0.113.9:4321")
	}
	if rec := doReqFormFrom(t, h, "/unlock/"+id, right, "203.0.113.9:4321"); rec.Code != http.StatusSeeOther {
		t.Fatalf("correct password = %d, want 303", rec.Code)
	}
	// Counter is back to zero: one more wrong guess is 1/10, not 10/10.
	if rec := doReqFormFrom(t, h, "/unlock/"+id, wrong, "203.0.113.9:4321"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong guess after reset = %d, want 401", rec.Code)
	}
}

func TestQueryPasswordCountsTowardLockout(t *testing.T) {
	h := newTestAPI(t)
	id := protectedShare(t, h)

	// Wrong ?pw= guesses on the public route burn the same per-IP budget.
	for i := 0; i < pwFailLimit; i++ {
		req := httptest.NewRequest("GET", "/share/"+id+"?pw=nope", nil)
		req.RemoteAddr = "203.0.113.9:4321"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
	}
	// Correct ?pw= from the now-blocked IP is ignored.
	req := httptest.NewRequest("GET", "/share/"+id+"?pw=hunter2", nil)
	req.RemoteAddr = "203.0.113.9:4321"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("blocked ?pw= = %d, want 429", rec.Code)
	}
	right := url.Values{"password": {"hunter2"}}.Encode()
	if sub := doReqFormFrom(t, h, "/unlock/"+id, right, "203.0.113.9:4321"); sub.Code != http.StatusTooManyRequests {
		t.Fatalf("form submit after ?pw= lockout = %d, want 429", sub.Code)
	}
}

func TestPasswordFormShowsLockoutNote(t *testing.T) {
	h := newTestAPI(t)
	id := protectedShare(t, h)

	form := doReq(t, h, "GET", "/share/"+id, "", "")
	if form.Code != 200 {
		t.Fatalf("form = %d, want 200", form.Code)
	}
	if body := form.Body.String(); !strings.Contains(body, "for an hour") || !strings.Contains(body, "up to 12 hours") {
		t.Fatalf("password form does not warn about the lockout: %s", form.Body)
	}
}
