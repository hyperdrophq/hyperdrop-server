package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// wantWrongWords checks that a wrong guess re-rendered the password form with
// exactly the error words want.
func wantWrongWords(t *testing.T, rec *httptest.ResponseRecorder, want, what string) {
	t.Helper()
	body := rec.Body.String()
	if rec.Code != http.StatusUnauthorized || !strings.Contains(body, `<p class="err">`+want+`</p>`) {
		t.Fatalf("%s: %d %.600s, want 401 with %q", what, rec.Code, body, want)
	}
}

// The error under the field after a wrong guess counts down the guesses the
// visitor's address has left at this share, then the pause page answers.
func TestSharePasswordFormCountsTriesLeft(t *testing.T) {
	f := newSharePWFixture(t)
	guess := formGuess(metaAppForm)
	const addr = "198.51.100.7:4000"
	for i := 1; i < pwFailLimit; i++ {
		want := fmt.Sprintf("Incorrect password. %d tries left.", pwFailLimit-i)
		if pwFailLimit-i == 1 {
			want = "Incorrect password. 1 try left."
		}
		wantWrongWords(t, guess(t, f, f.share, "nope", addr), want, fmt.Sprintf("guess %d", i))
	}
	wantAddressWait(t, guess(t, f, f.share, "nope", addr), "the last guess")
	wantAddressWait(t, guess(t, f, f.share, "nope", addr), "a guess after the pause starts")

	// Another address has its own count.
	wantWrongWords(t, guess(t, f, f.share, "nope", "198.51.100.8:4000"),
		fmt.Sprintf("Incorrect password. %d tries left.", pwFailLimit-1), "another address")
}

// A guess with no first-party address counts on the share's cross-site lane
// alone, so there is no count to give.
func TestSharePasswordFormCrossSiteSaysTryAgain(t *testing.T) {
	f := newSharePWFixture(t)
	rec := formGuess(metaCrossForm)(t, f, f.share, "nope", "198.51.100.9:4000")
	wantWrongWords(t, rec, "Incorrect password. Try again.", "a cross-site form")
	if strings.Contains(rec.Body.String(), "left.") {
		t.Fatalf("a cross-site guess was given a count: %.600s", rec.Body)
	}
}

// Before any guess the form says nothing about limits.
func TestSharePasswordFormHasNoLimitsNote(t *testing.T) {
	f := newSharePWFixture(t)
	rec := serveAs(f.h, httptest.NewRequest("GET", "https://"+fpApp+"/share/"+f.share, nil), "198.51.100.10:4000", metaTyped)
	body := rec.Body.String()
	if !strings.Contains(body, "Password required") {
		t.Fatalf("form = %d %.300s", rec.Code, body)
	}
	for _, w := range []string{`class="note"`, "limited", "Wrong guesses", "tries left", `class="err"`} {
		if strings.Contains(body, w) {
			t.Errorf("the form before any guess holds %q", w)
		}
	}
}

// The file link's form counts the same way and still names nothing of the
// share.
func TestFileLinkPasswordCountsTriesLeft(t *testing.T) {
	h := newTestAPI(t)
	id, _, key := protectedFileLink(t, h)
	for i := 1; i < pwFailLimit; i++ {
		want := fmt.Sprintf("Incorrect password. %d tries left.", pwFailLimit-i)
		if pwFailLimit-i == 1 {
			want = "Incorrect password. 1 try left."
		}
		rec := fileLinkUnlock(t, h, key, "nope", "/f/"+key)
		wantWrongWords(t, rec, want, fmt.Sprintf("guess %d", i))
		namesNothing(t, "wrong", rec, id, "secret")
	}
	rec := fileLinkUnlock(t, h, key, "nope", "/f/"+key)
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), shareAddrWait) {
		t.Fatalf("the last guess = %d %.300s, want the address's pause", rec.Code, rec.Body)
	}

	form := url.Values{"password": {"nope-share"}, "next": {"/f/" + key}}.Encode()
	req := httptest.NewRequest("POST", "/f/"+key+"/unlock", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "198.51.100.11:4000"
	metaCrossForm.apply(req)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	wantWrongWords(t, rec, "Incorrect password. Try again.", "a cross-site file link form")
	namesNothing(t, "cross-site wrong", rec, id, "secret")
}

// left reads the count without changing it: a key not tracked has its whole
// limit, each wrong guess takes one, a blocked key has none, and a lane has
// no count.
func TestPWLimiterLeft(t *testing.T) {
	l := newPWLimiter()
	now := time.Now()
	key := shareAddrKey("198.51.100.12", "s1")
	if got := l.left(key, now); got != pwFailLimit {
		t.Fatalf("untracked = %d, want %d", got, pwFailLimit)
	}
	for i := 1; i <= pwFailLimit; i++ {
		att, _, ok := l.admit(now, key)
		if !ok {
			t.Fatalf("guess %d refused", i)
		}
		att.failed("s1")
		if got, want := l.left(key, now), pwFailLimit-i; got != want {
			t.Fatalf("after %d = %d, want %d", i, got, want)
		}
		if got := l.left(key, now); got != pwFailLimit-i {
			t.Fatalf("a second read moved the count to %d", got)
		}
	}
	if !l.blocked(key, now) {
		t.Fatal("the limit did not block")
	}
	if got := l.left(shareLaneKey("s1"), now); got != 0 {
		t.Fatalf("lane = %d, want 0", got)
	}
}
