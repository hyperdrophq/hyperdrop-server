package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/metadb"
)

// wantRetryAnswer fails unless rec is status, with exactly the Retry-After
// value, the JSON content type and the given error body.
func wantRetryAnswer(t *testing.T, rec *httptest.ResponseRecorder, status int, retryAfter, body string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d, want %d (%s)", rec.Code, status, rec.Body)
	}
	if got := rec.Header().Values("Retry-After"); len(got) != 1 || got[0] != retryAfter {
		t.Fatalf("Retry-After = %q, want %q", got, retryAfter)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := rec.Body.String(); got != body {
		t.Fatalf("body = %q, want %q", got, body)
	}
}

func TestLockedOutAnswersWithTheRoundedWait(t *testing.T) {
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		until time.Time
		want  string
	}{
		{now.Add(90 * time.Second), "90"},
		{now.Add(90*time.Second + 400*time.Millisecond), "90"},
		{now.Add(90*time.Second + 600*time.Millisecond), "91"},
		{now, "1"},
		{now.Add(-time.Minute), "1"},
	} {
		rec := httptest.NewRecorder()
		writeLockedOut(rec, c.until, now, "wait")
		wantRetryAnswer(t, rec, http.StatusTooManyRequests, c.want, `{"code":"locked-out","error":"wait"}`+"\n")
	}
}

func TestCreateLimitAnswersWithItsRefillWait(t *testing.T) {
	_, hd := newTestAPIParts(t)
	hd.limits.create = newTokenLimiter(1, 1)
	u := metadb.User{Username: "bob"}
	rec := httptest.NewRecorder()
	if !hd.allowCreate(rec, u) {
		t.Fatal("the first create was refused")
	}
	rec = httptest.NewRecorder()
	if hd.allowCreate(rec, u) {
		t.Fatal("the second create was allowed")
	}
	wantRetryAnswer(t, rec, http.StatusTooManyRequests, "3600",
		`{"code":"rate-limited","error":"too many shares created just now, wait a moment and try again"}`+"\n")
}

func TestInboxUploadRefusalsCarryTheirRetryAfter(t *testing.T) {
	h, hd := newTestAPIParts(t)
	id := createInbox(t, h, `{"name":"inbox","receive":true}`)
	put := func(addr string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("PUT", "/receive/"+id+"/files/a.txt", strings.NewReader("x"))
		req.RemoteAddr = addr
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	key := addrKey("203.0.113.7")
	for i := 0; i < inboxUploadsPerAddr; i++ {
		release, ok := hd.inboxSlots.take(id, key)
		if !ok {
			t.Fatalf("slot %d refused", i)
		}
		defer release()
	}
	wantRetryAnswer(t, put("203.0.113.7:1000"), http.StatusTooManyRequests, "10",
		`{"code":"rate-limited","error":"too many uploads to this inbox at once, try again in a moment"}`+"\n")

	failed := addrKey("203.0.113.8")
	for i := 0; i < inboxFailBurst; i++ {
		hd.limits.inboxFail.allow(failed, time.Now())
	}
	rec := put("203.0.113.8:1000")
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("a paused address = %d %s (Retry-After %q)", rec.Code, rec.Body, rec.Header().Get("Retry-After"))
	}
	if got := rec.Body.String(); got != `{"code":"rate-limited","error":"too many uploads from your address failed just now, try again later"}`+"\n" {
		t.Fatalf("body = %q", got)
	}
}

func TestWatchRefusalCarriesItsRetryAfter(t *testing.T) {
	h, hd := newTestAPIParts(t)
	for i := 0; i < watchMaxPerOwner; i++ {
		if !hd.watch.watchSem.tryAcquire(metadb.DefaultAdminName) {
			t.Fatalf("watcher %d refused", i)
		}
	}
	rec := doReq(t, h, "GET", "/api/shares/watch?since=", testToken, "")
	wantRetryAnswer(t, rec, http.StatusTooManyRequests, "5",
		`{"code":"too-many-watchers","error":"too many open watchers for this account"}`+"\n")
}

func TestTicketRefusalCarriesItsRetryAfter(t *testing.T) {
	h := newTestAPI(t)
	id, slug := inboxWithFile(t, h)
	for i := 0; i < ticketsPerUser; i++ {
		ticketURL(t, h, testToken, id, slug)
	}
	rec := doReq(t, h, "POST", "/api/shares/"+id+"/download-ticket", testToken, `{"slug":"`+slug+`"}`)
	wantRetryAnswer(t, rec, http.StatusTooManyRequests, "5",
		`{"code":"too-many-tickets","error":"too many downloads asked for at once, try again in a moment"}`+"\n")
}
