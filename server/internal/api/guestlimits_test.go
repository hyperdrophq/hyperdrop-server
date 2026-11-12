package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/sharefs"
)

// Handing out an account with no quota is what lets a guest fill the disk (an
// unset limit skips the per-owner admission check), so creation refuses to
// guess: the admin must decide, including deliberately choosing "no limit".
func TestCreateUserRequiresAQuotaDecision(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)

	rec := doReq(t, h, "POST", "/api/users", testToken, `{"username":"bob"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("no quota → %d, want 400 (body %s)", rec.Code, rec.Body)
	}
	var e struct{ Error, Code string }
	unmarshal(t, rec, &e)
	if e.Code != "quota-required" {
		t.Fatalf("code = %q, want quota-required (%s)", e.Code, rec.Body)
	}

	// A quota creates the account…
	rec = doReq(t, h, "POST", "/api/users", testToken, `{"username":"bob","quotaBytes":1048576}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("with quota → %d: %s", rec.Code, rec.Body)
	}
	// …and so does an explicit, deliberate "no limit".
	rec = doReq(t, h, "POST", "/api/users", testToken, `{"username":"carol","quotaBytes":0}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("explicit unlimited → %d: %s", rec.Code, rec.Body)
	}
	var out struct {
		User struct {
			Username   string `json:"username"`
			QuotaBytes int64  `json:"quotaBytes"`
		} `json:"user"`
	}
	unmarshal(t, rec, &out)
	if out.User.Username != "carol" || out.User.QuotaBytes != 0 {
		t.Fatalf("carol = %+v", out.User)
	}
}

// Editing is unchanged: --remove-quota is an explicit gesture, not a default.
func TestUpdateUserCanStillClearTheQuota(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	seedUser(t, um, "alice")
	quota := int64(1 << 20)
	if _, err := um.UpdateUser("alice", metadb.Settings{QuotaBytes: &quota}); err != nil {
		t.Fatal(err)
	}
	rec := doReq(t, h, "PATCH", "/api/users/alice", testToken, `{"quotaBytes":0}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("clear quota → %d: %s", rec.Code, rec.Body)
	}
	u, err := um.User("alice")
	if err != nil || u.QuotaBytes != 0 {
		t.Fatalf("alice quota = %d (%v)", u.QuotaBytes, err)
	}
}

// Share CREATION is rate-limited per account: quotas bound how much a guest
// can store, this bounds how fast they can make shares (an empty share costs
// a directory and a meta write, and isn't swept for an hour).
func TestShareCreateRateLimitPerUser(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	aliceTok := seedUser(t, um, "alice")
	bobTok := seedUser(t, um, "bob")

	// Burn alice's burst.
	for i := 0; i < createBurst; i++ {
		if rec := doReq(t, h, "POST", "/api/shares", aliceTok, `{}`); rec.Code != http.StatusCreated {
			t.Fatalf("share %d → %d: %s", i, rec.Code, rec.Body)
		}
	}
	rec := doReq(t, h, "POST", "/api/shares", aliceTok, `{}`)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over the burst → %d, want 429 (%s)", rec.Code, rec.Body)
	}
	var e struct{ Error, Code string }
	unmarshal(t, rec, &e)
	if e.Code != "rate-limited" {
		t.Fatalf("code = %q, want rate-limited", e.Code)
	}
	if ra := rec.Header().Get("Retry-After"); ra == "" {
		t.Fatal("no Retry-After header")
	} else if n, err := strconv.Atoi(ra); err != nil || n < 1 {
		t.Fatalf("Retry-After = %q", ra)
	}

	// One account's limit is its own, so bob is unaffected…
	if rec := doReq(t, h, "POST", "/api/shares", bobTok, `{}`); rec.Code != http.StatusCreated {
		t.Fatalf("bob blocked by alice's limit: %d %s", rec.Code, rec.Body)
	}
	// …and the admin is exempt (they own the box).
	for i := 0; i < createBurst+5; i++ {
		if rec := doReq(t, h, "POST", "/api/shares", testToken, `{}`); rec.Code != http.StatusCreated {
			t.Fatalf("admin share %d → %d: %s", i, rec.Code, rec.Body)
		}
	}
}

func TestCreateLimiterRefills(t *testing.T) {
	l := newCreateLimiter()
	l.burst, l.perHour = 2, 3600 // 1 token/second, so refills are testable
	now := time.Now()
	for i := 0; i < 2; i++ {
		if _, ok := l.allow("alice", now); !ok {
			t.Fatalf("token %d denied inside the burst", i)
		}
	}
	retry, ok := l.allow("alice", now)
	if ok {
		t.Fatal("third call must be denied")
	}
	if retry < time.Second {
		t.Fatalf("retryAfter = %s, want ≥ 1s", retry)
	}
	// One second later exactly one token is back.
	if _, ok := l.allow("alice", now.Add(time.Second)); !ok {
		t.Fatal("token should have refilled after a second")
	}
	if _, ok := l.allow("alice", now.Add(time.Second)); ok {
		t.Fatal("only one token should have refilled")
	}
	// A bucket never fills past the burst, however long it idles.
	if _, ok := l.allow("alice", now.Add(time.Hour)); !ok {
		t.Fatal("denied after a long idle")
	}
	b := l.byUser["alice"]
	if b != nil && b.tokens > l.burst {
		t.Fatalf("tokens = %v, want ≤ burst %v", b.tokens, l.burst)
	}
}

// The shared caps protect a small VPS; the per-owner sub-cap keeps ONE account
// from holding all of them.
func TestFairSemPerOwnerCap(t *testing.T) {
	s := newFairSem(2, 1)
	ctx := context.Background()
	if !s.acquire(ctx, "alice") {
		t.Fatal("alice's first slot denied")
	}
	// alice is at her per-owner cap even though a global slot is free.
	tight, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if s.acquire(tight, "alice") {
		t.Fatal("alice took a second slot past her per-owner cap")
	}
	// Another owner still gets the free global slot.
	if !s.acquire(ctx, "bob") {
		t.Fatal("bob denied a free global slot")
	}
	// Global cap now reached: a third owner waits.
	tight2, cancel2 := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel2()
	if s.acquire(tight2, "carol") {
		t.Fatal("carol got a slot past the global cap")
	}
	// Releasing frees both levels for reuse.
	s.release("alice")
	if !s.acquire(ctx, "alice") {
		t.Fatal("alice denied after release")
	}
	s.release("alice")
	s.release("bob")
}

// A guest can trigger a 507 at will, so its text must not report server-wide
// free space: /api/usage is admin-only for the same reason.
func TestNoSpaceMessageHidesServerNumbersFromGuests(t *testing.T) {
	detail := sharefs.ErrNoSpace
	if got := spaceMessage(detail, false); got == detail.Error() {
		t.Fatal("guest got the detailed message")
	}
	if got := spaceMessage(detail, true); got != detail.Error() {
		t.Fatalf("admin lost the detail: %q", got)
	}
}

// End to end: a guest's own quota message still names their own numbers (it's
// their account), while the server-wide 507 stays generic.
func TestQuotaMessageStillNamesTheirOwnLimit(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	aliceTok := seedUser(t, um, "alice")
	quota := int64(1 << 20)
	if _, err := um.UpdateUser("alice", metadb.Settings{QuotaBytes: &quota}); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"name": "big", "reserveBytes": 8 << 20})
	rec := doReq(t, h, "POST", "/api/shares", aliceTok, string(body))
	if rec.Code != http.StatusInsufficientStorage {
		t.Fatalf("over quota → %d: %s", rec.Code, rec.Body)
	}
	var e struct{ Error, Code string }
	unmarshal(t, rec, &e)
	if e.Code != "quota" {
		t.Fatalf("code = %q, want quota", e.Code)
	}
	if !strings.Contains(e.Error, "quota") {
		t.Fatalf("quota error should describe their own limit: %q", e.Error)
	}
}

// A live share draws on the same per-account creation budget: the open-share
// cap stops at three at once, and this stops a create-and-stop loop.
func TestLiveShareCreateRateLimitPerUser(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	aliceTok := seedUser(t, um, "alice")
	for i := 0; i < createBurst; i++ {
		sh := createLiveShare(t, h, aliceTok, liveShareCreateBodyOne)
		if rec := doReq(t, h, "DELETE", "/api/live-share/"+sh.ID, aliceTok, ""); rec.Code != http.StatusOK {
			t.Fatalf("stop live share %d → %d: %s", i, rec.Code, rec.Body)
		}
	}
	rec := doReq(t, h, "POST", "/api/live-share", aliceTok, liveShareCreateBodyOne)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over the burst → %d, want 429 (%s)", rec.Code, rec.Body)
	}
	var e struct{ Error, Code string }
	unmarshal(t, rec, &e)
	if e.Code != "rate-limited" {
		t.Fatalf("code = %q, want rate-limited", e.Code)
	}
	if n, err := strconv.Atoi(rec.Header().Get("Retry-After")); err != nil || n < 1 {
		t.Fatalf("Retry-After = %q", rec.Header().Get("Retry-After"))
	}
	// The budget is the account's, stored and live alike.
	if rec := doReq(t, h, "POST", "/api/shares", aliceTok, `{}`); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("a stored share past the shared budget → %d, want 429", rec.Code)
	}
	// The admin is exempt.
	for i := 0; i < createBurst+5; i++ {
		sh := createLiveShare(t, h, testToken, liveShareCreateBodyOne)
		if rec := doReq(t, h, "DELETE", "/api/live-share/"+sh.ID, testToken, ""); rec.Code != http.StatusOK {
			t.Fatalf("admin stop %d → %d", i, rec.Code)
		}
	}
}
