package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/metadb"
)

// patchRequireTwoFactor flips the switch as the seeded admin, with a step-up.
func patchRequireTwoFactor(t *testing.T, h http.Handler, on bool) {
	t.Helper()
	body := fmt.Sprintf(`{"requireTwoFactor":%v,"currentPassword":%q%s}`, on, testAdminPassword, seededAdminTOTP(t))
	if rec := doReq(t, h, "PATCH", "/api/server/settings", testToken, body); rec.Code != http.StatusOK {
		t.Fatalf("PATCH requireTwoFactor %v = %d %s, want 200", on, rec.Code, rec.Body)
	}
}

// signedInBefore moves every token alice holds a minute into the past, so
// each one was signed in before a switch turned on now, at a second of its
// own (sign-in times are stored to the second).
func signedInBefore(t *testing.T, f webFixture) {
	t.Helper()
	execRaw(t, f.dir, `UPDATE tokens SET created_at = created_at - ? WHERE username = 'alice'`, time.Minute.Nanoseconds())
}

// aliceTokenID is the id of alice's device token raw.
func aliceTokenID(t *testing.T, f webFixture, raw string) string {
	t.Helper()
	u, err := f.db.User("alice")
	if err != nil {
		t.Fatal(err)
	}
	tok := tokenNamed(u, metadb.TokenHash(raw))
	if tok.ID == "" {
		t.Fatal("alice holds no such token")
	}
	return tok.ID
}

// wantShares fails t unless bearer may create a share.
func wantShares(t *testing.T, what string, h http.Handler, bearer string) {
	t.Helper()
	if rec := doReq(t, h, "POST", "/api/shares", bearer, `{"name":"x"}`); rec.Code != http.StatusCreated {
		t.Fatalf("%s: POST /api/shares = %d %s, want 201", what, rec.Code, rec.Body)
	}
}

// wantRestricted fails t unless both the share and the account read show
// a caller that owes a second factor.
func wantRestricted(t *testing.T, what string, share, me *httptest.ResponseRecorder) {
	t.Helper()
	wantSetupRequired(t, what+": POST /api/shares", share)
	if me.Code != http.StatusOK || !strings.Contains(me.Body.String(), `"twoFactorRequired":true`) {
		t.Errorf("%s: GET /api/me = %d %s, want 200 with twoFactorRequired true", what, me.Code, me.Body)
	}
}

func wantBearerRestricted(t *testing.T, what string, h http.Handler, bearer string) {
	t.Helper()
	wantRestricted(t, what, doReq(t, h, "POST", "/api/shares", bearer, `{"name":"x"}`), doReq(t, h, "GET", "/api/me", bearer, ""))
}

func wantWebRestricted(t *testing.T, what string, f webFixture, cookie string) {
	t.Helper()
	wantRestricted(t, what, f.req(t, "POST", "/api/shares", cookie, `{"name":"x"}`), f.req(t, "GET", "/api/me", cookie, ""))
}

func TestTheSwitchIsOffByDefaultAndAbsentFromSettings(t *testing.T) {
	f := newWebFixture(t, false)
	rec := doReq(t, f.h, "GET", "/api/server/settings", testToken, "")
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "requireTwoFactor") {
		t.Fatalf("GET /api/server/settings = %d %s, want 200 without requireTwoFactor", rec.Code, rec.Body)
	}
	if _, on := f.hd.requireTwoFactorSince(); on {
		t.Fatal("the switch reads on before anyone turned it on")
	}
	wantShares(t, "alice before the switch", f.h, f.aliceDevice)
	if tok, _ := login(t, f.h, "alice", "alice-pw"); tok == "" {
		t.Fatal("alice could not sign in")
	} else {
		wantShares(t, "alice's new sign-in with the switch off", f.h, tok)
	}
}

func TestTurningTheSwitchOnRecordsItsTime(t *testing.T) {
	f := newWebFixture(t, false)
	before := time.Now().Truncate(time.Second)
	patchRequireTwoFactor(t, f.h, true)
	after := time.Now()
	if body := doReq(t, f.h, "GET", "/api/server/settings", testToken, "").Body.String(); !strings.Contains(body, `"requireTwoFactor":true`) {
		t.Fatalf("GET /api/server/settings = %s, want requireTwoFactor true", body)
	}
	since, on := f.hd.requireTwoFactorSince()
	if !on || since.Before(before) || since.After(after) {
		t.Fatalf("since = %v (on %v), want on and within [%v, %v]", since, on, before, after)
	}
	earlier := strconv.FormatInt(time.Now().Add(-time.Hour).Truncate(time.Second).UnixNano(), 10)
	if err := f.db.SetSetting(requireTwoFactorKey, earlier); err != nil {
		t.Fatal(err)
	}
	patchRequireTwoFactor(t, f.h, true)
	if v, ok, err := f.db.Setting(requireTwoFactorKey); err != nil || !ok || v != earlier {
		t.Fatalf("after a second PATCH true the stored time = %q (ok %v, err %v), want %q kept", v, ok, err, earlier)
	}
}

func TestTokensSignedInBeforeTheSwitchKeepWorking(t *testing.T) {
	f := newWebFixture(t, false)
	signedInBefore(t, f)
	patchRequireTwoFactor(t, f.h, true)
	wantShares(t, "alice's device signed in before the switch", f.h, f.aliceDevice)
	if body := doReq(t, f.h, "GET", "/api/me", f.aliceDevice, "").Body.String(); strings.Contains(body, "twoFactorRequired") {
		t.Fatalf("GET /api/me = %s, want no twoFactorRequired", body)
	}
}

func TestEveryMintingPathAfterTheSwitchIsRestricted(t *testing.T) {
	f := newWebFixture(t, false)
	signedInBefore(t, f)
	approver := aliceTokenID(t, f, f.aliceDevice)
	patchRequireTwoFactor(t, f.h, true)

	tok, code := login(t, f.h, "alice", "alice-pw")
	if tok == "" {
		t.Fatalf("password login = %d", code)
	}
	wantBearerRestricted(t, "password login", f.h, tok)

	wantWebRestricted(t, "web sign-in", f, f.signIn(t, false))

	invite, err := f.db.MintInvite("alice")
	if err != nil {
		t.Fatal(err)
	}
	rec := doReq(t, f.h, "POST", "/api/auth/invite", "", fmt.Sprintf(`{"token":%q,"label":"tablet"}`, invite))
	if rec.Code != http.StatusOK {
		t.Fatalf("invite = %d %s", rec.Code, rec.Body)
	}
	var spent struct {
		Token string `json:"token"`
	}
	unmarshal(t, rec, &spent)
	wantBearerRestricted(t, "invite", f.h, spent.Token)

	now := time.Now()
	link, secret, err := f.db.MintDeviceLink("alice", approver, "m", false, now)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := f.db.ClaimDeviceLink(secret, "Pixel", "android", "m", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.db.ApproveDeviceLink("alice", approver, link.ID, claim.Number, now); err != nil {
		t.Fatal(err)
	}
	_, linked, pending, err := f.db.SpendDeviceLink(claim.ClaimID, claim.PollSecret, now)
	if err != nil || pending {
		t.Fatalf("device link spend: pending %v, %v", pending, err)
	}
	wantBearerRestricted(t, "device link", f.h, linked)

	_, desk, err := f.db.MintDesktopSignIn("alice", approver, "Phone sign-in: Mac", "macos", "m", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	wantBearerRestricted(t, "phone-approved computer", f.h, desk)

	_, web, err := f.db.MintWebSessionApprovedBy("alice", approver, "Phone sign-in: browser", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	wantWebRestricted(t, "phone-approved browser", f, web)

	wantShares(t, "alice's device signed in before the switch", f.h, f.aliceDevice)
}

func TestAPasswordChangeKeepsADevicesStanding(t *testing.T) {
	f := newWebFixture(t, false)
	signedInBefore(t, f)
	patchRequireTwoFactor(t, f.h, true)
	rec := doReq(t, f.h, "PATCH", "/api/me/password", f.aliceDevice, `{"currentPassword":"alice-pw","password":"violet-harbor-lantern-42"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH /api/me/password = %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Token string `json:"token"`
	}
	unmarshal(t, rec, &out)
	wantShares(t, "the token a password change re-minted", f.h, out.Token)
}

func TestTurningTheSwitchOffLiftsTheRestrictionAtOnce(t *testing.T) {
	f := newWebFixture(t, false)
	patchRequireTwoFactor(t, f.h, true)
	tok, code := login(t, f.h, "alice", "alice-pw")
	if tok == "" {
		t.Fatalf("password login = %d", code)
	}
	wantBearerRestricted(t, "a sign-in after the switch", f.h, tok)
	patchRequireTwoFactor(t, f.h, false)
	wantShares(t, "the same token after the switch is off", f.h, tok)
	if _, ok, err := f.db.Setting(requireTwoFactorKey); err != nil || ok {
		t.Fatalf("the switch's setting after off: present %v, err %v; want it gone", ok, err)
	}
	if body := doReq(t, f.h, "GET", "/api/server/settings", testToken, "").Body.String(); strings.Contains(body, "requireTwoFactor") {
		t.Fatalf("GET /api/server/settings = %s, want no requireTwoFactor", body)
	}
}

func TestEnrollingLiftsTheRestriction(t *testing.T) {
	f := newWebFixture(t, false)
	patchRequireTwoFactor(t, f.h, true)
	tok, code := login(t, f.h, "alice", "alice-pw")
	if tok == "" {
		t.Fatalf("password login = %d", code)
	}
	wantBearerRestricted(t, "a sign-in after the switch", f.h, tok)
	enableTOTP(t, f.h, tok, "alice-pw")
	wantShares(t, "the same token after enrolment", f.h, tok)
}

// A sign-in in the switch's own second counts as after it.
func TestASignInInTheSwitchsOwnSecondIsRestricted(t *testing.T) {
	f := newWebFixture(t, false)
	now := time.Now()
	if err := f.hd.setRequireTwoFactor(true, now); err != nil {
		t.Fatal(err)
	}
	since, on := f.hd.requireTwoFactorSince()
	if !on {
		t.Fatal("the switch reads off after turning it on")
	}
	u := metadb.User{Username: "alice", Role: metadb.RoleUser}
	if !f.hd.twoFactorRestricted(u, metadb.Token{ID: "t1", CreatedAt: since}) {
		t.Error("a token signed in in the switch's second is unrestricted, want restricted")
	}
	if f.hd.twoFactorRestricted(u, metadb.Token{ID: "t2", CreatedAt: since.Add(-time.Second)}) {
		t.Error("a token signed in the second before the switch is restricted, want unrestricted")
	}
}

// A caller with no token row has no sign-in time, so it counts as signed
// in after the switch.
func TestACallerWithNoTokenRowCountsAsSignedInAfterTheSwitch(t *testing.T) {
	f := newWebFixture(t, false)
	u := metadb.User{Username: "alice", Role: metadb.RoleUser}
	if f.hd.twoFactorRestricted(u, metadb.Token{}) {
		t.Fatal("no token row with the switch off is restricted, want unrestricted")
	}
	if err := f.hd.setRequireTwoFactor(true, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !f.hd.twoFactorRestricted(u, metadb.Token{}) {
		t.Fatal("no token row with the switch on is unrestricted, want restricted")
	}
}

// A switch that cannot be read restricts every account without a second
// factor, whenever its token was signed in, and says so in the log once.
func TestAnUnreadableSwitchRestrictsAccountsWithoutASecondFactor(t *testing.T) {
	buf := captureLog(t)
	f := newWebFixture(t, false)
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	u := metadb.User{Username: "alice", Role: metadb.RoleUser}
	old := metadb.Token{ID: "t1", CreatedAt: time.Now().Add(-24 * time.Hour)}
	for range 2 {
		if !f.hd.twoFactorRestricted(u, old) {
			t.Fatal("an account without a second factor is unrestricted while the switch cannot be read")
		}
	}
	if n := strings.Count(buf.String(), "reading the require switch"); n != 1 {
		t.Fatalf("the log names the unreadable switch %d times, want once: %q", n, buf.String())
	}
}

// A switch holding no time reads as on since the zero time, and the log
// says so once.
func TestAnUnparseableSwitchRestrictsAndLogsOnce(t *testing.T) {
	buf := captureLog(t)
	f := newWebFixture(t, false)
	signedInBefore(t, f)
	if err := f.db.SetSetting(requireTwoFactorKey, "not a time"); err != nil {
		t.Fatal(err)
	}
	wantBearerRestricted(t, "alice's device signed in before an unparseable switch", f.h, f.aliceDevice)
	wantBearerRestricted(t, "the same device again", f.h, f.aliceDevice)
	if n := strings.Count(buf.String(), "the require switch holds no time"); n != 1 {
		t.Fatalf("the log names the unparseable switch %d times, want once: %q", n, buf.String())
	}
	if err := f.db.DeleteSetting(requireTwoFactorKey); err != nil {
		t.Fatal(err)
	}
	wantShares(t, "alice once the switch is off", f.h, f.aliceDevice)
}
