package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// doReqFrom is doReq from a chosen client address: the step-up lockout
// counts per address as well as per account.
func doReqFrom(t *testing.T, h http.Handler, method, path, token, body, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func changePasswordBody(current string) string {
	return fmt.Sprintf(`{"password":"a-new-password","currentPassword":%q}`, current)
}

// A stolen token must not turn the password change into an unthrottled
// password oracle: wrong current passwords count like wrong logins.
func TestAWrongStepUpPasswordCountsOnTheLoginLockout(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	const addr = "203.0.113.9:4321"
	for i := range pwFailLimit - 1 {
		rec := doReqFrom(t, h, "PATCH", "/api/me/password", testToken, changePasswordBody("wrong"), addr)
		if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `"code":"wrong-password"`) {
			t.Fatalf("attempt %d = %d %s, want 401 wrong-password", i+1, rec.Code, rec.Body)
		}
	}
	if rec := doReqFrom(t, h, "PATCH", "/api/me/password", testToken, changePasswordBody("wrong"), addr); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt %d = %d, want 429", pwFailLimit, rec.Code)
	}
	// The right password is refused while blocked.
	if rec := doReqFrom(t, h, "PATCH", "/api/me/password", testToken, changePasswordBody(testAdminPassword), addr); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("right password while blocked = %d, want 429", rec.Code)
	}
}

// A stolen token's wrong step-ups block that token alone: the owner's other
// device still changes the password, turns the factor off or links a device.
func TestStepUpFailuresFromOneTokenDoNotBlockAnother(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	other, code := login(t, h, "admin", testAdminPassword)
	if code != http.StatusOK {
		t.Fatalf("login = %d", code)
	}
	for i := range pwFailLimit {
		addr := fmt.Sprintf("198.51.100.%d:1000", i+1)
		doReqFrom(t, h, "PATCH", "/api/me/password", testToken, changePasswordBody("wrong"), addr)
	}
	if rec := doReqFrom(t, h, "PATCH", "/api/me/password", testToken, changePasswordBody(testAdminPassword), "192.0.2.78:1000"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("the guessing token's step-up = %d, want 429", rec.Code)
	}
	body := fmt.Sprintf(`{"password":"a-new-password","currentPassword":%q,"totp":%q}`, testAdminPassword, seededAdminCode(t))
	if rec := doReqFrom(t, h, "PATCH", "/api/me/password", other, body, "192.0.2.77:1000"); rec.Code != http.StatusOK {
		t.Fatalf("the other token's step-up = %d %s, want 200", rec.Code, rec.Body)
	}
}

// Guesses spread over many addresses still meet the token's own count,
// and that count never stops the owner signing in.
func TestStepUpGuessesFromManyAddressesLockTheTokensStepUps(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	for i := range pwFailLimit {
		addr := fmt.Sprintf("198.51.100.%d:1000", i+1)
		doReqFrom(t, h, "PATCH", "/api/me/password", testToken, changePasswordBody("wrong"), addr)
	}
	if rec := doReqFrom(t, h, "PATCH", "/api/me/password", testToken, changePasswordBody(testAdminPassword), "192.0.2.77:1000"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("step-up from a fresh address = %d, want 429", rec.Code)
	}
	if rec := doReqFrom(t, h, "POST", "/api/auth/login", "", loginBody("admin", testAdminPassword, seededAdminCode(t)), "192.0.2.77:1000"); rec.Code != http.StatusOK {
		t.Fatalf("login from a fresh address = %d %s, want 200", rec.Code, rec.Body)
	}
}

// An address the login lockout blocked is blocked from step-ups too.
func TestALoginLockoutBlocksStepUpsFromThatAddress(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	const addr = "203.0.113.7:4321"
	for range pwFailLimit {
		doReqFrom(t, h, "POST", "/api/auth/login", "", loginBody("admin", "wrong", ""), addr)
	}
	if rec := doReqFrom(t, h, "PATCH", "/api/me/password", testToken, changePasswordBody(testAdminPassword), addr); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("step-up from a locked-out address = %d, want 429", rec.Code)
	}
}

// Wrong codes count, and the right password alone (enrolment's start asks
// for nothing more) cannot reset the count between guesses.
func TestTheRightPasswordAloneDoesNotResetTheCodeCount(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	enableTOTP(t, h, testToken, testAdminPassword)
	wrongCode := `{"currentPassword":"` + testAdminPassword + `","code":"000000"}`
	for i := range pwFailLimit - 1 {
		if rec := doReq(t, h, "POST", "/api/me/totp/recovery", testToken, wrongCode); rec.Code != http.StatusUnauthorized {
			t.Fatalf("wrong code %d = %d %s, want 401", i+1, rec.Code, rec.Body)
		}
	}
	if rec := doReq(t, h, "POST", "/api/me/totp", testToken, `{"currentPassword":"`+testAdminPassword+`"}`); rec.Code == http.StatusOK || rec.Code == http.StatusTooManyRequests {
		t.Fatalf("enrolment start with 2FA on = %d %s, want its refusal", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "POST", "/api/me/totp/recovery", testToken, wrongCode); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("wrong code %d = %d, want 429", pwFailLimit, rec.Code)
	}
}

// A step-up that proved the password and the code clears the count, so the
// owner's own typos never add up to a block.
func TestAFullStepUpClearsTheCount(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	_, recovery := enableTOTP(t, h, testToken, testAdminPassword)
	wrongCode := `{"currentPassword":"` + testAdminPassword + `","code":"000000"}`
	for range pwFailLimit - 1 {
		doReq(t, h, "POST", "/api/me/totp/recovery", testToken, wrongCode)
	}
	full := `{"currentPassword":"` + testAdminPassword + `","code":"` + recovery[0] + `"}`
	if rec := doReq(t, h, "POST", "/api/me/totp/recovery", testToken, full); rec.Code != http.StatusOK {
		t.Fatalf("full step-up = %d %s, want 200", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "POST", "/api/me/totp/recovery", testToken, wrongCode); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong code after a full step-up = %d, want 401", rec.Code)
	}
}

// On an account with no second factor the password is everything, so its
// success clears the count.
func TestThePasswordClearsTheCountWithoutASecondFactor(t *testing.T) {
	h, db, _ := newMultiUserAPI(t)
	clearSeededAdminTOTP(t, db)
	for range pwFailLimit - 1 {
		doReq(t, h, "POST", "/api/me/totp", testToken, `{"currentPassword":"wrong"}`)
	}
	if rec := doReq(t, h, "POST", "/api/me/totp", testToken, `{"currentPassword":"`+testAdminPassword+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("enrolment start = %d %s, want 200", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "POST", "/api/me/totp", testToken, `{"currentPassword":"wrong"}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password after a success = %d, want 401", rec.Code)
	}
}

// The admin-granting step-up counts on the same lockout.
func TestAWrongAdminGrantStepUpCountsOnTheLoginLockout(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	body := func(pw string) string {
		return `{"username":"carol","password":"carol-chosen-pw","role":"admin","currentPassword":"` + pw + `"}`
	}
	for range pwFailLimit {
		doReq(t, h, "POST", "/api/users", testToken, body("wrong"))
	}
	if rec := doReq(t, h, "POST", "/api/users", testToken, body(testAdminPassword)); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("admin grant after %d wrong passwords = %d %s, want 429", pwFailLimit, rec.Code, rec.Body)
	}
}

// A token mints more tokens by approving browser sign-ins, which on an
// account without a second factor takes no step-up; every session it mints
// counts its wrong step-ups on the account's counter as well as its own,
// so the account's guesses stay bounded however many sessions there are.
func TestSessionsMintedByApprovalShareTheAccountsStepUpCount(t *testing.T) {
	f := newWebFixture(t, true)
	session := func(i int) string {
		t.Helper()
		s := newWebSignIn(t, f, fmt.Sprintf("203.0.113.%d:4000", 60+i))
		claim := claimWebSignIn(t, f, f.aliceDevice, s.Code)
		_, out, _ := pollWebSignIn(t, f, s)
		if rec := approveWebSignIn(t, f, f.aliceDevice, claim.ID, out.Number, ""); rec.Code != http.StatusNoContent {
			t.Fatalf("approve %d: %d %s", i, rec.Code, rec.Body)
		}
		code, _, cookie := pollWebSignIn(t, f, s)
		if code != http.StatusOK || cookie == "" {
			t.Fatalf("poll %d: %d, cookie %q", i, code, cookie)
		}
		return cookie
	}
	elevate := func(cookie, password, addr string) int {
		return f.req(t, "POST", "/api/web/session/elevate", cookie, `{"currentPassword":"`+password+`"}`, from(addr)).Code
	}
	guesses := 0
	for i := 0; guesses < stepUpAccountFailLimit; i++ {
		cookie := session(i)
		for range min(pwFailLimit, stepUpAccountFailLimit-guesses) {
			guesses++
			// The guess that fills a count answers 429 instead of 401.
			if code := elevate(cookie, "wrong", fmt.Sprintf("198.51.100.%d:1000", guesses)); code != http.StatusUnauthorized && code != http.StatusTooManyRequests {
				t.Fatalf("wrong guess %d = %d, want 401 or 429", guesses, code)
			}
		}
	}
	if code := elevate(session(9), "alice-pw", "192.0.2.77:1000"); code != http.StatusTooManyRequests {
		t.Fatalf("a fresh session's step-up past the account's count = %d, want 429", code)
	}
	if code := doReqFrom(t, f.h, "POST", "/api/auth/login", "", loginBody("alice", "alice-pw", ""), "192.0.2.78:1000").Code; code != http.StatusOK {
		t.Fatalf("login after the step-ups were blocked = %d, want 200", code)
	}
}

// The account's counter waits stepUpAccountWait: one token's full count
// blocks that token for pwBlockFor but the owner's other tokens only until
// the account's wait is over.
func TestOneTokensGuessesBlockOtherTokensOnlyForTheAccountsWait(t *testing.T) {
	l := newPWLimiter()
	t0 := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	thief, owner, account := stepUpTokenKey("thief"), stepUpTokenKey("owner"), stepUpAccountKey("alice")
	for i := range pwFailLimit {
		guess(t, l, t0, "alice", fmt.Sprintf("198.51.100.%d", i+1), thief, account)
	}
	if !blocked(l, t0, "192.0.2.1", thief, account) {
		t.Fatal("the guessing token's step-up was admitted")
	}
	if blocked(l, t0, "192.0.2.2", owner, account) {
		t.Fatal("another token's step-up was blocked by one token's guesses")
	}
	for i := range stepUpAccountFailLimit - pwFailLimit {
		minted := stepUpTokenKey(fmt.Sprintf("minted%d", i))
		guess(t, l, t0, "alice", fmt.Sprintf("198.51.100.%d", 100+i), minted, account)
	}
	if !blocked(l, t0, "192.0.2.2", owner, account) {
		t.Fatal("another token's step-up was admitted past the account's count")
	}
	later := t0.Add(stepUpAccountWait + time.Second)
	if blocked(l, later, "192.0.2.2", owner, account) {
		t.Fatal("another token is still blocked after the account's wait")
	}
	if !blocked(l, later, "192.0.2.1", thief, account) {
		t.Fatal("the guessing token's own block ended with the account's wait")
	}
}
