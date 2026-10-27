package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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

// Guesses spread over many addresses still meet the account's own count,
// and that count never stops the owner signing in.
func TestStepUpGuessesFromManyAddressesLockTheAccountsStepUps(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	for i := range pwFailLimit {
		addr := fmt.Sprintf("198.51.100.%d:1000", i+1)
		doReqFrom(t, h, "PATCH", "/api/me/password", testToken, changePasswordBody("wrong"), addr)
	}
	if rec := doReqFrom(t, h, "PATCH", "/api/me/password", testToken, changePasswordBody(testAdminPassword), "192.0.2.77:1000"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("step-up from a fresh address = %d, want 429", rec.Code)
	}
	if rec := doReqFrom(t, h, "POST", "/api/auth/login", "", loginBody("admin", testAdminPassword, ""), "192.0.2.77:1000"); rec.Code != http.StatusOK {
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
		if rec := doReq(t, h, "DELETE", "/api/me/totp", testToken, wrongCode); rec.Code != http.StatusUnauthorized {
			t.Fatalf("wrong code %d = %d %s, want 401", i+1, rec.Code, rec.Body)
		}
	}
	if rec := doReq(t, h, "POST", "/api/me/totp", testToken, `{"currentPassword":"`+testAdminPassword+`"}`); rec.Code == http.StatusOK || rec.Code == http.StatusTooManyRequests {
		t.Fatalf("enrolment start with 2FA on = %d %s, want its refusal", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "DELETE", "/api/me/totp", testToken, wrongCode); rec.Code != http.StatusTooManyRequests {
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
		doReq(t, h, "DELETE", "/api/me/totp", testToken, wrongCode)
	}
	full := `{"currentPassword":"` + testAdminPassword + `","code":"` + recovery[0] + `"}`
	if rec := doReq(t, h, "POST", "/api/me/totp/recovery", testToken, full); rec.Code != http.StatusOK {
		t.Fatalf("full step-up = %d %s, want 200", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "DELETE", "/api/me/totp", testToken, wrongCode); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong code after a full step-up = %d, want 401", rec.Code)
	}
}

// On an account with no second factor the password is everything, so its
// success clears the count.
func TestThePasswordClearsTheCountWithoutASecondFactor(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
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
