package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/totp"
)

// codeNow is the authenticator's answer at this instant.
func codeNow(t *testing.T, secret string) string {
	t.Helper()
	return codeAt(t, secret, 0)
}

// nextCode is the answer for the step AFTER this one, which the skew window
// already accepts.
//
// Tests need it because CONFIRMING enrollment spends the current step: the
// replay guard is doing its job, and a real user who enrols and then
// immediately authenticates somewhere else waits for the next code in exactly
// this way.
func nextCode(t *testing.T, secret string) string {
	t.Helper()
	return codeAt(t, secret, 1)
}

func codeAt(t *testing.T, secret string, offset int64) string {
	t.Helper()
	c, err := totp.Code(secret, totp.StepAt(time.Now())+offset)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// enableTOTP walks the caller through the REAL enrollment routes rather than
// writing a user file, so every test below exercises the same path a client
// takes. For the seeded admin's bearer, whose factor testBackend already
// confirmed, it answers that factor and hands the test the recovery codes
// seededAdminCode has not spent, which seededAdminCode then no longer uses.
func enableTOTP(t *testing.T, h http.Handler, token, password string) (secret string, recovery []string) {
	t.Helper()
	if f, ok := seededFactors[t]; ok && token == testToken {
		seededFactors[t] = seededFactor{secret: f.secret}
		return f.secret, f.recovery
	}
	rec := doReq(t, h, "POST", "/api/me/totp", token, `{"currentPassword":"`+password+`"}`)
	if rec.Code != 200 {
		t.Fatalf("start enrollment: %d %s", rec.Code, rec.Body)
	}
	var start struct {
		Secret string `json:"secret"`
		URI    string `json:"uri"`
	}
	unmarshal(t, rec, &start)
	rec = doReq(t, h, "POST", "/api/me/totp/confirm", token, `{"code":"`+codeNow(t, start.Secret)+`"}`)
	if rec.Code != 200 {
		t.Fatalf("confirm enrollment: %d %s", rec.Code, rec.Body)
	}
	var conf struct {
		RecoveryCodes []string `json:"recoveryCodes"`
	}
	unmarshal(t, rec, &conf)
	if len(conf.RecoveryCodes) == 0 {
		t.Fatal("confirm returned no recovery codes")
	}
	return start.Secret, conf.RecoveryCodes
}

func loginBody(user, pw, code string) string {
	b := `{"username":"` + user + `","password":"` + pw + `"`
	if code != "" {
		b += `,"totp":"` + code + `"`
	}
	return b + `}`
}

func tryLogin(t *testing.T, h http.Handler, user, pw, code string) *httptest.ResponseRecorder {
	t.Helper()
	return doReq(t, h, "POST", "/api/auth/login", "", loginBody(user, pw, code))
}

// An enrollment the user walked away from must not half-lock the account.
func TestAnUnconfirmedEnrollmentReadsAsOff(t *testing.T) {
	h, db, _ := newMultiUserAPI(t)
	clearSeededAdminTOTP(t, db)
	rec := doReq(t, h, "POST", "/api/me/totp", testToken, `{"currentPassword":"`+testAdminPassword+`"}`)
	if rec.Code != 200 {
		t.Fatalf("start: %d %s", rec.Code, rec.Body)
	}
	if rec := tryLogin(t, h, "admin", testAdminPassword, ""); rec.Code != 200 {
		t.Fatalf("login during an unconfirmed enrollment = %d %s, want 200", rec.Code, rec.Body)
	}
	rec = doReq(t, h, "GET", "/api/me/totp", testToken, "")
	var st struct {
		Enabled bool `json:"enabled"`
		Pending bool `json:"pending"`
	}
	unmarshal(t, rec, &st)
	if st.Enabled || !st.Pending {
		t.Fatalf("status = %+v, want pending and not enabled", st)
	}
}

// 401 with a code, never a 200 carrying a flag: every existing client reads a
// non-2xx as a failed login, so a flagged 200 would be taken as success.
func TestLoginNeedsACodeOnceConfirmed(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	secret, _ := enableTOTP(t, h, testToken, testAdminPassword)

	rec := tryLogin(t, h, "admin", testAdminPassword, "")
	if rec.Code != 401 || !strings.Contains(rec.Body.String(), `"totp-required"`) {
		t.Fatalf("login with no code = %d %s, want 401 totp-required", rec.Code, rec.Body)
	}
	if rec := tryLogin(t, h, "admin", testAdminPassword, nextCode(t, secret)); rec.Code != 200 {
		t.Fatalf("login with a code = %d %s, want 200", rec.Code, rec.Body)
	}
	// A wrong password still says nothing about the code.
	if rec := tryLogin(t, h, "admin", "not-the-password", codeNow(t, secret)); rec.Code != 401 {
		t.Fatalf("wrong password = %d, want 401", rec.Code)
	}
}

// Without this a code read aloud over the phone is good for its whole window
// on any number of devices.
func TestACodeCannotLogInTwice(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	secret, _ := enableTOTP(t, h, testToken, testAdminPassword)
	code := nextCode(t, secret)
	if rec := tryLogin(t, h, "admin", testAdminPassword, code); rec.Code != 200 {
		t.Fatalf("first use = %d %s", rec.Code, rec.Body)
	}
	rec := tryLogin(t, h, "admin", testAdminPassword, code)
	if rec.Code != 401 || !strings.Contains(rec.Body.String(), `"totp-invalid"`) {
		t.Fatalf("replayed code = %d %s, want 401 totp-invalid", rec.Code, rec.Body)
	}
}

func TestARecoveryCodeWorksOnceAndNeverTwice(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	_, codes := enableTOTP(t, h, testToken, testAdminPassword)
	if rec := tryLogin(t, h, "admin", testAdminPassword, codes[0]); rec.Code != 200 {
		t.Fatalf("recovery login = %d %s, want 200", rec.Code, rec.Body)
	}
	if rec := tryLogin(t, h, "admin", testAdminPassword, codes[0]); rec.Code != 401 {
		t.Fatalf("reused recovery code = %d, want 401", rec.Code)
	}
	// The others survive, and the count reports the spend.
	if rec := tryLogin(t, h, "admin", testAdminPassword, codes[1]); rec.Code != 200 {
		t.Fatalf("second recovery code = %d %s, want 200", rec.Code, rec.Body)
	}
	rec := doReq(t, h, "GET", "/api/me/totp", testToken, "")
	var st struct {
		RecoveryCodesLeft int `json:"recoveryCodesLeft"`
	}
	unmarshal(t, rec, &st)
	if want := len(codes) - 2; st.RecoveryCodesLeft != want {
		t.Fatalf("codes left = %d, want %d", st.RecoveryCodesLeft, want)
	}
}

// Formatting is a reading aid, not part of the secret.
func TestARecoveryCodeIsAcceptedWithoutItsDash(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	_, codes := enableTOTP(t, h, testToken, testAdminPassword)
	plain := strings.ToLower(strings.ReplaceAll(codes[0], "-", ""))
	if rec := tryLogin(t, h, "admin", testAdminPassword, plain); rec.Code != 200 {
		t.Fatalf("undashed lowercase recovery code = %d %s, want 200", rec.Code, rec.Body)
	}
}

// The per-IP lockout must cover code guessing, and the success that clears it
// must be the WHOLE login: clearing on the password alone would let a caller
// holding a correct password reset the counter on every attempt and guess
// codes forever.
func TestAWrongCodeCountsOnTheLoginLockout(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	secret, _ := enableTOTP(t, h, testToken, testAdminPassword)
	for i := range pwFailLimit {
		rec := tryLogin(t, h, "admin", testAdminPassword, "000000")
		if rec.Code != 401 && rec.Code != 429 {
			t.Fatalf("attempt %d = %d %s, want 401 or 429", i, rec.Code, rec.Body)
		}
	}
	if rec := tryLogin(t, h, "admin", testAdminPassword, nextCode(t, secret)); rec.Code != 429 {
		t.Fatalf("after %d wrong codes a correct one = %d, want 429", pwFailLimit, rec.Code)
	}
}

// A stolen token must not be able to strip the protection its owner added.
func TestDisablingNeedsThePasswordAndACode(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	tok := seedUser(t, um, "alice")
	secret, _ := enableTOTP(t, h, tok, "alice-pw")

	wantStepUpRequired(t, "disable with no password", doReq(t, h, "DELETE", "/api/me/totp", tok, `{}`))
	if rec := doReq(t, h, "DELETE", "/api/me/totp", tok,
		`{"currentPassword":"alice-pw"}`); rec.Code != 401 {
		t.Fatalf("disable with no code = %d, want 401", rec.Code)
	}
	rec := doReq(t, h, "DELETE", "/api/me/totp", tok,
		`{"currentPassword":"alice-pw","code":"`+nextCode(t, secret)+`"}`)
	if rec.Code != 200 {
		t.Fatalf("disable = %d %s, want 200", rec.Code, rec.Body)
	}
	if rec := tryLogin(t, h, "alice", "alice-pw", ""); rec.Code != 200 {
		t.Fatalf("login after disabling = %d, want 200", rec.Code)
	}
}

func wantTwoFactorRequired(t *testing.T, what string, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), `"two-factor-required"`) {
		t.Fatalf("%s = %d %s, want 409 two-factor-required", what, rec.Code, rec.Body)
	}
}

// An admin always owes a second factor, so turning their own off is refused
// and the factor stays.
func TestAnAdminCannotTurnOffTheirOwnFactor(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	secret, _ := enableTOTP(t, h, testToken, testAdminPassword)
	wantTwoFactorRequired(t, "admin self turn-off", doReq(t, h, "DELETE", "/api/me/totp", testToken,
		`{"currentPassword":"`+testAdminPassword+`","code":"`+nextCode(t, secret)+`"}`))
	if rec := tryLogin(t, h, "admin", testAdminPassword, ""); rec.Code != 401 {
		t.Fatalf("admin login without a code after the refusal = %d, want 401", rec.Code)
	}
}

func TestAUserCannotTurnOffTheirFactorWhileTheSwitchIsOn(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	tok := seedUser(t, um, "alice")
	secret, _ := enableTOTP(t, h, tok, "alice-pw")
	patchRequireTwoFactor(t, h, true)

	wantTwoFactorRequired(t, "user self turn-off with the switch on", doReq(t, h, "DELETE", "/api/me/totp", tok,
		`{"currentPassword":"alice-pw","code":"`+nextCode(t, secret)+`"}`))
	if rec := tryLogin(t, h, "alice", "alice-pw", ""); rec.Code != 401 {
		t.Fatalf("alice login without a code after the refusal = %d, want 401", rec.Code)
	}

	patchRequireTwoFactor(t, h, false)
	rec := doReq(t, h, "DELETE", "/api/me/totp", tok,
		`{"currentPassword":"alice-pw","code":"`+nextCode(t, secret)+`"}`)
	if rec.Code != 200 {
		t.Fatalf("turn-off with the switch off = %d %s, want 200", rec.Code, rec.Body)
	}
}

// The refusal comes before the step-up, so the code it was sent stays good.
func TestTheTurnOffRefusalSpendsNoCode(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	tok := seedUser(t, um, "alice")
	secret, _ := enableTOTP(t, h, tok, "alice-pw")
	patchRequireTwoFactor(t, h, true)

	code := nextCode(t, secret)
	wantTwoFactorRequired(t, "refused turn-off", doReq(t, h, "DELETE", "/api/me/totp", tok,
		`{"currentPassword":"alice-pw","code":"`+code+`"}`))
	if rec := tryLogin(t, h, "alice", "alice-pw", code); rec.Code != 200 {
		t.Fatalf("login with the code the refusal was sent = %d %s, want 200", rec.Code, rec.Body)
	}
}

func TestAnAdminCanStillResetAnotherAdminsFactor(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	if _, err := um.CreateUser("boss", "boss-pw", metadb.RoleAdmin, metadb.Settings{}); err != nil {
		t.Fatal(err)
	}
	tok, err := um.MintToken("boss", "test")
	if err != nil {
		t.Fatal(err)
	}
	enableTOTP(t, h, tok, "boss-pw")
	if rec := doReq(t, h, "DELETE", "/api/users/boss/totp", testToken,
		`{"currentPassword":"`+testAdminPassword+`"`+seededAdminTOTP(t)+`}`); rec.Code != 200 {
		t.Fatalf("admin reset of another admin = %d %s, want 200", rec.Code, rec.Body)
	}
}

func TestChangingThePasswordNeedsTheCurrentOneAndACode(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	tok := seedUser(t, um, "alice")
	// Enrol alice, whose password is name+"-pw" by the seedUser convention.
	secret, _ := enableTOTP(t, h, tok, "alice-pw")

	wantStepUpRequired(t, "no current password", doReq(t, h, "PATCH", "/api/me/password", tok,
		`{"password":"brand-new"}`))
	if rec := doReq(t, h, "PATCH", "/api/me/password", tok,
		`{"currentPassword":"wrong","password":"brand-new"}`); rec.Code != 401 {
		t.Fatalf("wrong current password = %d, want 401", rec.Code)
	}
	if rec := doReq(t, h, "PATCH", "/api/me/password", tok,
		`{"currentPassword":"alice-pw","password":"brand-new"}`); rec.Code != 401 {
		t.Fatalf("no code with 2FA on = %d, want 401", rec.Code)
	}
	rec := doReq(t, h, "PATCH", "/api/me/password", tok,
		`{"currentPassword":"alice-pw","password":"brand-new","totp":"`+nextCode(t, secret)+`"}`)
	if rec.Code != 200 {
		t.Fatalf("full password change = %d %s, want 200", rec.Code, rec.Body)
	}
}

// An admin clearing their OWN factor with nothing but a bearer token would
// mean a stolen admin token defeats 2FA outright, and would make recovery
// codes decorative for the one account with no second admin to unlock it.
func TestTheAdminResetRefusesToTargetTheCaller(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	seedUser(t, um, "alice")
	enableTOTP(t, h, testToken, testAdminPassword)

	rec := doReq(t, h, "DELETE", "/api/users/admin/totp", testToken, "")
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), "totp-self-reset") {
		t.Fatalf("admin self-reset = %d %s, want 403 totp-self-reset", rec.Code, rec.Body)
	}
	// The admin's own factor is untouched by the refusal.
	if rec := tryLogin(t, h, "admin", testAdminPassword, ""); rec.Code != 401 {
		t.Fatalf("admin login after a refused self-reset = %d, want 401", rec.Code)
	}
}

func TestAdminResetsAnotherUsersTOTP(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	tok := seedUser(t, um, "alice")
	enableTOTP(t, h, tok, "alice-pw")
	if rec := tryLogin(t, h, "alice", "alice-pw", ""); rec.Code != 401 {
		t.Fatalf("alice login before reset = %d, want 401", rec.Code)
	}
	if rec := doReq(t, h, "DELETE", "/api/users/alice/totp", testToken, ""); rec.Code != 200 {
		t.Fatalf("admin reset = %d %s, want 200", rec.Code, rec.Body)
	}
	if rec := tryLogin(t, h, "alice", "alice-pw", ""); rec.Code != 200 {
		t.Fatalf("alice login after reset = %d, want 200", rec.Code)
	}
}

func TestANonAdminCannotResetAnyonesTOTP(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	tok := seedUser(t, um, "alice")
	seedUser(t, um, "bob")
	if rec := doReq(t, h, "DELETE", "/api/users/bob/totp", tok, ""); rec.Code != 403 {
		t.Fatalf("non-admin reset = %d, want 403", rec.Code)
	}
}

// The secret is readable exactly once, in the enrollment response.
func TestTheStatusRouteNeverRepeatsTheSecret(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	secret, codes := enableTOTP(t, h, testToken, testAdminPassword)
	rec := doReq(t, h, "GET", "/api/me/totp", testToken, "")
	body := rec.Body.String()
	if strings.Contains(body, secret) {
		t.Fatalf("status leaked the secret: %s", body)
	}
	for _, c := range codes {
		if strings.Contains(body, c) {
			t.Fatalf("status leaked a recovery code: %s", body)
		}
	}
}

func TestRegeneratingRecoveryCodesInvalidatesTheOldSet(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	secret, old := enableTOTP(t, h, testToken, testAdminPassword)
	rec := doReq(t, h, "POST", "/api/me/totp/recovery", testToken,
		`{"currentPassword":"`+testAdminPassword+`","code":"`+nextCode(t, secret)+`"}`)
	if rec.Code != 200 {
		t.Fatalf("regenerate = %d %s, want 200", rec.Code, rec.Body)
	}
	var out struct {
		RecoveryCodes []string `json:"recoveryCodes"`
	}
	unmarshal(t, rec, &out)
	if len(out.RecoveryCodes) == 0 || out.RecoveryCodes[0] == old[0] {
		t.Fatalf("regenerated set = %v, want a different one", out.RecoveryCodes)
	}
	if rec := tryLogin(t, h, "admin", testAdminPassword, old[0]); rec.Code != 401 {
		t.Fatalf("old recovery code after regeneration = %d, want 401", rec.Code)
	}
	if rec := tryLogin(t, h, "admin", testAdminPassword, out.RecoveryCodes[0]); rec.Code != 200 {
		t.Fatalf("new recovery code = %d, want 200", rec.Code)
	}
}
