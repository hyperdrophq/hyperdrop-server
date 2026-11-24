package api

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
)

// startReplace starts replacing token's authenticator with password and
// code, failing the test unless the server answers 200, and returns the
// pending secret.
func startReplace(t *testing.T, h http.Handler, token, password, code string) string {
	t.Helper()
	rec := doReq(t, h, "POST", "/api/me/totp/replace", token,
		`{"currentPassword":"`+password+`","code":"`+code+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("start the replace: %d %s", rec.Code, rec.Body)
	}
	var start struct {
		Secret  string `json:"secret"`
		URI     string `json:"uri"`
		Issuer  string `json:"issuer"`
		Account string `json:"account"`
	}
	unmarshal(t, rec, &start)
	if start.Secret == "" || start.URI == "" || start.Issuer != totpIssuer || start.Account == "" {
		t.Fatalf("the replace start answers %+v", start)
	}
	return start.Secret
}

// confirmReplace confirms token's pending replace with code.
func confirmReplace(t *testing.T, h http.Handler, token, code string) (int, string, []string) {
	t.Helper()
	rec := doReq(t, h, "POST", "/api/me/totp/replace/confirm", token, `{"code":"`+code+`"}`)
	var out struct {
		RecoveryCodes []string `json:"recoveryCodes"`
	}
	if rec.Code == http.StatusOK {
		unmarshal(t, rec, &out)
	}
	return rec.Code, errCode(t, rec.Body.String()), out.RecoveryCodes
}

// Between the two steps the account still has its old factor, and only it:
// a sign-in takes the old code and refuses the pending secret's.
func TestReplaceKeepsTheOldSecretUntilConfirmed(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	tok := seedUser(t, um, "alice")
	old, recovery := enableTOTP(t, h, tok, "alice-pw")
	pending := startReplace(t, h, tok, "alice-pw", recovery[0])

	rec := doReq(t, h, "GET", "/api/me/totp", tok, "")
	var st struct {
		Enabled bool `json:"enabled"`
		Pending bool `json:"pending"`
	}
	unmarshal(t, rec, &st)
	if !st.Enabled || st.Pending {
		t.Fatalf("status during a replace = %+v, want enabled and not an enrolment", st)
	}
	if rec := tryLogin(t, h, "alice", "alice-pw", codeNow(t, pending)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("sign-in with the pending secret's code = %d %s, want 401", rec.Code, rec.Body)
	}
	if rec := tryLogin(t, h, "alice", "alice-pw", nextCode(t, old)); rec.Code != http.StatusOK {
		t.Fatalf("sign-in with the old code during a replace = %d %s, want 200", rec.Code, rec.Body)
	}
	if rec := tryLogin(t, h, "alice", "alice-pw", recovery[1]); rec.Code != http.StatusOK {
		t.Fatalf("sign-in with an old recovery code during a replace = %d %s, want 200", rec.Code, rec.Body)
	}
}

// The confirm swaps the secret and the recovery codes in one step: the old
// secret and every old code stop working, the new ones work.
func TestReplaceConfirmSwapsAndIssuesNewRecoveryCodes(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	tok := seedUser(t, um, "alice")
	old, recovery := enableTOTP(t, h, tok, "alice-pw")
	pending := startReplace(t, h, tok, "alice-pw", recovery[0])

	status, code, fresh := confirmReplace(t, h, tok, codeNow(t, pending))
	if status != http.StatusOK || len(fresh) != len(recovery) {
		t.Fatalf("confirm = %d %s with %d codes, want 200 with %d", status, code, len(fresh), len(recovery))
	}
	for _, c := range fresh {
		if slices.Contains(recovery, c) {
			t.Fatalf("the new recovery codes repeat an old one: %s", c)
		}
	}
	rec := doReq(t, h, "GET", "/api/me/totp", tok, "")
	var st struct {
		Enabled           bool `json:"enabled"`
		Pending           bool `json:"pending"`
		RecoveryCodesLeft int  `json:"recoveryCodesLeft"`
	}
	unmarshal(t, rec, &st)
	if !st.Enabled || st.Pending || st.RecoveryCodesLeft != len(fresh) {
		t.Fatalf("status after the replace = %+v", st)
	}
	if rec := tryLogin(t, h, "alice", "alice-pw", nextCode(t, old)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("sign-in with the old secret = %d %s, want 401", rec.Code, rec.Body)
	}
	if rec := tryLogin(t, h, "alice", "alice-pw", recovery[1]); rec.Code != http.StatusUnauthorized {
		t.Fatalf("sign-in with an old recovery code = %d %s, want 401", rec.Code, rec.Body)
	}
	if rec := tryLogin(t, h, "alice", "alice-pw", codeNow(t, pending)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("the confirming code signs in again = %d %s, want 401", rec.Code, rec.Body)
	}
	if rec := tryLogin(t, h, "alice", "alice-pw", nextCode(t, pending)); rec.Code != http.StatusOK {
		t.Fatalf("sign-in with the new secret = %d %s, want 200", rec.Code, rec.Body)
	}
	if rec := tryLogin(t, h, "alice", "alice-pw", fresh[0]); rec.Code != http.StatusOK {
		t.Fatalf("sign-in with a new recovery code = %d %s, want 200", rec.Code, rec.Body)
	}
	if status, code, _ := confirmReplace(t, h, tok, codeAt(t, pending, 2)); status != http.StatusConflict || code != "totp-not-pending" {
		t.Fatalf("a second confirm = %d %s, want 409 totp-not-pending", status, code)
	}
}

// Starting a replace proves the password and the factor being replaced,
// and an account with no factor has nothing to replace.
func TestReplaceNeedsThePasswordAndAnOldCode(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	tok := seedUser(t, um, "alice")
	bob := seedUser(t, um, "bob")
	for _, tc := range []struct {
		token, body string
		status      int
		code        string
	}{
		{bob, `{"currentPassword":"bob-pw","code":"000000"}`, http.StatusConflict, "totp-off"},
	} {
		rec := doReq(t, h, "POST", "/api/me/totp/replace", tc.token, tc.body)
		if rec.Code != tc.status || errCode(t, rec.Body.String()) != tc.code {
			t.Fatalf("%s = %d %s, want %d %s", tc.body, rec.Code, rec.Body, tc.status, tc.code)
		}
	}
	old, _ := enableTOTP(t, h, tok, "alice-pw")
	for _, tc := range []struct {
		body   string
		status int
		code   string
	}{
		{`{}`, http.StatusForbidden, "step-up-required"},
		{`{"code":"` + nextCode(t, old) + `"}`, http.StatusForbidden, "step-up-required"},
		{`{"currentPassword":"wrong","code":"` + nextCode(t, old) + `"}`, http.StatusUnauthorized, "wrong-password"},
		{`{"currentPassword":"alice-pw"}`, http.StatusUnauthorized, "totp-required"},
		{`{"currentPassword":"alice-pw","code":"not-a-code"}`, http.StatusUnauthorized, "totp-invalid"},
	} {
		rec := doReq(t, h, "POST", "/api/me/totp/replace", tok, tc.body)
		if rec.Code != tc.status || errCode(t, rec.Body.String()) != tc.code {
			t.Fatalf("%s = %d %s, want %d %s", tc.body, rec.Code, rec.Body, tc.status, tc.code)
		}
	}
	if status, code, _ := confirmReplace(t, h, tok, nextCode(t, old)); status != http.StatusConflict || code != "totp-not-pending" {
		t.Fatalf("confirm with nothing pending = %d %s, want 409 totp-not-pending", status, code)
	}
	if rec := doReq(t, h, "POST", "/api/me/totp/replace/confirm", tok, `{"code":"123456","currentPassword":"alice-pw"}`); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), `does not know the field \"currentPassword\"`) {
		t.Fatalf("confirm with a field it does not take = %d %s, want 400", rec.Code, rec.Body)
	}
	startReplace(t, h, tok, "alice-pw", nextCode(t, old))
}

// The confirm takes no password, so its wrong codes count on the step-up's
// keys: guesses spread over many addresses still lock the token out.
func TestAWrongReplaceCodeCountsOnTheStepUpKeys(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	_, recovery := enableTOTP(t, h, testToken, testAdminPassword)
	pending := startReplace(t, h, testToken, testAdminPassword, recovery[0])
	wrongCode := "000000"
	if wrongCode == codeNow(t, pending) || wrongCode == nextCode(t, pending) || wrongCode == codeAt(t, pending, -1) {
		wrongCode = "111111"
	}
	for i := range pwFailLimit {
		addr := fmt.Sprintf("198.51.100.%d:1000", i+1)
		rec := doReqFrom(t, h, "POST", "/api/me/totp/replace/confirm", testToken, `{"code":"`+wrongCode+`"}`, addr)
		if i < pwFailLimit-1 && (rec.Code != http.StatusUnauthorized || errCode(t, rec.Body.String()) != "totp-invalid") {
			t.Fatalf("wrong code %d = %d %s, want 401 totp-invalid", i+1, rec.Code, rec.Body)
		}
	}
	rec := doReqFrom(t, h, "POST", "/api/me/totp/replace/confirm", testToken, `{"code":"`+codeNow(t, pending)+`"}`, "192.0.2.60:1000")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("the right code after %d wrong ones = %d %s, want 429", pwFailLimit, rec.Code, rec.Body)
	}
}

// A second start replaces the pending secret: the first one's code no
// longer confirms, the second one's does.
func TestASecondReplaceOverwritesThePending(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	tok := seedUser(t, um, "alice")
	_, recovery := enableTOTP(t, h, tok, "alice-pw")
	first := startReplace(t, h, tok, "alice-pw", recovery[0])
	second := startReplace(t, h, tok, "alice-pw", recovery[1])
	if first == second {
		t.Fatal("the second start answered the first secret")
	}
	if status, code, _ := confirmReplace(t, h, tok, codeNow(t, first)); status != http.StatusUnauthorized || code != "totp-invalid" {
		t.Fatalf("confirm with the first secret's code = %d %s, want 401 totp-invalid", status, code)
	}
	if status, code, fresh := confirmReplace(t, h, tok, codeNow(t, second)); status != http.StatusOK || len(fresh) == 0 {
		t.Fatalf("confirm with the second secret's code = %d %s", status, code)
	}
}
