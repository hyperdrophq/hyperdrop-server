package api

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

type createdWithInvite struct {
	Password    string `json:"password"`
	InviteToken string `json:"inviteToken"`
}

func spendInvite(t *testing.T, h http.Handler, token string) (string, int, string) {
	t.Helper()
	rec := doReq(t, h, "POST", "/api/auth/invite", "", fmt.Sprintf(`{"token":%q,"label":"laptop"}`, token))
	if rec.Code != 200 {
		return "", rec.Code, rec.Body.String()
	}
	var out struct {
		Token string `json:"token"`
	}
	unmarshal(t, rec, &out)
	return out.Token, rec.Code, rec.Body.String()
}

// Creating an account answers a one-time invite beside the password: the
// first device that presents it signs in as the account, and the invite
// is spent by that. The password stays the lasting credential.
func TestCreatingAUserMintsAOneTimeInvite(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	rec := doReq(t, h, "POST", "/api/users", testToken, `{"username":"carol","quotaBytes":1024}`)
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var out createdWithInvite
	unmarshal(t, rec, &out)
	if !strings.HasPrefix(out.InviteToken, "hd_i_") {
		t.Fatalf("inviteToken: %q", out.InviteToken)
	}
	token, code, body := spendInvite(t, h, out.InviteToken)
	if code != 200 || !strings.HasPrefix(token, "hd_u_") {
		t.Fatalf("spend: %d %s", code, body)
	}
	if rec := doReq(t, h, "GET", "/api/me", token, ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"carol"`) {
		t.Fatalf("the device token is not carol's: %d %s", rec.Code, rec.Body)
	}
	if _, code, body := spendInvite(t, h, out.InviteToken); code != 404 || !strings.Contains(body, `"invite-invalid"`) {
		t.Fatalf("second spend: %d %s", code, body)
	}
	if _, code := login(t, h, "carol", out.Password); code != 200 {
		t.Fatalf("the password still signs in after the invite: %d", code)
	}
}

// A chosen password gets an invite too: the admin knows the password, the
// invited person only needs the link.
func TestAChosenPasswordStillGetsAnInvite(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	rec := doReq(t, h, "POST", "/api/users", testToken, `{"username":"carol","password":"chosen-one","quotaBytes":1024}`)
	var out createdWithInvite
	unmarshal(t, rec, &out)
	if out.InviteToken == "" || out.Password != "" {
		t.Fatalf("out: %+v", out)
	}
}

func TestAPasswordResetMintsAFreshInvite(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	rec := doReq(t, h, "POST", "/api/users", testToken, `{"username":"carol","quotaBytes":1024}`)
	var first createdWithInvite
	unmarshal(t, rec, &first)
	rec = doReq(t, h, "PATCH", "/api/users/carol", testToken, `{"resetPassword":true}`)
	if rec.Code != 200 {
		t.Fatalf("reset: %d %s", rec.Code, rec.Body)
	}
	var second createdWithInvite
	unmarshal(t, rec, &second)
	if second.InviteToken == "" || second.InviteToken == first.InviteToken {
		t.Fatalf("reset invite: %q", second.InviteToken)
	}
	if _, code, _ := spendInvite(t, h, first.InviteToken); code != 404 {
		t.Fatalf("the invite from before the reset still spends: %d", code)
	}
	if _, code, body := spendInvite(t, h, second.InviteToken); code != 200 {
		t.Fatalf("the reset's invite: %d %s", code, body)
	}
}

func TestSpendingAnInviteIsRateLimitedLikeLogin(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	var last int
	for i := 0; i < 12; i++ {
		_, last, _ = spendInvite(t, h, fmt.Sprintf("hd_i_%032d", i))
	}
	if last != 429 {
		t.Fatalf("after twelve bad invites: %d, want 429", last)
	}
}

func TestSpendingAnInviteNeedsAToken(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	rec := doReq(t, h, "POST", "/api/auth/invite", "", `{}`)
	if rec.Code != 400 {
		t.Fatalf("empty: %d", rec.Code)
	}
}
