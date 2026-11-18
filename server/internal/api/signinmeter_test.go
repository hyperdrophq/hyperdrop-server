package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A correct password costs a bcrypt compare and a durable commit, so an account
// cannot run them without limit, whoever holds its password.
func TestCorrectPasswordsAreMeteredPerAccount(t *testing.T) {
	b := testBackend(t)
	hh := newHandler(b, "test", testDomain(t), nil, Deployment{})
	h := hh.routes()
	now := time.Now()
	hh.signInMeter.now = func() time.Time { return now }
	seedUser(t, b.DB, "bob")
	seedUser(t, b.DB, "amy")
	login := func(name, password string) (int, string) {
		body, _ := json.Marshal(map[string]string{"username": name, "password": password, "label": "t"})
		rec := doReqBare(t, h, "POST", "/api/auth/login", "", string(body))
		return rec.Code, rec.Body.String()
	}
	for i := range signInMeterMax {
		if code, body := login("bob", "bob-pw"); code != 200 {
			t.Fatalf("sign-in %d = %d %s", i, code, body)
		}
	}
	if code, body := login("bob", "bob-pw"); code != 429 || errCode(t, body) != "locked-out" || strings.Contains(body, "failed") {
		t.Fatalf("past the meter = %d %s, want 429 locked-out naming no failure", code, body)
	}
	if code, body := login("amy", "amy-pw"); code != 200 {
		t.Fatalf("another account = %d %s", code, body)
	}
	now = now.Add(signInMeterWindow + time.Second)
	if code, body := login("bob", "bob-pw"); code != 200 {
		t.Fatalf("after the window = %d %s", code, body)
	}
}

// The meter counts the compare, not the finished sign-in: a caller holding the
// password of an account with a second factor never finishes one.
func TestAMissingCodeStillSpendsTheMeter(t *testing.T) {
	b := testBackend(t)
	hh := newHandler(b, "test", testDomain(t), nil, Deployment{})
	h := hh.routes()
	seedUser(t, b.DB, "bob")
	confirmTOTPInStore(t, b.DB, "bob")
	body, _ := json.Marshal(map[string]string{"username": "bob", "password": "bob-pw"})
	for range signInMeterMax {
		doReqBare(t, h, "POST", "/api/auth/login", "", string(body))
	}
	rec := doReqBare(t, h, "POST", "/api/auth/login", "", string(body))
	if rec.Code != 429 || errCode(t, rec.Body.String()) != "locked-out" {
		t.Fatalf("= %d %s, want 429 locked-out", rec.Code, rec.Body)
	}
}

// A wrong password never spends the meter, or a stranger could lock the owner
// out by guessing; those guesses have their own lane.
func TestAWrongPasswordDoesNotSpendTheMeter(t *testing.T) {
	b := testBackend(t)
	hh := newHandler(b, "test", testDomain(t), nil, Deployment{})
	seedUser(t, b.DB, "bob")
	body, _ := json.Marshal(map[string]string{"username": "bob", "password": "wrong-share"})
	if rec := doReqBare(t, hh.routes(), "POST", "/api/auth/login", "", string(body)); rec.Code != 401 {
		t.Fatalf("= %d %s", rec.Code, rec.Body)
	}
	if got := len(hh.signInMeter.accounts); got != 0 {
		t.Fatalf("a wrong password spent the meter of %d accounts", got)
	}
}

// A step-up runs the same compare, and on an account with a second factor a missing
// code counts on no lockout, so the meter is what bounds it.
func TestAStepUpSpendsTheMeter(t *testing.T) {
	b := testBackend(t)
	hh := newHandler(b, "test", testDomain(t), nil, Deployment{})
	h := hh.routes()
	tok := seedUser(t, b.DB, "bob")
	confirmTOTPInStore(t, b.DB, "bob")
	stepUp := func() *httptest.ResponseRecorder {
		return doReqBare(t, h, "POST", "/api/me/device-links", tok, `{"currentPassword":"bob-pw"}`)
	}
	for i := range signInMeterMax {
		if rec := stepUp(); rec.Code == 429 {
			t.Fatalf("step-up %d refused early: %s", i, rec.Body)
		}
	}
	if rec := stepUp(); rec.Code != 429 || errCode(t, rec.Body.String()) != "locked-out" {
		t.Fatalf("past the meter = %d %s, want 429 locked-out", rec.Code, rec.Body)
	}
	body, _ := json.Marshal(map[string]string{"username": "bob", "password": "bob-pw"})
	if rec := doReqBare(t, h, "POST", "/api/auth/login", "", string(body)); rec.Code != 429 {
		t.Fatalf("a sign-in past the meter = %d %s, want 429", rec.Code, rec.Body)
	}
}

// A wrong current password has its lockout, and spends nothing.
func TestAWrongStepUpPasswordDoesNotSpendTheMeter(t *testing.T) {
	b := testBackend(t)
	hh := newHandler(b, "test", testDomain(t), nil, Deployment{})
	tok := seedUser(t, b.DB, "bob")
	rec := doReqBare(t, hh.routes(), "POST", "/api/me/device-links", tok, `{"currentPassword":"wrong"}`)
	if rec.Code != 401 {
		t.Fatalf("= %d %s, want 401", rec.Code, rec.Body)
	}
	if got := len(hh.signInMeter.accounts); got != 0 {
		t.Fatalf("a wrong password spent the meter of %d accounts", got)
	}
}
