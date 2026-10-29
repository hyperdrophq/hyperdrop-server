package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// A guest who signs in to their own account between guesses at the admin's
// password does not reset those guesses: a success clears only the guesses
// made at the account it proved.
func TestSigningInToYourOwnAccountKeepsTheGuessesAtAnother(t *testing.T) {
	h, db, _ := newMultiUserAPI(t)
	seedUser(t, db, "guest")
	const addr = "203.0.113.20:1000"
	for round := range 5 {
		for range pwFailLimit - 1 {
			rec := doReqFrom(t, h, "POST", "/api/auth/login", "", loginBody("admin", "wrong", ""), addr)
			if rec.Code == http.StatusTooManyRequests {
				return
			}
		}
		if rec := doReqFrom(t, h, "POST", "/api/auth/login", "", loginBody("guest", "guest-pw", ""), addr); rec.Code == http.StatusTooManyRequests {
			return
		} else if rec.Code != http.StatusOK {
			t.Fatalf("round %d: guest login = %d %s", round, rec.Code, rec.Body)
		}
	}
	t.Fatal("45 wrong guesses at the admin's password from one address and no lockout")
}

// The holder of one share's password cannot reset the guesses made at
// another share's.
func TestOpeningOneShareKeepsTheGuessesAtAnother(t *testing.T) {
	h := newTestAPI(t)
	known := protectedShare(t, h)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"other","password":"swordfish"}`)
	var cr struct{ ID string }
	unmarshal(t, rec, &cr)
	other := cr.ID
	const addr = "203.0.113.21:1000"
	wrong := url.Values{"password": {"nope"}}.Encode()
	right := url.Values{"password": {"hunter2"}}.Encode()
	for range 5 {
		for range pwFailLimit - 1 {
			if rec := doReqFormFrom(t, h, "/unlock/"+other, wrong, addr); rec.Code == http.StatusTooManyRequests {
				return
			}
		}
		if rec := doReqFormFrom(t, h, "/unlock/"+known, right, addr); rec.Code == http.StatusTooManyRequests {
			return
		}
	}
	t.Fatal("unlocking a known share kept resetting the guesses at another")
}

// A burst sent at once has no more guesses checked than the address has
// left: the right password queued behind the burst is refused, not checked
// after the address was already locked out.
func TestABurstOfLoginsIsCheckedOnlyUpToTheBudget(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	const addr = "203.0.113.22:1000"
	for range cap(bcryptSem) {
		bcryptSem <- struct{}{}
	}
	released := false
	release := func() {
		if !released {
			released = true
			for range cap(bcryptSem) {
				<-bcryptSem
			}
		}
	}
	defer release()
	const burst = 30
	codes := make(chan int, burst)
	var wg sync.WaitGroup
	for range burst {
		wg.Go(func() {
			codes <- doReqFrom(t, h, "POST", "/api/auth/login", "", loginBody("admin", "wrong", ""), addr).Code
		})
	}
	// Everything past the budget is refused at once; the rest wait for a slot.
	refused := 0
	for refused < burst-pwFailLimit {
		select {
		case c := <-codes:
			if c != http.StatusTooManyRequests {
				t.Fatalf("a burst request answered %d before any compare ran", c)
			}
			refused++
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d of the burst were refused", refused)
		}
	}
	if rec := doReqFrom(t, h, "POST", "/api/auth/login", "", loginBody("admin", testAdminPassword, ""), addr); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("the right password behind a full burst = %d %s, want 429", rec.Code, rec.Body)
	}
	release()
	wg.Wait()
	close(codes)
	checked := 0
	for c := range codes {
		if c == http.StatusUnauthorized {
			checked++
		}
	}
	if checked > pwFailLimit-1 {
		t.Fatalf("%d wrong guesses answered 401, the budget allows %d before the block", checked, pwFailLimit-1)
	}
}

// An IPv6 host owns a /64: guesses spread over its addresses are one key.
func TestLoginGuessesFromOneIPv6Slash64CountTogether(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	for i := range pwFailLimit {
		doReqFrom(t, h, "POST", "/api/auth/login", "", loginBody("admin", "wrong", ""), fmt.Sprintf("[2001:db8:5:6::%x]:1000", i+1))
	}
	rec := doReqFrom(t, h, "POST", "/api/auth/login", "", loginBody("admin", testAdminPassword, ""), "[2001:db8:5:6:ffff:ffff:ffff:1]:1000")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("login from the same /64 = %d %s, want 429", rec.Code, rec.Body)
	}
	if rec := doReqFrom(t, h, "POST", "/api/auth/login", "", loginBody("admin", testAdminPassword, ""), "[2001:db8:5:7::1]:1000"); rec.Code != http.StatusOK {
		t.Fatalf("login from another /64 = %d %s, want 200", rec.Code, rec.Body)
	}
}

// Someone holding the password cannot guess codes at sign-in by rotating
// addresses: the codes also count under the account. The owner's password
// alone, without a code guess, still reaches the code question.
func TestLoginCodeGuessesFromManyAddressesLockTheAccountsCodes(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	secret, _ := enableTOTP(t, h, testToken, testAdminPassword)
	wrongCode := "000000"
	if wrongCode == codeNow(t, secret) || wrongCode == nextCode(t, secret) {
		wrongCode = "111111"
	}
	for i := range pwFailLimit {
		doReqFrom(t, h, "POST", "/api/auth/login", "", loginBody("admin", testAdminPassword, wrongCode), fmt.Sprintf("198.51.100.%d:1000", i+1))
	}
	fresh := "192.0.2.50:1000"
	rec := doReqFrom(t, h, "POST", "/api/auth/login", "", loginBody("admin", testAdminPassword, nextCode(t, secret)), fresh)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("a code from a fresh address after %d wrong ones = %d %s, want 429", pwFailLimit, rec.Code, rec.Body)
	}
	// A stranger without the password cannot reach the account key. The
	// wrong codes spent the account's free guesses on its stranger lane, and
	// the refused code above gave back the spaced slot it took (an abandoned
	// attempt checks no wrong guess), so the stranger's wrong password is
	// checked on that slot and the next one meets the lane's short wait,
	// never the codes' block.
	rec = doReqFrom(t, h, "POST", "/api/auth/login", "", loginBody("admin", "wrong", ""), "192.0.2.51:1000")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a wrong password from a fresh address = %d %s, want the lane's spaced slot and 401", rec.Code, rec.Body)
	}
	rec = doReqFrom(t, h, "POST", "/api/auth/login", "", loginBody("admin", "wrong", ""), "192.0.2.52:1000")
	if rec.Code != http.StatusTooManyRequests || errCode(t, rec.Body.String()) != "locked-out" {
		t.Fatalf("the next wrong password from a fresh address = %d %s, want the lane's 429", rec.Code, rec.Body)
	}
	if secs, err := strconv.Atoi(rec.Header().Get("Retry-After")); err != nil || secs > int(laneSpacing/time.Second) {
		t.Fatalf("the next wrong password from a fresh address waits %q, want the lane's %v at most", rec.Header().Get("Retry-After"), laneSpacing)
	}
}

// A lockout's 429 is coded and says when to retry.
func TestALockoutNamesItselfAndWhenToRetry(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	const addr = "203.0.113.23:1000"
	var rec *httptest.ResponseRecorder
	for range pwFailLimit {
		rec = doReqFrom(t, h, "POST", "/api/auth/login", "", loginBody("admin", "wrong", ""), addr)
	}
	if rec.Code != http.StatusTooManyRequests || errCode(t, rec.Body.String()) != "locked-out" {
		t.Fatalf("the blocking guess = %d %s, want 429 locked-out", rec.Code, rec.Body)
	}
	secs, err := strconv.Atoi(rec.Header().Get("Retry-After"))
	if err != nil || secs < int(pwBlockFor/time.Second)-60 {
		t.Fatalf("Retry-After = %q, want about %v", rec.Header().Get("Retry-After"), pwBlockFor)
	}
	rec = doReqFrom(t, h, "PATCH", "/api/me/password", testToken, changePasswordBody(testAdminPassword), addr)
	if rec.Code != http.StatusTooManyRequests || errCode(t, rec.Body.String()) != "locked-out" || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("a step-up from the locked-out address = %d %s, want 429 locked-out with Retry-After", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "try again later") {
		t.Fatalf("the step-up's lockout lost its message: %s", rec.Body)
	}
}

// Confirming an enrollment takes no password, so its wrong codes count on
// the step-up's keys: a stolen token cannot guess the code of an enrollment
// its owner left pending.
func TestWrongEnrollmentCodesCountOnTheLockout(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	rec := doReq(t, h, "POST", "/api/me/totp", testToken, `{"currentPassword":"`+testAdminPassword+`"}`)
	var start struct {
		Secret string `json:"secret"`
	}
	unmarshal(t, rec, &start)
	wrongCode := "000000"
	if wrongCode == codeNow(t, start.Secret) || wrongCode == nextCode(t, start.Secret) || wrongCode == codeAt(t, start.Secret, -1) {
		wrongCode = "111111"
	}
	for i := range pwFailLimit {
		addr := fmt.Sprintf("198.51.100.%d:1000", i+1)
		rec := doReqFrom(t, h, "POST", "/api/me/totp/confirm", testToken, `{"code":"`+wrongCode+`"}`, addr)
		if i < pwFailLimit-1 && (rec.Code != http.StatusUnauthorized || errCode(t, rec.Body.String()) != "totp-invalid") {
			t.Fatalf("wrong code %d = %d %s, want 401 totp-invalid", i+1, rec.Code, rec.Body)
		}
	}
	rec = doReqFrom(t, h, "POST", "/api/me/totp/confirm", testToken, `{"code":"`+codeNow(t, start.Secret)+`"}`, "192.0.2.60:1000")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("the right code after %d wrong ones = %d %s, want 429", pwFailLimit, rec.Code, rec.Body)
	}
}
