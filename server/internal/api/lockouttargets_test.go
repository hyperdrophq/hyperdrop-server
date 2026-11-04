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
	if rec := doReqFrom(t, h, "POST", "/api/auth/login", "", loginBody("admin", testAdminPassword, seededAdminCode(t)), "[2001:db8:5:7::1]:1000"); rec.Code != http.StatusOK {
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
	h, db, _ := newMultiUserAPI(t)
	clearSeededAdminTOTP(t, db)
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

// failFrom sends one wrong sign-in for a name of its own (no lane is shared)
// from remote and returns the status.
func failFrom(t *testing.T, h http.Handler, i int, remote string) int {
	t.Helper()
	return doReqFrom(t, h, "POST", "/api/auth/login", "", loginBody(fmt.Sprintf("nobody%d", i), "wrong", ""), remote).Code
}

// Guesses from the /64s of one /56 count together.
func TestFiftyFailuresAcrossOneSlash56Block(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	for i := range 50 {
		want := http.StatusUnauthorized
		if i == 49 {
			want = http.StatusTooManyRequests // the failure that reaches the limit is answered with the block
		}
		if c := failFrom(t, h, i, fmt.Sprintf("[2001:db8:5:%x::1]:1000", 0x100+i)); c != want {
			t.Fatalf("failure %d = %d, want %d", i+1, c, want)
		}
	}
	if c := failFrom(t, h, 99, "[2001:db8:5:1ff::1]:1000"); c != http.StatusTooManyRequests {
		t.Fatalf("a fresh /64 in the blocked /56 = %d, want 429", c)
	}
	if c := failFrom(t, h, 98, "[2001:db8:5:200::1]:1000"); c != http.StatusUnauthorized {
		t.Fatalf("another /56 in the same /48 = %d, want 401", c)
	}
}

// Guesses from the /56s of one /48 count together.
func TestTwoHundredFailuresAcrossOneSlash48Block(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	for i := range 200 {
		want := http.StatusUnauthorized
		if i == 199 {
			want = http.StatusTooManyRequests // the failure that reaches the limit is answered with the block
		}
		if c := failFrom(t, h, i, fmt.Sprintf("[2001:db8:7:%x::1]:1000", i*256)); c != want {
			t.Fatalf("failure %d = %d, want %d", i+1, c, want)
		}
	}
	if c := failFrom(t, h, 999, "[2001:db8:7:ff00::1]:1000"); c != http.StatusTooManyRequests {
		t.Fatalf("a fresh /56 in the blocked /48 = %d, want 429", c)
	}
	if c := failFrom(t, h, 998, "[2001:db8:8::1]:1000"); c != http.StatusUnauthorized {
		t.Fatalf("another /48 = %d, want 401", c)
	}
}

// fillBcrypt holds every compare slot until the returned release runs.
func fillBcrypt(t *testing.T) func() {
	t.Helper()
	for range cap(bcryptSem) {
		bcryptSem <- struct{}{}
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			for range cap(bcryptSem) {
				<-bcryptSem
			}
		})
	}
	t.Cleanup(release)
	return release
}

func waitBcryptQueued(t *testing.T, want int32) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); bcryptQueued.Load() != want; {
		if time.Now().After(deadline) {
			t.Fatalf("queue holds %d, want %d", bcryptQueued.Load(), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestASlash48HoldsAtMostFourQueuePlaces(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	release := fillBcrypt(t)
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Go(func() { failFrom(t, h, i, fmt.Sprintf("[2001:db8:9:%x::1]:1000", i+1)) })
	}
	waitBcryptQueued(t, 4)
	fifth := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		fifth <- doReqFrom(t, h, "POST", "/api/auth/login", "", loginBody("nobody50", "wrong", ""), "[2001:db8:9:ff::1]:1000")
	}()
	var rec *httptest.ResponseRecorder
	select {
	case rec = <-fifth:
	case <-time.After(3 * time.Second):
		release()
		t.Fatal("the fifth place from one /48 queued instead of being refused")
	}
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != "2" {
		t.Fatalf("fifth place from the /48 = %d Retry-After %q, want 503 and 2", rec.Code, rec.Header().Get("Retry-After"))
	}
	other := make(chan int, 1)
	go func() { other <- failFrom(t, h, 51, "[2001:db8:a::1]:1000") }()
	waitBcryptQueued(t, 5)
	release()
	wg.Wait()
	if c := <-other; c != http.StatusUnauthorized {
		t.Fatalf("another /48 = %d, want to queue and answer 401", c)
	}
}

func TestIPv4HasNoPrefixCap(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	release := fillBcrypt(t)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() { failFrom(t, h, i, fmt.Sprintf("198.51.100.%d:1000", i+1)) })
	}
	waitBcryptQueued(t, 8)
	release()
	wg.Wait()
}
