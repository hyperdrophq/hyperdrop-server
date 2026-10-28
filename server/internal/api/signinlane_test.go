package api

import (
	"fmt"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// accountWait is the body text of a lane's wait on both sign-in routes.
const accountWait = "too many failed sign-ins for this account, try again later"

// laneAddrs answers a run of distinct client addresses, so each guess counts
// once against its own address and only the account's lane gathers them.
func laneAddrs(base int) func() string {
	n := base
	return func() string {
		n++
		return fmt.Sprintf("198.18.%d.%d:4000", n/250, n%250+1)
	}
}

// wrongLogin is one wrong app login at name from addr, answered 401.
func wrongLogin(t *testing.T, f webFixture, name, addr string) {
	t.Helper()
	if rec := doReqFrom(t, f.h, "POST", "/api/auth/login", "", loginBody(name, "wrong", ""), addr); rec.Code != 401 {
		t.Fatalf("wrong login at %s from %s: %d %s, want 401", name, addr, rec.Code, rec.Body)
	}
}

// throttleAlice spends alice's lane: its free guesses and the next spaced
// one, each from its own address, then checks that the next guess waits.
func throttleAlice(t *testing.T, f webFixture, next func() string) {
	t.Helper()
	for range laneFree + 1 {
		wrongLogin(t, f, "alice", next())
	}
	rec := doReqFrom(t, f.h, "POST", "/api/auth/login", "", loginBody("alice", "wrong", ""), next())
	if rec.Code != 429 {
		t.Fatalf("a wrong login past alice's lane: %d %s, want 429", rec.Code, rec.Body)
	}
}

// wantAccountWait checks a lane's answer: 429 locked-out, the account's
// wording, and a Retry-After of laneSpacing at most.
func wantAccountWait(t *testing.T, rec *httptest.ResponseRecorder, what string) {
	t.Helper()
	if rec.Code != 429 || errCode(t, rec.Body.String()) != "locked-out" || !strings.Contains(rec.Body.String(), accountWait) {
		t.Fatalf("%s: %d %s, want 429 locked-out with the account's wait", what, rec.Code, rec.Body)
	}
	after, err := strconv.Atoi(rec.Header().Get("Retry-After"))
	if err != nil || after < 1 || after > int(laneSpacing/time.Second) {
		t.Fatalf("%s: Retry-After = %q, want 1 to 30", what, rec.Header().Get("Retry-After"))
	}
}

// shareOneLane makes six wrong app logins and four wrong web sign-ins at
// alice, then an eleventh wrong app login, each from its own address, and
// answers the next web sign-in and the next app login with the right
// password.
func shareOneLane(t *testing.T) (web, app *httptest.ResponseRecorder) {
	t.Helper()
	f := newWebFixture(t, true)
	next := laneAddrs(0)
	for range 6 {
		wrongLogin(t, f, "alice", next())
	}
	for i := range 4 {
		if rec := f.req(t, "POST", "/api/web/session", "", `{"username":"alice","password":"wrong"}`, from(next())); rec.Code != 401 {
			t.Fatalf("wrong web sign-in %d: %d %s, want 401", i+1, rec.Code, rec.Body)
		}
	}
	wrongLogin(t, f, "alice", next())
	web = f.req(t, "POST", "/api/web/session", "", `{"username":"alice","password":"wrong"}`, from(next()))
	app = doReqFrom(t, f.h, "POST", "/api/auth/login", "", loginBody("alice", "alice-pw", ""), next())
	return web, app
}

func TestTheAppsAndTheWebShareOneLane(t *testing.T) {
	web, app := shareOneLane(t)
	if web.Code != 429 || errCode(t, web.Body.String()) != "locked-out" {
		t.Fatalf("the web sign-in past the shared lane: %d %s, want 429 locked-out", web.Code, web.Body)
	}
	if app.Code != 429 || errCode(t, app.Body.String()) != "locked-out" {
		t.Fatalf("the right password in the app past the shared lane: %d %s, want 429 locked-out", app.Code, app.Body)
	}
}

func TestALaneWaitIsTheAccountsAndShort(t *testing.T) {
	web, app := shareOneLane(t)
	wantAccountWait(t, web, "the web sign-in")
	wantAccountWait(t, app, "the app login")
}

func TestALaneRefusalChecksNoPassword(t *testing.T) {
	f := newWebFixture(t, true)
	next := laneAddrs(0)
	throttleAlice(t, f, next)
	const burst = 20
	addrs := make([]string, burst)
	for i := range addrs {
		addrs[i] = next()
	}
	codes := make([]int, burst)
	var wg sync.WaitGroup
	for i := range burst {
		wg.Go(func() {
			codes[i] = doReqFrom(t, f.h, "POST", "/api/auth/login", "", loginBody("alice", "alice-pw", ""), addrs[i]).Code
		})
	}
	wg.Wait()
	refused, admitted := 0, 0
	for _, c := range codes {
		switch c {
		case 429:
			refused++
		case 200:
			admitted++
		default:
			t.Fatalf("a right-password login in the burst answered %d", c)
		}
	}
	if refused < burst-1 || admitted > 1 {
		t.Fatalf("burst of %d: %d refused, %d admitted, want at least %d refused and at most 1 admitted",
			burst, refused, admitted, burst-1)
	}
}

func TestAnotherAccountIsNotSlowedByALane(t *testing.T) {
	f := newWebFixture(t, true)
	next := laneAddrs(0)
	throttleAlice(t, f, next)
	if rec := doReqFrom(t, f.h, "POST", "/api/auth/login", "", loginBody("admin", testAdminPassword, ""), next()); rec.Code != 200 {
		t.Fatalf("the admin's login while alice's lane waits: %d %s, want 200", rec.Code, rec.Body)
	}
	if rec := f.req(t, "POST", "/api/web/session", "", `{"username":"admin","password":"`+testAdminPassword+`"}`, from(next())); rec.Code != 200 {
		t.Fatalf("the admin's web sign-in while alice's lane waits: %d %s, want 200", rec.Code, rec.Body)
	}
}

// A real name and a name no account has get the same answers in a full map
// of lanes, so the lane does not tell which names exist.
func TestRealAndUnknownNamesWaitAlike(t *testing.T) {
	f := newWebFixture(t, true)
	l := f.hd.limits.login
	now := time.Now()
	l.mu.Lock()
	for i := len(l.lanes); i < laneMaxKeys; i++ {
		l.lanes[signInLaneKey(fmt.Sprintf("throwaway%d", i))] = &laneState{fails: 1, lastFail: now}
	}
	l.mu.Unlock()

	type answer struct {
		code int
		body string
	}
	run := func(name string, next func() string) ([]answer, string) {
		var got []answer
		var last *httptest.ResponseRecorder
		for range laneFree + 2 {
			last = doReqFrom(t, f.h, "POST", "/api/auth/login", "", loginBody(name, "wrong", ""), next())
			got = append(got, answer{last.Code, last.Body.String()})
		}
		return got, last.Header().Get("Retry-After")
	}
	alice, aliceAfter := run("alice", laneAddrs(0))
	nobody, nobodyAfter := run("nobody", laneAddrs(1000))
	if fmt.Sprint(alice) != fmt.Sprint(nobody) {
		t.Fatalf("alice and nobody answered differently:\n%v\n%v", alice, nobody)
	}
	if last := alice[len(alice)-1]; last.code != 429 {
		t.Fatalf("the twelfth wrong login: %d %s, want 429", last.code, last.body)
	}
	for _, after := range []string{aliceAfter, nobodyAfter} {
		if n, err := strconv.Atoi(after); err != nil || n < 29 || n > 30 {
			t.Fatalf("Retry-After = %q, want 29 or 30", after)
		}
	}
}

// strongPassword is a chosen password the common-password list does not
// hold.
const strongPassword = "violet-harbor-lantern-58"

func TestAnAdminPasswordResetFreesTheLane(t *testing.T) {
	f := newWebFixture(t, true)
	next := laneAddrs(0)
	throttleAlice(t, f, next)
	if rec := doReqFrom(t, f.h, "PATCH", "/api/users/alice", testToken, `{"password":"`+strongPassword+`"}`, next()); rec.Code != 200 {
		t.Fatalf("the admin setting alice's password: %d %s", rec.Code, rec.Body)
	}
	if rec := doReqFrom(t, f.h, "POST", "/api/auth/login", "", loginBody("alice", strongPassword, ""), next()); rec.Code != 200 {
		t.Fatalf("alice's new password after the admin set it: %d %s, want 200", rec.Code, rec.Body)
	}
}

func TestAPasswordChangeFreesTheLane(t *testing.T) {
	f := newWebFixture(t, true)
	next := laneAddrs(0)
	throttleAlice(t, f, next)
	body := `{"password":"` + strongPassword + `","currentPassword":"alice-pw"}`
	if rec := doReqFrom(t, f.h, "PATCH", "/api/me/password", f.aliceDevice, body, next()); rec.Code != 200 {
		t.Fatalf("alice changing her password: %d %s", rec.Code, rec.Body)
	}
	if rec := doReqFrom(t, f.h, "POST", "/api/auth/login", "", loginBody("alice", strongPassword, ""), next()); rec.Code != 200 {
		t.Fatalf("alice's new password after she changed it: %d %s, want 200", rec.Code, rec.Body)
	}
}

// An account with a second factor, past its lane's free guesses, signs in
// with one spaced slot: the password-only leg answers totp-required and gives
// the slot back, so the leg with the code is admitted at once.
func TestASecondFactorSignInPastTheFreeGuessesTakesOneSlot(t *testing.T) {
	for _, web := range []bool{false, true} {
		t.Run(fmt.Sprintf("web=%v", web), func(t *testing.T) {
			f := newWebFixture(t, true)
			secret, _ := enableTOTP(t, f.h, f.aliceDevice, "alice-pw")
			next := laneAddrs(0)
			for range laneFree {
				wrongLogin(t, f, "alice", next())
			}
			addr := next()
			send := func(code string) *httptest.ResponseRecorder {
				if web {
					return f.req(t, "POST", "/api/web/session", "", loginBody("alice", "alice-pw", code), from(addr))
				}
				return doReqFrom(t, f.h, "POST", "/api/auth/login", "", loginBody("alice", "alice-pw", code), addr)
			}
			if rec := send(""); rec.Code != 401 || errCode(t, rec.Body.String()) != "totp-required" {
				t.Fatalf("the password-only leg: %d %s, want 401 totp-required", rec.Code, rec.Body)
			}
			if rec := send(nextCode(t, secret)); rec.Code != 200 {
				t.Fatalf("the leg with the code: %d %s, want 200", rec.Code, rec.Body)
			}
		})
	}
}

func TestTheStepUpNeverReadsTheSignInLane(t *testing.T) {
	f := newWebFixture(t, true)
	next := laneAddrs(0)
	throttleAlice(t, f, next)
	if rec := doReqFrom(t, f.h, "POST", "/api/me/totp", f.aliceDevice, `{"currentPassword":"alice-pw"}`, next()); rec.Code != 200 {
		t.Fatalf("alice's step-up while her lane waits: %d %s, want 200", rec.Code, rec.Body)
	}
}
