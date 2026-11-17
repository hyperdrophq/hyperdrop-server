package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/metadb"
)

// Signing a computer in phone first: the computer shows a hddesk2 code
// carrying a one-time public key, a signed-in phone tells its server to
// expect a computer holding that key, the computer arrives at the address
// it was told and proves the key, and the arrival joins the claimed state
// of the hddesk1 flow: the phone approves with the number, the computer's
// poll collects the token.

type desktopExpectOut struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type desktopArriveOut struct {
	ID         string `json:"id"`
	PollSecret string `json:"pollSecret"`
	Number     int    `json:"number"`
}

type desktopArrivalOut struct {
	State       string `json:"state"`
	ID          string `json:"id"`
	Label       string `json:"label"`
	Platform    string `json:"platform"`
	Address     string `json:"address"`
	SameNetwork bool   `json:"sameNetwork"`
}

// computerKey is the key pair a computer makes for one attempt, its public
// half as the hddesk2 code carries it.
type computerKey struct {
	pub  string
	priv ed25519.PrivateKey
}

func newComputerKey(t *testing.T) computerKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return computerKey{pub: base64.RawURLEncoding.EncodeToString(pub), priv: priv}
}

// proof is the arrival's signature for serverID.
func (k computerKey) proof(serverID string) string {
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(k.priv, []byte(desktopArriveMessage(serverID, k.pub))))
}

func expectReq(t *testing.T, f webFixture, token string, k computerKey, label string, edit ...func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"key":"` + k.pub + `","label":` + strconv.Quote(label) + `,"platform":"macos"}`
	return approverReq(t, f, "/api/me/desktop-sign-ins/expect", token, body, edit...)
}

func expectDesktop(t *testing.T, f webFixture, token string, k computerKey, label string) desktopExpectOut {
	t.Helper()
	rec := expectReq(t, f, token, k, label)
	if rec.Code != 201 {
		t.Fatalf("expect: %d %s", rec.Code, rec.Body)
	}
	var out desktopExpectOut
	unmarshal(t, rec, &out)
	return out
}

func arriveReq(t *testing.T, f webFixture, key, proof string, edit ...func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	return deskReq(t, f, "/api/auth/desktop-sign-in/arrive", `{"key":"`+key+`","proof":"`+proof+`"}`, edit...)
}

func arriveDesktop(t *testing.T, f webFixture, k computerKey) desktopArriveOut {
	t.Helper()
	rec := arriveReq(t, f, k.pub, k.proof(f.hd.fs.ServerID()))
	if rec.Code != 200 {
		t.Fatalf("arrive: %d %s", rec.Code, rec.Body)
	}
	var out desktopArriveOut
	unmarshal(t, rec, &out)
	return out
}

// arrivalReq is the phone reading its expected request.
func arrivalReq(t *testing.T, f webFixture, token, id string, edit ...func(*http.Request)) (*httptest.ResponseRecorder, desktopArrivalOut) {
	t.Helper()
	r := httptest.NewRequest("GET", "/api/me/desktop-sign-ins/"+id, nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("X-HyperDrop-Client", "2.0.0 ios")
	for _, e := range edit {
		e(r)
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)
	var out desktopArrivalOut
	if rec.Code == 200 || rec.Code == 202 {
		unmarshal(t, rec, &out)
	}
	return rec, out
}

func wantNoExpected(t *testing.T, what string, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != 404 || errCode(t, rec.Body.String()) != "no-expected-sign-in" {
		t.Fatalf("%s: %d %s, want 404 no-expected-sign-in", what, rec.Code, rec.Body)
	}
}

func TestAnExpectedComputerArrivesAndIsApproved(t *testing.T) {
	f := newWebFixture(t, true)
	k := newComputerKey(t)
	start := time.Now()
	exp := expectDesktop(t, f, f.aliceDevice, k, "Work\u202e Mac")
	if exp.ID == "" {
		t.Fatalf("expect %+v", exp)
	}
	if d := exp.ExpiresAt.Sub(start); d < 5*time.Minute-5*time.Second || d > 5*time.Minute+5*time.Second {
		t.Fatalf("expiresAt is %v from now, want 5 minutes", d)
	}
	if rec, out := arrivalReq(t, f, f.aliceDevice, exp.ID); rec.Code != 202 || out.State != "expected" {
		t.Fatalf("before the arrival: %d %s, want 202 expected", rec.Code, rec.Body)
	}

	arr := arriveDesktop(t, f, k)
	if arr.ID != exp.ID || len(arr.PollSecret) != 43 || arr.Number < 10 || arr.Number > 99 {
		t.Fatalf("arrive %+v", arr)
	}
	s := desktopSignInOut{ID: arr.ID, PollSecret: arr.PollSecret}
	if rec, out := pollDesktop(t, f, s); rec.Code != 202 || out.State != "claimed" || out.Number != arr.Number {
		t.Fatalf("poll after the arrival: %d %s", rec.Code, rec.Body)
	}
	rec, got := arrivalReq(t, f, f.aliceDevice, exp.ID)
	if rec.Code != 200 || got.State != "arrived" || got.ID != exp.ID || got.Label != "Work Mac" ||
		got.Platform != "macos" || got.Address != "198.51.100.20" {
		t.Fatalf("the arrival: %d %s", rec.Code, rec.Body)
	}
	wantNoNumber(t, rec)

	if rec := approveDesktop(t, f, f.aliceDevice, exp.ID, arr.Number, ""); rec.Code != 204 {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body)
	}
	rec, out := pollDesktop(t, f, s)
	if rec.Code != 200 || !strings.HasPrefix(out.Token, "hd_u_") || out.User.Username != "alice" {
		t.Fatalf("poll after the approval: %d %s", rec.Code, rec.Body)
	}
	u, err := f.db.User("alice")
	if err != nil {
		t.Fatal(err)
	}
	tok := tokenNamed(u, metadb.TokenHash(out.Token))
	if tok.SignInMethod != metadb.SignInMethodPhone || tok.ClientPlatform != "macos" || tok.Label != "Phone sign-in: Work Mac" {
		t.Fatalf("the computer's token row %+v", tok)
	}
	if again, _ := pollDesktop(t, f, s); again.Code != 410 {
		t.Fatalf("a second poll: %d, want 410", again.Code)
	}
	// The key is spent: arriving with it again finds nothing expected.
	wantNoExpected(t, "a second arrival", arriveReq(t, f, k.pub, k.proof(f.hd.fs.ServerID())))
}

// A proof made by another key, over another server's identity or over
// another key's text is refused as if nothing were expected, and leaves the
// expectation for the computer that holds the key.
func TestArriveWithoutTheKeysProofIsRefused(t *testing.T) {
	f := newWebFixture(t, true)
	k := newComputerKey(t)
	exp := expectDesktop(t, f, f.aliceDevice, k, "Mac")
	other := newComputerKey(t)
	id := f.hd.fs.ServerID()
	for name, proof := range map[string]string{
		"another key's signature":        other.proof(id),
		"a signature for another server": k.proof("srv-elsewhere"),
		"a signature over another key": base64.RawURLEncoding.EncodeToString(
			ed25519.Sign(k.priv, []byte(desktopArriveMessage(id, other.pub)))),
		"no proof":         "",
		"a short proof":    "AAAA",
		"not base64":       "!!!!",
		"the key as proof": k.pub,
	} {
		wantNoExpected(t, name, arriveReq(t, f, k.pub, proof))
	}
	if rec, out := arrivalReq(t, f, f.aliceDevice, exp.ID); rec.Code != 202 || out.State != "expected" {
		t.Fatalf("after the refusals: %d %s, want still expected", rec.Code, rec.Body)
	}
	arriveDesktop(t, f, k)
}

// The refusal is one answer whatever the reason: a key nobody expects, an
// expectation that ran out, one already arrived, one the phone cancelled.
func TestArriveAtAServerExpectingNoSuchKeyIsNoExpectedSignIn(t *testing.T) {
	f := newWebFixture(t, true)
	now := time.Now()
	f.hd.desktopSignIns.clock = func() time.Time { return now }
	id := f.hd.fs.ServerID()
	var bodies []string
	refuse := func(name string, k computerKey) {
		t.Helper()
		rec := arriveReq(t, f, k.pub, k.proof(id))
		wantNoExpected(t, name, rec)
		bodies = append(bodies, rec.Body.String())
	}

	refuse("an unknown key", newComputerKey(t))

	lapsed := newComputerKey(t)
	expectDesktop(t, f, f.aliceDevice, lapsed, "Mac")
	now = now.Add(desktopExpectFor)
	refuse("an expectation that ran out", lapsed)

	used := newComputerKey(t)
	expectDesktop(t, f, f.aliceDevice, used, "Mac")
	arriveDesktop(t, f, used)
	refuse("a key already arrived", used)

	denied := newComputerKey(t)
	exp := expectDesktop(t, f, f.aliceDevice, denied, "Mac")
	if rec := approverReq(t, f, "/api/me/desktop-sign-ins/"+exp.ID+"/deny", f.aliceDevice, `{}`); rec.Code != 204 {
		t.Fatalf("deny before the arrival: %d %s", rec.Code, rec.Body)
	}
	refuse("an expectation the phone cancelled", denied)

	for _, b := range bodies[1:] {
		if b != bodies[0] {
			t.Fatalf("the refusals differ:\n%s\n%s", bodies[0], b)
		}
	}
}

// The expect asks of the phone everything the hddesk1 claim asks.
func TestExpectAppliesTheClaimsRules(t *testing.T) {
	t.Run("an administrator's account", func(t *testing.T) {
		f := newWebFixture(t, true)
		wantRefusal(t, "an admin's expect", expectReq(t, f, testToken, newComputerKey(t), "Mac"), 403, "desktop-sign-in-admin")
	})
	t.Run("a computer signed in by phone", func(t *testing.T) {
		f := newWebFixture(t, true)
		wantRefusal(t, "a computer's expect", expectReq(t, f, phoneSignedIn(t, f), newComputerKey(t), "Mac"), 403, "desktop-sign-in-refused")
	})
	t.Run("the daily cap", func(t *testing.T) {
		f := newWebFixture(t, true)
		for range metadb.DesktopSignInsPerDay {
			phoneSignedIn(t, f)
		}
		wantRefusal(t, "a fourth expect", expectReq(t, f, f.aliceDevice, newComputerKey(t), "Mac"), 429, "desktop-sign-in-limit")
	})
	t.Run("the switch off", func(t *testing.T) {
		f := newWebFixture(t, true)
		k := newComputerKey(t)
		expectDesktop(t, f, f.aliceDevice, k, "Mac")
		if err := f.hd.setDesktopSwitch(false); err != nil {
			t.Fatal(err)
		}
		wantRefusal(t, "an expect while off", expectReq(t, f, f.aliceDevice, newComputerKey(t), "Mac"), 403, "desktop-sign-in-off")
		wantRefusal(t, "an arrival while off", arriveReq(t, f, k.pub, k.proof(f.hd.fs.ServerID())), 403, "desktop-sign-in-off")
		if err := f.hd.setDesktopSwitch(true); err != nil {
			t.Fatal(err)
		}
		wantNoExpected(t, "the expectation the switch dropped", arriveReq(t, f, k.pub, k.proof(f.hd.fs.ServerID())))
	})
	t.Run("a token younger than a day", func(t *testing.T) {
		withFreshDeviceRule(t)
		f := newWebFixture(t, true)
		wantRefusal(t, "a fresh device's expect", expectReq(t, f, f.aliceDevice, newComputerKey(t), "Mac"), 403, "device-too-new")
		oldDevice(t, f, f.aliceDevice)
		expectDesktop(t, f, f.aliceDevice, newComputerKey(t), "Mac")
	})
	t.Run("the client header", func(t *testing.T) {
		f := newWebFixture(t, true)
		wantRefusal(t, "no header", expectReq(t, f, f.aliceDevice, newComputerKey(t), "Mac", header("X-HyperDrop-Client", "")), 400, "client-required")
	})
	t.Run("a malformed key or platform", func(t *testing.T) {
		f := newWebFixture(t, true)
		for name, body := range map[string]string{
			"no key":         `{"key":"","label":"Mac","platform":"macos"}`,
			"a short key":    `{"key":"AAAA","label":"Mac","platform":"macos"}`,
			"a phone":        `{"key":"` + newComputerKey(t).pub + `","label":"Mac","platform":"ios"}`,
			"no platform":    `{"key":"` + newComputerKey(t).pub + `","label":"Mac","platform":""}`,
			"an extra field": `{"key":"` + newComputerKey(t).pub + `","label":"Mac","platform":"macos","x":1}`,
		} {
			if rec := approverReq(t, f, "/api/me/desktop-sign-ins/expect", f.aliceDevice, body); rec.Code != 400 {
				t.Fatalf("%s: %d %s, want 400", name, rec.Code, rec.Body)
			}
		}
	})
	// One key is one spelling: a key whose unused trailing bits are set
	// decodes to the same bytes, and is refused, so it can never stand for
	// a key already expected.
	t.Run("a key spelled another way", func(t *testing.T) {
		f := newWebFixture(t, true)
		k := newComputerKey(t)
		alt := otherSpelling(t, k.pub)
		if b1, _ := base64.RawURLEncoding.DecodeString(k.pub); string(b1) != mustDecodeLoose(t, alt) {
			t.Fatal("the two spellings are not one key")
		}
		expectDesktop(t, f, f.aliceDevice, k, "Mac")
		body := `{"key":"` + alt + `","label":"Mac","platform":"macos"}`
		wantRefusal(t, "the other spelling", approverReq(t, f, "/api/me/desktop-sign-ins/expect", f.aliceDevice, body), 400, "invalid")
		wantNoExpected(t, "an arrival with the other spelling", arriveReq(t, f, alt, k.proof(f.hd.fs.ServerID())))
		arriveDesktop(t, f, k)
	})
	// An admin's account promoted between the expect and the poll mints
	// nothing: the mint asks again.
	t.Run("the mint asks again", func(t *testing.T) {
		f := newWebFixture(t, true)
		k := newComputerKey(t)
		exp := expectDesktop(t, f, f.aliceDevice, k, "Mac")
		arr := arriveDesktop(t, f, k)
		if rec := approveDesktop(t, f, f.aliceDevice, exp.ID, arr.Number, ""); rec.Code != 204 {
			t.Fatalf("approve: %d %s", rec.Code, rec.Body)
		}
		admin := metadb.RoleAdmin
		if _, err := f.db.UpdateUser("alice", metadb.Settings{Role: &admin}); err != nil {
			t.Fatal(err)
		}
		rec, _ := pollDesktop(t, f, desktopSignInOut{ID: arr.ID, PollSecret: arr.PollSecret})
		wantRefusal(t, "poll of a promoted account", rec, 403, "desktop-sign-in-admin")
	})
}

// wantNoNumber fails when an answer to the phone names the number the
// computer shows: the person types it.
func wantNoNumber(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if strings.Contains(rec.Body.String(), "number") {
		t.Fatalf("the phone's read carries the number: %s", rec.Body)
	}
}

// otherSpelling is key with its last character's unused bits set: the
// same 32 bytes under a loose decoder.
func otherSpelling(t *testing.T, key string) string {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, key[len(key)-1])
	if last < 0 || last&3 != 0 {
		t.Fatalf("key %q does not end on a canonical character", key)
	}
	return key[:len(key)-1] + string(alphabet[last|1])
}

func mustDecodeLoose(t *testing.T, s string) string {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A key two phones expected stays burned: a third expect of it, from either
// account or a third, starts nothing, and the computer holding it signs in
// nowhere, so whoever saw the code cannot expect it again after the burn and
// own the expectation. Both orders: the owner first, then whoever saw the
// code, and the other way round.
func TestABurnedKeyStaysBurned(t *testing.T) {
	for _, ownerFirst := range []bool{true, false} {
		name := "the owner first"
		if !ownerFirst {
			name = "the attacker first"
		}
		t.Run(name, func(t *testing.T) {
			f := newWebFixture(t, true)
			now := time.Now()
			f.hd.desktopSignIns.clock = func() time.Time { return now }
			owner, attacker := f.aliceDevice, seedUser(t, f.db, "mallory")
			carol := seedUser(t, f.db, "carol")
			k := newComputerKey(t)
			first, second := owner, attacker
			if !ownerFirst {
				first, second = attacker, owner
			}
			exp := expectDesktop(t, f, first, k, "Mac")
			wantDesktopExpired(t, "the second expect", expectReq(t, f, second, k, "Mac"))
			for who, tok := range map[string]string{"the owner": owner, "the attacker": attacker, "a third account": carol} {
				wantDesktopExpired(t, who+"'s third expect", expectReq(t, f, tok, k, "Mac"))
			}
			rec, _ := arrivalReq(t, f, first, exp.ID)
			wantDesktopExpired(t, "the first expectation after the burn", rec)
			rec = arriveReq(t, f, k.pub, k.proof(f.hd.fs.ServerID()))
			wantNoExpected(t, "the computer's arrival", rec)
			// Still burned just before burnedKeyFor, forgotten after it.
			now = now.Add(burnedKeyFor - time.Second)
			wantDesktopExpired(t, "an expect just before the burn ends", expectReq(t, f, attacker, k, "Mac"))
			now = now.Add(time.Second)
			expectDesktop(t, f, attacker, k, "Mac")
			// No account's phone signed a computer in.
			for acct, tok := range map[string]string{"alice": owner, "mallory": attacker, "carol": carol} {
				u, err := f.db.User(acct)
				if err != nil {
					t.Fatal(err)
				}
				if n, _ := f.db.SignInsApprovedSince(tokenNamed(u, metadb.TokenHash(tok)).ID, time.Now().Add(-time.Hour)); n != 0 {
					t.Fatalf("%s signed a computer in", acct)
				}
			}
		})
	}
}

// Burned keys count against the book's cap with the live requests.
func TestBurnedKeysCountAgainstTheCap(t *testing.T) {
	now := time.Now()
	b := webSignIns{burned: map[string]burnedKey{}}
	for i := range webSignInMax {
		b.burned[strconv.Itoa(i)] = burnedKey{until: now.Add(time.Hour), account: "u" + strconv.Itoa(i)}
	}
	if _, _, ok, err := b.expect("fresh", "Mac", "macos", "alice", "t1", now); ok || err != errWebSignInsFull {
		t.Fatalf("an expect with the book full of burned keys: ok %v err %v", ok, err)
	}
}

// One account expecting fresh keys twice each burns only its own share:
// past burnedPerAccount live burned keys its expects answer 429
// desktop-sign-in-attempts, the book holds no more of its keys, and another
// account's expect still works. Its share frees itself as the keys are
// forgotten.
func TestOneAccountCannotFloodTheBurnedKeys(t *testing.T) {
	f := newWebFixture(t, true)
	now := time.Now()
	f.hd.desktopSignIns.clock = func() time.Time { return now }
	mallory := seedUser(t, f.db, "mallory")
	for range burnedPerAccount {
		k := newComputerKey(t)
		expectDesktop(t, f, mallory, k, "Mac")
		wantDesktopExpired(t, "mallory's second expect", expectReq(t, f, mallory, k, "Mac"))
	}
	for range 3 {
		wantRefusal(t, "an expect past the share", expectReq(t, f, mallory, newComputerKey(t), "Mac"), 429, "desktop-sign-in-attempts")
	}
	b := &f.hd.desktopSignIns
	b.mu.Lock()
	held, total := b.burnedBy("mallory"), len(b.burned)+len(b.m)
	b.mu.Unlock()
	if held != burnedPerAccount || total != burnedPerAccount {
		t.Fatalf("mallory holds %d burned keys, the book %d entries; want %d each", held, total, burnedPerAccount)
	}
	k := newComputerKey(t)
	expectDesktop(t, f, f.aliceDevice, k, "Mac")
	arriveDesktop(t, f, k)
	now = now.Add(burnedKeyFor)
	expectDesktop(t, f, mallory, newComputerKey(t), "Mac")
}

// Two accounts taking turns cannot grow the book either: m2 expects a key,
// mallory expects it too and burns it, charged to mallory. Once mallory is
// at its share it is refused before it can burn m2's request, m2's own
// burns then fill m2's share, and the book stops growing at the two shares
// and m2's one live request.
func TestTwoAccountsTakingTurnsCannotGrowTheBook(t *testing.T) {
	var b webSignIns
	now := time.Now()
	sizes := map[int]bool{}
	for i := range 2000 {
		key := strconv.Itoa(i)
		_, _, _, _ = b.expect(key, "Mac", "macos", "m2", "t2", now)
		_, _, ok, err := b.expect(key, "Mac", "macos", "mallory", "t1", now)
		if ok {
			t.Fatalf("round %d: mallory's second expect of the key started a request", i)
		}
		if i > 100 && err != errTooManyExpects {
			t.Fatalf("round %d: mallory's expect answered %v, want errTooManyExpects", i, err)
		}
		if i > 100 {
			sizes[len(b.m)+len(b.burned)] = true
		}
	}
	mallory, m2 := b.burnedBy("mallory"), b.burnedBy("m2")
	if mallory > burnedPerAccount+1 || m2 > burnedPerAccount+1 || len(sizes) != 1 {
		t.Fatalf("mallory charged %d, m2 charged %d, book sizes %v", mallory, m2, sizes)
	}
	for size := range sizes {
		if size > 2*(burnedPerAccount+1)+1 {
			t.Fatalf("the book holds %d", size)
		}
	}
}

// An account at its share burns at most its one live request more, by any
// path that consumes it, and then starts nothing.
func TestAnAccountAtItsShareBurnsAtMostOneMore(t *testing.T) {
	for _, how := range []string{"deny", "a wrong number", "a replacing claim", "the switch"} {
		t.Run(how, func(t *testing.T) {
			f := newWebFixture(t, true)
			b := &f.hd.desktopSignIns
			now := time.Now()
			b.clock = func() time.Time { return now }
			b.mu.Lock()
			b.burned = map[string]burnedKey{}
			for i := range burnedPerAccount - 1 {
				b.burned["old"+strconv.Itoa(i)] = burnedKey{until: now.Add(time.Hour), account: "alice"}
			}
			b.mu.Unlock()
			k1, k2 := newComputerKey(t), newComputerKey(t)
			expectDesktop(t, f, f.aliceDevice, k1, "Mac")
			// The share check passes at one below; this expect burns k1, its
			// own live request, and starts k2's.
			exp := expectDesktop(t, f, f.aliceDevice, k2, "Mac")
			switch how {
			case "deny":
				approverReq(t, f, "/api/me/desktop-sign-ins/"+exp.ID+"/deny", f.aliceDevice, `{}`)
			case "a wrong number":
				arr := arriveDesktop(t, f, k2)
				wrong := 10
				if arr.Number == 10 {
					wrong = 11
				}
				approveDesktop(t, f, f.aliceDevice, exp.ID, wrong, "")
			case "a replacing claim":
				claimDesktop(t, f, f.aliceDevice, newDesktopSignIn(t, f, "alice", "Other").Code)
			case "the switch":
				if err := f.hd.setDesktopSwitch(false); err != nil {
					t.Fatal(err)
				}
				if err := f.hd.setDesktopSwitch(true); err != nil {
					t.Fatal(err)
				}
			}
			for range 3 {
				wantRefusal(t, "an expect past the share", expectReq(t, f, f.aliceDevice, newComputerKey(t), "Mac"), 429, "desktop-sign-in-attempts")
			}
			b.mu.Lock()
			n := b.burnedBy("alice")
			b.mu.Unlock()
			if n != burnedPerAccount+1 {
				t.Fatalf("alice is charged %d burned keys, want %d", n, burnedPerAccount+1)
			}
		})
	}
}

// A phone-first key whose request the phone denied, or replaced with
// another expect, is burned with it: nobody holding the computer's code can
// expect it again and catch the computer's arrival, and the arrival signs
// nothing in. The burn is charged to the denying or replacing account.
func TestADeniedOrReplacedKeyIsBurned(t *testing.T) {
	for _, how := range []string{"denied", "denied after the arrival", "replaced", "replaced by a claim"} {
		t.Run(how, func(t *testing.T) {
			f := newWebFixture(t, true)
			mallory := seedUser(t, f.db, "mallory")
			k := newComputerKey(t)
			exp := expectDesktop(t, f, f.aliceDevice, k, "Mac")
			switch how {
			case "denied after the arrival":
				arriveDesktop(t, f, k)
				fallthrough
			case "denied":
				if rec := approverReq(t, f, "/api/me/desktop-sign-ins/"+exp.ID+"/deny", f.aliceDevice, `{}`); rec.Code != 204 {
					t.Fatalf("deny: %d %s", rec.Code, rec.Body)
				}
			case "replaced":
				expectDesktop(t, f, f.aliceDevice, newComputerKey(t), "Mac")
			case "replaced by a claim":
				s := newDesktopSignIn(t, f, "alice", "Other Mac")
				claimDesktop(t, f, f.aliceDevice, s.Code)
			}
			wantDesktopExpired(t, "another account's expect of the key", expectReq(t, f, mallory, k, "Mac"))
			wantDesktopExpired(t, "the owner's own expect of the key", expectReq(t, f, f.aliceDevice, k, "Mac"))
			wantNoExpected(t, "the computer's arrival", arriveReq(t, f, k.pub, k.proof(f.hd.fs.ServerID())))
			b := &f.hd.desktopSignIns
			b.mu.Lock()
			charged := b.burned[k.pub].account
			b.mu.Unlock()
			if charged != "alice" {
				t.Fatalf("the burn is charged to %q, want alice", charged)
			}
		})
	}
}

func TestTheArrivalCarriesSameNetworkAndNoNumber(t *testing.T) {
	f := newWebFixture(t, true)
	k := newComputerKey(t)
	exp := expectDesktop(t, f, f.aliceDevice, k, "Mac")
	arriveDesktop(t, f, k)
	rec, elsewhere := arrivalReq(t, f, f.aliceDevice, exp.ID)
	if rec.Code != 200 || elsewhere.SameNetwork {
		t.Fatalf("read from another network: %d %s", rec.Code, rec.Body)
	}
	wantNoNumber(t, rec)
	rec, here := arrivalReq(t, f, f.aliceDevice, exp.ID, from("198.51.100.20:6000"))
	if rec.Code != 200 || !here.SameNetwork {
		t.Fatalf("read from the computer's network: %d %s", rec.Code, rec.Body)
	}
	wantNoNumber(t, rec)
	rec, _ = arrivalReq(t, f, f.aliceDevice, exp.ID, header("X-HyperDrop-Client", ""))
	wantRefusal(t, "a read without the client header", rec, 400, "client-required")
	// Another account's phone reads nothing.
	bob := seedUser(t, f.db, "bob")
	rec, _ = arrivalReq(t, f, bob, exp.ID)
	wantDesktopExpired(t, "another account's read", rec)
}

// A wrong typed number is refused at the approve, as the hddesk1 approve
// refuses it, burns the request, and the computer is not signed in: its
// poll finds nothing and no token is minted; the right number after it
// approves nothing either.
func TestAWrongTypedNumberSignsNothingIn(t *testing.T) {
	f := newWebFixture(t, true)
	k := newComputerKey(t)
	exp := expectDesktop(t, f, f.aliceDevice, k, "Mac")
	arr := arriveDesktop(t, f, k)
	wrong := 10
	if arr.Number == 10 {
		wrong = 11
	}
	wantRefusal(t, "a wrong number", approveDesktop(t, f, f.aliceDevice, exp.ID, wrong, ""), 409, "device-link-wrong-number")
	wantDesktopExpired(t, "the right number after a wrong one", approveDesktop(t, f, f.aliceDevice, exp.ID, arr.Number, ""))
	rec, out := pollDesktop(t, f, desktopSignInOut{ID: arr.ID, PollSecret: arr.PollSecret})
	wantDesktopExpired(t, "the computer's poll after a wrong number", rec)
	if out.Token != "" || strings.Contains(rec.Body.String(), "hd_u_") {
		t.Fatalf("a token after a wrong number: %s", rec.Body)
	}
	if rec := approveDesktop(t, f, f.aliceDevice, exp.ID, 9, ""); rec.Code != 400 {
		t.Fatalf("a number outside 10-99: %d %s, want 400", rec.Code, rec.Body)
	}
}

func TestAnExpectExpires(t *testing.T) {
	f := newWebFixture(t, true)
	now := time.Now()
	f.hd.desktopSignIns.clock = func() time.Time { return now }
	k := newComputerKey(t)
	exp := expectDesktop(t, f, f.aliceDevice, k, "Mac")
	now = now.Add(desktopExpectFor - time.Second)
	if rec, out := arrivalReq(t, f, f.aliceDevice, exp.ID); rec.Code != 202 || out.State != "expected" {
		t.Fatalf("just before: %d %s", rec.Code, rec.Body)
	}
	now = now.Add(time.Second)
	rec, _ := arrivalReq(t, f, f.aliceDevice, exp.ID)
	wantDesktopExpired(t, "the expectation that ran out", rec)

	// An arrival gets the claimed lifetime.
	k2 := newComputerKey(t)
	exp2 := expectDesktop(t, f, f.aliceDevice, k2, "Mac")
	arriveDesktop(t, f, k2)
	now = now.Add(webSignInClaimedFor - time.Second)
	if rec, out := arrivalReq(t, f, f.aliceDevice, exp2.ID); rec.Code != 200 || out.State != "arrived" {
		t.Fatalf("an arrival just before its claimed lifetime: %d %s", rec.Code, rec.Body)
	}
	now = now.Add(time.Second)
	rec, _ = arrivalReq(t, f, f.aliceDevice, exp2.ID)
	wantDesktopExpired(t, "the arrival that ran out", rec)
}

func TestArriveCountsOnTheSignInLockout(t *testing.T) {
	f := newWebFixture(t, true)
	stranger := newComputerKey(t)
	locked := false
	for i := 0; i < 2*pwFailLimit; i++ {
		rec := arriveReq(t, f, stranger.pub, stranger.proof(f.hd.fs.ServerID()))
		if rec.Code == 429 {
			if errCode(t, rec.Body.String()) != "locked-out" {
				t.Fatalf("the lockout: %s", rec.Body)
			}
			locked = true
			break
		}
		wantNoExpected(t, "a guess", rec)
	}
	if !locked {
		t.Fatalf("%d wrong arrivals never locked the address out", 2*pwFailLimit)
	}
	// The lockout holds the address back from a real arrival too, and
	// another address is untouched.
	k := newComputerKey(t)
	expectDesktop(t, f, f.aliceDevice, k, "Mac")
	wantRefusal(t, "a real arrival from the locked address", arriveReq(t, f, k.pub, k.proof(f.hd.fs.ServerID())), 429, "locked-out")
	if rec := arriveReq(t, f, k.pub, k.proof(f.hd.fs.ServerID()), from("203.0.113.50:7000")); rec.Code != 200 {
		t.Fatalf("an arrival from another address: %d %s", rec.Code, rec.Body)
	}
}

// The computer's arrival answers only an installed app, inside the window.
func TestArriveRefusesABrowserAndNeedsTheClientHeader(t *testing.T) {
	f := newWebFixture(t, true)
	k := newComputerKey(t)
	expectDesktop(t, f, f.aliceDevice, k, "Mac")
	proof := k.proof(f.hd.fs.ServerID())
	for name, edit := range map[string]func(*http.Request){
		"an Origin":        header("Origin", "https://evil.example"),
		"a Sec-Fetch-Site": header("Sec-Fetch-Site", "none"),
		"the web client":   header("X-HyperDrop-Client", "2.0.0 web"),
	} {
		wantRefusal(t, name, arriveReq(t, f, k.pub, proof, edit), 403, "desktop-sign-in-refused")
	}
	wantRefusal(t, "no header", arriveReq(t, f, k.pub, proof, header("X-HyperDrop-Client", "")), 400, "client-required")
	wantRefusal(t, "an old client", arriveReq(t, f, k.pub, proof, header("X-HyperDrop-Client", "1.0.0 macos")), 409, "client-outdated")
	if rec := arriveReq(t, f, k.pub, proof); rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("the arrival after the refusals: %d %v %s", rec.Code, rec.Header(), rec.Body)
	}
}

// The server's arrival text and core/joincode's are one: this fixture is
// pinned on both sides.
func TestDesktopArriveMessageFixture(t *testing.T) {
	const want = "hddesk2-arrive\nsrv-1\nAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	if got := desktopArriveMessage("srv-1", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"); got != want {
		t.Fatalf("message %q, want %q", got, want)
	}
}
