package metadb

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// pushUser makes an account with one token and answers that token's hash.
func pushUser(t *testing.T, db *DB, name string) string {
	t.Helper()
	if _, err := db.CreateUser(name, "pw", RoleUser, Settings{}); err != nil {
		t.Fatal(err)
	}
	raw, err := db.MintToken(name, "phone")
	if err != nil {
		t.Fatal(err)
	}
	return TokenHash(raw)
}

// must fails the test at a setup step that errs.
func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func reg(handle string) PushRegistration {
	return PushRegistration{Relay: "https://relay.test", Handle: handle,
		PublicKey: []byte(strings.Repeat("k", 32)), Tag: "entry-1", Muted: []string{"domain"}}
}

func TestARegistrationLivesOnItsTokenRow(t *testing.T) {
	db := openTest(t)
	h := pushUser(t, db, "alice")
	if _, ok, err := db.PushOf(h); ok || err != nil {
		t.Fatalf("a fresh token reads as registered: %v %v", ok, err)
	}
	if err := db.SetPush(h, reg(strings.Repeat("a", 32))); err != nil {
		t.Fatal(err)
	}
	got, ok, err := db.PushOf(h)
	if err != nil || !ok || got.Handle != strings.Repeat("a", 32) || got.Tag != "entry-1" || got.Relay != "https://relay.test" ||
		!got.Mutes("domain") || got.Mutes("inboxReceived") || got.Username != "alice" || got.TokenID == "" {
		t.Fatalf("PushOf = %+v %v %v", got, ok, err)
	}
	targets, err := db.PushTargets("alice")
	if err != nil || len(targets) != 1 || string(targets[0].PublicKey) != strings.Repeat("k", 32) {
		t.Fatalf("targets = %+v %v", targets, err)
	}
	if users, _ := db.PushUsers(); !slices.Equal(users, []string{"alice"}) {
		t.Fatalf("users = %v", users)
	}
	if err := db.ClearPush(h); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := db.PushOf(h); ok {
		t.Fatal("cleared registration still there")
	}
	if users, _ := db.PushUsers(); len(users) != 0 {
		t.Fatalf("users after clear = %v", users)
	}
	if err := db.SetPush(TokenHash("nobody"), reg("b")); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("an unknown token: %v", err)
	}
}

// An empty tag and no mutes round-trip as such.
func TestARegistrationWithNoTagOrMutes(t *testing.T) {
	db := openTest(t)
	h := pushUser(t, db, "alice")
	r := reg(strings.Repeat("a", 32))
	r.Tag, r.Muted = "", nil
	if err := db.SetPush(h, r); err != nil {
		t.Fatal(err)
	}
	got, ok, err := db.PushOf(h)
	if err != nil || !ok || got.Tag != "" || got.Muted != nil {
		t.Fatalf("PushOf = %+v %v %v", got, ok, err)
	}
}

// Several devices of one account are answered oldest token first.
func TestPushTargetsAreOldestFirst(t *testing.T) {
	db := openTest(t)
	h1 := pushUser(t, db, "alice")
	raw, err := db.MintToken("alice", "ipad")
	if err != nil {
		t.Fatal(err)
	}
	h2 := TokenHash(raw)
	if _, err := db.w.Exec(`UPDATE tokens SET created_at = created_at + 1000000000 WHERE sha256 = ?`, h2); err != nil {
		t.Fatal(err)
	}
	must(t, db.SetPush(h2, reg(strings.Repeat("b", 32))))
	must(t, db.SetPush(h1, reg(strings.Repeat("a", 32))))
	pushUser(t, db, "bob")
	targets, err := db.PushTargets("alice")
	if err != nil || len(targets) != 2 || targets[0].Handle != strings.Repeat("a", 32) || targets[1].Handle != strings.Repeat("b", 32) {
		t.Fatalf("targets = %+v %v", targets, err)
	}
	if users, _ := db.PushUsers(); !slices.Equal(users, []string{"alice"}) {
		t.Fatalf("users = %v", users)
	}
}

// Signing out deletes the token row, and the registration goes with it.
func TestRevokingTheTokenDropsTheRegistration(t *testing.T) {
	db := openTest(t)
	h := pushUser(t, db, "alice")
	must(t, db.SetPush(h, reg(strings.Repeat("a", 32))))
	u, _ := db.User("alice")
	for _, tok := range u.Tokens {
		if tok.SHA256 == h {
			if err := db.RevokeToken("alice", tok.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	if targets, _ := db.PushTargets("alice"); len(targets) != 0 {
		t.Fatalf("a revoked device still receives: %+v", targets)
	}
}

// The handle is a capability: nothing that lists or exports tokens carries it.
func TestNoTokenListingCarriesTheRegistration(t *testing.T) {
	db := openTest(t)
	h := pushUser(t, db, "alice")
	handle := strings.Repeat("c", 32)
	must(t, db.SetPush(h, reg(handle)))
	u, _ := db.User("alice")
	all, _ := db.Users()
	for _, v := range []any{u, all} {
		b, _ := json.Marshal(v)
		if strings.Contains(string(b), handle) || strings.Contains(string(b), "relay.test") {
			t.Fatalf("a listing carries the registration: %s", b)
		}
	}
}

func TestAGoneHandleIsDroppedWhereverItIs(t *testing.T) {
	db := openTest(t)
	h := pushUser(t, db, "alice")
	other := pushUser(t, db, "bob")
	must(t, db.SetPush(h, reg(strings.Repeat("d", 32))))
	must(t, db.SetPush(other, reg(strings.Repeat("e", 32))))
	if err := db.DropPushHandle(strings.Repeat("d", 32)); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := db.PushOf(h); ok {
		t.Fatal("a handle the relay called gone is still registered")
	}
	if _, ok, _ := db.PushOf(other); !ok {
		t.Fatal("dropping one handle dropped another")
	}
}

func TestOnlyARecentComputerCountsAsInUse(t *testing.T) {
	db := openTest(t)
	h := pushUser(t, db, "alice")
	now := time.Now()
	since := now.Add(-5 * time.Minute)
	at := now.Add(-time.Minute)
	must(t, db.SetConsoleActivity(h, &at))
	if active, _ := db.DesktopActiveSince("alice", since); active {
		t.Fatal("a token with no platform counted as a computer")
	}
	// The platform comes from X-HyperDrop-Client, which UserByToken records.
	if _, err := db.w.Exec(`UPDATE tokens SET client_platform = 'macos' WHERE sha256 = ?`, h); err != nil {
		t.Fatal(err)
	}
	if active, err := db.DesktopActiveSince("alice", since); !active || err != nil {
		t.Fatalf("a Mac active a minute ago is not in use: %v", err)
	}
	if active, _ := db.DesktopActiveSince("bob", since); active {
		t.Fatal("another account's Mac counted")
	}
	// Unregistering push is not leaving the computer.
	if err := db.ClearPush(h); err != nil {
		t.Fatal(err)
	}
	if active, _ := db.DesktopActiveSince("alice", since); !active {
		t.Fatal("ClearPush cleared the console activity")
	}
	old := now.Add(-6 * time.Minute)
	must(t, db.SetConsoleActivity(h, &old))
	if active, _ := db.DesktopActiveSince("alice", since); active {
		t.Fatal("a Mac idle for six minutes is in use")
	}
	must(t, db.SetConsoleActivity(h, nil))
	if active, _ := db.DesktopActiveSince("alice", since); active {
		t.Fatal("a cleared activity counts")
	}
	if _, err := db.w.Exec(`UPDATE tokens SET client_platform = 'ios' WHERE sha256 = ?`, h); err != nil {
		t.Fatal(err)
	}
	must(t, db.SetConsoleActivity(h, &at))
	if active, _ := db.DesktopActiveSince("alice", since); active {
		t.Fatal("a phone counted as a computer")
	}
}

func TestPushStateIsKeptPerOwnerAndPrunedWithTheLastRegistration(t *testing.T) {
	db := openTest(t)
	h := pushUser(t, db, "alice")
	must(t, db.SetPush(h, reg(strings.Repeat("e", 32))))
	if err := db.SetPushState("alice", "inbox", `{"links":{}}`); err != nil {
		t.Fatal(err)
	}
	if err := db.SetPushState("alice", "inbox", `{"links":{"x":1}}`); err != nil {
		t.Fatal(err)
	}
	must(t, db.SetPushState("", "domain", `{"state":"connected"}`))
	if v, ok, _ := db.PushState("alice", "inbox"); !ok || v != `{"links":{"x":1}}` {
		t.Fatalf("state = %q %v", v, ok)
	}
	if _, ok, err := db.PushState("alice", "revoke"); ok || err != nil {
		t.Fatalf("an unset kind: %v %v", ok, err)
	}
	must(t, db.PrunePushState())
	if _, ok, _ := db.PushState("alice", "inbox"); !ok {
		t.Fatal("pruned the state of an owner who still receives")
	}
	must(t, db.ClearPush(h))
	must(t, db.PrunePushState())
	if _, ok, _ := db.PushState("alice", "inbox"); ok {
		t.Fatal("an owner with no registration kept state that would replay on the next registration")
	}
	if _, ok, _ := db.PushState("", "domain"); !ok {
		t.Fatal("the server's own state was pruned")
	}
}

// A suspended or expired account is neither a push target nor evaluated,
// and its memory is pruned; its registration stays, so re-enabling it
// pushes again, and the memory it gains then survives the prune.
func TestASuspendedOrExpiredAccountIsNotPushedTo(t *testing.T) {
	db := openTest(t)
	h := pushUser(t, db, "alice")
	must(t, db.SetPush(h, reg(strings.Repeat("e", 32))))
	must(t, db.SetPushState("alice", "inbox", `{}`))
	on, off := false, true
	past := time.Now().Add(-time.Minute)
	future := time.Now().Add(time.Hour)
	for _, c := range []struct {
		name   string
		s      Settings
		pushed bool
	}{
		{"suspended", Settings{Disabled: &off}, false},
		{"re-enabled", Settings{Disabled: &on}, true},
		{"expired", Settings{AccountExpiresAt: &past}, false},
		{"expiring later", Settings{AccountExpiresAt: &future}, true},
	} {
		if _, err := db.UpdateUser("alice", c.s); err != nil {
			t.Fatal(err)
		}
		targets, err := db.PushTargets("alice")
		must(t, err)
		users, err := db.PushUsers()
		must(t, err)
		if (len(targets) == 1) != c.pushed || (len(users) == 1) != c.pushed {
			t.Fatalf("%s: targets %d users %v, want pushed=%v", c.name, len(targets), users, c.pushed)
		}
		must(t, db.PrunePushState())
		_, kept, _ := db.PushState("alice", "inbox")
		if !c.pushed && kept {
			t.Fatalf("%s: the account's memory survived the prune", c.name)
		}
		if c.pushed && !kept {
			t.Fatalf("%s: a pushable account's memory was pruned", c.name)
		}
		if _, ok, _ := db.PushOf(h); !ok {
			t.Fatalf("%s: the registration itself was removed", c.name)
		}
		must(t, db.SetPushState("alice", "inbox", `{}`))
	}
}

// None of the push writes is a share change.
func TestPushWritesNotifyNoSubscriber(t *testing.T) {
	db := openTest(t)
	h := pushUser(t, db, "alice")
	ch, cancel := db.Subscribe()
	defer cancel()
	now := time.Now()
	must(t, db.SetPush(h, reg(strings.Repeat("f", 32))))
	must(t, db.SetConsoleActivity(h, &now))
	must(t, db.SetPushState("alice", "inbox", "{}"))
	must(t, db.PrunePushState())
	must(t, db.DropPushHandle(strings.Repeat("f", 32)))
	must(t, db.ClearPush(h))
	select {
	case <-ch:
		t.Fatal("a push write notified Subscribe")
	default:
	}
}

// Only a usable registration is stored, so a stored handle always means one.
func TestAnUnusableRegistrationIsRefused(t *testing.T) {
	db := openTest(t)
	h := pushUser(t, db, "alice")
	for name, mod := range map[string]func(*PushRegistration){
		"no handle":       func(r *PushRegistration) { r.Handle = "" },
		"no relay":        func(r *PushRegistration) { r.Relay = "" },
		"no key":          func(r *PushRegistration) { r.PublicKey = nil },
		"short key":       func(r *PushRegistration) { r.PublicKey = r.PublicKey[:31] },
		"unknown kind":    func(r *PushRegistration) { r.Muted = []string{"shareReady"} },
		"empty kind":      func(r *PushRegistration) { r.Muted = []string{"domain", ""} },
		"comma in a kind": func(r *PushRegistration) { r.Muted = []string{"domain,inboxReceived"} },
	} {
		r := reg(strings.Repeat("a", 32))
		mod(&r)
		if err := db.SetPush(h, r); !errors.Is(err, ErrBadPush) || !errors.Is(err, ErrBadRequest) {
			t.Errorf("%s: %v", name, err)
		}
		if _, ok, _ := db.PushOf(h); ok {
			t.Fatalf("%s: stored", name)
		}
	}
	r := reg(strings.Repeat("a", 32))
	r.Muted = slices.Clone(PushKinds)
	must(t, db.SetPush(h, r))
	if got, _, _ := db.PushOf(h); !slices.Equal(got.Muted, PushKinds) {
		t.Fatalf("every kind muted reads back %v", got.Muted)
	}
	must(t, db.DropPushHandle(""))
	if _, ok, _ := db.PushOf(h); !ok {
		t.Fatal("dropping the empty handle dropped a registration")
	}
}
