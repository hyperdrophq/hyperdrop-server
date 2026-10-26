package metadb

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// webTestDB is a fresh database holding alice, password "pw-alice", and the
// directory it lives in, for a test that edits a row by hand.
func webTestDB(t *testing.T) (*DB, string) {
	t.Helper()
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.CreateUser("alice", "pw-alice", RoleUser, Settings{}); err != nil {
		t.Fatal(err)
	}
	return db, dir
}

// webRow is the account's token row for the web session raw.
func webRow(t *testing.T, db *DB, raw string) (Token, bool) {
	t.Helper()
	u, err := db.User("alice")
	if err != nil {
		t.Fatal(err)
	}
	for _, tok := range u.Tokens {
		if tok.SHA256 == WebSessionHash(raw) {
			return tok, true
		}
	}
	return Token{}, false
}

func TestWebSessionHashDiffersFromTokenHash(t *testing.T) {
	db, dir := webTestDB(t)
	if WebSessionHash("hd_w_x") == TokenHash("hd_w_x") {
		t.Fatal("the web hash equals the bearer hash")
	}
	raw, err := db.MintWebSession("alice", "Web browser · Chrome on Windows", false, at)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(raw, WebTokenPrefix) || len(raw) != len(WebTokenPrefix)+64 {
		t.Fatalf("raw = %q", raw)
	}
	// A server that knows nothing of web sessions looks a bearer up by its
	// plain SHA-256, which the row never holds.
	if _, err := db.UserByToken(raw, ClientInfo{}); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("a web session as a bearer: %v, want ErrBadCredentials", err)
	}
	tok, ok := webRow(t, db, raw)
	if !ok || tok.SHA256 == TokenHash(raw) || tok.Kind != TokenKindWeb {
		t.Fatalf("row = %+v (found %v)", tok, ok)
	}
	// Even a web row that held the bearer hash is not a bearer token here.
	execRawMeta(t, dir, `UPDATE tokens SET sha256 = ? WHERE id = ?`, TokenHash(raw), tok.ID)
	if _, err := db.UserByToken(raw, ClientInfo{}); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("a web row as a bearer: %v, want ErrBadCredentials", err)
	}
	// And a device token is never a web session.
	dev, err := db.MintToken("alice", "mac")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.UserByWebSession(dev, ClientInfo{}, at, true); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("a device token as a web session: %v", err)
	}
}

// execRawMeta runs one statement on the database in dir through a handle of
// its own.
func execRawMeta(t *testing.T, dir, query string, args ...any) {
	t.Helper()
	if _, err := rawDB(t, dir).Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}

func TestMintWebSessionExpiries(t *testing.T) {
	db, _ := webTestDB(t)
	public, err := db.MintWebSession("alice", "public", false, at)
	if err != nil {
		t.Fatal(err)
	}
	keep, err := db.MintWebSession("alice", "keep", true, at)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := webRow(t, db, public)
	if p.Keep || !p.IdleUntil.Equal(at.Add(30*time.Minute)) || !p.ExpiresAt.Equal(at.Add(12*time.Hour)) ||
		!p.CreatedAt.Equal(at) || p.Label != "public" || !p.ElevatedUntil.IsZero() {
		t.Fatalf("public session = %+v", p)
	}
	k, _ := webRow(t, db, keep)
	if !k.Keep || !k.IdleUntil.Equal(at.Add(30*24*time.Hour)) || !k.ExpiresAt.Equal(at.Add(30*24*time.Hour)) {
		t.Fatalf("kept session = %+v", k)
	}
	if idle, abs := WebSessionLimits(false); idle != 30*time.Minute || abs != 12*time.Hour {
		t.Fatalf("public limits %v %v", idle, abs)
	}
	if idle, abs := WebSessionLimits(true); idle != 30*24*time.Hour || abs != 30*24*time.Hour {
		t.Fatalf("kept limits %v %v", idle, abs)
	}
}

func TestMintWebSessionIfPasswordIs(t *testing.T) {
	db, _ := webTestDB(t)
	u, err := db.Authenticate("alice", "pw-alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.MintWebSessionIfPasswordIs("alice", "l", "not-the-hash", "", false, at); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("a replaced password: %v", err)
	}
	raw, err := db.MintWebSessionIfPasswordIs("alice", "l", u.PasswordHash, "", true, at)
	if err != nil {
		t.Fatal(err)
	}
	if tok, ok := webRow(t, db, raw); !ok || !tok.Keep {
		t.Fatalf("row = %+v", tok)
	}
}

func TestUserByWebSessionExpiresIdle(t *testing.T) {
	db, _ := webTestDB(t)
	raw, err := db.MintWebSession("alice", "l", false, at)
	if err != nil {
		t.Fatal(err)
	}
	u, tok, err := db.UserByWebSession(raw, ClientInfo{Version: "1.2.0", Platform: "web"}, at.Add(29*time.Minute), false)
	if err != nil || u.Username != "alice" || tok.SHA256 != WebSessionHash(raw) || tok.ClientPlatform != "web" {
		t.Fatalf("inside the idle limit: %+v %+v %v", u, tok, err)
	}
	if !tok.IdleUntil.Equal(at.Add(30 * time.Minute)) {
		t.Fatalf("an untouched lookup moved the idle limit to %v", tok.IdleUntil)
	}
	if _, _, err := db.UserByWebSession(raw, ClientInfo{}, at.Add(30*time.Minute), true); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("at the idle limit: %v", err)
	}
	if _, ok := webRow(t, db, raw); ok {
		t.Fatal("an expired session's row survived its lookup")
	}
}

func TestUserByWebSessionExpiresAbsolute(t *testing.T) {
	db, _ := webTestDB(t)
	raw, err := db.MintWebSession("alice", "l", false, at)
	if err != nil {
		t.Fatal(err)
	}
	for now := at.Add(20 * time.Minute); now.Before(at.Add(12 * time.Hour)); now = now.Add(20 * time.Minute) {
		if _, _, err := db.UserByWebSession(raw, ClientInfo{}, now, true); err != nil {
			t.Fatalf("at %v: %v", now.Sub(at), err)
		}
	}
	if _, _, err := db.UserByWebSession(raw, ClientInfo{}, at.Add(12*time.Hour), true); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("at the absolute limit: %v", err)
	}
	if _, ok := webRow(t, db, raw); ok {
		t.Fatal("an expired session's row survived its lookup")
	}
}

func TestAKeptSessionSlides(t *testing.T) {
	db, _ := webTestDB(t)
	raw, err := db.MintWebSession("alice", "l", true, at)
	if err != nil {
		t.Fatal(err)
	}
	now := at.Add(29 * 24 * time.Hour)
	_, tok, err := db.UserByWebSession(raw, ClientInfo{}, now, true)
	if err != nil {
		t.Fatal(err)
	}
	if !tok.IdleUntil.Equal(now.Add(30*24*time.Hour)) || !tok.ExpiresAt.Equal(now.Add(30*24*time.Hour)) {
		t.Fatalf("kept session after use = %+v", tok)
	}
	if _, _, err := db.UserByWebSession(raw, ClientInfo{}, at.Add(31*24*time.Hour), false); err != nil {
		t.Fatalf("a day past the first 30: %v", err)
	}
}

func TestTouchCoalescedToAMinute(t *testing.T) {
	db, _ := webTestDB(t)
	raw, err := db.MintWebSession("alice", "l", false, at)
	if err != nil {
		t.Fatal(err)
	}
	// The first lookup stamps the last use.
	if _, _, err := db.UserByWebSession(raw, ClientInfo{}, at.Add(10*time.Second), true); err != nil {
		t.Fatal(err)
	}
	before := db.writeCount()
	_, tok, err := db.UserByWebSession(raw, ClientInfo{}, at.Add(30*time.Second), true)
	if err != nil {
		t.Fatal(err)
	}
	if db.writeCount() != before || !tok.IdleUntil.Equal(at.Add(30*time.Minute)) {
		t.Fatalf("a touch within the minute wrote %d time(s), idle until %v", db.writeCount()-before, tok.IdleUntil)
	}
	_, tok, err = db.UserByWebSession(raw, ClientInfo{}, at.Add(70*time.Second), true)
	if err != nil {
		t.Fatal(err)
	}
	if db.writeCount() != before+1 || !tok.IdleUntil.Equal(at.Add(70*time.Second+30*time.Minute)) {
		t.Fatalf("a touch past the minute wrote %d time(s), idle until %v", db.writeCount()-before, tok.IdleUntil)
	}
	if stored, _ := webRow(t, db, raw); !stored.IdleUntil.Equal(tok.IdleUntil) {
		t.Fatalf("stored idle limit %v, answered %v", stored.IdleUntil, tok.IdleUntil)
	}
}

func TestPasswordChangeRevokesWebSessions(t *testing.T) {
	db, _ := webTestDB(t)
	raw, err := db.MintWebSession("alice", "l", true, at)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetPassword("alice", "pw-alice-2"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.UserByWebSession(raw, ClientInfo{}, at.Add(time.Minute), true); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("after a password change: %v", err)
	}
}

func TestRevokeWebSessionsLeavesDeviceTokens(t *testing.T) {
	db, _ := webTestDB(t)
	if _, err := db.CreateUser("bob", "pw-bob", RoleUser, Settings{}); err != nil {
		t.Fatal(err)
	}
	dev, err := db.MintToken("alice", "mac")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alice", "bob"} {
		if _, err := db.MintWebSession(name, "l", false, at); err != nil {
			t.Fatal(err)
		}
	}
	n, err := db.RevokeWebSessions()
	if err != nil || n != 2 {
		t.Fatalf("RevokeWebSessions = %d, %v; want 2", n, err)
	}
	u, err := db.UserByToken(dev, ClientInfo{})
	if err != nil || len(u.Tokens) != 1 || u.Tokens[0].Kind != "" {
		t.Fatalf("the device token: %+v, %v", u.Tokens, err)
	}
}

func TestEndWebSession(t *testing.T) {
	db, _ := webTestDB(t)
	dev, err := db.MintToken("alice", "mac")
	if err != nil {
		t.Fatal(err)
	}
	keep, err := db.MintWebSession("alice", "keep", false, at)
	if err != nil {
		t.Fatal(err)
	}
	gone, err := db.MintWebSession("alice", "gone", false, at)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.EndWebSession(gone); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.UserByWebSession(gone, ClientInfo{}, at, false); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("the ended session: %v", err)
	}
	if _, _, err := db.UserByWebSession(keep, ClientInfo{}, at, false); err != nil {
		t.Fatalf("the other session: %v", err)
	}
	// Ending a session already gone, a value that names none, and a device
	// token's value changes nothing.
	for _, raw := range []string{gone, WebTokenPrefix + strings.Repeat("0", 64), dev, ""} {
		if err := db.EndWebSession(raw); err != nil {
			t.Fatalf("EndWebSession(%q): %v", raw, err)
		}
	}
	if _, err := db.UserByToken(dev, ClientInfo{}); err != nil {
		t.Fatalf("the device token: %v", err)
	}
}

func TestPruneWebSessions(t *testing.T) {
	db, _ := webTestDB(t)
	public, err := db.MintWebSession("alice", "public", false, at)
	if err != nil {
		t.Fatal(err)
	}
	kept, err := db.MintWebSession("alice", "keep", true, at)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.MintToken("alice", "mac"); err != nil {
		t.Fatal(err)
	}
	if n, err := db.PruneWebSessions(at.Add(29 * time.Minute)); err != nil || n != 0 {
		t.Fatalf("within the idle limit: %d, %v", n, err)
	}
	if n, err := db.PruneWebSessions(at.Add(31 * time.Minute)); err != nil || n != 1 {
		t.Fatalf("past the idle limit: %d, %v; want 1", n, err)
	}
	if _, ok := webRow(t, db, public); ok {
		t.Fatal("the idle public session survived the prune")
	}
	if _, ok := webRow(t, db, kept); !ok {
		t.Fatal("the kept session was pruned")
	}
	if u, _ := db.User("alice"); len(u.Tokens) != 2 {
		t.Fatalf("tokens left: %+v", u.Tokens)
	}
}

func TestElevateWebSession(t *testing.T) {
	db, _ := webTestDB(t)
	raw, err := db.MintWebSession("alice", "l", false, at)
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := webRow(t, db, raw)
	until := at.Add(10 * time.Minute)
	if err := db.ElevateWebSession("alice", tok.ID, until); err != nil {
		t.Fatal(err)
	}
	if got, _ := webRow(t, db, raw); !got.ElevatedUntil.Equal(until) {
		t.Fatalf("elevated until %v, want %v", got.ElevatedUntil, until)
	}
	if _, err := db.MintToken("alice", "mac"); err != nil {
		t.Fatal(err)
	}
	u, _ := db.User("alice")
	for _, d := range u.Tokens {
		if d.Kind == "" {
			if err := db.ElevateWebSession("alice", d.ID, until); !errors.Is(err, ErrNoSuchToken) {
				t.Fatalf("elevating a device token: %v", err)
			}
		}
	}
	if err := db.ElevateWebSession("bob", tok.ID, until); !errors.Is(err, ErrNoSuchToken) {
		t.Fatalf("elevating another account's session: %v", err)
	}
}

// A password change made from a web session signs every device and session
// out and hands the browser a new session of the same kind and label.
func TestSetPasswordMintingWebSession(t *testing.T) {
	db, _ := webTestDB(t)
	const label = "Web browser · Chrome on Windows"
	old, err := db.MintWebSession("alice", label, true, at)
	if err != nil {
		t.Fatal(err)
	}
	dev, err := db.MintToken("alice", "mac")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := db.SetPasswordMintingWebSession("alice", "pw-alice-2", label, true, at.Add(-48*time.Hour), at)
	if err != nil {
		t.Fatal(err)
	}
	if raw == old || !strings.HasPrefix(raw, WebTokenPrefix) {
		t.Fatalf("new session %q (old %q)", raw, old)
	}
	if _, _, err := db.UserByWebSession(old, ClientInfo{}, at.Add(time.Minute), true); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("the old session after the change: %v", err)
	}
	if _, err := db.UserByToken(dev, ClientInfo{}); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("the device token after the change: %v", err)
	}
	tok, ok := webRow(t, db, raw)
	if !ok || tok.Kind != TokenKindWeb || !tok.Keep || tok.Label != label {
		t.Fatalf("new session row %+v (found %v)", tok, ok)
	}
	// The new session keeps the caller's sign-in time; its limits count from
	// the change.
	if !tok.CreatedAt.Equal(at.Add(-48*time.Hour)) || !tok.IdleUntil.Equal(at.Add(WebKeepFor)) {
		t.Fatalf("new session signed in %v, idle until %v; want %v and %v", tok.CreatedAt, tok.IdleUntil, at.Add(-48*time.Hour), at.Add(WebKeepFor))
	}
	if u, _ := db.User("alice"); len(u.Tokens) != 1 {
		t.Fatalf("tokens left: %+v, want the new session alone", u.Tokens)
	}
	if _, err := db.Authenticate("alice", "pw-alice-2"); err != nil {
		t.Fatalf("the new password: %v", err)
	}
	if _, err := db.SetPasswordMintingWebSession("nobody", "pw-nobody-2", label, false, at, at); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("an unknown account: %v", err)
	}
}

// A phone-approved session is minted only while the approving device is
// still signed in and the account active, as a public session recording
// that device.
func TestMintWebSessionApprovedBy(t *testing.T) {
	db, _ := webTestDB(t)
	if _, err := db.MintToken("alice", "phone"); err != nil {
		t.Fatal(err)
	}
	u, err := db.User("alice")
	if err != nil {
		t.Fatal(err)
	}
	devID := u.Tokens[0].ID
	got, raw, err := db.MintWebSessionApprovedBy("alice", devID, "Web browser · Chrome on Windows", at)
	if err != nil || got.Username != "alice" {
		t.Fatalf("mint: %+v %v", got, err)
	}
	tok, ok := webRow(t, db, raw)
	if !ok || tok.Kind != TokenKindWeb || tok.Keep || tok.ViaToken != devID || !tok.ExpiresAt.Equal(at.Add(WebAbsolute)) {
		t.Fatalf("row %+v (found %v)", tok, ok)
	}
	if _, _, err := db.MintWebSessionApprovedBy("alice", tok.ID, "x", at); !errors.Is(err, ErrNoSuchToken) {
		t.Fatalf("approved by a web session: %v, want ErrNoSuchToken", err)
	}
	if _, _, err := db.MintWebSessionApprovedBy("bob", devID, "x", at); !errors.Is(err, ErrNoSuchToken) {
		t.Fatalf("another account's device: %v, want ErrNoSuchToken", err)
	}
	off := true
	if _, err := db.UpdateUser("alice", Settings{Disabled: &off}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.MintWebSessionApprovedBy("alice", devID, "x", at); !errors.Is(err, ErrInactive) {
		t.Fatalf("a suspended account: %v, want ErrInactive", err)
	}
	if err := db.RevokeToken("alice", devID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.MintWebSessionApprovedBy("alice", devID, "x", at); !errors.Is(err, ErrNoSuchToken) {
		t.Fatalf("a signed-out device: %v, want ErrNoSuchToken", err)
	}
}

// TokenLive answers a device token while its row exists, a web session
// while it is also inside its limits, and neither for a suspended account
// or another account's name.
func TestTokenLive(t *testing.T) {
	db, _ := webTestDB(t)
	dev, err := db.MintToken("alice", "mac")
	if err != nil {
		t.Fatal(err)
	}
	web, err := db.MintWebSession("alice", "Web browser · Chrome on Windows", false, at)
	if err != nil {
		t.Fatal(err)
	}
	u, err := db.User("alice")
	if err != nil {
		t.Fatal(err)
	}
	var devID, webID string
	for _, tok := range u.Tokens {
		switch tok.SHA256 {
		case TokenHash(dev):
			devID = tok.ID
		case WebSessionHash(web):
			webID = tok.ID
		}
	}
	live := func(name, id string, now time.Time) (string, bool) {
		t.Helper()
		kind, ok, err := db.TokenLive(name, id, now)
		if err != nil {
			t.Fatal(err)
		}
		return kind, ok
	}
	if kind, ok := live("alice", devID, at); !ok || kind != "" {
		t.Fatalf("the device token: %q %v", kind, ok)
	}
	if kind, ok := live("alice", webID, at.Add(29*time.Minute)); !ok || kind != TokenKindWeb {
		t.Fatalf("the web session inside its limits: %q %v", kind, ok)
	}
	if _, ok := live("alice", webID, at.Add(30*time.Minute)); ok {
		t.Fatal("the web session past its idle limit is live")
	}
	if _, ok := live("bob", devID, at); ok {
		t.Fatal("alice's token is live under another name")
	}
	if _, ok := live("alice", "nope", at); ok {
		t.Fatal("an unknown id is live")
	}
	off := true
	if _, err := db.UpdateUser("alice", Settings{Disabled: &off}); err != nil {
		t.Fatal(err)
	}
	if _, ok := live("alice", devID, at); ok {
		t.Fatal("a suspended account's token is live")
	}
}
