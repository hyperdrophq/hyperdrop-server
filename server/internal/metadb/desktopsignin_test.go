package metadb

import (
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// desktopTestDB is a fresh database holding alice (a user) signed in on one
// device labelled "iPhone", and that device token's id.
func desktopTestDB(t *testing.T) (*DB, string) {
	t.Helper()
	db := openTest(t)
	if _, err := db.CreateUser("alice", "pw-alice", RoleUser, Settings{}); err != nil {
		t.Fatal(err)
	}
	return db, mintedID(t, db, "alice", "iPhone")
}

// mintedID mints a device token for name labelled label and answers its id.
func mintedID(t *testing.T, db *DB, name, label string) string {
	t.Helper()
	raw, err := db.MintToken(name, label)
	if err != nil {
		t.Fatal(err)
	}
	return tokenOf(t, db, name, TokenHash(raw)).ID
}

// tokenOf is name's token row whose hash is hash.
func tokenOf(t *testing.T, db *DB, name, hash string) Token {
	t.Helper()
	u, err := db.User(name)
	if err != nil {
		t.Fatal(err)
	}
	for _, tok := range u.Tokens {
		if tok.SHA256 == hash {
			return tok
		}
	}
	t.Fatalf("%s holds no token with hash %s", name, hash)
	return Token{}
}

// tokenIDs are name's token ids in the account's order.
func tokenIDs(t *testing.T, db *DB, name string) []string {
	t.Helper()
	u, err := db.User(name)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, tok := range u.Tokens {
		out = append(out, tok.ID)
	}
	return out
}

// signInEvent is one sign_in_events row.
type signInEvent struct {
	Username, TokenID, Label, ApproverTokenID, ApproverLabel, AddrMark string
	At                                                                 time.Time
}

// signInEvents are name's audit rows, newest first.
func signInEvents(t *testing.T, db *DB, name string) []signInEvent {
	t.Helper()
	var out []signInEvent
	err := db.read(func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT username, at, coalesce(token_id, ''), label, coalesce(approver_token_id, ''),
			approver_label, addr_mark FROM sign_in_events WHERE username = ? ORDER BY at DESC, id DESC`, name)
		if err != nil {
			return err
		}
		return eachRow(rows, func() error {
			var e signInEvent
			var ns int64
			if err := rows.Scan(&e.Username, &ns, &e.TokenID, &e.Label, &e.ApproverTokenID, &e.ApproverLabel, &e.AddrMark); err != nil {
				return err
			}
			e.At = fromNS(ns)
			out = append(out, e)
			return nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// insertSignInEvents writes n audit rows for name by hand, the i-th at
// first + i minutes, labelled "old <i>".
func insertSignInEvents(t *testing.T, db *DB, name string, n int, first time.Time) {
	t.Helper()
	err := db.write(func(tx *sql.Tx) error {
		for i := range n {
			if _, err := tx.Exec(`INSERT INTO sign_in_events(username, at, token_id, label, approver_token_id, approver_label, addr_mark)
				VALUES(?, ?, NULL, ?, NULL, 'iPhone', 'm')`, name, toNS(first.Add(time.Duration(i)*time.Minute)),
				fmt.Sprintf("old %d", i)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestMintDesktopSignInStampsTheToken(t *testing.T) {
	db, approver := desktopTestDB(t)
	u, raw, err := db.MintDesktopSignIn("alice", approver, "Phone sign-in: Mac", "macos", "mark-1", at)
	if err != nil {
		t.Fatal(err)
	}
	if u.Username != "alice" || !strings.HasPrefix(raw, "hd_u_") {
		t.Fatalf("u = %q, raw = %q", u.Username, raw)
	}
	if got, err := db.UserByToken(raw, ClientInfo{}); err != nil || got.Username != "alice" {
		t.Fatalf("the minted token as a bearer: %v %v", got.Username, err)
	}
	tok := tokenOf(t, db, "alice", TokenHash(raw))
	if tok.SignInMethod != SignInMethodPhone || tok.ApprovedByLabel != "iPhone" || tok.ViaToken != approver {
		t.Fatalf("method %q, approved by %q, via %q", tok.SignInMethod, tok.ApprovedByLabel, tok.ViaToken)
	}
	if tok.Label != "Phone sign-in: Mac" || tok.ClientPlatform != "macos" || !tok.CreatedAt.Equal(secs(at)) || tok.Kind != "" {
		t.Fatalf("token = %+v", tok)
	}
	for _, tk := range userNamed(t, db, "alice").Tokens {
		if tk.ID == approver && (tk.SignInMethod != "" || tk.ApprovedByLabel != "") {
			t.Fatalf("the approver itself reads as signed in by phone: %+v", tk)
		}
	}
	want := []signInEvent{{Username: "alice", At: at, TokenID: tok.ID, Label: "Phone sign-in: Mac",
		ApproverTokenID: approver, ApproverLabel: "iPhone", AddrMark: "mark-1"}}
	if got := signInEvents(t, db, "alice"); !slices.Equal(got, want) {
		t.Fatalf("events = %+v, want %+v", got, want)
	}
	if n, err := db.SignInsApprovedSince(approver, at.Add(-DesktopSignInWindow)); err != nil || n != 1 {
		t.Fatalf("SignInsApprovedSince = %d, %v", n, err)
	}
}

// The account the mint answers already holds the token it minted.
func TestMintDesktopSignInAnswersTheAccountWithItsNewToken(t *testing.T) {
	db, approver := desktopTestDB(t)
	u, raw, err := db.MintDesktopSignIn("alice", approver, "Phone sign-in: Mac", "macos", "m", at)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(u.Tokens, func(tok Token) bool { return tok.SHA256 == TokenHash(raw) }) {
		t.Fatalf("the answered account's tokens %+v lack the minted one", u.Tokens)
	}
}

// An off-shape platform is never written onto the row.
func TestMintDesktopSignInDropsAnOffShapePlatform(t *testing.T) {
	db, approver := desktopTestDB(t)
	_, raw, err := db.MintDesktopSignIn("alice", approver, "Mac", "Mac OS\u202e", "m", at)
	if err != nil {
		t.Fatal(err)
	}
	if tok := tokenOf(t, db, "alice", TokenHash(raw)); tok.ClientPlatform != "" {
		t.Fatalf("platform = %q", tok.ClientPlatform)
	}
}

func userNamed(t *testing.T, db *DB, name string) User {
	t.Helper()
	u, err := db.User(name)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// refusedMint asserts a mint answers want and leaves alice's tokens and audit
// rows as they were.
func refusedMint(t *testing.T, db *DB, name, approver string, now time.Time, want error) {
	t.Helper()
	tokens, events := tokenIDs(t, db, name), signInEvents(t, db, name)
	_, raw, err := db.MintDesktopSignIn(name, approver, "Mac", "macos", "m", now)
	if !errors.Is(err, want) || raw != "" {
		t.Fatalf("mint = %q, %v; want %v", raw, err, want)
	}
	if got := tokenIDs(t, db, name); !slices.Equal(got, tokens) {
		t.Fatalf("a refused mint changed the tokens: %v, was %v", got, tokens)
	}
	if got := signInEvents(t, db, name); !slices.Equal(got, events) {
		t.Fatalf("a refused mint changed the audit rows: %v, was %v", got, events)
	}
}

func TestMintDesktopSignInRefusesARevokedApprover(t *testing.T) {
	db, approver := desktopTestDB(t)
	if err := db.RevokeToken("alice", approver); err != nil {
		t.Fatal(err)
	}
	refusedMint(t, db, "alice", approver, at, ErrNoSuchToken)
}

// A password change signs every device out, the approver with them.
func TestMintDesktopSignInRefusesAfterAPasswordChange(t *testing.T) {
	db, approver := desktopTestDB(t)
	if err := db.SetPassword("alice", "a-new-password"); err != nil {
		t.Fatal(err)
	}
	refusedMint(t, db, "alice", approver, at, ErrNoSuchToken)
}

func TestMintDesktopSignInRefusesAnotherAccountsApprover(t *testing.T) {
	db, _ := desktopTestDB(t)
	if _, err := db.CreateUser("bob", "pw-bob-bob", RoleUser, Settings{}); err != nil {
		t.Fatal(err)
	}
	bobs := mintedID(t, db, "bob", "bob's phone")
	refusedMint(t, db, "alice", bobs, at, ErrNoSuchToken)
}

func TestMintDesktopSignInRefusesAWebApprover(t *testing.T) {
	db, _ := desktopTestDB(t)
	raw, err := db.MintWebSession("alice", "Web browser", false, at)
	if err != nil {
		t.Fatal(err)
	}
	web := tokenOf(t, db, "alice", WebSessionHash(raw)).ID
	refusedMint(t, db, "alice", web, at, ErrNoSuchToken)
}

// A computer signed in by phone never approves another sign-in.
func TestMintDesktopSignInRefusesAPhoneApprover(t *testing.T) {
	db, approver := desktopTestDB(t)
	_, raw, err := db.MintDesktopSignIn("alice", approver, "Mac", "macos", "m", at)
	if err != nil {
		t.Fatal(err)
	}
	planted := tokenOf(t, db, "alice", TokenHash(raw)).ID
	refusedMint(t, db, "alice", planted, at.Add(48*time.Hour), ErrNoSuchToken)
}

func TestMintDesktopSignInRefusesAnAdmin(t *testing.T) {
	db, _ := desktopTestDB(t)
	if err := db.EnsureAdmin("root", "pw-root-root"); err != nil {
		t.Fatal(err)
	}
	refusedMint(t, db, "root", mintedID(t, db, "root", "root's phone"), at, ErrAdminRefused)
}

func TestMintDesktopSignInRefusesAnInactiveAccount(t *testing.T) {
	db, approver := desktopTestDB(t)
	off := true
	if _, err := db.UpdateUser("alice", Settings{Disabled: &off}); err != nil {
		t.Fatal(err)
	}
	refusedMint(t, db, "alice", approver, at, ErrInactive)
}

func TestMintDesktopSignInRefusesTheFourthInADay(t *testing.T) {
	db, approver := desktopTestDB(t)
	for i := range DesktopSignInsPerDay {
		if _, _, err := db.MintDesktopSignIn("alice", approver, "Mac", "macos", "m", at.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatalf("sign-in %d: %v", i+1, err)
		}
	}
	refusedMint(t, db, "alice", approver, at.Add(23*time.Hour), ErrSignInLimit)
	if n, err := db.SignInsApprovedSince(approver, at.Add(23*time.Hour).Add(-DesktopSignInWindow)); err != nil || n != DesktopSignInsPerDay {
		t.Fatalf("SignInsApprovedSince = %d, %v", n, err)
	}
	// The limit is the approving device's, not the account's.
	if _, _, err := db.MintDesktopSignIn("alice", mintedID(t, db, "alice", "iPad"), "Mac", "macos", "m", at.Add(time.Hour)); err != nil {
		t.Fatalf("another approver: %v", err)
	}
	later := at.Add(2*time.Second + DesktopSignInWindow + time.Second)
	if _, _, err := db.MintDesktopSignIn("alice", approver, "Mac", "macos", "m", later); err != nil {
		t.Fatalf("a day and a second after the third: %v", err)
	}
}

func TestMintDesktopSignInNeverTrims(t *testing.T) {
	old := MaxTokensPerAccount
	MaxTokensPerAccount = 3
	t.Cleanup(func() { MaxTokensPerAccount = old })
	db, approver := desktopTestDB(t)
	mintedID(t, db, "alice", "laptop")
	tablet := mintedID(t, db, "alice", "tablet")
	refusedMint(t, db, "alice", approver, at, ErrTooManyDevices)
	if err := db.RevokeToken("alice", tablet); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.MintDesktopSignIn("alice", approver, "Mac", "macos", "m", at); err != nil {
		t.Fatalf("below the bound: %v", err)
	}
	if n := len(tokenIDs(t, db, "alice")); n != 3 {
		t.Fatalf("%d tokens, want 3", n)
	}
}

func TestSignInEventsKeepTheNewest100(t *testing.T) {
	db, approver := desktopTestDB(t)
	if _, err := db.CreateUser("bob", "pw-bob-bob", RoleUser, Settings{}); err != nil {
		t.Fatal(err)
	}
	insertSignInEvents(t, db, "alice", SignInEventsKept, at.Add(-48*time.Hour))
	insertSignInEvents(t, db, "bob", SignInEventsKept+5, at.Add(-48*time.Hour))
	oldest := signInEvents(t, db, "alice")[SignInEventsKept-1]
	if _, _, err := db.MintDesktopSignIn("alice", approver, "Mac", "macos", "m", at); err != nil {
		t.Fatal(err)
	}
	got := signInEvents(t, db, "alice")
	if len(got) != SignInEventsKept || got[0].At != at || got[0].Label != "Mac" {
		t.Fatalf("%d rows, newest %+v", len(got), got[0])
	}
	if slices.Contains(got, oldest) {
		t.Fatal("the oldest row survived")
	}
	if n := len(signInEvents(t, db, "bob")); n != SignInEventsKept+5 {
		t.Fatalf("bob's rows: %d; another account's mint trims only its own", n)
	}
}

func TestPruneSignInEventsDropsOlderThan90Days(t *testing.T) {
	db, _ := desktopTestDB(t)
	insertSignInEvents(t, db, "alice", 1, at.Add(-SignInEventsFor-time.Hour))
	insertSignInEvents(t, db, "alice", 1, at.Add(-SignInEventsFor+time.Hour))
	n, err := db.PruneSignInEvents(at.Add(-SignInEventsFor))
	if err != nil || n != 1 {
		t.Fatalf("PruneSignInEvents = %d, %v", n, err)
	}
	got := signInEvents(t, db, "alice")
	if len(got) != 1 || !got[0].At.Equal(at.Add(-SignInEventsFor+time.Hour)) {
		t.Fatalf("left %+v", got)
	}
}

// The audit rows go with their account.
func TestSignInEventsGoWithTheirAccount(t *testing.T) {
	db, approver := desktopTestDB(t)
	if _, _, err := db.MintDesktopSignIn("alice", approver, "Mac", "macos", "m", at); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteUser("alice"); err != nil {
		t.Fatal(err)
	}
	if got := signInEvents(t, db, "alice"); len(got) != 0 {
		t.Fatalf("rows outlived the account: %+v", got)
	}
}

func TestTokenKeepsApprovedByLabelAfterTheApproverGoes(t *testing.T) {
	db, approver := desktopTestDB(t)
	_, raw, err := db.MintDesktopSignIn("alice", approver, "Mac", "macos", "m", at)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.RevokeToken("alice", approver); err != nil {
		t.Fatal(err)
	}
	tok := tokenOf(t, db, "alice", TokenHash(raw))
	if tok.ViaToken != "" || tok.ApprovedByLabel != "iPhone" || tok.SignInMethod != SignInMethodPhone {
		t.Fatalf("after the approver went: via %q, approved by %q, method %q", tok.ViaToken, tok.ApprovedByLabel, tok.SignInMethod)
	}
	if e := signInEvents(t, db, "alice"); len(e) != 1 || e[0].ApproverLabel != "iPhone" || e[0].ApproverTokenID != approver {
		t.Fatalf("events = %+v", e)
	}
}
