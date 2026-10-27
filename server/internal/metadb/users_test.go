package metadb

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func ptr[T any](v T) *T { return &v }

func TestCreateUserStoresSettingsAndRejectsBadNames(t *testing.T) {
	db := openTest(t)
	exp := at.Add(48 * time.Hour)
	u, err := db.CreateUser("alice", "pw", RoleUser, Settings{
		QuotaBytes: ptr(int64(100)), NoEmbed: ptr(true), AccountExpiresAt: &exp, SourceRoots: ptr([]string{"photos", "docs"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if u.Username != "alice" || u.Role != RoleUser || u.QuotaBytes != 100 || !u.NoEmbed || u.PasswordHash == "" || u.PasswordHash == "pw" {
		t.Fatalf("created user = %+v", u)
	}
	if u.AccountExpiresAt == nil || !u.AccountExpiresAt.Equal(exp) || len(u.SourceRoots) != 2 {
		t.Fatalf("expiry/roots not stored: %+v", u)
	}
	got, err := db.User("alice")
	if err != nil || got.QuotaBytes != 100 || len(got.SourceRoots) != 2 || got.SourceRoots[0] != "docs" {
		t.Fatalf("User() = %+v, %v (roots come back sorted)", got, err)
	}
	if _, err := db.CreateUser("alice", "pw", RoleUser, Settings{}); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate: err = %v, want ErrExists", err)
	}
	for _, bad := range []string{"ab", "Alice", "a b", "toolongtoolongtoolongtoolongtoolong"} {
		if _, err := db.CreateUser(bad, "pw", RoleUser, Settings{}); !errors.Is(err, ErrBadName) {
			t.Errorf("%q: err = %v, want ErrBadName", bad, err)
		}
	}
	if _, err := db.User("nobody"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("missing: err = %v", err)
	}
}

func TestUpdateUserAppliesOnlyPointersAndClearsExpiry(t *testing.T) {
	db := openTest(t)
	exp := at.Add(time.Hour)
	if _, err := db.CreateUser("alice", "pw", RoleUser, Settings{QuotaBytes: ptr(int64(5)), AccountExpiresAt: &exp}); err != nil {
		t.Fatal(err)
	}
	u, err := db.UpdateUser("alice", Settings{Role: ptr(RoleAdmin), Disabled: ptr(true)})
	if err != nil || u.Role != RoleAdmin || !u.Disabled || u.QuotaBytes != 5 || u.AccountExpiresAt == nil {
		t.Fatalf("partial update: %+v, %v", u, err)
	}
	u, err = db.UpdateUser("alice", Settings{ClearAccountExpiry: true, SourceRoots: ptr([]string{})})
	if err != nil || u.AccountExpiresAt != nil || len(u.SourceRoots) != 0 {
		t.Fatalf("clear: %+v, %v", u, err)
	}
	if !u.Active(at) {
		// disabled is still true
	} else {
		t.Fatal("a disabled account must not be active")
	}
}

func TestUsersAreSortedAndDeleteIsRefusedWhileSharesExist(t *testing.T) {
	db := openTest(t)
	for _, n := range []string{"carol", "alice", "bob"} {
		if _, err := db.CreateUser(n, "pw", RoleUser, Settings{}); err != nil {
			t.Fatal(err)
		}
	}
	list, err := db.Users()
	if err != nil || len(list) != 3 || list[0].Username != "alice" || list[2].Username != "carol" {
		t.Fatalf("Users() = %v, %v", list, err)
	}
	seedShare(t, db, "abcdefghjk", "bob")
	if err := db.DeleteUser("bob"); !errors.Is(err, ErrConflict) {
		t.Fatalf("delete owner of shares: err = %v, want ErrConflict", err)
	}
	if err := db.DeleteUser("carol"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.User("carol"); !errors.Is(err, ErrUserNotFound) {
		t.Fatal("carol still exists")
	}
	if err := db.DeleteUser("carol"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("second delete: %v", err)
	}
}

func TestEnsureAdminCreatesOnceAndResetAdminFollowsTheRules(t *testing.T) {
	db := openTest(t)
	if err := db.EnsureAdmin("", ""); err == nil {
		t.Fatal("EnsureAdmin with no password on an empty volume must fail")
	}
	if err := db.EnsureAdmin("", "secret"); err != nil {
		t.Fatal(err)
	}
	names, _ := db.AdminNames()
	if len(names) != 1 || names[0] != DefaultAdminName {
		t.Fatalf("AdminNames = %v", names)
	}
	if err := db.EnsureAdmin("other", "x"); err != nil {
		t.Fatal("EnsureAdmin must be a no-op once an admin exists")
	}
	if _, err := db.User("other"); !errors.Is(err, ErrUserNotFound) {
		t.Fatal("EnsureAdmin created a second admin")
	}
	if _, err := db.ResetAdmin("", ""); err == nil {
		t.Fatal("ResetAdmin without a password must fail")
	}
	name, err := db.ResetAdmin("", "newpw")
	if err != nil || name != DefaultAdminName {
		t.Fatalf("ResetAdmin single admin: %q, %v", name, err)
	}
	if _, err := db.Authenticate(DefaultAdminName, "newpw"); err != nil {
		t.Fatalf("new password rejected: %v", err)
	}
	if _, err := db.CreateUser("bob", "pw", RoleUser, Settings{}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ResetAdmin("bob", "x"); err == nil {
		t.Fatal("resetting a non-admin must be refused")
	}
	name, err = db.ResetAdmin("fresh", "x")
	if err != nil || name != "fresh" {
		t.Fatalf("ResetAdmin new name: %q, %v", name, err)
	}
	if _, err = db.ResetAdmin("", "x"); err == nil {
		t.Fatal("two admins and no name must be refused")
	}
}

func TestAuthenticateAndPasswordChangeRevokesTokens(t *testing.T) {
	db := openTest(t)
	if _, err := db.CreateUser("alice", "pw", RoleUser, Settings{}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Authenticate("alice", "wrong"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err := db.Authenticate("nobody", "pw"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("unknown user: %v", err)
	}
	raw, err := db.MintToken("alice", "mac")
	if err != nil || !strings.HasPrefix(raw, "hd_u_") || len(raw) != 5+64 {
		t.Fatalf("MintToken: %q, %v", raw, err)
	}
	u, err := db.UserByToken(raw, ClientInfo{})
	if err != nil || u.Username != "alice" || len(u.Tokens) != 1 || u.Tokens[0].Label != "mac" || u.Tokens[0].SHA256 != TokenHash(raw) {
		t.Fatalf("UserByToken: %+v, %v", u, err)
	}
	if _, err := db.UserByToken("hd_u_nope", ClientInfo{}); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("bad token: %v", err)
	}
	if err := db.SetPasswordKeepingTokens("alice", "pw2"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.UserByToken(raw, ClientInfo{}); err != nil {
		t.Fatal("SetPasswordKeepingTokens must keep the token")
	}
	if err := db.SetPassword("alice", "pw3"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.UserByToken(raw, ClientInfo{}); !errors.Is(err, ErrBadCredentials) {
		t.Fatal("SetPassword must revoke every token")
	}
	if _, err := db.Authenticate("alice", "pw3"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.UpdateUser("alice", Settings{Disabled: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Authenticate("alice", "pw3"); !errors.Is(err, ErrInactive) {
		t.Fatalf("disabled: %v", err)
	}
}

func TestTokensRevokeIndividuallyAndRecordLastUse(t *testing.T) {
	db := openTest(t)
	if _, err := db.CreateUser("alice", "pw", RoleUser, Settings{}); err != nil {
		t.Fatal(err)
	}
	a, _ := db.MintToken("alice", "a")
	b, _ := db.MintToken("alice", "b")
	u, _ := db.User("alice")
	if len(u.Tokens) != 2 {
		t.Fatalf("tokens = %d", len(u.Tokens))
	}
	if _, err := db.UserByToken(a, ClientInfo{}); err != nil {
		t.Fatal(err)
	}
	u, _ = db.User("alice")
	var used int
	for _, tok := range u.Tokens {
		if !tok.LastUsedAt.IsZero() {
			used++
		}
	}
	if used != 1 {
		t.Fatalf("last-used stamped on %d tokens, want 1", used)
	}
	if err := db.RevokeToken("alice", u.Tokens[0].ID); err != nil {
		t.Fatal(err)
	}
	u, _ = db.User("alice")
	if len(u.Tokens) != 1 {
		t.Fatalf("after revoke: %d tokens", len(u.Tokens))
	}
	_ = b
	if _, err := db.MintTokenIfPasswordIs("alice", "c", "stale-hash", "", at); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("stale hash: %v", err)
	}
	if _, err := db.MintTokenIfPasswordIs("alice", "c", u.PasswordHash, "", at); err != nil {
		t.Fatalf("current hash, no 2FA: %v", err)
	}
	if _, err := db.UserByToken(TokenHash("not-a-raw-token"), ClientInfo{}); !errors.Is(err, ErrBadCredentials) {
		t.Fatal("a hash passed as a raw token must not authenticate")
	}
}

func TestAReplacementTokenKeepsTheDevicesSignInTime(t *testing.T) {
	db := openTest(t)
	if _, err := db.CreateUser("alice", "pw", RoleUser, Settings{}); err != nil {
		t.Fatal(err)
	}
	signedIn := at.Add(-72 * time.Hour)
	raw, err := db.MintTokenCreatedAt("alice", "mac", signedIn)
	if err != nil {
		t.Fatal(err)
	}
	u, err := db.User("alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(u.Tokens) != 1 || u.Tokens[0].SHA256 != TokenHash(raw) || !u.Tokens[0].CreatedAt.Equal(secs(signedIn)) {
		t.Fatalf("tokens = %+v, want one created at %v", u.Tokens, secs(signedIn))
	}
}

// A chosen password is measured in bytes, as bcrypt reads it.
func TestCheckChosenPasswordBoundsTheLength(t *testing.T) {
	for pw, want := range map[string]error{
		"":                      ErrPasswordTooShort,
		"seven77":               ErrPasswordTooShort,
		"eight888":              nil,
		"  spaces count too  ":  nil,
		strings.Repeat("x", 72): nil,
		strings.Repeat("x", 73): ErrPasswordTooLong,
		strings.Repeat("é", 36): nil,
		strings.Repeat("é", 37): ErrPasswordTooLong,
	} {
		got := CheckChosenPassword(pw)
		if want == nil && got != nil || want != nil && !errors.Is(got, want) {
			t.Errorf("CheckChosenPassword(%q) = %v, want %v", pw, got, want)
		}
	}
}
