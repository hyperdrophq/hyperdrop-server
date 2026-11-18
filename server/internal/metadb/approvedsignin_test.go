package metadb

import (
	"testing"
	"time"
)

func approvedTokenIn(t *testing.T, u User, hash string) Token {
	t.Helper()
	for _, tok := range u.Tokens {
		if tok.SHA256 == hash {
			return tok
		}
	}
	t.Fatalf("the answer lists no token for that sign-in: %d tokens", len(u.Tokens))
	return Token{}
}

// A browser a phone approved is marked, and names its approver as it was
// labelled: the alarm is raised from those, and the account the mint answers
// holds the new row, or the alarm has no token to name.
func TestABrowserAPhoneApprovedIsMarked(t *testing.T) {
	db := openTest(t)
	if _, err := db.CreateUser("bob", "bob-password-1", RoleUser, Settings{}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.MintToken("bob", "Pixel 9"); err != nil {
		t.Fatal(err)
	}
	u, err := db.User("bob")
	if err != nil {
		t.Fatal(err)
	}
	u, raw, err := db.MintWebSessionApprovedBy("bob", u.Tokens[0].ID, "Web browser · Firefox", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tok := approvedTokenIn(t, u, WebSessionHash(raw))
	if tok.SignInMethod != SignInMethodApproved || tok.ApprovedByLabel != "Pixel 9" {
		t.Fatalf("method %q, approved by %q", tok.SignInMethod, tok.ApprovedByLabel)
	}
}

// A phone added through a device link is marked apart from a computer a phone
// signed in, which may never approve another device: the new phone may.
func TestAPhoneAddedByLinkIsMarkedAndMayStillApprove(t *testing.T) {
	db := openTest(t)
	if _, err := db.CreateUser("bob", "bob-password-1", RoleUser, Settings{}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.MintToken("bob", "MacBook"); err != nil {
		t.Fatal(err)
	}
	u, err := db.User("bob")
	if err != nil {
		t.Fatal(err)
	}
	minter := u.Tokens[0].ID
	now := time.Now()
	_, secret, err := db.MintDeviceLink("bob", minter, "mark", false, now)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := db.ClaimDeviceLink(secret, "Pixel 9", "android", "mark", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.ApproveDeviceLink("bob", minter, claim.LinkID, claim.Number, now); err != nil {
		t.Fatal(err)
	}
	u, raw, pending, err := db.SpendDeviceLink(claim.ClaimID, claim.PollSecret, now)
	if err != nil || pending {
		t.Fatalf("spend: %v, pending %v", err, pending)
	}
	tok := approvedTokenIn(t, u, TokenHash(raw))
	if tok.SignInMethod != SignInMethodApproved || tok.ApprovedByLabel != "MacBook" || tok.ClientPlatform != "android" {
		t.Fatalf("method %q, approved by %q, platform %q", tok.SignInMethod, tok.ApprovedByLabel, tok.ClientPlatform)
	}
	if tok.SignInMethod == SignInMethodPhone {
		t.Fatal("marked so it may not approve")
	}
	if _, _, err := db.MintWebSessionApprovedBy("bob", tok.ID, "Web browser · Firefox", now); err != nil {
		t.Fatalf("the new phone cannot approve a browser: %v", err)
	}
}
