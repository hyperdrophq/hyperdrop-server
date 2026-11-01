package metadb

import (
	"database/sql"
	"errors"
	"testing"
	"time"
)

// setViaToken records that token via approved token id.
func setViaToken(t *testing.T, db *DB, id, via string) {
	t.Helper()
	err := db.write(func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE tokens SET via_token = ? WHERE id = ?`, nullIfEmpty(via), id)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func viaTokenPair(t *testing.T) (db *DB, a, b Token) {
	t.Helper()
	db = openTest(t)
	if _, err := db.CreateUser("alice", "pw-alice", RoleUser, Settings{}); err != nil {
		t.Fatal(err)
	}
	for _, label := range []string{"desktop", "phone"} {
		if _, err := db.MintToken("alice", label); err != nil {
			t.Fatal(err)
		}
	}
	u, err := db.User("alice")
	if err != nil || len(u.Tokens) != 2 {
		t.Fatalf("tokens: %+v, %v", u.Tokens, err)
	}
	a, b = u.Tokens[0], u.Tokens[1]
	if a.Label != "desktop" {
		a, b = b, a
	}
	setViaToken(t, db, b.ID, a.ID)
	return db, a, b
}

func tokenByLabel(t *testing.T, db *DB, label string) Token {
	t.Helper()
	u, err := db.User("alice")
	if err != nil {
		t.Fatal(err)
	}
	for _, tok := range u.Tokens {
		if tok.Label == label {
			return tok
		}
	}
	t.Fatalf("no token %q in %+v", label, u.Tokens)
	return Token{}
}

func TestRevokingATokenNullsTheTokensItApproved(t *testing.T) {
	db, a, _ := viaTokenPair(t)
	if err := db.RevokeToken("alice", a.ID); err != nil {
		t.Fatal(err)
	}
	if got := tokenByLabel(t, db, "phone").ViaToken; got != "" {
		t.Fatalf("ViaToken = %q after the approver was revoked", got)
	}
}

// linkAccount makes alice with two devices and answers their token ids.
func linkAccount(t *testing.T) (db *DB, desktop, laptop Token) {
	t.Helper()
	db = openTest(t)
	if _, err := db.CreateUser("alice", "pw-alice", RoleUser, Settings{}); err != nil {
		t.Fatal(err)
	}
	for _, label := range []string{"desktop", "laptop"} {
		if _, err := db.MintToken("alice", label); err != nil {
			t.Fatal(err)
		}
	}
	return db, tokenByLabel(t, db, "desktop"), tokenByLabel(t, db, "laptop")
}

// mintLink mints a link from the desktop at at and answers it with its secret.
func mintLink(t *testing.T, db *DB, tok Token) (DeviceLink, string) {
	t.Helper()
	link, secret, err := db.MintDeviceLink("alice", tok.ID, "203.0.113.7", false, at)
	if err != nil {
		t.Fatal(err)
	}
	return link, secret
}

func linkState(t *testing.T, db *DB, tok Token, id string, now time.Time) string {
	t.Helper()
	link, err := db.DeviceLinkFor("alice", tok.ID, id, now)
	if err != nil {
		t.Fatal(err)
	}
	return link.State
}

func tokenCount(t *testing.T, db *DB) int {
	t.Helper()
	u, err := db.User("alice")
	if err != nil {
		t.Fatal(err)
	}
	return len(u.Tokens)
}

func otherNumber(n int) int {
	if n == 99 {
		return 10
	}
	return n + 1
}

func TestALinkIsClaimedApprovedAndSpentOnce(t *testing.T) {
	db, desktop, _ := linkAccount(t)
	link, secret := mintLink(t, db, desktop)
	if link.State != "minted" || !link.ExpiresAt.Equal(at.Add(30*time.Second)) || !link.WindowEndsAt.Equal(at.Add(3*time.Minute)) {
		t.Fatalf("minted link: %+v", link)
	}
	if link.ID == "" || secret == "" || link.Username != "alice" || link.MintedByToken != desktop.ID {
		t.Fatalf("minted link: %+v, secret %q", link, secret)
	}
	claim, err := db.ClaimDeviceLink(secret, "Pixel 9", "android", "203.0.113.7", at.Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if claim.Number < 10 || claim.Number > 99 || claim.Approver != "desktop" || claim.Username != "alice" ||
		claim.ClaimID == "" || claim.PollSecret == "" {
		t.Fatalf("claim: %+v", claim)
	}
	got, err := db.DeviceLinkFor("alice", desktop.ID, link.ID, at.Add(6*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if got.State != "claimed" || got.ClaimLabel != "Pixel 9" || got.ClaimPlatform != "android" || !got.ClaimSameAddr {
		t.Fatalf("claimed link: %+v", got)
	}
	if err := db.ApproveDeviceLink("alice", desktop.ID, link.ID, claim.Number, at.Add(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	u, token, pending, err := db.SpendDeviceLink(claim.ClaimID, claim.PollSecret, at.Add(11*time.Second))
	if err != nil || pending || token == "" || u.Username != "alice" {
		t.Fatalf("spend: %q, pending %v, %+v, %v", token, pending, u, err)
	}
	phone := tokenByLabel(t, db, "Pixel 9")
	if phone.ViaToken != desktop.ID || phone.SHA256 != TokenHash(token) {
		t.Fatalf("phone token: %+v", phone)
	}
	if _, _, _, err := db.SpendDeviceLink(claim.ClaimID, claim.PollSecret, at.Add(12*time.Second)); !errors.Is(err, ErrDeviceLinkInvalid) {
		t.Fatalf("second spend: %v", err)
	}
	if s := linkState(t, db, desktop, link.ID, at.Add(13*time.Second)); s != "spent" {
		t.Fatalf("state = %q", s)
	}
}

func TestSpendIsPendingUntilApproved(t *testing.T) {
	db, desktop, _ := linkAccount(t)
	link, secret := mintLink(t, db, desktop)
	claim, err := db.ClaimDeviceLink(secret, "Pixel 9", "android", "198.51.100.2", at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := db.DeviceLinkFor("alice", desktop.ID, link.ID, at.Add(time.Second)); err != nil || got.ClaimSameAddr {
		t.Fatalf("a claim from another address: %+v, %v", got, err)
	}
	n := tokenCount(t, db)
	_, token, pending, err := db.SpendDeviceLink(claim.ClaimID, claim.PollSecret, at.Add(2*time.Second))
	if err != nil || !pending || token != "" {
		t.Fatalf("spend before approve: %q, pending %v, %v", token, pending, err)
	}
	if tokenCount(t, db) != n {
		t.Fatal("a pending spend minted a token")
	}
}

func TestASecondClaimBurnsTheLink(t *testing.T) {
	db, desktop, _ := linkAccount(t)
	link, secret := mintLink(t, db, desktop)
	first, err := db.ClaimDeviceLink(secret, "Pixel 9", "android", "203.0.113.7", at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ClaimDeviceLink(secret, "iPhone", "ios", "192.0.2.9", at.Add(2*time.Second)); !errors.Is(err, ErrDeviceLinkInvalid) {
		t.Fatalf("second claim: %v", err)
	}
	if s := linkState(t, db, desktop, link.ID, at.Add(3*time.Second)); s != "burned" {
		t.Fatalf("state = %q", s)
	}
	if _, _, _, err := db.SpendDeviceLink(first.ClaimID, first.PollSecret, at.Add(4*time.Second)); !errors.Is(err, ErrDeviceLinkInvalid) {
		t.Fatalf("first claimer's spend: %v", err)
	}
}

func TestAWrongNumberBurnsTheLink(t *testing.T) {
	db, desktop, _ := linkAccount(t)
	link, secret := mintLink(t, db, desktop)
	claim, err := db.ClaimDeviceLink(secret, "Pixel 9", "android", "203.0.113.7", at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	err = db.ApproveDeviceLink("alice", desktop.ID, link.ID, otherNumber(claim.Number), at.Add(2*time.Second))
	if !errors.Is(err, ErrDeviceLinkWrongNumber) {
		t.Fatalf("wrong number: %v", err)
	}
	if s := linkState(t, db, desktop, link.ID, at.Add(3*time.Second)); s != "burned" {
		t.Fatalf("state = %q", s)
	}
	if err := db.ApproveDeviceLink("alice", desktop.ID, link.ID, claim.Number, at.Add(4*time.Second)); !errors.Is(err, ErrDeviceLinkInvalid) {
		t.Fatalf("approve after the burn: %v", err)
	}
}

func TestAnUnclaimedLinkExpiresAfterThirtySeconds(t *testing.T) {
	db, desktop, _ := linkAccount(t)
	link, secret := mintLink(t, db, desktop)
	if _, err := db.ClaimDeviceLink(secret, "Pixel 9", "android", "203.0.113.7", at.Add(30*time.Second)); !errors.Is(err, ErrDeviceLinkInvalid) {
		t.Fatalf("late claim: %v", err)
	}
	if s := linkState(t, db, desktop, link.ID, at.Add(30*time.Second)); s != "expired" {
		t.Fatalf("state = %q", s)
	}
}

func TestRenewKeepsTheIDAndReplacesTheSecret(t *testing.T) {
	db, desktop, _ := linkAccount(t)
	link, secret := mintLink(t, db, desktop)
	renewed, secret2, err := db.RenewDeviceLink("alice", desktop.ID, link.ID, at.Add(31*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if renewed.ID != link.ID || secret2 == "" || secret2 == secret || renewed.State != "minted" ||
		!renewed.ExpiresAt.Equal(at.Add(61*time.Second)) || !renewed.WindowEndsAt.Equal(link.WindowEndsAt) {
		t.Fatalf("renewed: %+v, secret %q", renewed, secret2)
	}
	if _, err := db.ClaimDeviceLink(secret, "Pixel 9", "android", "203.0.113.7", at.Add(32*time.Second)); !errors.Is(err, ErrDeviceLinkInvalid) {
		t.Fatalf("old secret's claim: %v", err)
	}
	if _, _, err := db.RenewDeviceLink("alice", desktop.ID, link.ID, at.Add(3*time.Minute)); !errors.Is(err, ErrDeviceLinkInvalid) {
		t.Fatalf("renew past the window: %v", err)
	}
	if _, err := db.ClaimDeviceLink(secret2, "Pixel 9", "android", "203.0.113.7", at.Add(33*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.RenewDeviceLink("alice", desktop.ID, link.ID, at.Add(34*time.Second)); !errors.Is(err, ErrDeviceLinkInvalid) {
		t.Fatalf("renew of a claimed link: %v", err)
	}
}

func TestAnApprovedLinkPolledAfterItsWindowMintsNothing(t *testing.T) {
	db, desktop, _ := linkAccount(t)
	link, secret := mintLink(t, db, desktop)
	claimAt := at.Add(2 * time.Second)
	claim, err := db.ClaimDeviceLink(secret, "Pixel 9", "android", "203.0.113.7", claimAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.ApproveDeviceLink("alice", desktop.ID, link.ID, claim.Number, claimAt.Add(4*time.Minute+59*time.Second)); err != nil {
		t.Fatal(err)
	}
	n := tokenCount(t, db)
	if _, _, _, err := db.SpendDeviceLink(claim.ClaimID, claim.PollSecret, claimAt.Add(5*time.Minute+time.Second)); !errors.Is(err, ErrDeviceLinkInvalid) {
		t.Fatalf("late spend: %v", err)
	}
	if tokenCount(t, db) != n {
		t.Fatal("a late spend minted a token")
	}
}

func TestABurnAfterApprovalWins(t *testing.T) {
	db, desktop, _ := linkAccount(t)
	link, secret := mintLink(t, db, desktop)
	claim, err := db.ClaimDeviceLink(secret, "Pixel 9", "android", "203.0.113.7", at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.ApproveDeviceLink("alice", desktop.ID, link.ID, claim.Number, at.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := db.BurnDeviceLink("alice", desktop.ID, link.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := db.SpendDeviceLink(claim.ClaimID, claim.PollSecret, at.Add(3*time.Second)); !errors.Is(err, ErrDeviceLinkInvalid) {
		t.Fatalf("spend after the burn: %v", err)
	}
}

func TestMintingKillsTheAccountsOtherLink(t *testing.T) {
	db, desktop, laptop := linkAccount(t)
	_, first := mintLink(t, db, desktop)
	mintLink(t, db, laptop)
	if _, err := db.ClaimDeviceLink(first, "Pixel 9", "android", "203.0.113.7", at.Add(time.Second)); !errors.Is(err, ErrDeviceLinkInvalid) {
		t.Fatalf("claim of the older link: %v", err)
	}
}

func TestOnlyTheMintingTokenSeesTheLink(t *testing.T) {
	db, desktop, laptop := linkAccount(t)
	link, secret := mintLink(t, db, desktop)
	if _, err := db.DeviceLinkFor("alice", laptop.ID, link.ID, at); !errors.Is(err, ErrDeviceLinkInvalid) {
		t.Fatalf("read by another token: %v", err)
	}
	if _, _, err := db.RenewDeviceLink("alice", laptop.ID, link.ID, at.Add(time.Second)); !errors.Is(err, ErrDeviceLinkInvalid) {
		t.Fatalf("renew by another token: %v", err)
	}
	claim, err := db.ClaimDeviceLink(secret, "Pixel 9", "android", "203.0.113.7", at.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.ApproveDeviceLink("alice", laptop.ID, link.ID, claim.Number, at.Add(3*time.Second)); !errors.Is(err, ErrDeviceLinkInvalid) {
		t.Fatalf("approve by another token: %v", err)
	}
	if err := db.BurnDeviceLink("alice", laptop.ID, link.ID); !errors.Is(err, ErrDeviceLinkInvalid) {
		t.Fatalf("burn by another token: %v", err)
	}
	if s := linkState(t, db, desktop, link.ID, at.Add(4*time.Second)); s != "claimed" {
		t.Fatalf("state = %q", s)
	}
}

func TestRevokingTheMintingDeviceKillsItsLink(t *testing.T) {
	for _, signOut := range []struct {
		name string
		do   func(db *DB, desktop Token) error
	}{
		{"revoke", func(db *DB, desktop Token) error { return db.RevokeToken("alice", desktop.ID) }},
		{"password", func(db *DB, _ Token) error { return db.SetPassword("alice", "pw-new") }},
	} {
		t.Run(signOut.name, func(t *testing.T) {
			db, desktop, _ := linkAccount(t)
			link, secret := mintLink(t, db, desktop)
			claim, err := db.ClaimDeviceLink(secret, "Pixel 9", "android", "203.0.113.7", at.Add(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			if err := db.ApproveDeviceLink("alice", desktop.ID, link.ID, claim.Number, at.Add(2*time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := signOut.do(db, desktop); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := db.SpendDeviceLink(claim.ClaimID, claim.PollSecret, at.Add(3*time.Second)); !errors.Is(err, ErrDeviceLinkInvalid) {
				t.Fatalf("spend after the sign-out: %v", err)
			}
		})
	}
}

func TestADisabledAccountCannotCollect(t *testing.T) {
	db, desktop, _ := linkAccount(t)
	link, secret := mintLink(t, db, desktop)
	claim, err := db.ClaimDeviceLink(secret, "Pixel 9", "android", "203.0.113.7", at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.ApproveDeviceLink("alice", desktop.ID, link.ID, claim.Number, at.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	off := true
	if _, err := db.UpdateUser("alice", Settings{Disabled: &off}); err != nil {
		t.Fatal(err)
	}
	n := tokenCount(t, db)
	if _, _, _, err := db.SpendDeviceLink(claim.ClaimID, claim.PollSecret, at.Add(3*time.Second)); !errors.Is(err, ErrInactive) {
		t.Fatalf("spend on a disabled account: %v", err)
	}
	if tokenCount(t, db) != n {
		t.Fatal("a disabled account's spend minted a token")
	}
}

func TestAWrongPollSecretIsRefused(t *testing.T) {
	db, desktop, _ := linkAccount(t)
	link, secret := mintLink(t, db, desktop)
	claim, err := db.ClaimDeviceLink(secret, "Pixel 9", "android", "203.0.113.7", at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.ApproveDeviceLink("alice", desktop.ID, link.ID, claim.Number, at.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := db.SpendDeviceLink(claim.ClaimID, claim.PollSecret+"x", at.Add(3*time.Second)); !errors.Is(err, ErrDeviceLinkInvalid) {
		t.Fatalf("wrong poll secret: %v", err)
	}
	if _, token, _, err := db.SpendDeviceLink(claim.ClaimID, claim.PollSecret, at.Add(4*time.Second)); err != nil || token == "" {
		t.Fatalf("right poll secret: %q, %v", token, err)
	}
}

func TestPruneRemovesLinksOlderThanADay(t *testing.T) {
	db, desktop, _ := linkAccount(t)
	if _, err := db.CreateUser("bob", "pw-bob", RoleUser, Settings{}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.MintToken("bob", "desktop"); err != nil {
		t.Fatal(err)
	}
	bob, err := db.User("bob")
	if err != nil {
		t.Fatal(err)
	}
	old, _, err := db.MintDeviceLink("alice", desktop.ID, "203.0.113.7", false, at)
	if err != nil {
		t.Fatal(err)
	}
	fresh, _, err := db.MintDeviceLink("bob", bob.Tokens[0].ID, "203.0.113.8", false, at.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	now := at.Add(25 * time.Hour)
	n, err := db.PruneDeviceLinks(now.Add(-24 * time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("prune: %d, %v", n, err)
	}
	if _, err := db.DeviceLinkFor("alice", desktop.ID, old.ID, now); !errors.Is(err, ErrDeviceLinkInvalid) {
		t.Fatalf("pruned link: %v", err)
	}
	if _, err := db.DeviceLinkFor("bob", bob.Tokens[0].ID, fresh.ID, now); err != nil {
		t.Fatalf("kept link: %v", err)
	}
}

func TestMintRecordsSteppedUp(t *testing.T) {
	db, desktop, _ := linkAccount(t)
	for _, steppedUp := range []bool{true, false} {
		link, _, err := db.MintDeviceLink("alice", desktop.ID, "203.0.113.7", steppedUp, at)
		if err != nil {
			t.Fatal(err)
		}
		got, err := db.DeviceLinkFor("alice", desktop.ID, link.ID, at)
		if err != nil || got.SteppedUp != steppedUp {
			t.Fatalf("minted stepped up %v: %+v, %v", steppedUp, got, err)
		}
	}
}

func TestMatchDeviceLinkNumber(t *testing.T) {
	db, desktop, _ := linkAccount(t)
	link, secret := mintLink(t, db, desktop)
	if _, err := db.MatchDeviceLinkNumber("alice", desktop.ID, link.ID, 42, at.Add(time.Second)); !errors.Is(err, ErrDeviceLinkInvalid) {
		t.Fatalf("an unclaimed link: %v", err)
	}
	claim, err := db.ClaimDeviceLink(secret, "Pixel 9", "android", "203.0.113.7", at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	steppedUp, err := db.MatchDeviceLinkNumber("alice", desktop.ID, link.ID, claim.Number, at.Add(2*time.Second))
	if err != nil || steppedUp {
		t.Fatalf("the right number: stepped up %v, %v", steppedUp, err)
	}
	if s := linkState(t, db, desktop, link.ID, at.Add(3*time.Second)); s != "claimed" {
		t.Fatalf("a matched number moved the link to %q", s)
	}
	if _, err := db.MatchDeviceLinkNumber("alice", desktop.ID, link.ID, otherNumber(claim.Number), at.Add(4*time.Second)); !errors.Is(err, ErrDeviceLinkWrongNumber) {
		t.Fatalf("a wrong number: %v", err)
	}
	if s := linkState(t, db, desktop, link.ID, at.Add(5*time.Second)); s != "burned" {
		t.Fatalf("a wrong number left the link %q", s)
	}
}

func TestAMatchedSteppedUpLinkSaysSo(t *testing.T) {
	db, desktop, _ := linkAccount(t)
	link, secret, err := db.MintDeviceLink("alice", desktop.ID, "203.0.113.7", true, at)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := db.ClaimDeviceLink(secret, "Pixel 9", "android", "203.0.113.7", at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if steppedUp, err := db.MatchDeviceLinkNumber("alice", desktop.ID, link.ID, claim.Number, at.Add(2*time.Second)); err != nil || !steppedUp {
		t.Fatalf("stepped up %v, %v", steppedUp, err)
	}
}

func TestAClaimLastsFiveMinutes(t *testing.T) {
	db, desktop, _ := linkAccount(t)
	link, secret := mintLink(t, db, desktop)
	claimAt := at.Add(time.Second)
	if _, err := db.ClaimDeviceLink(secret, "Pixel 9", "android", "203.0.113.7", claimAt); err != nil {
		t.Fatal(err)
	}
	if s := linkState(t, db, desktop, link.ID, claimAt.Add(5*time.Minute-time.Second)); s != "claimed" {
		t.Fatalf("at 4:59 the claim is %q", s)
	}
	if s := linkState(t, db, desktop, link.ID, claimAt.Add(5*time.Minute)); s != "expired" {
		t.Fatalf("at 5:00 the claim is %q", s)
	}
}

func TestAClaimAnswersItsLinkID(t *testing.T) {
	db, desktop, _ := linkAccount(t)
	link, secret := mintLink(t, db, desktop)
	claim, err := db.ClaimDeviceLink(secret, "Pixel 9", "android", "203.0.113.7", at.Add(time.Second))
	if err != nil || claim.LinkID != link.ID {
		t.Fatalf("claim's link id %q, want %q (%v)", claim.LinkID, link.ID, err)
	}
}
