package metadb

import (
	"database/sql"
	"errors"
	"slices"
	"testing"
	"time"

	"hyperdrop/server/internal/metadb/prevrelease"
)

// rollbackVolume is what this tree wrote before the previous release opens
// the volume: the raw credentials and ids the later steps check against.
type rollbackVolume struct {
	phone, studio, desktop, desktop2  string // alice's device token ids
	rawPhone, rawDesktop, rawDesktop2 string
	webID, approvedWebID              string // alice's web session ids
	rawWeb                            string
	bobPhone                          string
	linkID, linkSecret                string // a device link the studio minted
	shareID, slugA, slugC             string
	tokenCount                        int
	recovery                          []string // the owner's recovery codes
}

// writeReleaseVolume fills dataDir with this tree's metadb: an administrator;
// alice with a phone, a computer signed in by password, two computers the
// phone signed in (their sign_in_events rows beside them), a web session and
// one the phone approved, and a device link; bob with a computer his phone
// signed in; a share of alice's with two committed files; and the
// administrator's second factor with its recovery codes.
func writeReleaseVolume(t *testing.T, dataDir string, now time.Time) rollbackVolume {
	t.Helper()
	db, err := Open(dataDir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()
	for _, u := range []struct{ name, role string }{{"owner", RoleAdmin}, {"alice", RoleUser}, {"bob", RoleUser}} {
		if _, err := db.CreateUser(u.name, "pw-"+u.name, u.role, Settings{}); err != nil {
			t.Fatal(err)
		}
	}
	var v rollbackVolume
	if v.rawPhone, err = db.MintToken("alice", "iPhone"); err != nil {
		t.Fatal(err)
	}
	v.phone = tokenOf(t, db, "alice", TokenHash(v.rawPhone)).ID
	v.studio = mintedID(t, db, "alice", "Mac Studio")
	if _, v.rawDesktop, err = db.MintDesktopSignIn("alice", v.phone, "MacBook", "macos", "mark-1", now); err != nil {
		t.Fatal(err)
	}
	v.desktop = tokenOf(t, db, "alice", TokenHash(v.rawDesktop)).ID
	if _, v.rawDesktop2, err = db.MintDesktopSignIn("alice", v.phone, "Windows PC", "windows", "mark-2", now); err != nil {
		t.Fatal(err)
	}
	v.desktop2 = tokenOf(t, db, "alice", TokenHash(v.rawDesktop2)).ID
	if v.rawWeb, err = db.MintWebSession("alice", "Firefox", false, now); err != nil {
		t.Fatal(err)
	}
	v.webID = tokenOf(t, db, "alice", WebSessionHash(v.rawWeb)).ID
	_, rawApproved, err := db.MintWebSessionApprovedBy("alice", v.phone, "Chrome", now)
	if err != nil {
		t.Fatal(err)
	}
	v.approvedWebID = tokenOf(t, db, "alice", WebSessionHash(rawApproved)).ID
	link, secret, err := db.MintDeviceLink("alice", v.studio, "203.0.113.7", false, now)
	if err != nil {
		t.Fatal(err)
	}
	v.linkID, v.linkSecret = link.ID, secret

	v.bobPhone = mintedID(t, db, "bob", "Pixel")
	if _, _, err := db.MintDesktopSignIn("bob", v.bobPhone, "ThinkPad", "linux", "mark-3", now); err != nil {
		t.Fatal(err)
	}

	d, err := db.CreateShare(CreateOptions{Name: "Holiday", Owner: "alice", Folder: true,
		Files: []PendingFile{{Path: "a.txt", Size: 3}, {Path: "b/c.txt", Size: 5}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []PendingFile{{Path: "a.txt", Size: 3}, {Path: "b/c.txt", Size: 5}} {
		if _, err := db.CommitFile(CommitInput{ShareID: d.ID, Path: f.Path, Size: f.Size, Mime: "text/plain"}); err != nil {
			t.Fatal(err)
		}
	}
	v.shareID = d.ID
	v.slugA, v.slugC = fileSlug(t, db, d.ID, "a.txt"), fileSlug(t, db, d.ID, "b/c.txt")

	desktop := tokenOf(t, db, "alice", TokenHash(v.rawDesktop))
	if desktop.SignInMethod != SignInMethodPhone || desktop.ApprovedByLabel != "iPhone" || desktop.ViaToken != v.phone {
		t.Fatalf("the computer the phone signed in: %+v", desktop)
	}
	if n := len(signInEvents(t, db, "alice")); n != 2 {
		t.Fatalf("alice's sign-in events before the rollback = %d, want 2", n)
	}
	v.tokenCount = len(tokenIDs(t, db, "alice"))

	totpSecret, err := db.StartTOTP("owner")
	if err != nil {
		t.Fatal(err)
	}
	if v.recovery, err = db.ConfirmTOTP("owner", codeAt(t, totpSecret, now), now); err != nil {
		t.Fatal(err)
	}
	return v
}

// prevToken is alice's token with id in the previous release's reading.
func prevToken(t *testing.T, u prevrelease.User, id string) prevrelease.Token {
	t.Helper()
	for _, tok := range u.Tokens {
		if tok.ID == id {
			return tok
		}
	}
	t.Fatalf("%s holds no token %s in the previous release's reading", u.Username, id)
	return prevrelease.Token{}
}

// Every update path restarts the previous binary when the new one does not
// come healthy, so the previous server release (prevrelease, frozen from its
// commit by freeze.sh) must open, serve and edit a volume this tree wrote,
// and this tree must read the volume back whole afterwards: the additive
// columns and the sign_in_events rows kept, every row the previous release
// wrote read as it wrote it.
func TestThePreviousReleaseServesAVolumeThisTreeWrote(t *testing.T) {
	if prevrelease.Version == "" || prevrelease.Commit == "" {
		t.Fatal("prevrelease carries no frozen release")
	}
	dir := t.TempDir()
	now := time.Now()
	v := writeReleaseVolume(t, dir, now)

	// The provisioner's operator subcommands open the volume as it is.
	asIs, err := prevrelease.OpenAsIs(dir)
	if err != nil {
		t.Fatalf("server %s OpenAsIs: %v", prevrelease.Version, err)
	}
	if admins, err := asIs.AdminNames(); err != nil || !slices.Equal(admins, []string{"owner"}) {
		t.Fatalf("server %s admins: %v, %v", prevrelease.Version, admins, err)
	}
	if err := asIs.Close(); err != nil {
		t.Fatal(err)
	}

	prev, err := prevrelease.Open(dir)
	if err != nil {
		t.Fatalf("server %s serving open: %v", prevrelease.Version, err)
	}
	client := prevrelease.ClientInfo{Version: prevrelease.Version, Platform: "macos"}

	u, err := prev.User("alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(u.Tokens) != v.tokenCount {
		t.Fatalf("server %s reads %d tokens of alice, want %d", prevrelease.Version, len(u.Tokens), v.tokenCount)
	}
	if tok := prevToken(t, u, v.desktop); tok.Label != "MacBook" || tok.ViaToken != v.phone || tok.Kind != "" {
		t.Fatalf("server %s reads the computer the phone signed in as %+v", prevrelease.Version, tok)
	}
	if tok := prevToken(t, u, v.webID); tok.Kind != prevrelease.TokenKindWeb {
		t.Fatalf("server %s reads the web session as %+v", prevrelease.Version, tok)
	}
	if tok := prevToken(t, u, v.approvedWebID); tok.Kind != prevrelease.TokenKindWeb || tok.ViaToken != v.phone {
		t.Fatalf("server %s reads the approved web session as %+v", prevrelease.Version, tok)
	}

	for _, raw := range []string{v.rawDesktop, v.rawPhone} {
		if got, err := prev.UserByToken(raw, client); err != nil || got.Username != "alice" {
			t.Fatalf("server %s authenticates a token as %q: %v", prevrelease.Version, got.Username, err)
		}
	}
	if got, _, err := prev.UserByWebSession(v.rawWeb, client, time.Now(), true); err != nil || got.Username != "alice" {
		t.Fatalf("server %s authenticates the web session as %q: %v", prevrelease.Version, got.Username, err)
	}

	if err := prev.RevokeToken("alice", v.desktop2); err != nil {
		t.Fatalf("server %s signs out a computer the phone signed in: %v", prevrelease.Version, err)
	}
	if _, err := prev.UserByToken(v.rawDesktop2, client); !errors.Is(err, prevrelease.ErrBadCredentials) {
		t.Fatalf("server %s still accepts the signed-out computer: %v", prevrelease.Version, err)
	}
	rawLaptop, err := prev.MintToken("alice", "Linux laptop")
	if err != nil {
		t.Fatalf("server %s mints a token: %v", prevrelease.Version, err)
	}
	if got, err := prev.UserByToken(rawLaptop, client); err != nil || got.Username != "alice" {
		t.Fatalf("server %s authenticates the token it minted as %q: %v", prevrelease.Version, got.Username, err)
	}

	claim, err := prev.ClaimDeviceLink(v.linkSecret, "Pixel 9", "android", "198.51.100.2", now.Add(time.Second))
	if err != nil {
		t.Fatalf("server %s claims the device link: %v", prevrelease.Version, err)
	}
	if err := prev.ApproveDeviceLink("alice", v.studio, v.linkID, claim.Number, now.Add(2*time.Second)); err != nil {
		t.Fatalf("server %s approves the device link: %v", prevrelease.Version, err)
	}
	_, rawPixel, pending, err := prev.SpendDeviceLink(claim.ClaimID, claim.PollSecret, now.Add(3*time.Second))
	if err != nil || pending || rawPixel == "" {
		t.Fatalf("server %s spends the device link: pending %v, %v", prevrelease.Version, pending, err)
	}

	page, err := prev.List(prevrelease.ListQuery{Owner: "alice"})
	if err != nil {
		t.Fatalf("server %s lists shares: %v", prevrelease.Version, err)
	}
	if len(page.Shares) != 1 || page.Shares[0].ID != v.shareID || len(page.Shares[0].Files) != 2 || page.TotalBytes != 8 {
		t.Fatalf("server %s lists %+v", prevrelease.Version, page)
	}
	if f, err := prev.ResolveSlug(v.shareID, v.slugC); err != nil || f.Path != "b/c.txt" {
		t.Fatalf("server %s resolves a slug to %+v: %v", prevrelease.Version, f, err)
	}
	if _, err := prev.UpdateShare(v.shareID, prevrelease.UpdateOptions{SetName: true, Name: "Holiday 2026"}); err != nil {
		t.Fatalf("server %s renames the share: %v", prevrelease.Version, err)
	}
	if _, err := prev.CommitFile(prevrelease.CommitInput{ShareID: v.shareID, Path: "b/d.txt", Size: 4, Mime: "text/plain"}); err != nil {
		t.Fatalf("server %s commits a file: %v", prevrelease.Version, err)
	}
	notes, err := prev.CreateShare(prevrelease.CreateOptions{Name: "Notes", Owner: "alice",
		Files: []prevrelease.PendingFile{{Path: "notes.txt", Size: 2}}})
	if err != nil {
		t.Fatalf("server %s creates a share: %v", prevrelease.Version, err)
	}
	if err := prev.DeleteUser("bob"); err != nil {
		t.Fatalf("server %s deletes an account a phone signed a computer in for: %v", prevrelease.Version, err)
	}
	if _, err := prev.PruneWebSessions(time.Now()); err != nil {
		t.Fatalf("server %s prunes web sessions: %v", prevrelease.Version, err)
	}
	// A recovery code is stored keyed with the volume secret, which the
	// previous release does not know: it refuses the code, and spends none.
	if err := prev.VerifySecondFactor("owner", v.recovery[0], now.Add(time.Minute)); !errors.Is(err, prevrelease.ErrTOTPInvalid) {
		t.Fatalf("server %s checks a keyed recovery code: %v, want ErrTOTPInvalid", prevrelease.Version, err)
	}
	if owner, err := prev.User("owner"); err != nil || owner.RecoveryCodesLeft != len(v.recovery) {
		t.Fatalf("server %s reads the owner's codes left as %d: %v", prevrelease.Version, owner.RecoveryCodesLeft, err)
	}
	if err := prev.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := Open(dir)
	if err != nil {
		t.Fatalf("this tree reopens the volume server %s served: %v", prevrelease.Version, err)
	}
	defer db.Close()
	err = db.read(func(tx *sql.Tx) error {
		var integrity string
		if err := tx.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil {
			return err
		}
		if integrity != "ok" {
			t.Errorf("integrity_check: %s", integrity)
		}
		rows, err := tx.Query(`PRAGMA foreign_key_check`)
		if err != nil {
			return err
		}
		defer rows.Close()
		if rows.Next() {
			t.Error("foreign_key_check reports a dangling reference")
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}

	desktop := tokenOf(t, db, "alice", TokenHash(v.rawDesktop))
	if desktop.SignInMethod != SignInMethodPhone || desktop.ApprovedByLabel != "iPhone" || desktop.ViaToken != v.phone ||
		desktop.ClientVersion != prevrelease.Version {
		t.Fatalf("the computer the phone signed in reads back as %+v", desktop)
	}
	laptop := tokenOf(t, db, "alice", TokenHash(rawLaptop))
	if laptop.SignInMethod != "" || laptop.ApprovedByLabel != "" || laptop.ViaToken != "" {
		t.Fatalf("the token server %s minted reads back as %+v", prevrelease.Version, laptop)
	}
	if pixel := tokenOf(t, db, "alice", TokenHash(rawPixel)); pixel.ViaToken != v.studio || pixel.SignInMethod != "" {
		t.Fatalf("the phone the device link signed in reads back as %+v", pixel)
	}
	ids := tokenIDs(t, db, "alice")
	if slices.Contains(ids, v.desktop2) || len(ids) != v.tokenCount+1 {
		t.Fatalf("alice's tokens read back as %v (%d before, one revoked, two minted)", ids, v.tokenCount)
	}
	if web := tokenOf(t, db, "alice", WebSessionHash(v.rawWeb)); web.Kind != TokenKindWeb || web.ID != v.webID {
		t.Fatalf("the web session reads back as %+v", web)
	}
	if got, _, err := db.UserByWebSession(v.rawWeb, ClientInfo{}, time.Now(), false); err != nil || got.Username != "alice" {
		t.Fatalf("this tree authenticates the web session as %q: %v", got.Username, err)
	}
	if got, err := db.UserByToken(v.rawDesktop, ClientInfo{}); err != nil || got.Username != "alice" {
		t.Fatalf("this tree authenticates the computer as %q: %v", got.Username, err)
	}

	events := signInEvents(t, db, "alice")
	if len(events) != 2 {
		t.Fatalf("alice's sign-in events read back as %+v", events)
	}
	for _, e := range events {
		if e.ApproverTokenID != v.phone || e.ApproverLabel != "iPhone" {
			t.Fatalf("a sign-in event reads back as %+v", e)
		}
	}
	if !slices.ContainsFunc(events, func(e signInEvent) bool { return e.TokenID == v.desktop2 && e.Label == "Windows PC" }) {
		t.Fatalf("the revoked computer's sign-in event is gone: %+v", events)
	}
	if n, err := db.SignInsApprovedSince(v.phone, now.Add(-DesktopSignInWindow)); err != nil || n != 2 {
		t.Fatalf("the phone's approvals read back as %d: %v", n, err)
	}
	if _, _, err := db.MintDesktopSignIn("alice", v.phone, "iMac", "macos", "mark-4", now); err != nil {
		t.Fatalf("the phone's third sign-in of the day: %v", err)
	}
	if _, _, err := db.MintDesktopSignIn("alice", v.phone, "Studio desk", "macos", "mark-5", now); !errors.Is(err, ErrSignInLimit) {
		t.Fatalf("the phone's fourth sign-in of the day: %v, want ErrSignInLimit", err)
	}
	if _, err := db.User("bob"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("bob after server %s deleted him: %v", prevrelease.Version, err)
	}
	if events := signInEvents(t, db, "bob"); len(events) != 0 {
		t.Fatalf("bob's sign-in events outlive his account: %+v", events)
	}

	page2, err := db.List(ListQuery{Owner: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if page2.Total != 2 || page2.TotalBytes != 12 {
		t.Fatalf("alice's shares read back as %+v", page2)
	}
	d, err := db.Share(v.shareID)
	if err != nil {
		t.Fatal(err)
	}
	if d.Name != "Holiday 2026" || len(d.Files) != 3 || fileSlug(t, db, v.shareID, "a.txt") != v.slugA ||
		fileSlug(t, db, v.shareID, "b/c.txt") != v.slugC {
		t.Fatalf("the share reads back as %+v", d)
	}
	if f, err := db.File(notes.ID, "notes.txt"); err != nil || !f.Pending {
		t.Fatalf("the pending file server %s declared reads back as %+v: %v", prevrelease.Version, f, err)
	}
	if err := db.VerifySecondFactor("owner", v.recovery[0], now.Add(time.Minute)); err != nil {
		t.Fatalf("the recovery code server %s refused, back on this tree: %v", prevrelease.Version, err)
	}
}
