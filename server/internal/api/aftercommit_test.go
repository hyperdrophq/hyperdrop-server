package api

import (
	"testing"

	"hyperdrop/server/internal/linked"
	"hyperdrop/server/internal/metadb"
)

// An allowlist edit's second pass judges by the allowlist as stored when it
// runs, not the one its request carried: a narrowing whose second pass runs
// after a later edit restored the folder leaves the share serving.
func TestTheLateRevokePassReadsTheStoredAllowlist(t *testing.T) {
	vol := seedLinkedVolume(t)
	roots, err := linked.NewRoots(nil, []string{vol}, nil)
	if err != nil {
		t.Fatal(err)
	}
	b := testBackendWithRoots(t, roots)
	hd := newHandler(b, "2.0.0", testDomain(t), nil, Deployment{})
	grantedUser(t, hd.routes(), "bob", "photo/2024")
	sh, err := b.DB.CreateShare(metadb.CreateOptions{Name: "trip", Owner: "bob", Folder: true,
		Sources: []string{"photo/2024"}})
	if err != nil {
		t.Fatal(err)
	}

	// Edit A narrows to nothing and commits; edit B restores the folder and
	// commits before A's second pass runs.
	none := []string{}
	narrow := metadb.Settings{SourceRoots: &none}
	if _, err := b.DB.UpdateUserAccess("bob", narrow, nil); err != nil {
		t.Fatal(err)
	}
	again := []string{"photo/2024"}
	if _, err := b.DB.UpdateUserAccess("bob", metadb.Settings{SourceRoots: &again}, nil); err != nil {
		t.Fatal(err)
	}
	if err := hd.revokeLateSources("bob", narrow); err != nil {
		t.Fatal(err)
	}
	d, err := b.DB.Share(sh.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Sources) != 1 || d.Sources[0].Revoked() {
		t.Fatalf("sources %+v: the stored allowlist grants the folder, so it must serve", d.Sources)
	}
}

// A password reset is committed before anything else the request does, and
// its answer carries the password whatever fails after the commit: a
// generated password exists nowhere else. Here the invite cannot be minted.
func TestAResetPasswordIsAnsweredWhenTheInviteFails(t *testing.T) {
	dir := t.TempDir()
	b := testBackendAt(t, dir)
	h := New(b, "2.0.0", testDomain(t), nil)
	seedUser(t, b.DB, "alice")
	execRaw(t, dir, `CREATE TRIGGER no_invites BEFORE UPDATE OF invite_hash ON users
		WHEN NEW.invite_hash IS NOT NULL BEGIN SELECT RAISE(ABORT, 'no invites'); END`)
	rec := doReq(t, h, "PATCH", "/api/users/alice", testToken, `{"resetPassword":true}`)
	if rec.Code != 200 {
		t.Fatalf("reset: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Password    string `json:"password"`
		InviteToken string `json:"inviteToken"`
	}
	unmarshal(t, rec, &out)
	if out.Password == "" || out.InviteToken != "" {
		t.Fatalf("answer %s: want the password and no invite", rec.Body)
	}
	if _, code := login(t, h, "alice", out.Password); code != 200 {
		t.Fatalf("login with the answered password: %d", code)
	}
}
