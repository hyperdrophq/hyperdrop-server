package api

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/sealpw"
	"hyperdrop/server/internal/sharefs"
)

// sharePassword answers the share's password as GET /api/shares/{id} gives
// it ("" when absent) and its hasPassword.
func sharePassword(t *testing.T, h http.Handler, token, id string) (string, bool) {
	t.Helper()
	rec := doReq(t, h, "GET", "/api/shares/"+id, token, "")
	if rec.Code != 200 {
		t.Fatalf("get = %d %s", rec.Code, rec.Body)
	}
	var got struct {
		Password    *string `json:"password"`
		HasPassword bool    `json:"hasPassword"`
	}
	unmarshal(t, rec, &got)
	if got.Password == nil {
		return "", got.HasPassword
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("a password answered with Cache-Control %q", cc)
	}
	return *got.Password, got.HasPassword
}

func TestTheOwnerReadsThePasswordBack(t *testing.T) {
	h := newTestAPI(t)
	id := createShareWithPassword(t, h, "doc", "hunter2")
	if pw, _ := sharePassword(t, h, testToken, id); pw != "hunter2" {
		t.Fatalf("password = %q", pw)
	}
	rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"password":"swordfish"}`)
	if rec.Code != 200 {
		t.Fatalf("patch = %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "swordfish") || strings.Contains(rec.Body.String(), `"password"`) {
		t.Fatalf("the PATCH answer carries the password: %s", rec.Body)
	}
	if pw, _ := sharePassword(t, h, testToken, id); pw != "swordfish" {
		t.Fatalf("after a change = %q", pw)
	}
	doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"password":""}`)
	if pw, has := sharePassword(t, h, testToken, id); pw != "" || has {
		t.Fatalf("after removal = %q has %v", pw, has)
	}
}

func TestTheCreateAnswerDoesNotCarryThePassword(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"doc","password":"hunter2"}`)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "hunter2") || strings.Contains(rec.Body.String(), `"password"`) {
		t.Fatalf("the create answer carries the password: %s", rec.Body)
	}
}

func TestAnotherAccountNeverReadsIt(t *testing.T) {
	h, b := newTestAPIBackend(t)
	bob := seedUser(t, b.DB, "bob")
	id := createShareWithPassword(t, h, "doc", "hunter2")
	if rec := doReq(t, h, "GET", "/api/shares/"+id, bob, ""); rec.Code != 404 || strings.Contains(rec.Body.String(), "hunter2") {
		t.Fatalf("another account: %d %s", rec.Code, rec.Body)
	}
}

// An admin reading another account's share is refused like anyone else: the
// owner's bearer is the only reader.
func TestAnAdminNeverReadsAnotherAccountsPassword(t *testing.T) {
	h, b := newTestAPIBackend(t)
	bob := seedUser(t, b.DB, "bob")
	rec := doReq(t, h, "POST", "/api/shares", bob, `{"name":"doc","password":"hunter2"}`)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	var cr struct{ ID string }
	unmarshal(t, rec, &cr)
	if pw, _ := sharePassword(t, h, bob, cr.ID); pw != "hunter2" {
		t.Fatalf("owner reads %q", pw)
	}
	if rec := doReq(t, h, "GET", "/api/shares/"+cr.ID, testToken, ""); rec.Code != 404 || strings.Contains(rec.Body.String(), "hunter2") {
		t.Fatalf("admin: %d %s", rec.Code, rec.Body)
	}
}

// The listing, the change feed and a batch edit answer the share without
// it; only the share route carries it.
func TestOnlyTheShareRouteCarriesThePassword(t *testing.T) {
	h := newTestAPI(t)
	var start struct {
		Cursor string `json:"cursor"`
	}
	unmarshal(t, doReq(t, h, "GET", "/api/shares/changes", testToken, ""), &start)
	id := createShareWithPassword(t, h, "doc", "hunter2")
	for _, path := range []string{"/api/shares", "/api/shares/changes?since=" + start.Cursor} {
		rec := doReq(t, h, "GET", path, testToken, "")
		if !strings.Contains(rec.Body.String(), id) {
			t.Fatalf("%s does not answer the share: %s", path, rec.Body)
		}
		if strings.Contains(rec.Body.String(), "hunter2") || strings.Contains(rec.Body.String(), `"password"`) {
			t.Fatalf("%s carries the password: %s", path, rec.Body)
		}
	}
	rec := doReq(t, h, "POST", "/api/shares/edit", testToken, `{"ids":["`+id+`"],"password":"swordfish"}`)
	if rec.Code/100 != 2 {
		t.Fatalf("batch edit = %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "swordfish") || strings.Contains(rec.Body.String(), `"password"`) {
		t.Fatalf("batch edit result carries the password: %s", rec.Body)
	}
	if pw, _ := sharePassword(t, h, testToken, id); pw != "swordfish" {
		t.Fatalf("a batch-set password reads %q", pw)
	}
}

// A batch hashes one password but seals one copy per share, each bound to
// its own share id.
func TestABatchSealsEachShareItsOwnCopy(t *testing.T) {
	h, b := newTestAPIBackend(t)
	one := createShareWithPassword(t, h, "one", "a")
	two := createShareWithPassword(t, h, "two", "b")
	rec := doReq(t, h, "POST", "/api/shares/edit", testToken, `{"ids":["`+one+`","`+two+`"],"password":"same"}`)
	if rec.Code/100 != 2 {
		t.Fatalf("batch edit = %d %s", rec.Code, rec.Body)
	}
	for _, id := range []string{one, two} {
		if pw, _ := sharePassword(t, h, testToken, id); pw != "same" {
			t.Fatalf("%s reads %q", id, pw)
		}
	}
	d1, _ := b.DB.Share(one)
	d2, _ := b.DB.Share(two)
	if bytes.Equal(d1.PasswordSealed, d2.PasswordSealed) {
		t.Fatal("two shares hold the same sealed copy")
	}
}

func TestAScheduledPasswordIsReadableOnceApplied(t *testing.T) {
	h, b := newTestAPIBackend(t)
	id := createShareWithPassword(t, h, "doc", "hunter2")
	if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"password":"later","applyInSeconds":60}`); rec.Code != 200 {
		t.Fatalf("schedule = %d %s", rec.Code, rec.Body)
	}
	if pw, _ := sharePassword(t, h, testToken, id); pw != "hunter2" {
		t.Fatalf("before the time = %q", pw)
	}
	if _, err := b.DB.ApplyDue(time.Now().Add(2 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	if pw, _ := sharePassword(t, h, testToken, id); pw != "later" {
		t.Fatalf("after the time = %q", pw)
	}
}

func TestASealedCopyThatNoLongerOpensReadsAsSet(t *testing.T) {
	h, b := newTestAPIBackend(t)
	id := createShareWithPassword(t, h, "doc", "hunter2")
	// The same volume served under another secret, as after a restore that
	// brought the database without its secret.
	if err := os.WriteFile(filepath.Join(b.FS.DataDir(), "secret"), bytes.Repeat([]byte{3}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	fs, err := sharefs.Open(b.FS.DataDir())
	if err != nil {
		t.Fatal(err)
	}
	h = New(Backend{DB: b.DB, FS: fs}, "2.0.0", testDomain(t), nil)
	pw, has := sharePassword(t, h, testToken, id)
	if pw != "" || !has {
		t.Fatalf("after a secret change: password %q hasPassword %v, want \"\" and true", pw, has)
	}
}

func TestTheStoredCopyIsNotThePlaintext(t *testing.T) {
	h, b := newTestAPIBackend(t)
	id := createShareWithPassword(t, h, "doc", "hunter2")
	d, err := b.DB.Share(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.PasswordSealed) == 0 || bytes.Contains(d.PasswordSealed, []byte("hunter2")) {
		t.Fatalf("sealed copy = %q", d.PasswordSealed)
	}
}

// reopenUnder closes b's database, runs fn against the same volume's file
// directly, as a writer that knows nothing of the sealed copies (a hand
// edit, an operator tool), and answers a handler and backend over the
// volume reopened by this tree.
func reopenUnder(t *testing.T, dir string, b Backend, fn func(raw *sql.DB)) (http.Handler, Backend) {
	t.Helper()
	b.DB.Close()
	raw, err := sql.Open("sqlite", filepath.Join(dir, metadb.FileName))
	if err != nil {
		t.Fatal(err)
	}
	fn(raw)
	raw.Close()
	db, err := metadb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	nb := Backend{DB: db, FS: b.FS}
	return New(nb, "2.0.0", testDomain(t), nil), nb
}

// rawExec runs one statement against the raw volume.
func rawExec(t *testing.T, raw *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := raw.Exec(q, args...); err != nil {
		t.Fatal(err)
	}
}

func bcryptOf(t *testing.T, pw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

// A writer changes the hash and leaves the copy: the copy no longer opens
// beside the new hash, so the owner sees "set", never p1.
func TestAPasswordHashChangedBesideItsCopyReadsAsSet(t *testing.T) {
	dir := t.TempDir()
	b := testBackendAt(t, dir)
	h := New(b, "2.0.0", testDomain(t), nil)
	id := createShareWithPassword(t, h, "doc", "p1")
	if pw, _ := sharePassword(t, h, testToken, id); pw != "p1" {
		t.Fatalf("before = %q", pw)
	}
	h, _ = reopenUnder(t, dir, b, func(raw *sql.DB) {
		rawExec(t, raw, `UPDATE shares SET password_hash = ? WHERE id = ?`, bcryptOf(t, "p2"), id)
	})
	pw, has := sharePassword(t, h, testToken, id)
	if pw != "" || !has {
		t.Fatalf("after the hash changed: password %q hasPassword %v", pw, has)
	}
}

// The boot sweep clears every copy that no longer opens beside its row's
// hash (a hash changed or removed beside it, a copy sealed under another
// server's secret, a schedule whose hash was rewritten) and keeps the copies
// that do.
func TestTheBootSweepClearsCopiesThatNoLongerOpen(t *testing.T) {
	const wantBefore, wantCleared = 8, 4
	dir := t.TempDir()
	b := testBackendAt(t, dir)
	h := New(b, "2.0.0", testDomain(t), nil)
	good := createShareWithPassword(t, h, "good", "g")
	goodLater := createShareWithPassword(t, h, "good-later", "g1")
	stale := createShareWithPassword(t, h, "stale", "s1")
	removed := createShareWithPassword(t, h, "removed", "r1")
	foreign := createShareWithPassword(t, h, "foreign", "f1")
	rescheduled := createShareWithPassword(t, h, "rescheduled", "x1")
	for _, id := range []string{goodLater, rescheduled} {
		if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"password":"later","applyInSeconds":600}`); rec.Code != 200 {
			t.Fatalf("schedule = %d %s", rec.Code, rec.Body)
		}
	}
	// A copy imported from another server: sealed under that server's secret.
	fd, err := b.DB.Share(foreign)
	if err != nil {
		t.Fatal(err)
	}
	other, err := sealpw.Seal(bytes.Repeat([]byte{9}, 32), foreign, fd.PasswordHash, "f1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.DB.UpdateShare(foreign, metadb.UpdateOptions{SetPassword: true, PasswordHash: fd.PasswordHash, PasswordSealed: other}); err != nil {
		t.Fatal(err)
	}
	h, nb := reopenUnder(t, dir, b, func(raw *sql.DB) {
		rawExec(t, raw, `UPDATE shares SET password_hash = ? WHERE id = ?`, bcryptOf(t, "s2"), stale)
		rawExec(t, raw, `UPDATE shares SET password_hash = NULL WHERE id = ?`, removed)
		rawExec(t, raw, `UPDATE scheduled SET password_hash = ? WHERE share_id = ? AND kind = 'password'`, bcryptOf(t, "x2"), rescheduled)
	})
	before, err := nb.DB.SealedCopies()
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != wantBefore {
		t.Fatalf("copies before the sweep = %d, want %d: %+v", len(before), wantBefore, before)
	}
	n, err := SweepSealed(context.Background(), nb.DB, nb.FS.Secret())
	if err != nil || n != wantCleared {
		t.Fatalf("SweepSealed = %d, %v; want %d cleared", n, err, wantCleared)
	}
	after, err := nb.DB.SealedCopies()
	if err != nil {
		t.Fatal(err)
	}
	kept := map[string]bool{}
	for _, c := range after {
		kept[c.Table+"/"+c.ShareID] = true
	}
	want := map[string]bool{"shares/" + good: true, "shares/" + goodLater: true, "scheduled/" + goodLater: true,
		"shares/" + rescheduled: true}
	if len(kept) != len(want) || len(after) != len(want) {
		t.Fatalf("kept %v, want %v", kept, want)
	}
	for k := range want {
		if !kept[k] {
			t.Fatalf("kept %v, want %v", kept, want)
		}
	}
	if n, err := SweepSealed(context.Background(), nb.DB, nb.FS.Secret()); err != nil || n != 0 {
		t.Fatalf("a second sweep = %d, %v", n, err)
	}
	if pw, _ := sharePassword(t, h, testToken, good); pw != "g" {
		t.Fatalf("the good copy reads %q", pw)
	}
	for _, id := range []string{stale, foreign} {
		if pw, has := sharePassword(t, h, testToken, id); pw != "" || !has {
			t.Fatalf("%s after the sweep: %q %v", id, pw, has)
		}
	}
}

// fakeSealedStore records how the sweep clears, refusing the batches and
// the single copies its fail set names.
type fakeSealedStore struct {
	copies  []metadb.SealedCopy
	fail    map[string]bool // share ids whose clear fails
	batches []int
	singles int
	cleared map[string]bool
}

func (f *fakeSealedStore) SealedCopies() ([]metadb.SealedCopy, error) { return f.copies, nil }

func (f *fakeSealedStore) ClearSealedBatch(cs []metadb.SealedCopy) error {
	f.batches = append(f.batches, len(cs))
	for _, c := range cs {
		if f.fail[c.ShareID] {
			return errors.New("refused")
		}
	}
	for _, c := range cs {
		f.cleared[c.ShareID] = true
	}
	return nil
}

func (f *fakeSealedStore) ClearSealed(c metadb.SealedCopy) error {
	f.singles++
	if f.fail[c.ShareID] {
		return errors.New("refused")
	}
	f.cleared[c.ShareID] = true
	return nil
}

func staleCopies(n int) []metadb.SealedCopy {
	out := make([]metadb.SealedCopy, n)
	for i := range out {
		out[i] = metadb.SealedCopy{Table: metadb.SealedInShares, ShareID: fmt.Sprintf("id%07d", i), Hash: "h", Sealed: []byte("x")}
	}
	return out
}

// Many stale copies clear in a handful of transactions, not one each.
func TestTheSweepClearsInBatches(t *testing.T) {
	f := &fakeSealedStore{copies: staleCopies(2*sealedSweepBatch + 7), cleared: map[string]bool{}}
	n, err := SweepSealed(context.Background(), f, bytes.Repeat([]byte{1}, 32))
	if err != nil || n != len(f.copies) {
		t.Fatalf("SweepSealed = %d, %v", n, err)
	}
	if want := []int{sealedSweepBatch, sealedSweepBatch, 7}; fmt.Sprint(f.batches) != fmt.Sprint(want) || f.singles != 0 {
		t.Fatalf("batches %v singles %d, want %v and 0", f.batches, f.singles, want)
	}
}

// A copy whose clear fails is skipped: its batch is retried one copy at a
// time, and every other copy, in that batch and in later ones, is cleared.
func TestAFailingClearDoesNotStopTheSweep(t *testing.T) {
	f := &fakeSealedStore{copies: staleCopies(sealedSweepBatch + 3), cleared: map[string]bool{}}
	bad := f.copies[1].ShareID
	f.fail = map[string]bool{bad: true}
	n, err := SweepSealed(context.Background(), f, bytes.Repeat([]byte{1}, 32))
	if err == nil || n != len(f.copies)-1 {
		t.Fatalf("SweepSealed = %d, %v; want %d and the error", n, err, len(f.copies)-1)
	}
	if f.singles != sealedSweepBatch || len(f.batches) != 2 {
		t.Fatalf("singles %d batches %v", f.singles, f.batches)
	}
	for _, c := range f.copies {
		if c.ShareID != bad && !f.cleared[c.ShareID] {
			t.Fatalf("%s was not cleared", c.ShareID)
		}
	}
	if f.cleared[bad] {
		t.Fatal("the failing copy reads as cleared")
	}
}

// A canceled sweep stops before its next batch.
func TestACanceledSweepStopsBetweenBatches(t *testing.T) {
	f := &fakeSealedStore{copies: staleCopies(3), cleared: map[string]bool{}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if n, err := SweepSealed(ctx, f, bytes.Repeat([]byte{1}, 32)); n != 0 || !errors.Is(err, context.Canceled) || len(f.batches) != 0 {
		t.Fatalf("SweepSealed = %d, %v, batches %v", n, err, f.batches)
	}
}
