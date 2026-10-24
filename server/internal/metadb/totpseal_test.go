package metadb

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/volsecret"
)

// storedTOTP reads users.totp_secret straight off the row.
func storedTOTP(t *testing.T, dir, name string) string {
	t.Helper()
	var v *string
	if err := rawDB(t, dir).QueryRow(`SELECT totp_secret FROM users WHERE username = ?`, name).Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v == nil {
		return ""
	}
	return *v
}

// volumeBytes is every file the database is made of: the file, its WAL and
// its shared memory, whichever exist.
func volumeBytes(t *testing.T, dir string) []byte {
	t.Helper()
	var all []byte
	for _, suffix := range []string{"", "-wal", "-shm"} {
		b, err := os.ReadFile(filepath.Join(dir, FileName+suffix))
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		all = append(all, b...)
	}
	return all
}

func TestATOTPSecretIsStoredOnlySealedAndStillSignsIn(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.CreateUser("alice", "pw", RoleUser, Settings{}); err != nil {
		t.Fatal(err)
	}
	secret, err := db.StartTOTP("alice")
	if err != nil {
		t.Fatal(err)
	}
	stored := storedTOTP(t, dir, "alice")
	if !strings.HasPrefix(stored, sealedTOTPPrefix) || strings.Contains(stored, secret) {
		t.Fatalf("a pending enrolment is stored as %q", stored)
	}
	if _, err := db.ConfirmTOTP("alice", codeAt(t, secret, at), at); err != nil {
		t.Fatal(err)
	}
	if got := storedTOTP(t, dir, "alice"); got != stored {
		t.Fatalf("the confirm rewrote the sealed secret: %q, was %q", got, stored)
	}
	u, err := db.User("alice")
	if err != nil || !u.TwoFactorEnabled() || u.TOTPStored != stored {
		t.Fatalf("alice: %+v, %v", u, err)
	}
	// Sign-in and step-up both open the sealed secret.
	later := at.Add(2 * time.Minute)
	if _, err := db.MintTokenIfPasswordIs("alice", "l", u.PasswordHash, codeAt(t, secret, later), later); err != nil {
		t.Fatalf("sign-in with a code: %v", err)
	}
	if _, err := db.MintTokenIfPasswordIs("alice", "l", u.PasswordHash, "", later); !errors.Is(err, ErrTOTPRequired) {
		t.Fatalf("sign-in without a code: %v", err)
	}
	evenLater := later.Add(time.Minute)
	if err := db.VerifySecondFactor("alice", codeAt(t, secret, evenLater), evenLater); err != nil {
		t.Fatalf("step-up with a code: %v", err)
	}
	if err := db.VerifySecondFactor("alice", "000000", evenLater.Add(time.Minute)); !errors.Is(err, ErrTOTPInvalid) {
		t.Fatalf("step-up with a wrong code: %v", err)
	}
	db.Close()
	if bytes.Contains(volumeBytes(t, dir), []byte(secret)) {
		t.Fatal("the database file holds the plaintext secret")
	}
}

// The username is the associated data: a sealed secret written onto another
// account's row opens for no code there, and the account is not let in
// without one.
func TestASealedSecretMovedToAnotherAccountDoesNotOpen(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, n := range []string{"alice", "bob"} {
		if _, err := db.CreateUser(n, "pw", RoleUser, Settings{}); err != nil {
			t.Fatal(err)
		}
	}
	secret, err := db.StartTOTP("alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ConfirmTOTP("alice", codeAt(t, secret, at), at); err != nil {
		t.Fatal(err)
	}
	if _, err := rawDB(t, dir).Exec(`UPDATE users SET (totp_secret, totp_confirmed_at) =
		(SELECT totp_secret, totp_confirmed_at FROM users WHERE username = 'alice') WHERE username = 'bob'`); err != nil {
		t.Fatal(err)
	}
	bob, err := db.User("bob")
	if err != nil || !bob.TwoFactorEnabled() {
		t.Fatalf("bob: %+v, %v", bob, err)
	}
	later := at.Add(2 * time.Minute)
	if _, err := db.MintTokenIfPasswordIs("bob", "l", bob.PasswordHash, codeAt(t, secret, later), later); !errors.Is(err, ErrTOTPInvalid) {
		t.Fatalf("alice's secret opened on bob's row: %v", err)
	}
	if err := db.VerifySecondFactor("bob", codeAt(t, secret, later), later); !errors.Is(err, ErrTOTPInvalid) {
		t.Fatalf("step-up with alice's secret on bob's row: %v", err)
	}
	if _, err := db.MintTokenIfPasswordIs("bob", "l", bob.PasswordHash, "", later); !errors.Is(err, ErrTOTPRequired) {
		t.Fatalf("bob without a code: %v", err)
	}
	alice, err := db.User("alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.MintTokenIfPasswordIs("alice", "l", alice.PasswordHash, codeAt(t, secret, later), later); err != nil {
		t.Fatalf("alice's own row: %v", err)
	}
}

// A volume a 1.4.0 or older server enrolled holds plaintext secrets; the
// test writes them into the rows directly. OpenAsIs leaves them; the serving
// open seals every one, confirmed and pending, in place, a second serving
// open changes nothing, and no byte of the database keeps a plaintext
// secret.
func TestTheServingOpenSealsPlaintextSecrets(t *testing.T) {
	dir := t.TempDir()
	db0, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := db0.EnsureAdmin("root", "pw-root"); err != nil {
		t.Fatal(err)
	}
	// Enough enrolled accounts that the users table spans several pages and
	// splits while they are written, so freed pages held plaintext too.
	const enrolled = 60
	secrets := map[string]string{}
	for i := range enrolled {
		name := fmt.Sprintf("user%03d", i)
		if _, err := db0.CreateUser(name, "pw", RoleUser, Settings{}); err != nil {
			t.Fatal(err)
		}
		s, err := db0.StartTOTP(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db0.ConfirmTOTP(name, codeAt(t, s, at), at); err != nil {
			t.Fatal(err)
		}
		secrets[name] = s
	}
	if _, err := db0.CreateUser("pending", "pw", RoleUser, Settings{}); err != nil {
		t.Fatal(err)
	}
	pending, err := db0.StartTOTP("pending")
	if err != nil {
		t.Fatal(err)
	}
	db0.Close()
	raw := rawDB(t, dir)
	plain := map[string]string{"pending": pending}
	for name, s := range secrets {
		plain[name] = s
	}
	for name, s := range plain {
		if _, err := raw.Exec(`UPDATE users SET totp_secret = ? WHERE username = ?`, s, name); err != nil {
			t.Fatal(err)
		}
	}
	raw.Close()
	if storedTOTP(t, dir, "user000") != secrets["user000"] {
		t.Fatal("the row does not hold the secret in plaintext; this test proves nothing")
	}

	op, err := OpenAsIs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if u, err := op.User("user000"); err != nil || u.TOTPStored != secrets["user000"] {
		t.Fatalf("OpenAsIs: %+v, %v", u, err)
	}
	op.Close()
	if storedTOTP(t, dir, "user000") != secrets["user000"] {
		t.Fatal("OpenAsIs sealed a secret; only the serving open may")
	}

	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	all := volumeBytes(t, dir)
	for name, s := range secrets {
		if got := storedTOTP(t, dir, name); !strings.HasPrefix(got, sealedTOTPPrefix) {
			t.Fatalf("%s is stored as %q after the serving open", name, got)
		}
		if bytes.Contains(all, []byte(s)) {
			t.Fatalf("the open database still holds %s's plaintext secret", name)
		}
	}
	if bytes.Contains(all, []byte(pending)) || !strings.HasPrefix(storedTOTP(t, dir, "pending"), sealedTOTPPrefix) {
		t.Fatal("a pending enrolment kept its plaintext secret")
	}
	sealed := map[string]string{}
	for name := range secrets {
		sealed[name] = storedTOTP(t, dir, name)
	}
	later := at.Add(2 * time.Minute)
	u, _ := db.User("user007")
	if _, err := db.MintTokenIfPasswordIs("user007", "l", u.PasswordHash, codeAt(t, secrets["user007"], later), later); err != nil {
		t.Fatalf("sign-in with a sealed secret: %v", err)
	}
	if _, err := db.ConfirmTOTP("pending", codeAt(t, pending, later), later); err != nil {
		t.Fatalf("finishing an enrolment started before the seal: %v", err)
	}
	db.Close()
	if bytes.Contains(volumeBytes(t, dir), []byte(secrets["user001"])) {
		t.Fatal("the closed database holds a plaintext secret")
	}

	db, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for name, want := range sealed {
		if got := storedTOTP(t, dir, name); got != want {
			t.Fatalf("a second serving open resealed %s: %q, was %q", name, got, want)
		}
	}
}

// The key is <data>/secret, never a row: a backup holds neither it nor a
// plaintext secret, and served beside another volume's secret its sealed
// secrets open for no code while the factor still gates the account.
func TestABackupAloneOpensNoSecret(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateUser("alice", "pw", RoleUser, Settings{}); err != nil {
		t.Fatal(err)
	}
	secret, err := db.StartTOTP("alice")
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := db.ConfirmTOTP("alice", codeAt(t, secret, at), at)
	if err != nil {
		t.Fatal(err)
	}
	backup, err := Backup(db, t.TempDir(), at)
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(filepath.Join(dir, volsecret.FileName))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, key) || bytes.Contains(b, []byte(secret)) {
		t.Fatal("the backup holds the volume secret or the plaintext TOTP secret")
	}

	elsewhere := t.TempDir()
	if err := copyFile(backup, filepath.Join(elsewhere, FileName)); err != nil {
		t.Fatal(err)
	}
	other, err := Open(elsewhere)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	u, err := other.User("alice")
	if err != nil || !u.TwoFactorEnabled() {
		t.Fatalf("alice elsewhere: %+v, %v", u, err)
	}
	later := at.Add(2 * time.Minute)
	if _, err := other.MintTokenIfPasswordIs("alice", "l", u.PasswordHash, codeAt(t, secret, later), later); !errors.Is(err, ErrTOTPInvalid) {
		t.Fatalf("a TOTP code opened under another volume's secret: %v", err)
	}
	if _, err := other.MintTokenIfPasswordIs("alice", "l", u.PasswordHash, "", later); !errors.Is(err, ErrTOTPRequired) {
		t.Fatalf("no code under another volume's secret: %v", err)
	}
	if _, err := other.MintTokenIfPasswordIs("alice", "l", u.PasswordHash, recovery[0], later); err != nil {
		t.Fatalf("a recovery code under another volume's secret: %v", err)
	}
}
