package metadb

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/metadb/prevrelease"
)

// storedRecoveryCodes is what name's recovery_codes rows hold.
func storedRecoveryCodes(t *testing.T, db *DB, name string) []string {
	t.Helper()
	var out []string
	err := db.read(func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT sha256 FROM recovery_codes WHERE username = ?`, name)
		if err != nil {
			return err
		}
		out, err = scanStrings(rows)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// plainRecoveryHash is a code's unkeyed SHA-256, as the previous release
// stores it.
func plainRecoveryHash(code string) string {
	sum := sha256.Sum256([]byte(NormalizeRecoveryCode(code)))
	return hex.EncodeToString(sum[:])
}

// A recovery code is stored keyed with the volume secret, so a copy of the
// database alone cannot be searched for the codes it accepts.
func TestRecoveryCodesAreStoredKeyed(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	secret, err := db.StartTOTP("alice")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	codes, err := db.ConfirmTOTP("alice", codeAt(t, secret, now), now)
	if err != nil {
		t.Fatal(err)
	}
	stored := storedRecoveryCodes(t, db, "alice")
	if len(stored) != len(codes) {
		t.Fatalf("%d rows for %d codes", len(stored), len(codes))
	}
	for _, s := range stored {
		if !strings.HasPrefix(s, recoveryKeyedPrefix) {
			t.Fatalf("a recovery code is stored as %q, not keyed", s)
		}
		for _, c := range codes {
			if strings.Contains(s, plainRecoveryHash(c)) {
				t.Fatalf("the code %s is stored as its plain SHA-256", c)
			}
		}
	}
}

// A volume the previous release enrolled holds plain hashes: the serving
// open keys every one of them in place, and each code still signs in once.
func TestExistingRecoveryCodesAreRekeyedAndStillWork(t *testing.T) {
	dir := t.TempDir()
	prev, err := prevrelease.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prev.CreateUser("alice", "pw-alice", prevrelease.RoleUser, prevrelease.Settings{}); err != nil {
		t.Fatal(err)
	}
	secret, err := prev.StartTOTP("alice")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	codes, err := prev.ConfirmTOTP("alice", codeAt(t, secret, now), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := prev.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	stored := storedRecoveryCodes(t, db, "alice")
	if len(stored) != len(codes) {
		t.Fatalf("%d rows after the open for %d codes", len(stored), len(codes))
	}
	for _, s := range stored {
		if !strings.HasPrefix(s, recoveryKeyedPrefix) {
			t.Fatalf("a plain hash survived the serving open: %q", s)
		}
	}
	later := now.Add(time.Minute)
	if err := db.VerifySecondFactor("alice", codes[0], later); err != nil {
		t.Fatalf("a re-keyed code: %v", err)
	}
	if err := db.VerifySecondFactor("alice", codes[0], later); !errors.Is(err, ErrTOTPInvalid) {
		t.Fatalf("a re-keyed code spent twice: %v, want ErrTOTPInvalid", err)
	}
	typed := strings.ToLower(strings.ReplaceAll(codes[1], "-", ""))
	if err := db.VerifySecondFactor("alice", typed, later); err != nil {
		t.Fatalf("a re-keyed code typed without its dash: %v", err)
	}
	if u, err := db.User("alice"); err != nil || u.RecoveryCodesLeft != len(codes)-2 {
		t.Fatalf("codes left = %d, %v; want %d", u.RecoveryCodesLeft, err, len(codes)-2)
	}

	// A second open finds nothing left to key.
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if got := storedRecoveryCodes(t, again, "alice"); len(got) != len(codes)-2 {
		t.Fatalf("%d rows after a second open, want %d", len(got), len(codes)-2)
	}
	if err := again.VerifySecondFactor("alice", codes[2], later); err != nil {
		t.Fatalf("a code after a second open: %v", err)
	}
}
