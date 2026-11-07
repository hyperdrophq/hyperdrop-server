package metadb

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func hasShare(t *testing.T, db *DB, id string) bool {
	t.Helper()
	var n int
	err := db.read(func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT count(*) FROM shares WHERE id = ?`, id).Scan(&n)
	})
	if err != nil {
		t.Fatal(err)
	}
	return n == 1
}

// corrupt overwrites a page in the middle of the file, the shape a bad
// sector or a torn write leaves behind.
func corrupt(t *testing.T, path string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	junk := make([]byte, 4096)
	for i := range junk {
		junk[i] = 0xFF
	}
	if _, err := f.WriteAt(junk, 4096); err != nil {
		t.Fatal(err)
	}
}

func TestBackupWritesAConsistentCopyAndKeepsThree(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	seedUser(t, db, "admin")
	seedShare(t, db, "s1s1", "admin")
	backups := filepath.Join(dir, "backups")
	var last string
	for i := range 4 {
		p, err := Backup(db, backups, at.AddDate(0, 0, i))
		if err != nil {
			t.Fatal(err)
		}
		last = p
	}
	names, _ := filepath.Glob(filepath.Join(backups, "hyperdrop-*.db"))
	if len(names) != KeepBackups {
		t.Fatalf("kept %d: %v", len(names), names)
	}
	if err := quickCheck(last); err != nil {
		t.Fatal(err)
	}
	if got := NewestBackup(backups); got != last {
		t.Fatalf("newest %q, want %q", got, last)
	}
}

func TestACorruptDatabaseBootsFromTheNewestGoodBackup(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	id := "s1s1"
	seedUser(t, db, "admin")
	seedShare(t, db, id, "admin")
	if _, err := Backup(db, filepath.Join(dir, "backups"), at); err != nil {
		t.Fatal(err)
	}
	db.Close()
	corrupt(t, filepath.Join(dir, FileName))

	db2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	if !hasShare(t, db2, id) {
		t.Fatal("the restored copy lacks the share")
	}
	rec, ok := ReadRecovered(dir)
	if !ok || rec.Backup == "" || !strings.HasPrefix(filepath.Base(rec.Corrupt), FileName+".corrupt-") {
		t.Fatalf("marker %+v %v", rec, ok)
	}
	if _, err := os.Stat(rec.Corrupt); err != nil {
		t.Fatal("the corrupt file was not kept")
	}
}

func TestACorruptDatabaseWithNoBackupRefusesToBoot(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	corrupt(t, filepath.Join(dir, FileName))
	if _, err := Open(dir); !errors.Is(err, ErrNoUsableDatabase) {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, FileName)); err != nil {
		t.Fatal("the damaged file was moved")
	}
	if names, _ := filepath.Glob(filepath.Join(dir, FileName+".corrupt-*")); len(names) != 0 {
		t.Fatalf("a copy was made although nothing replaced the file: %v", names)
	}
}

func TestALostWALIsNotACorruption(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	seedUser(t, db, "admin")
	seedShare(t, db, "s1s1", "admin")
	Backup(db, filepath.Join(dir, "backups"), at)
	seedShare(t, db, "s2s2", "admin")
	db.Close()
	os.Remove(filepath.Join(dir, FileName+"-wal"))
	db2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	if _, ok := ReadRecovered(dir); ok {
		t.Fatal("a recovered marker was written for a healthy file")
	}
}

func TestClearRecoveredRemovesTheMarker(t *testing.T) {
	dir := t.TempDir()
	db, _ := Open(dir)
	seedUser(t, db, "admin")
	seedShare(t, db, "s1s1", "admin")
	Backup(db, filepath.Join(dir, "backups"), at)
	db.Close()
	corrupt(t, filepath.Join(dir, FileName))
	db2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	db2.Close()
	ClearRecovered(dir)
	if _, ok := ReadRecovered(dir); ok {
		t.Fatal("marker survived Clear")
	}
}

// A refusal must hold on the next boot too: the damaged file stays where it
// is, so a restart meets the same refusal rather than an empty database.
func TestARefusedRecoveryHoldsAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	corrupt(t, filepath.Join(dir, FileName))
	for range 2 {
		if _, err := Open(dir); !errors.Is(err, ErrNoUsableDatabase) {
			t.Fatalf("got %v", err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, FileName)); err != nil {
		t.Fatal("the damaged file was moved although nothing replaced it")
	}
}

// A file the process cannot read is not a damaged file: nothing is moved,
// nothing is restored, and the boot fails with the real reason.
func TestAnUnreadableDatabaseIsNotRecoveredOver(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads anything")
	}
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	seedUser(t, db, "admin")
	seedShare(t, db, "s1s1", "admin")
	Backup(db, filepath.Join(dir, "backups"), at)
	seedShare(t, db, "s2s2", "admin")
	db.Close()
	path := filepath.Join(dir, FileName)
	os.Chmod(path, 0)
	t.Cleanup(func() { os.Chmod(path, 0o644) })
	_, err = Open(dir)
	if err == nil || errors.Is(err, ErrNoUsableDatabase) {
		t.Fatalf("got %v", err)
	}
	if _, ok := ReadRecovered(dir); ok {
		t.Fatal("a recovery ran over an unreadable file")
	}
	os.Chmod(path, 0o644)
	db2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	if !hasShare(t, db2, "s2s2") {
		t.Fatal("the newer share was lost to a restore")
	}
}

// The marker names the backup's own time, which is what the owner needs to
// know: shares made after it are the ones to share again.
func TestTheMarkerNamesTheBackupsTime(t *testing.T) {
	dir := t.TempDir()
	db, _ := Open(dir)
	seedUser(t, db, "admin")
	seedShare(t, db, "s1s1", "admin")
	Backup(db, filepath.Join(dir, "backups"), at)
	db.Close()
	corrupt(t, filepath.Join(dir, FileName))
	db2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	db2.Close()
	rec, _ := ReadRecovered(dir)
	if !rec.BackupAt.Equal(at) {
		t.Fatalf("backupAt %v, want %v", rec.BackupAt, at)
	}
}

// A restored database's change journal is another timeline: every cursor
// a client holds, whether below or above the restored head, must answer
// Reset, or a replica keeps rows the restore removed.
func TestARestoreInvalidatesEveryOldCursor(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	seedUser(t, db, "admin")
	mustShare(t, db, CreateOptions{Name: "one", Owner: "admin"})
	early, _ := db.Cursor()
	Backup(db, filepath.Join(dir, "backups"), at)
	mustShare(t, db, CreateOptions{Name: "two", Owner: "admin"})
	mustShare(t, db, CreateOptions{Name: "three", Owner: "admin"})
	late, _ := db.Cursor()
	db.Close()
	corrupt(t, filepath.Join(dir, FileName))
	db2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	for _, c := range []string{early, late, "0"} {
		if b, err := db2.Since(c, "admin", 10); err != nil || !b.Reset {
			t.Fatalf("cursor %s after a restore: %+v, %v", c, b, err)
		}
	}
	// The restored journal carries on: a walk from the new head continues.
	head, _ := db2.Cursor()
	mustShare(t, db2, CreateOptions{Name: "four", Owner: "admin"})
	if b, err := db2.Since(head, "admin", 10); err != nil || b.Reset || len(b.Changes) != 1 {
		t.Fatalf("since the restored head: %+v, %v", b, err)
	}
}

// TestTheStoreIsCreatedOwnerOnly pins that every file and directory the
// store creates is readable by the service account alone: the database holds
// password hashes, second-factor secrets and token hashes, and an install
// that lets the server create its own data directory must not publish them
// to every local account.
func TestTheStoreIsCreatedOwnerOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	seedUser(t, db, "admin")
	backups := filepath.Join(dir, "backups")
	backup, err := Backup(db, backups, at)
	if err != nil {
		t.Fatal(err)
	}
	main := filepath.Join(dir, FileName)
	for _, p := range []string{dir, main, main + "-wal", main + "-shm", backups, backup} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s is %v, want no group or other bits", p, st.Mode().Perm())
		}
	}
	db.Close()
	corrupt(t, main)
	db, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, p := range []string{main, filepath.Join(dir, RecoveredMarker)} {
		if st, err := os.Stat(p); err != nil || st.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s after the restore: %v, %v", p, st.Mode().Perm(), err)
		}
	}
}
