package metadb

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
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
		p, err := Backup(context.Background(), db, backups, at.AddDate(0, 0, i))
		if err != nil {
			t.Fatal(err)
		}
		last = p
	}
	names, _ := filepath.Glob(filepath.Join(backups, "hyperdrop-*.db"))
	if len(names) != KeepBackups {
		t.Fatalf("kept %d: %v", len(names), names)
	}
	for _, p := range append(names, backups) {
		if st, err := os.Stat(p); err != nil || st.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s: %v, %v; want no group or other bits", p, st.Mode().Perm(), err)
		}
	}
	if err := quickCheck(last); err != nil {
		t.Fatal(err)
	}
	if got := NewestBackup(backups); got != last {
		t.Fatalf("newest %q, want %q", got, last)
	}
	if got := shareIDsIn(t, last); !slices.Equal(got, []string{"s1s1"}) {
		t.Fatalf("the copy holds %v", got)
	}
}

// shareIDsIn opens a copy read-only and answers its share ids in order.
func shareIDsIn(t *testing.T, path string) []string {
	t.Helper()
	c, err := sql.Open("sqlite", fileURI(path)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rows, err := c.Query(`SELECT id FROM shares ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := scanStrings(rows)
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

// setBeforeBackupCopy runs before just as every backup's copy starts,
// for the length of the test.
func setBeforeBackupCopy(t *testing.T, before func()) {
	t.Helper()
	old := beforeBackupCopy
	beforeBackupCopy = before
	t.Cleanup(func() { beforeBackupCopy = old })
}

// readAll answers each file's bytes by path.
func readAll(t *testing.T, paths []string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		out[p] = b
	}
	return out
}

// sameFiles fails the test unless dir's copies are exactly want, byte for
// byte, and dir holds no part file.
func sameFiles(t *testing.T, dir string, want map[string][]byte) {
	t.Helper()
	got := backups(dir)
	if len(got) != len(want) {
		t.Fatalf("copies %v, want %d", got, len(want))
	}
	for _, p := range got {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(b, want[p]) {
			t.Fatalf("%s changed", p)
		}
	}
	if parts, _ := filepath.Glob(filepath.Join(dir, "*.part")); len(parts) != 0 {
		t.Fatalf("part files left: %v", parts)
	}
}

// corruptLastPage overwrites the database's last page, which the open's
// own reads never reach.
func corruptLastPage(t *testing.T, path string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	header := make([]byte, 100)
	if _, err := f.ReadAt(header, 0); err != nil {
		t.Fatal(err)
	}
	pageSize := int64(binary.BigEndian.Uint16(header[16:18]))
	if pageSize == 1 {
		pageSize = 65536
	}
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() < 3*pageSize {
		t.Fatalf("the database has %d bytes, too few pages to damage the last", st.Size())
	}
	junk := bytes.Repeat([]byte{0xFF}, int(pageSize))
	if _, err := f.WriteAt(junk, st.Size()-pageSize); err != nil {
		t.Fatal(err)
	}
}

// A copy taken while another connection writes holds the database as it was
// at one moment: the shares that existed when it began, and of the shares
// written meanwhile an unbroken run from the first, never a later one
// without an earlier. The writes are not held back and all of them land.
func TestABackupDuringWritesIsOneSnapshot(t *testing.T) {
	db := openTest(t)
	seedUser(t, db, "admin")
	for _, id := range []string{"a1a1", "b2b2", "c3c3"} {
		seedShare(t, db, id, "admin")
	}
	if err := db.write(func(tx *sql.Tx) error {
		for i := range 5000 {
			if _, err := tx.Exec(`INSERT INTO shares(id,owner,name,name_lower,created_at) VALUES(?,?,?,?,?)`,
				fmt.Sprintf("f%05d", i), "admin", "filler", "filler", toNS(at)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	type result struct {
		n   int
		err error
	}
	stop, wrote := make(chan struct{}), make(chan result)
	setBeforeBackupCopy(t, func() {
		go func() {
			n := 0
			for {
				select {
				case <-stop:
					wrote <- result{n, nil}
					return
				default:
				}
				id := fmt.Sprintf("w%06d", n+1)
				if err := db.write(func(tx *sql.Tx) error {
					_, err := tx.Exec(`INSERT INTO shares(id,owner,name,name_lower,created_at) VALUES(?,?,?,?,?)`, id, "admin", "N", "n", toNS(at))
					return err
				}); err != nil {
					<-stop
					wrote <- result{n, err}
					return
				}
				n++
			}
		}()
	})
	p, err := Backup(context.Background(), db, filepath.Join(t.TempDir(), "backups"), at)
	close(stop)
	w := <-wrote
	if err != nil {
		t.Fatal(err)
	}
	if w.err != nil {
		t.Fatalf("a write during the copy: %v", w.err)
	}
	n := w.n
	if err := quickCheck(p); err != nil {
		t.Fatal(err)
	}
	var copied []string
	for _, id := range shareIDsIn(t, p) {
		if strings.HasPrefix(id, "w") {
			copied = append(copied, id)
		} else if id[0] != 'f' && !slices.Contains([]string{"a1a1", "b2b2", "c3c3"}, id) {
			t.Fatalf("the copy holds %s", id)
		}
	}
	slices.Sort(copied)
	for i, id := range copied {
		if want := fmt.Sprintf("w%06d", i+1); id != want {
			t.Fatalf("the copy holds %v: %s where %s belongs", copied, id, want)
		}
	}
	for _, id := range []string{"a1a1", "b2b2", "c3c3"} {
		if !slices.Contains(shareIDsIn(t, p), id) {
			t.Fatalf("the copy lacks %s", id)
		}
	}
	t.Logf("%d shares written during the copy, %d of them in it", n, len(copied))
	if n == 0 || !hasShare(t, db, fmt.Sprintf("w%06d", n)) {
		t.Fatalf("the writes during the copy did not land (%d written)", n)
	}
}

// The copy is a plain rollback-journal database: restoring it copies one
// file, and checking it creates no -wal or -shm beside it.
func TestTheCopyIsNotInWALMode(t *testing.T) {
	db := openTest(t)
	seedUser(t, db, "admin")
	seedShare(t, db, "s1s1", "admin")
	dir := filepath.Join(t.TempDir(), "backups")
	p, err := Backup(context.Background(), db, dir, at)
	if err != nil {
		t.Fatal(err)
	}
	c, err := sql.Open("sqlite", fileURI(p)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	var mode string
	err = c.QueryRow(`PRAGMA journal_mode`).Scan(&mode)
	c.Close()
	if err != nil || mode != "delete" {
		t.Fatalf("journal_mode %q, %v", mode, err)
	}
	if err := quickCheck(p); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if ok, _ := filepath.Match("hyperdrop-*.db", e.Name()); !ok {
			t.Errorf("backups/ holds %s", e.Name())
		}
	}
}

// A page the live file holds damaged is copied as it is, and the copy's
// check catches it: the copy is removed, the older copies stay as they
// were, and the data directory records that the database owes a check.
func TestADamagedSourceIsCaughtOnTheCopy(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	seedUser(t, db, "admin")
	for i := range 200 {
		seedShare(t, db, fmt.Sprintf("s%05d", i), "admin")
	}
	bdir := filepath.Join(dir, "backups")
	for i := range 3 {
		if _, err := Backup(context.Background(), db, bdir, at.AddDate(0, 0, i)); err != nil {
			t.Fatal(err)
		}
	}
	good := readAll(t, backups(bdir))
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	corruptLastPage(t, filepath.Join(dir, FileName))

	db, err = OpenAsIs(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = Backup(context.Background(), db, bdir, at.AddDate(0, 0, 3))
	if !errors.Is(err, ErrCopyDamaged) || !errors.Is(err, errCorrupt) {
		t.Fatalf("got %v, want ErrCopyDamaged", err)
	}
	sameFiles(t, bdir, good)
	data, err := os.ReadFile(filepath.Join(dir, CheckOwedFile))
	if err != nil {
		t.Fatal(err)
	}
	var owed struct {
		At     time.Time `json:"at"`
		Reason string    `json:"reason"`
	}
	if err := json.Unmarshal(data, &owed); err != nil || !owed.At.Equal(at.AddDate(0, 0, 3)) || owed.Reason == "" {
		t.Fatalf("marker %s: %v", data, err)
	}
	if st, err := os.Stat(filepath.Join(dir, CheckOwedFile)); err != nil || st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("marker mode %v, %v", st.Mode().Perm(), err)
	}
}

// corruptSchemaTree overwrites page 1 past the file header: the root of
// sqlite_schema, which every statement that names a table reads first.
func corruptSchemaTree(t *testing.T, path string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	header := make([]byte, 100)
	if _, err := f.ReadAt(header, 0); err != nil {
		t.Fatal(err)
	}
	pageSize := int(binary.BigEndian.Uint16(header[16:18]))
	if pageSize == 1 {
		pageSize = 65536
	}
	if _, err := f.WriteAt(bytes.Repeat([]byte{0xFF}, pageSize-100), 100); err != nil {
		t.Fatal(err)
	}
}

// Damage SQLite reports while the copy reads the live file, before any
// copy exists to check, is the same damage: ErrCopyDamaged, the marker, no
// part file and the older copies as they were.
func TestDamageMetDuringTheCopyIsADamagedCopy(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	seedUser(t, db, "admin")
	seedShare(t, db, "s1s1", "admin")
	bdir := filepath.Join(dir, "backups")
	for i := range 3 {
		if _, err := Backup(context.Background(), db, bdir, at.AddDate(0, 0, i)); err != nil {
			t.Fatal(err)
		}
	}
	good := readAll(t, backups(bdir))
	// The damage reaches the file under a serving process: every page is in
	// the main file and no read connection holds a page of it cached, so
	// the copy's connection reads page 1 from the disk. (An open of a file
	// so damaged refuses before it could back anything up.)
	defer db.Close()
	if _, err := db.w.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	db.r.SetMaxIdleConns(0)
	db.r.SetMaxIdleConns(8)
	corruptSchemaTree(t, filepath.Join(dir, FileName))
	now := at.AddDate(0, 0, 3)
	_, err = Backup(context.Background(), db, bdir, now)
	if !errors.Is(err, ErrCopyDamaged) || !errors.Is(err, errCorrupt) {
		t.Fatalf("got %v, want ErrCopyDamaged", err)
	}
	sameFiles(t, bdir, good)
	data, err := os.ReadFile(filepath.Join(dir, CheckOwedFile))
	if err != nil {
		t.Fatal(err)
	}
	var owed struct {
		At     time.Time `json:"at"`
		Reason string    `json:"reason"`
	}
	if err := json.Unmarshal(data, &owed); err != nil || !owed.At.Equal(now) || owed.Reason == "" {
		t.Fatalf("marker %s: %v", data, err)
	}
}

// A backup cut short leaves no part file and no change to the copies, and
// the connection it read through goes back to the pool out of its
// transaction.
func TestACancelledBackupLeavesNothing(t *testing.T) {
	db := openTest(t)
	seedUser(t, db, "admin")
	seedShare(t, db, "s1s1", "admin")
	dir := filepath.Join(t.TempDir(), "backups")
	if _, err := Backup(context.Background(), db, dir, at); err != nil {
		t.Fatal(err)
	}
	good := readAll(t, backups(dir))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	setBeforeBackupCopy(t, cancel)
	if _, err := Backup(ctx, db, dir, at.AddDate(0, 0, 1)); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
	sameFiles(t, dir, good)
	setBeforeBackupCopy(t, nil)
	// Every pooled read connection is free to start a transaction, and the
	// write connection is not held back by a snapshot left open.
	for range 16 {
		if !hasShare(t, db, "s1s1") {
			t.Fatal("the share is gone")
		}
	}
	seedShare(t, db, "s2s2", "admin")
	if !hasShare(t, db, "s2s2") {
		t.Fatal("a write after the cancelled backup did not land")
	}
}

// Two backups at once, the daily pass's and an update's, both finish: the
// second waits for the first rather than removing its part file as stale.
func TestTwoBackupsAtOnceBothFinish(t *testing.T) {
	db := openTest(t)
	seedUser(t, db, "admin")
	seedShare(t, db, "s1s1", "admin")
	dir := filepath.Join(t.TempDir(), "backups")
	second := make(chan error, 1)
	var once sync.Once
	setBeforeBackupCopy(t, func() {
		once.Do(func() {
			go func() {
				_, err := Backup(context.Background(), db, dir, at.AddDate(0, 0, 1))
				second <- err
			}()
			// Long enough for an unserialized second backup to have swept
			// the part files; a serialized one is still waiting.
			select {
			case err := <-second:
				second <- err
			case <-time.After(300 * time.Millisecond):
			}
		})
	})
	if _, err := Backup(context.Background(), db, dir, at); err != nil {
		t.Fatalf("the first backup: %v", err)
	}
	if err := <-second; err != nil {
		t.Fatalf("the second backup: %v", err)
	}
	if got := backups(dir); len(got) != 2 {
		t.Fatalf("copies %v", got)
	}
}

// A part file a crash left behind is removed by the next backup.
func TestAStalePartIsRemovedByTheNextBackup(t *testing.T) {
	db := openTest(t)
	seedUser(t, db, "admin")
	dir := filepath.Join(t.TempDir(), "backups")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(dir, "hyperdrop-20200101T000000Z.db.part")
	if err := os.WriteFile(stale, []byte("half a copy"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Backup(context.Background(), db, dir, at); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("the stale part is still there: %v", err)
	}
	if got := backups(dir); len(got) != 1 {
		t.Fatalf("copies %v", got)
	}
}

// A serving open whose check passes has paid the check a damaged copy
// owed, and removes the marker; an open as is checks nothing and keeps it.
func TestAPassingBootCheckClearsACheckOwed(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	seedUser(t, db, "admin")
	db.Close()
	marker := filepath.Join(dir, CheckOwedFile)
	if err := os.WriteFile(marker, []byte(`{"at":"2026-09-19T12:00:00Z","reason":"test"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	asIs, err := OpenAsIs(dir)
	if err != nil {
		t.Fatal(err)
	}
	asIs.Close()
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("an open as is removed the marker: %v", err)
	}
	db, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if !db.OpenStats().Checked {
		t.Fatal("the serving open did not check")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("the marker survived a passing check: %v", err)
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
	if _, err := Backup(context.Background(), db, filepath.Join(dir, "backups"), at); err != nil {
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
	if got := db2.OpenStats().Recovered; got != rec.Backup {
		t.Fatalf("OpenStats().Recovered = %q, want the backup %q", got, rec.Backup)
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
	Backup(context.Background(), db, filepath.Join(dir, "backups"), at)
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
	Backup(context.Background(), db, filepath.Join(dir, "backups"), at)
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
	Backup(context.Background(), db, filepath.Join(dir, "backups"), at)
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
	Backup(context.Background(), db, filepath.Join(dir, "backups"), at)
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
	Backup(context.Background(), db, filepath.Join(dir, "backups"), at)
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
	backup, err := Backup(context.Background(), db, backups, at)
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

// A copy holds only what the database holds now: no free pages, and none of
// the deleted content the live file still keeps in freed space.
func TestTheCopyCarriesNoDeletedContent(t *testing.T) {
	db := openTest(t)
	seedUser(t, db, "admin")
	const gone = "remanence-marker-of-a-deleted-share"
	err := db.write(func(tx *sql.Tx) error {
		for i := range 400 {
			name := fmt.Sprintf("%s-%04d", gone, i)
			if _, err := tx.Exec(`INSERT INTO shares(id,owner,name,name_lower,created_at) VALUES(?,?,?,?,?)`,
				fmt.Sprintf("d%05d", i), "admin", name, name, toNS(at)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	seedShare(t, db, "keep1", "admin")
	if err := db.write(func(tx *sql.Tx) error {
		_, err := tx.Exec(`DELETE FROM shares WHERE id LIKE 'd%'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.w.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	live, err := os.ReadFile(filepath.Join(db.dataDir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(live, []byte(gone)) {
		t.Fatal("the live file kept no deleted content; the test proves nothing")
	}

	p, err := Backup(context.Background(), db, filepath.Join(t.TempDir(), "backups"), at)
	if err != nil {
		t.Fatal(err)
	}
	copied, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(copied, []byte(gone)) {
		t.Fatal("the copy carries a deleted share's name")
	}
	c, err := sql.Open("sqlite", fileURI(p)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var free int
	if err := c.QueryRow(`PRAGMA freelist_count`).Scan(&free); err != nil || free != 0 {
		t.Fatalf("freelist_count %d, %v", free, err)
	}
	if got := shareIDsIn(t, p); !slices.Equal(got, []string{"keep1"}) {
		t.Fatalf("the copy holds %v", got)
	}
}
