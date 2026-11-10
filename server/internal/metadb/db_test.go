package metadb

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestOpenStampsAFreshDirectoryAndReopensIt(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	var v int
	if err := db.read(func(tx *sql.Tx) error { return tx.QueryRow(`PRAGMA user_version`).Scan(&v) }); err != nil {
		t.Fatal(err)
	}
	if v != SchemaVersion {
		t.Fatalf("user_version = %d, want %d", v, SchemaVersion)
	}
	db.Close()
	if _, err := os.Stat(filepath.Join(dir, "hyperdrop.db")); err != nil {
		t.Fatalf("database file: %v", err)
	}
	db, err = Open(dir)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	db.Close()
}

func TestOpenRefusesOtherStamps(t *testing.T) {
	for _, tc := range []struct {
		stamp int
		want  error
	}{{SchemaVersion + 1, ErrSchemaTooNew}, {9, ErrSchemaTooNew}, {SchemaVersion + 100, ErrSchemaTooNew}} {
		dir := t.TempDir()
		db, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		db.Close()
		raw, err := sql.Open("sqlite", filepath.Join(dir, "hyperdrop.db"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := raw.Exec(`PRAGMA user_version = ` + itoa(tc.stamp)); err != nil {
			t.Fatal(err)
		}
		raw.Close()
		if _, err := Open(dir); !errors.Is(err, tc.want) {
			t.Errorf("stamp %d: Open error = %v, want %v", tc.stamp, err, tc.want)
		}
		if _, err := OpenAsIs(dir); !errors.Is(err, tc.want) {
			t.Errorf("stamp %d: OpenAsIs error = %v, want %v", tc.stamp, err, tc.want)
		}
	}
}

// A non-empty database stamped 0 is not a fresh one: applying the schema
// over it would fail halfway or silently adopt foreign tables.
func TestOpenRefusesAStampZeroDatabaseThatHoldsTables(t *testing.T) {
	dir := t.TempDir()
	raw, err := sql.Open("sqlite", filepath.Join(dir, "hyperdrop.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE stranger (x)`); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	if _, err := Open(dir); !errors.Is(err, ErrSchemaUnknown) {
		t.Fatalf("Open error = %v, want ErrSchemaUnknown", err)
	}
}

func TestOpenSetsThePragmas(t *testing.T) {
	db := openTest(t)
	var mode string
	var sync, fk int
	err := db.read(func(tx *sql.Tx) error {
		if err := tx.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
			return err
		}
		if err := tx.QueryRow(`PRAGMA synchronous`).Scan(&sync); err != nil {
			return err
		}
		return tx.QueryRow(`PRAGMA foreign_keys`).Scan(&fk)
	})
	if err != nil {
		t.Fatal(err)
	}
	if mode != "wal" || sync != 2 || fk != 1 {
		t.Fatalf("journal_mode=%s synchronous=%d foreign_keys=%d, want wal 2 1", mode, sync, fk)
	}
}

func TestSubscribeWakesOnNotify(t *testing.T) {
	db := openTest(t)
	ch, cancel := db.Subscribe()
	defer cancel()
	db.notify()
	select {
	case <-ch:
	default:
		t.Fatal("no wake after notify")
	}
	db.notify()
	db.notify() // coalesces: a slow subscriber sees one pending wake, never blocks the writer
	select {
	case <-ch:
	default:
		t.Fatal("no wake after repeated notify")
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

// TestADataDirectoryNamedLikeAURIOpensWithEveryPragma pins that the
// database's path reaches SQLite whole: a directory name holding ?, # or %
// neither truncates the path nor drops the pragmas the invariants rest on.
func TestADataDirectoryNamedLikeAURIOpensWithEveryPragma(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a?b#c%41d")
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "a")); err == nil {
		t.Fatal("SQLite opened the path cut at the ?")
	}
	for _, h := range []*sql.DB{db.w, db.r} {
		var fk, sync int
		var journal string
		if err := h.QueryRow(`PRAGMA foreign_keys`).Scan(&fk); err != nil {
			t.Fatal(err)
		}
		if err := h.QueryRow(`PRAGMA synchronous`).Scan(&sync); err != nil {
			t.Fatal(err)
		}
		if err := h.QueryRow(`PRAGMA journal_mode`).Scan(&journal); err != nil {
			t.Fatal(err)
		}
		if fk != 1 || sync != 2 || journal != "wal" {
			t.Fatalf("foreign_keys %d, synchronous %d, journal %q: want 1, 2 (FULL), wal", fk, sync, journal)
		}
	}
	if err := quickCheck(filepath.Join(dir, FileName)); err != nil {
		t.Fatalf("quickCheck: %v", err)
	}
}
