package metadb

import (
	"testing"
	"time"
)

// openTest opens a fresh database in a temporary directory and closes it
// when the test ends.
func openTest(t *testing.T) *DB {
	t.Helper()
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// writeCount is how many write transactions db has opened.
func (db *DB) writeCount() int64 { return db.writes.Load() }

// at is a fixed instant tests use so stored times compare exactly.
var at = time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)

// fileSlug answers the slug a share minted for one of its paths.
func fileSlug(t *testing.T, db *DB, id, path string) string {
	t.Helper()
	d, err := db.Share(id)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range d.Files {
		if f.Path == path {
			return f.Slug
		}
	}
	t.Fatalf("share %s holds no %q", id, path)
	return ""
}
