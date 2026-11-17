package metadb

import (
	"database/sql"
	"testing"
	"time"

	"hyperdrop/server/internal/shareid"
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

// allGalleryRows is every gallery row of a share, keyed by slug: what a
// test counts to prove a prune left nothing behind. The public page reads
// rows by slug (GalleryOf).
func (db *DB) allGalleryRows(shareID string) (items map[string]GalleryItem, err error) {
	if !shareid.ValidID(shareID) {
		return nil, ErrNotFound
	}
	items = map[string]GalleryItem{}
	err = db.read(func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT slug, width, height, duration_ms, taken_at FROM gallery WHERE share_id = ? ORDER BY slug`, shareID)
		if err != nil {
			return err
		}
		return eachRow(rows, func() error {
			var slug string
			var w, h, ms, taken sql.NullInt64
			if err := rows.Scan(&slug, &w, &h, &ms, &taken); err != nil {
				return err
			}
			items[slug] = GalleryItem{Width: int(w.Int64), Height: int(h.Int64), DurationMS: int(ms.Int64), TakenAt: fromNSPtr(taken)}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return items, nil
}
