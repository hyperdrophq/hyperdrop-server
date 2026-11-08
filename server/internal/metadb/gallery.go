package metadb

import (
	"database/sql"
	"time"

	"hyperdrop/server/internal/shareid"
)

// GalleryItem is one file's poster-side metadata, keyed by slug.
type GalleryItem struct {
	Width, Height, DurationMS int
	TakenAt                   *time.Time
}

// SetGallery merges items into the share's gallery metadata. A slug that
// names no file is ignored rather than refused: the app backfills tiles for
// files that may have been replaced meanwhile.
func (db *DB) SetGallery(shareID string, items map[string]GalleryItem) error {
	return db.commit(func(tx *sql.Tx) error {
		h, err := readHead(tx, shareID)
		if err != nil {
			return err
		}
		for slug, it := range items {
			w, hh, ms := nullUnlessPositive(it.Width), nullUnlessPositive(it.Height), nullUnlessPositive(it.DurationMS)
			if _, err := tx.Exec(`INSERT INTO gallery(share_id, slug, width, height, duration_ms, taken_at)
				SELECT ?, ?, ?, ?, ?, ?
				WHERE EXISTS (SELECT 1 FROM files WHERE share_id = ? AND slug = ?)
				   OR EXISTS (SELECT 1 FROM linked_slugs WHERE share_id = ? AND slug = ?)
				ON CONFLICT(share_id, slug) DO UPDATE SET width = excluded.width, height = excluded.height,
				duration_ms = excluded.duration_ms, taken_at = excluded.taken_at`,
				shareID, slug, w, hh, ms, toNSPtr(it.TakenAt), shareID, slug, shareID, slug); err != nil {
				return err
			}
		}
		return recordChange(tx, h.owner, shareID, false, time.Now())
	})
}

// pruneGalleryRows removes every gallery row whose slug names nothing the share
// holds any more. A share holds two kinds of slug: its own files', and its
// linked entries', which are minted beside the walk and live in linked_slugs.
// A prune that read `files` alone would take a NAS gallery's rows with it the
// first time any file left the share.
func pruneGalleryRows(tx *sql.Tx, shareID string) error {
	_, err := tx.Exec(`DELETE FROM gallery WHERE share_id = ?
		AND slug NOT IN (SELECT slug FROM files WHERE share_id = ?)
		AND slug NOT IN (SELECT slug FROM linked_slugs WHERE share_id = ?)`, shareID, shareID, shareID)
	return err
}

// GalleryOf is Gallery for the named slugs alone: one seek per slug, the
// slugs carried as one JSON parameter, so a page of tiles reads its own rows
// and not the share's.
func (db *DB) GalleryOf(shareID string, slugs []string) (items map[string]GalleryItem, err error) {
	if !shareid.ValidID(shareID) {
		return nil, ErrNotFound
	}
	items = map[string]GalleryItem{}
	if len(slugs) == 0 {
		return items, nil
	}
	err = db.read(func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT g.slug, g.width, g.height, g.duration_ms, g.taken_at FROM json_each(?) j
			JOIN gallery g ON g.share_id = ? AND g.slug = j.value`, idSet(slugs), shareID)
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
