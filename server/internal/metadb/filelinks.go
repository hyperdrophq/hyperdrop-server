package metadb

import (
	"database/sql"
	"errors"
	"time"

	"hyperdrop/server/internal/shareid"
)

// A file's direct link is a row of file_links: a server-minted key naming
// one (share, slug) pair. The key follows the slug, so a replace, a move
// and a rename keep the link working; a delete leaves the row, which
// PruneOrphanFileLinks removes once the slug is held by neither files nor
// linked_slugs. A share's delete removes its keys through the foreign key.

// MintFileKeys answers the key of each slug named, minting one for a slug
// that has none. A slug held by neither files (a pending row counts) nor
// linked_slugs is left out of the answer, and so is a malformed one. An
// inbox share refuses with ErrInbox and writes nothing. All of it is one
// transaction. A mint that inserts a key records a journal row in it, so a
// client following the change feed re-reads the share and learns the
// fileKey; the share's modifiedAt stays put. A mint answering only existing
// keys writes nothing.
func (db *DB) MintFileKeys(shareID string, slugs []string, now time.Time) (map[string]string, error) {
	if !shareid.ValidID(shareID) {
		return nil, ErrNotFound
	}
	keys := make(map[string]string, len(slugs))
	err := db.commit(func(tx *sql.Tx) error {
		h, err := readHead(tx, shareID)
		if err != nil {
			return err
		}
		if h.inbox {
			return ErrInbox
		}
		minted := false
		for _, slug := range slugs {
			if !shareid.ValidSlug(slug) {
				continue
			}
			var key string
			err := tx.QueryRow(`SELECT file_key FROM file_links WHERE share_id = ? AND slug = ?`, shareID, slug).Scan(&key)
			if err == nil {
				keys[slug] = key
				continue
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			var held bool
			if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM files WHERE share_id = ? AND slug = ?)
				OR EXISTS(SELECT 1 FROM linked_slugs WHERE share_id = ? AND slug = ?)`,
				shareID, slug, shareID, slug).Scan(&held); err != nil {
				return err
			}
			if !held {
				continue
			}
			key = shareid.NewFileKey()
			if _, err := tx.Exec(`INSERT INTO file_links(file_key, share_id, slug, created_at) VALUES(?, ?, ?, ?)`,
				key, shareID, slug, toNS(now)); err != nil {
				return err
			}
			keys[slug] = key
			minted = true
		}
		if !minted {
			return nil
		}
		return recordChange(tx, h.owner, shareID, false, now)
	})
	if err != nil {
		return nil, err
	}
	return keys, nil
}

// StopFileKey deletes the key of one file; a file with none is not an error
// and writes nothing. A delete records a journal row in the same
// transaction, without moving the share's modifiedAt, so a client following
// the change feed re-reads the share and drops the fileKey.
func (db *DB) StopFileKey(shareID, slug string, now time.Time) error {
	if !shareid.ValidID(shareID) {
		return ErrNotFound
	}
	return db.commit(func(tx *sql.Tx) error {
		res, err := tx.Exec(`DELETE FROM file_links WHERE share_id = ? AND slug = ?`, shareID, slug)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n == 0 {
			return err
		}
		var owner string
		if err := tx.QueryRow(`SELECT owner FROM shares WHERE id = ?`, shareID).Scan(&owner); err != nil {
			return err
		}
		return recordChange(tx, owner, shareID, false, now)
	})
}

// ResolveFileKey answers the share and slug a key names, ErrNotFound for a
// key of the wrong shape (without a query) or one that names nothing.
func (db *DB) ResolveFileKey(key string) (shareID, slug string, err error) {
	if !shareid.ValidFileKey(key) {
		return "", "", ErrNotFound
	}
	err = db.read(func(tx *sql.Tx) error {
		err := tx.QueryRow(`SELECT share_id, slug FROM file_links WHERE file_key = ?`, key).Scan(&shareID, &slug)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	})
	if err != nil {
		return "", "", err
	}
	return shareID, slug, nil
}

// FileKeys answers every key a share holds, by slug.
func (db *DB) FileKeys(shareID string) (map[string]string, error) {
	if !shareid.ValidID(shareID) {
		return nil, ErrNotFound
	}
	keys := map[string]string{}
	err := db.read(func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT slug, file_key FROM file_links WHERE share_id = ?`, shareID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var slug, key string
			if err := rows.Scan(&slug, &key); err != nil {
				return err
			}
			keys[slug] = key
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return keys, nil
}

// PruneOrphanFileLinks deletes the keys whose (share, slug) is held by
// neither files nor linked_slugs and answers how many. A hidden linked
// entry keeps its linked_slugs row, so its key survives.
func (db *DB) PruneOrphanFileLinks() (n int, err error) {
	err = db.write(func(tx *sql.Tx) error {
		res, err := tx.Exec(`DELETE FROM file_links
			WHERE NOT EXISTS (SELECT 1 FROM files f WHERE f.share_id = file_links.share_id AND f.slug = file_links.slug)
			  AND NOT EXISTS (SELECT 1 FROM linked_slugs l WHERE l.share_id = file_links.share_id AND l.slug = file_links.slug)`)
		if err != nil {
			return err
		}
		c, err := res.RowsAffected()
		n = int(c)
		return err
	})
	return
}
