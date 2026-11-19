package api

import (
	"context"
	"log"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/sealpw"
)

// sealPassword answers the readable copy of a share password (sealpw), bound
// to the share id and to the bcrypt hash written beside it. id is a validated
// share id and hash the hash the same write stores.
func (h *handler) sealPassword(id, hash, password string) ([]byte, error) {
	return sealpw.Seal(h.fs.Secret(), id, hash, password)
}

// readablePassword answers the share's password for its owner, or "" when
// it has none, set it before the server kept a copy, or holds a copy that
// does not open beside the row's hash under this volume's secret: each of
// those reads as "Set" in the apps. Any failure to open is "", never an
// error and never another value.
func (h *handler) readablePassword(d metadb.Share) string {
	if d.PasswordHash == "" || len(d.PasswordSealed) == 0 {
		return ""
	}
	pw, err := sealpw.Open(h.fs.Secret(), d.ID, d.PasswordHash, d.PasswordSealed)
	if err != nil {
		return ""
	}
	return pw
}

// sealedSweepBatch bounds the copies one sweep transaction clears.
const sealedSweepBatch = 500

// sealedStore is what the sweep needs of metadb.DB.
type sealedStore interface {
	SealedCopies() ([]metadb.SealedCopy, error)
	ClearSealedBatch([]metadb.SealedCopy) error
	ClearSealed(metadb.SealedCopy) error
}

// SweepSealed clears every stored copy that no longer opens beside its row's
// hash under secret: a hash the previous release changed or removed, a
// schedule it rewrote, a copy imported from another server. The serving
// process runs it once in the background after boot; serving meanwhile is
// safe because every read already treats such a copy as absent.
//
// Stale copies are cleared sealedSweepBatch to a transaction. A batch that
// fails is retried one copy at a time, and a copy that still fails is logged
// (its table and share id, never the copy) and skipped, so one bad row
// cannot keep the rest. A copy rewritten while it runs is left as it is
// (the clear compares before clearing). It stops between batches when ctx
// is done. It answers how many it cleared and the first error it met.
func SweepSealed(ctx context.Context, db sealedStore, secret []byte) (int, error) {
	copies, err := db.SealedCopies()
	if err != nil {
		return 0, err
	}
	var stale []metadb.SealedCopy
	for _, c := range copies {
		if c.Hash != "" {
			if _, err := sealpw.Open(secret, c.ShareID, c.Hash, c.Sealed); err == nil {
				continue
			}
		}
		stale = append(stale, c)
	}
	cleared := 0
	var first error
	note := func(err error) {
		if first == nil {
			first = err
		}
	}
	for len(stale) > 0 {
		if err := ctx.Err(); err != nil {
			note(err)
			break
		}
		batch := stale[:min(len(stale), sealedSweepBatch)]
		stale = stale[len(batch):]
		err := db.ClearSealedBatch(batch)
		if err == nil {
			cleared += len(batch)
			continue
		}
		log.Printf("sealed passwords: a batch of %d did not clear (%v); clearing one at a time", len(batch), err)
		for _, c := range batch {
			if err := db.ClearSealed(c); err != nil {
				log.Printf("sealed passwords: %s %s not cleared: %v", c.Table, c.ShareID, err)
				note(err)
				continue
			}
			cleared++
		}
	}
	return cleared, first
}
