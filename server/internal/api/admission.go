package api

import (
	"fmt"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/sharefs"
)

// ownerRoom is the advisory quota check before bytes are staged: the
// account's quota against the usage, less what the path this upload writes
// already holds, since an overwrite costs the difference rather than the
// whole file. rel is "" for a check that names no path (a share's
// reservation). CommitFile enforces the quota inside the writing
// transaction; this only spares a client an upload that would be refused
// at the end.
func (h *handler) ownerRoom(u metadb.User, shareID, rel string, bytes int64) error {
	if u.QuotaBytes <= 0 {
		return nil
	}
	var old int64
	if rel != "" {
		if f, err := h.db.File(shareID, rel); err == nil && !f.Pending {
			old = f.Size
		}
	}
	usage, err := h.db.Usage(u.Username)
	if err == nil && usage.Bytes-old+bytes > u.QuotaBytes {
		return fmt.Errorf("%w: this account holds %d of %d bytes", metadb.ErrQuota, usage.Bytes, u.QuotaBytes)
	}
	return nil
}

// admitBytes is what a batch entry runs before it stages: the owner's room
// for rel, then the disk's (sharefs.AdmitWrite, which draws on the share's
// reservation and holds a rolling window of the rest, charged to the
// account, until the caller releases it).
func (h *handler) admitBytes(u metadb.User, shareID, rel string, bytes int64) (*sharefs.WriteHold, error) {
	if err := h.ownerRoom(u, shareID, rel, bytes); err != nil {
		return nil, err
	}
	return h.fs.AdmitWrite(shareID, u.Username, bytes)
}
