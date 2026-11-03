package api

import (
	"fmt"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/sharefs"
)

// ownerRoom is the advisory quota check before bytes are staged: the
// account's quota against the usage, less what the path this upload writes
// already holds, since an overwrite costs the difference rather than the
// whole file. Every byte the account's open publishes hold counts too
// (sharefs.StagedBytes), as stagedRoom counts it: those bytes are on the disk
// until their publish commits or goes. rel is "" for a check that names no
// path (a share's reservation). CommitFile enforces the quota on committed
// bytes inside the writing transaction; this only spares a client an upload
// that would be refused at the end.
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
	if err != nil {
		return nil
	}
	staged := h.fs.StagedBytes(u.Username)
	if usage.Bytes+staged-old+bytes > u.QuotaBytes {
		return fmt.Errorf("%w: this account holds %d of %d bytes and its open publishes %d more",
			metadb.ErrQuota, usage.Bytes, u.QuotaBytes, staged)
	}
	return nil
}

// stagedRoom is ownerRoom for bytes staged into publish pid: the account's
// committed bytes plus every byte its open publishes hold (as each staged
// path declared it, sharefs.StagedBytes), less what rel already declared in
// this publish, plus bytes, must fit the quota. A staged file is charged
// whole, the file it replaces included, since both are on the disk until
// the commit; the commit's transaction charges the net change.
func (h *handler) stagedRoom(u metadb.User, shareID, pid, rel string, bytes int64) error {
	if u.QuotaBytes <= 0 {
		return nil
	}
	usage, err := h.db.Usage(u.Username)
	if err != nil {
		return nil
	}
	staged := h.fs.StagedBytes(u.Username) - h.fs.StagedDeclared(shareID, pid, rel)
	if usage.Bytes+staged+bytes > u.QuotaBytes {
		return fmt.Errorf("%w: this account holds %d of %d bytes and its open publishes %d more",
			metadb.ErrQuota, usage.Bytes, u.QuotaBytes, staged)
	}
	return nil
}

// admitStaged is admitBytes for a batch entry staged into publish pid: the
// quota is stagedRoom's.
func (h *handler) admitStaged(u metadb.User, shareID, pid, rel string, bytes int64) (*sharefs.WriteHold, error) {
	if err := h.stagedRoom(u, shareID, pid, rel, bytes); err != nil {
		return nil, err
	}
	return h.fs.AdmitWrite(shareID, u.Username, bytes)
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
