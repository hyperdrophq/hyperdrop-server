package api

import (
	"fmt"
	"math"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/sharefs"
)

// overQuota reports whether charges, less credit, pass quota. The sum saturates:
// a declared total is the client's own number, and a wrapped sum would pass any
// quota.
func overQuota(quota, credit int64, charges ...int64) bool {
	var used int64
	for _, c := range charges {
		if c > math.MaxInt64-used {
			used = math.MaxInt64
			break
		}
		used += c
	}
	return used-credit > quota
}

// ownerRoom is the advisory quota check before bytes are staged: the
// account's quota against the usage, less what the path this upload writes
// already holds, since an overwrite costs the difference rather than the
// whole file. Everything else the account holds counts too (sharefs.QuotaHeld),
// its tiles and posters, its open publishes, its ranged parts and its other
// shares' reservations, as stagedRoom counts it: those bytes are on the disk or promised
// until they commit or go, and without them an account could hold any number of
// parts one byte short of done, or reserve many times its quota and have other
// accounts' uploads refused for room it never fills. What
// rel's own part is charged is what this upload replaces, so it counts once.
// rel is "" for a check that names no path (a share's reservation). CommitFile
// enforces the quota on committed bytes inside the writing transaction; this
// spares a client an upload that would be refused at the end, and is the only
// limit on bytes that never commit.
func (h *handler) ownerRoom(u metadb.User, shareID, rel string, bytes int64) error {
	if u.QuotaBytes <= 0 {
		return nil
	}
	var old, ownPart int64
	if rel != "" {
		if f, err := h.db.File(shareID, rel); err == nil && !f.Pending {
			old = f.Size
		}
		ownPart = h.fs.PartCharge(shareID, rel)
	}
	usage, err := h.db.Usage(u.Username)
	if err != nil {
		return nil
	}
	staged := h.fs.QuotaHeld(u.Username, shareID)
	if overQuota(u.QuotaBytes, old+ownPart, usage.Bytes, staged, bytes) {
		return fmt.Errorf("%w: this account holds %d of %d bytes and its uploads and previews %d more",
			metadb.ErrQuota, usage.Bytes, u.QuotaBytes, staged-ownPart)
	}
	return nil
}

// stagedRoom is ownerRoom for bytes staged into publish pid: the account's
// committed bytes plus every byte its uploads hold (as each declared it,
// sharefs.QuotaHeld), less what rel already declared in
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
	declared := h.fs.StagedDeclared(shareID, pid, rel)
	staged := h.fs.QuotaHeld(u.Username, shareID)
	if overQuota(u.QuotaBytes, declared, usage.Bytes, staged, bytes) {
		return fmt.Errorf("%w: this account holds %d of %d bytes and its uploads and previews %d more",
			metadb.ErrQuota, usage.Bytes, u.QuotaBytes, staged-declared)
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
	if err := h.fileRoom(u, shareID, rel); err != nil {
		return nil, err
	}
	return h.fs.AdmitWrite(shareID, u.Username, bytes)
}

// sidecarRoom is the quota check before a gallery tile or a poster adds bytes to
// the disk (sharefs.SidecarRoom): the same room as any upload. CommitFile's
// transaction counts committed bytes alone, so this check and ownerRoom are what
// keep previews and files inside one quota together.
func (h *handler) sidecarRoom(id, owner string, bytes int64) error {
	quota, err := h.db.QuotaOf(owner)
	if err != nil {
		return nil
	}
	return h.ownerRoom(metadb.User{Username: owner, QuotaBytes: quota}, id, "", bytes)
}

// fileRoom is the advisory check before a file a person is uploading lands: a new
// path past the account's file limit is refused before its bytes are staged.
// CommitFile decides it inside the writing transaction; this spares the upload.
func (h *handler) fileRoom(u metadb.User, shareID, rel string) error {
	limit := metadb.FileLimit(u.QuotaBytes)
	if limit == 0 {
		return nil
	}
	if rel != "" {
		if f, err := h.db.File(shareID, rel); err == nil && !f.Pending {
			return nil
		}
	}
	usage, err := h.db.Usage(u.Username)
	if err != nil || int64(usage.Committed) < limit {
		return nil
	}
	return fmt.Errorf("%w: this account holds %d files, the most its quota allows", metadb.ErrQuota, usage.Committed)
}
