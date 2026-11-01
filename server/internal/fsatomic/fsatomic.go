// Package fsatomic holds the one durable file-replace the server uses for the
// files it keeps outside the database, such as the per-volume cookie secret
// (sharefs). Each holds a key, so a write must never leave a truncated or
// empty file in its place.
package fsatomic

import (
	"os"
	"path/filepath"
)

// Write atomically replaces path with data at perm, via tmp + fsync + rename
// + an fsync of the directory.
//
// The first fsync is the point: without it a power loss right after the
// rename can leave an EMPTY file where a complete one was, since the rename
// can reach the disk before the bytes do. The directory's fsync makes the
// rename itself durable, so a file written once (a first boot's secret, from
// which clients capture the server's identity) is still there after a crash.
// A failed write or rename removes the tmp rather than leaving it to be
// mistaken for a partial record; a failed directory sync leaves a whole file
// either way, so it is not an error.
//
// perm is the caller's: every current caller passes 0600, since each file
// holds a key or a bearer token.
func Write(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	// Close can report a deferred write error, so it must not be discarded,
	// but it must not mask an earlier one either.
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}
