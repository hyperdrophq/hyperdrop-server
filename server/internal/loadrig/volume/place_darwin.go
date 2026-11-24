//go:build darwin

package volume

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// cloneFile makes dst a copy of blob without copying its bytes: an APFS
// clone, which shares the blob's blocks yet is a file of its own (its own
// inode, one link, its own deletion cost), as an uploaded file is. It
// answers false without an error on a file system that cannot clone, where
// the pool makes a hard link instead.
func cloneFile(blob, dst string) (cloned bool, err error) {
	err = unix.Clonefile(blob, dst, unix.CLONE_NOFOLLOW)
	if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EXDEV) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("clone %s: %w", dst, err)
	}
	return true, nil
}
