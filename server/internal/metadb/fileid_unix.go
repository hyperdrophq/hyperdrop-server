//go:build unix

package metadb

import (
	"os"
	"syscall"
)

// fileIdentity answers the inode fi names, which a file replaced under the
// same name (a restore, a copy) does not keep.
func fileIdentity(fi os.FileInfo) (inode uint64, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Ino), true
}
