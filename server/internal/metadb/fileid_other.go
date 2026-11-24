//go:build !unix

package metadb

import "os"

// fileIdentity answers no inode on a system without one, so no clean-close
// record is trusted there.
func fileIdentity(os.FileInfo) (inode uint64, ok bool) { return 0, false }
