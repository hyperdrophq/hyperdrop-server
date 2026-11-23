//go:build !unix

package sharefs

// statfsInodes answers no inode count on a system that has none to report, which
// leaves the inode reserve off.
func statfsInodes(string) (free, total int64, err error) { return 0, 0, nil }
