//go:build !darwin

package volume

// cloneFile makes no clones on this system: every stored file is a hard
// link to a blob file (blobPool.link).
func cloneFile(blob, dst string) (cloned bool, err error) { return false, nil }
