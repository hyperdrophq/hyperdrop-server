//go:build !unix

package linked

import (
	"errors"
	"os"
	"path/filepath"
)

var errAncestryTooDeep = errors.New("linked roots: directory ancestry deeper than the walk allows")

// dirID is a directory's identity as os.SameFile compares it.
type dirID = os.FileInfo

// statID answers the identity of the directory at path.
func statID(path string) (dirID, error) { return os.Stat(path) }

func sameDir(a, b dirID) bool { return os.SameFile(a, b) }

// handleAncestry answers the identities of the directory the handle or was
// opened at and of each directory above it, read from the path prefixes of
// its resolved name. A path is raceable where the unix build's ".." walk is
// not; this build serves only the Windows dev server, which never ships.
func handleAncestry(or *os.Root, max int) ([]dirID, error) {
	var out []dirID
	p := realPath(or.Name())
	for range max {
		info, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		out = append(out, info)
		if filepath.Dir(p) == p {
			return out, nil
		}
		p = filepath.Dir(p)
	}
	return nil, errAncestryTooDeep
}
