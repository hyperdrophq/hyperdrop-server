package webapp

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"hyperdrop/server/internal/shareid"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
)

// Unpacking a bundle's archive within the caps, through os.Root.

// memberName is a tar member's path inside the bundle, "." for the root
// directory, or ok false when it could reach outside the bundle or be read
// two ways.
func memberName(raw string) (string, bool) {
	if raw == "" || strings.HasPrefix(raw, "/") || strings.ContainsAny(raw, "\\\x00") {
		return "", false
	}
	for seg := range strings.SplitSeq(raw, "/") {
		if seg == ".." {
			return "", false
		}
	}
	name := path.Clean(raw)
	if name == "." {
		return name, true
	}
	if !fs.ValidPath(name) || !shareid.ValidRelPath(name) {
		return "", false
	}
	return name, true
}

func bad(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrBadArchive}, args...)...)
}

// extract unpacks a gzip tar of regular files and directories into dir,
// within the caps, every file synced. It requires index.html at the root.
func extract(archive []byte, dir string) error {
	zr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return bad("not gzip: %v", err)
	}
	defer zr.Close()
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()

	tr := tar.NewReader(zr)
	seen := map[string]bool{}
	dirs := map[string]bool{".": true}
	var entries int
	var total int64
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return bad("%v", err)
		}
		if entries++; entries > maxEntries {
			return bad("more than %d entries", maxEntries)
		}
		name, ok := memberName(h.Name)
		if !ok {
			return bad("the path %q", h.Name)
		}
		if name == metaName {
			return bad("%s is the server's own record", metaName)
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if name == "." {
				continue
			}
			if seen[name] {
				return bad("%s appears twice", name)
			}
			seen[name] = true
			if err := root.MkdirAll(name, 0o755); err != nil {
				return bad("%s: %v", name, err)
			}
			for p := name; p != "."; p = path.Dir(p) {
				dirs[p] = true
			}
		case tar.TypeReg:
			if name == "." || seen[name] {
				return bad("%s appears twice", h.Name)
			}
			seen[name] = true
			if h.Size > maxFile {
				return bad("%s is over %d bytes", name, maxFile)
			}
			if total += h.Size; total > maxTotal {
				return bad("over %d bytes in all", maxTotal)
			}
			if parent := path.Dir(name); !dirs[parent] {
				if err := root.MkdirAll(parent, 0o755); err != nil {
					return bad("%s: %v", name, err)
				}
				for p := parent; p != "."; p = path.Dir(p) {
					dirs[p] = true
				}
			}
			if err := writeMember(root, name, tr, h.Size); err != nil {
				return err
			}
		default:
			return bad("%s is not a regular file or directory", name)
		}
	}
	if !seen["index.html"] || dirs["index.html"] {
		return bad("no index.html at its root")
	}
	for d := range dirs {
		f, err := root.Open(d)
		if err != nil {
			return err
		}
		err = f.Sync()
		f.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// writeMember creates name, which must not exist (a case-folding filesystem
// would otherwise let two members share one file), with exactly size bytes.
func writeMember(root *os.Root, name string, r io.Reader, size int64) error {
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return bad("%s: %v", name, err)
	}
	n, err := io.Copy(f, io.LimitReader(r, size))
	if err == nil && n != size {
		err = bad("%s is truncated", name)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
