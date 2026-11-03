package sharefs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"hyperdrop/server/internal/shareid"
)

// probePrefix names every scratch file and directory the case probes make
// in shares/. No share id begins with ".", so none is ever taken for a
// share, and Open removes whatever a crash left there.
const probePrefix = ".casefold-"

// FoldsCase reports whether the data volume stores report.pdf and
// Report.pdf as one file. Bytes are stored by name (files/<rel>), so on
// such a volume every decision about whether two relpaths collide folds
// too: the path locks here by shareid.FoldPath, and the database's and the
// inbox's name checks, which the API sets from this answer.
func (f *FS) FoldsCase() bool { return f.foldsCase }

// SetFoldsCase overrides what Open's probe found, before anything is
// served: a test runs the folded decisions on a volume that does not fold.
// SameName then compares names by shareid.FoldPath rather than asking the
// volume, which would keep them apart.
func (f *FS) SetFoldsCase(folds bool) {
	f.foldsCase, f.simulated = folds, folds
	if folds {
		shareid.PrepareFold()
	}
}

// SameName reports whether the data volume takes the path segments a and b
// for one name. FoldPath only finds candidates (two names with one key may
// be two files here: APFS keeps İ apart from i, exFAT keeps straße apart
// from strasse), so before a write is spelled as another name, the volume is
// asked: a file made as a in a scratch directory of shares/, and looked for
// as b. A probe that cannot run answers true, the answer that never puts two
// rows on one file.
func (f *FS) SameName(a, b string) bool {
	if a == b {
		return true
	}
	if !validSegment(a) || !validSegment(b) {
		return shareid.FoldPath(a) == shareid.FoldPath(b)
	}
	if f.simulated {
		return shareid.FoldPath(a) == shareid.FoldPath(b)
	}
	dir, err := os.MkdirTemp(filepath.Join(f.dataDir, sharesDirName), probePrefix+"*")
	if err != nil {
		return true
	}
	defer os.RemoveAll(dir)
	fh, err := os.OpenFile(filepath.Join(dir, a), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return true
	}
	fi, err := fh.Stat()
	fh.Close()
	if err != nil {
		return true
	}
	other, err := os.Lstat(filepath.Join(dir, b))
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	if err != nil {
		return true
	}
	return os.SameFile(fi, other)
}

// SamePath reports whether the data volume takes the relpaths held and
// incoming of share id, which differ at most in their last segment's
// spelling, for one entry. When held has bytes on disk (a stored file, or
// a folder holding one) the volume is asked about those exact files:
// incoming names the same file or directory, or it does not. Otherwise
// (a pending row, a folder that is only a record) SameName asks with a
// scratch pair.
func (f *FS) SamePath(id, held, incoming string) bool {
	if held == incoming {
		return true
	}
	if !f.simulated && shareid.ValidRelPath(held) && shareid.ValidRelPath(incoming) {
		if root, err := f.root(id); err == nil {
			defer root.Close()
			if hfi, err := root.Lstat(fileRel(held)); err == nil {
				ifi, err := root.Lstat(fileRel(incoming))
				if errors.Is(err, fs.ErrNotExist) {
					return false
				}
				return err != nil || os.SameFile(hfi, ifi)
			}
		}
	}
	return f.SameName(lastSegment(held), lastSegment(incoming))
}

func lastSegment(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// validSegment is one relpath segment, which names nothing but itself
// inside a directory.
func validSegment(s string) bool {
	return !strings.Contains(s, "/") && shareid.ValidRelPath(s)
}

// probeFoldsCase makes a file in dir, looks for it under its upper-case
// name and removes it: the volume folds case when that name finds the same
// file. ext4's casefold is a per-directory attribute that new directories
// inherit, so dir is the directory every share's directory is made in. A
// data directory the server cannot write to fails here, as it would fail
// every upload.
func probeFoldsCase(dir string) (bool, error) {
	f, err := os.CreateTemp(dir, probePrefix+"probe-*")
	if err != nil {
		return false, err
	}
	name := f.Name()
	defer os.Remove(name)
	fi, err := f.Stat()
	f.Close()
	if err != nil {
		return false, err
	}
	other, err := os.Lstat(filepath.Join(dir, strings.ToUpper(filepath.Base(name))))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return os.SameFile(fi, other), nil
}

// removeStaleProbes removes what a probe interrupted by a crash left in
// shares/. Best effort: what cannot be read or removed now is tried again at
// the next start.
func removeStaleProbes(dir string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), probePrefix) {
			os.RemoveAll(filepath.Join(dir, e.Name()))
		}
	}
}
