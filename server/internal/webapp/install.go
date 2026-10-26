// Package webapp installs the web client's signed bundle into the data
// directory, serves it at /app and fetches newer bundles from the web release
// manifest. It knows nothing about what is inside a bundle beyond its
// index.html: the bundle is the web client's own product, verified with
// core/webbundle and served as static files.
//
// Layout under <data>/web:
//
//	<version>-<build>/          an install, complete before it is named
//	<version>-<build>/.hyperdrop-web.json   its version, build and contract
//	current                     "<version>-<build>\n", the install served
//	.staging-<random>/          an extraction in progress, removed at boot
//
// The install current names and the one before it are kept (one rollback);
// older ones are removed after each switch.
package webapp

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"hyperdrop/core/webbundle"
	"hyperdrop/server/internal/fsatomic"
	"hyperdrop/server/internal/shareid"
)

const (
	maxEntries   = 2000
	maxTotal     = 64 << 20
	maxFile      = 16 << 20
	metaName     = ".hyperdrop-web.json"
	pointerName  = "current"
	stagingStart = ".staging-"
)

var (
	// ErrOutsideWindow refuses a correctly signed bundle whose contract this
	// server does not serve (webbundle.Serves).
	ErrOutsideWindow = errors.New("the web bundle's contract is outside this server's window")
	// ErrBadArchive refuses an archive that is not a plain tree of files and
	// directories within the caps, with index.html at its root.
	ErrBadArchive = errors.New("the web bundle archive is not acceptable")
)

// writePointer replaces the current pointer durably.
var writePointer = fsatomic.Write

// Installed is the bundle a Store serves.
type Installed struct {
	Version  string
	Build    int
	Contract string
	Dir      string
}

type meta struct {
	Version  string `json:"version"`
	Build    int    `json:"build"`
	Contract string `json:"contract"`
}

// Store is the web client's installs under one data directory.
type Store struct {
	root     string
	keys     []string
	contract string

	install sync.Mutex // one install at a time

	mu  sync.RWMutex
	cur *Installed // what current names; nil when nothing is installed
	dev string     // a directory served unsigned instead (UseDevDir)
}

// Open reads <dataDir>/web, creating it, and removes what an interrupted
// extraction left. keys are the trusted web release keys (base64 Ed25519) and
// serverContract this server's own version. A pointer that does not name a
// complete install reads as nothing installed.
func Open(dataDir string, keys []string, serverContract string) (*Store, error) {
	root := filepath.Join(dataDir, "web")
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, fmt.Errorf("web client: %w", err)
	}
	s := &Store{root: root, keys: keys, contract: serverContract}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("web client: %w", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), stagingStart) {
			if err := os.RemoveAll(filepath.Join(root, e.Name())); err != nil {
				log.Printf("web client: removing %s: %v", e.Name(), err)
			}
		}
	}
	raw, err := os.ReadFile(filepath.Join(root, pointerName))
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("web client: %w", err)
	default:
		name := strings.TrimSuffix(string(raw), "\n")
		inst, err := s.read(name)
		if err != nil {
			log.Printf("web client: the current install %q is unusable, so none is served: %v", name, err)
		} else {
			s.cur = &inst
		}
	}
	return s, nil
}

// installName is the directory of one version and build.
func installName(version string, build int) string {
	return version + "-" + strconv.Itoa(build)
}

// read loads the install directory name, which must be one Install made.
func (s *Store) read(name string) (Installed, error) {
	if name == "" || strings.HasPrefix(name, ".") || !filepath.IsLocal(name) || strings.ContainsAny(name, `/\`) {
		return Installed{}, errors.New("not an install name")
	}
	dir := filepath.Join(s.root, name)
	data, err := os.ReadFile(filepath.Join(dir, metaName))
	if err != nil {
		return Installed{}, err
	}
	var m meta
	if err := json.Unmarshal(data, &m); err != nil {
		return Installed{}, err
	}
	if installName(m.Version, m.Build) != name {
		return Installed{}, fmt.Errorf("its record names %s build %d", m.Version, m.Build)
	}
	return Installed{Version: m.Version, Build: m.Build, Contract: m.Contract, Dir: dir}, nil
}

// Current is the bundle served: the development directory when one is set,
// else the install the pointer names. A nil Store serves nothing.
func (s *Store) Current() (Installed, bool) {
	if s == nil {
		return Installed{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.dev != "" {
		return Installed{Version: "dev", Contract: s.contract, Dir: s.dev}, true
	}
	if s.cur == nil {
		return Installed{}, false
	}
	return *s.cur, true
}

// UseDevDir serves dir unsigned in place of any install, with this server's
// own contract. The caller decides when that is allowed.
func (s *Store) UseDevDir(dir string) {
	s.mu.Lock()
	s.dev = dir
	s.mu.Unlock()
}

// installed is the install the pointer names, ignoring a development
// directory.
func (s *Store) installed() (Installed, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cur == nil {
		return Installed{}, false
	}
	return *s.cur, true
}

// Install verifies archive against sig for this version, build and contract,
// refuses a contract this server does not serve, extracts it and makes it
// current, keeping the install it replaces. Any error leaves the current
// install as it was. Installing the current version and build again does
// nothing.
func (s *Store) Install(archive, sig []byte, version string, build int, contract string) error {
	if err := webbundle.Verify(s.keys, sig, version, build, contract, archive); err != nil {
		return err
	}
	if !webbundle.Serves(contract, s.contract) {
		return fmt.Errorf("%w: it speaks %s, this server is %s", ErrOutsideWindow, contract, s.contract)
	}
	s.install.Lock()
	defer s.install.Unlock()

	name := installName(version, build)
	old, hasOld := s.installed()
	if hasOld && filepath.Base(old.Dir) == name {
		return nil
	}
	staging, err := os.MkdirTemp(s.root, stagingStart)
	if err != nil {
		return err
	}
	staged := false
	defer func() {
		if !staged {
			os.RemoveAll(staging)
		}
	}()
	if err := extract(archive, staging); err != nil {
		return err
	}
	m, _ := json.Marshal(meta{Version: version, Build: build, Contract: contract})
	if err := writeSynced(filepath.Join(staging, metaName), m); err != nil {
		return err
	}
	if err := syncDir(staging); err != nil {
		return err
	}

	final := filepath.Join(s.root, name)
	// A directory of this name is a complete install that is not current (the
	// previous one, or one a crash left before its pointer was written): it is
	// replaced by the extraction just verified.
	if err := os.RemoveAll(final); err != nil {
		return err
	}
	if err := os.Rename(staging, final); err != nil {
		return err
	}
	staged = true
	if err := syncDir(s.root); err != nil {
		os.RemoveAll(final)
		return err
	}
	if err := writePointer(filepath.Join(s.root, pointerName), []byte(name+"\n"), 0o600); err != nil {
		os.RemoveAll(final)
		return fmt.Errorf("web client: switching to %s: %w", name, err)
	}
	inst := Installed{Version: version, Build: build, Contract: contract, Dir: final}
	s.mu.Lock()
	s.cur = &inst
	s.mu.Unlock()

	keep := map[string]bool{name: true}
	if hasOld {
		keep[filepath.Base(old.Dir)] = true
	}
	s.prune(keep)
	return nil
}

// prune removes every install directory but keep's. Staging directories are
// left alone: the install lock is held, so any present is an earlier crash's,
// which Open removes.
func (s *Store) prune(keep map[string]bool) {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		log.Printf("web client: listing installs: %v", err)
		return
	}
	for _, e := range entries {
		if !e.IsDir() || keep[e.Name()] || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		if err := os.RemoveAll(filepath.Join(s.root, e.Name())); err != nil {
			log.Printf("web client: removing the old install %s: %v", e.Name(), err)
		}
	}
}

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

func writeSynced(p string, data []byte) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	d.Close()
	return err
}
