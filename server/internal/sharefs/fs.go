package sharefs

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"hyperdrop/server/internal/shareid"
	"hyperdrop/server/internal/volsecret"
)

const (
	sharesDirName  = "shares"
	filesDirName   = "files"
	partsDirName   = "parts"
	thumbsDirName  = "thumbs"
	posterFileName = "poster.jpg"
	partHashExt    = ".hash"
	partSessionExt = ".session"
	partRangesExt  = ".ranges"
	partPrevExt    = ".prev"
	partPathExt    = ".path"
	stageDirName   = "stage"
	stageOwnerName = "owner"
	journalName    = "commit.json"
	secretFileName = volsecret.FileName

	// SidecarMaxBytes bounds one thumbnail or poster on the way in.
	SidecarMaxBytes = 4 << 20

	// defaultAbandonedUpload is how long after its last byte an interrupted
	// upload is taken as abandoned: its staged part is deleted and the
	// pending row it belonged to goes with it. Long enough that a closed
	// laptop or a dropped connection still resumes mid-file, short enough
	// that a transfer nobody will finish stops holding disk.
	DefaultAbandonedUpload = 3 * time.Hour

	// DefaultStageMaxFiles bounds the distinct paths one publish stages: a
	// commit makes at most as many live.
	DefaultStageMaxFiles = 20000
	// DefaultStageLifetime is how long after it opened a publish is swept
	// however recently it was written, unless it holds a commit journal:
	// a stage kept alive by one small write now and then would hold disk
	// for good.
	DefaultStageLifetime = 24 * time.Hour
)

// stageMaxFiles is the FS's StageMaxFiles, or DefaultStageMaxFiles.
func (f *FS) stageMaxFiles() int {
	if f.StageMaxFiles > 0 {
		return f.StageMaxFiles
	}
	return DefaultStageMaxFiles
}

// stageLifetime is the FS's StageLifetime, or DefaultStageLifetime.
func (f *FS) stageLifetime() time.Duration {
	if f.StageLifetime > 0 {
		return f.StageLifetime
	}
	return DefaultStageLifetime
}

// AbandonedUploadWindow is that window: the FS's AbandonedWindow, or
// DefaultAbandonedUpload when it is not set.
func (f *FS) AbandonedUploadWindow() time.Duration {
	if f.AbandonedWindow > 0 {
		return f.AbandonedWindow
	}
	return DefaultAbandonedUpload
}

// FS is the file layer over one data directory.
type FS struct {
	dataDir string

	// AbandonedWindow overrides DefaultAbandonedUpload (the operator's
	// HYPERDROP_ABANDONED_UPLOAD_TTL); 0 keeps the default.
	AbandonedWindow time.Duration

	// WriteWindow overrides defaultWriteWindow, the most of an admitted
	// write that is promised to other uploads at once; 0 keeps the default.
	WriteWindow int64

	// StageMaxFiles overrides DefaultStageMaxFiles; 0 keeps the default.
	StageMaxFiles int
	// StageLifetime overrides DefaultStageLifetime; 0 keeps the default.
	StageLifetime time.Duration

	// ReservePercent is the share of the disk kept free for the system,
	// FlatReserve for a flat 1 GiB, 0 for none;
	// uploads that would dip into it fail with ErrDiskFull. 0 keeps no
	// reserve and still admits uploads against the free space.
	ReservePercent int
	// DiskSpace probes free and total bytes of the filesystem holding dir.
	// Open sets the real Statfs probe; tests replace it.
	DiskSpace func(dir string) (free, total int64, err error)

	secret []byte

	// inflight counts the bytes of ranged chunks still arriving (PartSize).
	inflight inflightBytes

	// shareLocks holds one RWMutex per share. Writers of a share's bytes
	// hold it shared; RemoveShare holds it exclusively, so a commit can
	// never recreate a directory the delete is removing.
	shareLocks keyedLocks[sync.RWMutex]
	// pathLocks holds one lock per {share, relpath} upload, plain or staged
	// in any publish.
	pathLocks keyedLocks[pathLock]
	// swapLocks holds one RWMutex per share, apart from shareLocks: a
	// publish's commit holds it exclusively across its renames, a visitor's
	// row read and open hold it shared (WithSwap, ReadSwapped).
	swapLocks keyedLocks[sync.RWMutex]

	resMu        sync.Mutex
	reservations map[string]reservation
	// holds are the writes admitted and still landing.
	holds map[*WriteHold]struct{}

	// stagedMu guards staged: the shares a part was staged in since boot, or
	// that still held a part when the boot pass ran. SweepStaleParts reads
	// only these, so an idle volume costs it no disk access.
	stagedMu sync.Mutex
	staged   map[string]bool

	// stagesMu guards stages: every open publish, by share and then
	// publish id, with its owner, its opening time and the bytes each of
	// its staged paths declared. OpenStage adds one, every removal of a
	// stage or a share forgets it, and the boot pass records the ones it
	// keeps; OpenPublishes and StagedBytes count an owner's from it.
	stagesMu sync.Mutex
	stages   map[string]map[string]*stageState

	// foldsCase is whether the volume under shares/ matches names
	// case-insensitively (probeFoldsCase), read once at Open; simulated is
	// a test's SetFoldsCase, which compares names by key (SameName).
	foldsCase, simulated bool
}

// Open prepares the data directory: shares/ exists, the secret exists, the
// disk probe is armed. It reads no share.
func Open(dataDir string) (*FS, error) {
	if err := os.MkdirAll(filepath.Join(dataDir, sharesDirName), 0o700); err != nil {
		return nil, err
	}
	secret, err := volsecret.LoadOrCreate(dataDir)
	if err != nil {
		return nil, err
	}
	shares := filepath.Join(dataDir, sharesDirName)
	removeStaleProbes(shares)
	folds, err := probeFoldsCase(shares)
	if err != nil {
		return nil, err
	}
	if folds {
		shareid.PrepareFold()
	}
	f := &FS{dataDir: dataDir, secret: secret, DiskSpace: statfsSpace, foldsCase: folds,
		reservations: map[string]reservation{}, holds: map[*WriteHold]struct{}{}, staged: map[string]bool{},
		stages: map[string]map[string]*stageState{}}
	return f, nil
}

// DataDir is the directory Open was given.
func (f *FS) DataDir() string { return f.dataDir }

// ShareDir is a share's directory, whether or not it exists yet.
func (f *FS) ShareDir(id string) (string, error) {
	if !shareid.ValidID(id) {
		return "", ErrNotFound
	}
	return filepath.Join(f.dataDir, sharesDirName, id), nil
}

// FilePath is a stored file's absolute path. Callers that serve or stat a
// file open it through Open instead; this is for the few places that hand a
// path to another program.
func (f *FS) FilePath(id, rel string) (string, error) {
	dir, err := f.ShareDir(id)
	if err != nil {
		return "", err
	}
	if !shareid.ValidRelPath(rel) {
		return "", ErrBadPath
	}
	return filepath.Join(dir, fileRel(rel)), nil
}

// fileRel is a relpath's location inside the share root.
func fileRel(rel string) string { return filepath.Join(filesDirName, filepath.FromSlash(rel)) }

// partRel is where a relpath's bytes stage while they upload: a flat
// directory of hashed names, so a file can never collide with a directory
// ("a" against "a/b") and nothing a client sends is a path component here.
func partRel(rel string) string { return filepath.Join(partsDirName, partName(rel)) }

// partName is a relpath's staged file name: the hex SHA-256 of the relpath.
func partName(rel string) string {
	sum := sha256.Sum256([]byte(rel))
	return hex.EncodeToString(sum[:]) + ".part"
}

// partAt locates one upload's staged bytes: under parts/ for a plain upload,
// under stage/<pid>/ for a publish's (stage is the publish id). path is the
// part's location inside the share root.
type partAt struct{ stage, rel, path string }

func plainPart(rel string) partAt { return partAt{rel: rel, path: partRel(rel)} }

func stagedPart(pid, rel string) partAt {
	return partAt{stage: pid, rel: rel, path: stagedPartRel(pid, rel)}
}

// inflightKey keys the part's arriving bytes, so a staged upload's never
// count toward the plain upload of the same path.
func (p partAt) inflightKey(id string) string {
	if p.stage == "" {
		return inflightKey(id, p.rel)
	}
	return inflightKey(id, p.rel) + "\x00" + p.stage
}

// root opens the share's directory as an os.Root. Every byte of a share is
// reached through it, so a symlink planted inside the share cannot lead
// outside it. ErrNotFound when the directory does not exist.
func (f *FS) root(id string) (*os.Root, error) {
	dir, err := f.ShareDir(id)
	if err != nil {
		return nil, err
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return r, nil
}

// ensureRoot is root for the write paths: the share directory is created on
// its first upload, so the path is composed from a validated id and made
// before it is opened.
func (f *FS) ensureRoot(id string) (*os.Root, error) {
	dir, err := f.ShareDir(id)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return os.OpenRoot(dir)
}

// keyedLocks hands out one T per key, counted so the map never keeps an
// entry nobody holds. The zero value is ready to use.
type keyedLocks[T any] struct {
	mu sync.Mutex
	m  map[string]*keyedLock[T]
}

type keyedLock[T any] struct {
	lock T
	refs int
}

// acquire answers key's T, created on first use; done gives the reference
// back.
func (k *keyedLocks[T]) acquire(key string) (l *T, done func()) {
	k.mu.Lock()
	if k.m == nil {
		k.m = map[string]*keyedLock[T]{}
	}
	e := k.m[key]
	if e == nil {
		e = &keyedLock[T]{}
		k.m[key] = e
	}
	e.refs++
	k.mu.Unlock()
	return &e.lock, func() {
		k.mu.Lock()
		if e.refs--; e.refs == 0 {
			delete(k.m, key)
		}
		k.mu.Unlock()
	}
}

type pathLock struct {
	// mu is held exclusively by every operation on a whole part (Write,
	// Commit, CommitRanged, Discard, RemoveFile) and shared by ranged
	// chunk writes, which run in parallel.
	mu sync.RWMutex
	// meta serializes a ranged write's check of the part and its record of a
	// range: the two short steps around the unlocked copy.
	meta sync.Mutex
}

// pathLockFor is the {share, relpath} lock, the relpath folded on a volume
// that folds case, where two spellings are one file. done gives the
// reference back.
func (f *FS) pathLockFor(id, rel string) (l *pathLock, done func()) {
	return f.pathLocks.acquire(id + "\x00" + f.pathKey(rel))
}

// pathKey is the name a relpath's lock goes by: folded on a volume that
// folds case.
func (f *FS) pathKey(rel string) string {
	if f.foldsCase {
		return shareid.FoldPath(rel)
	}
	return rel
}

// lockPath takes the {share, relpath} lock exclusively, from part open
// through commit. Returns the unlock func.
func (f *FS) lockPath(id, rel string) func() {
	l, done := f.pathLockFor(id, rel)
	l.mu.Lock()
	return func() { l.mu.Unlock(); done() }
}

// rlockPath takes the {share, relpath} lock shared, for one ranged chunk.
func (f *FS) rlockPath(id, rel string) (*pathLock, func()) {
	l, done := f.pathLockFor(id, rel)
	l.mu.RLock()
	return l, func() { l.mu.RUnlock(); done() }
}

// lockShare takes a share exclusively: RemoveShare holds it while the directory
// goes. Returns the release func.
func (f *FS) lockShare(id string) func() {
	l, done := f.shareLocks.acquire(id)
	l.Lock()
	return func() { l.Unlock(); done() }
}

// tryLockShare takes a share exclusively when nothing holds it, and answers
// false without waiting otherwise.
func (f *FS) tryLockShare(id string) (func(), bool) {
	l, done := f.shareLocks.acquire(id)
	if !l.TryLock() {
		done()
		return nil, false
	}
	return func() { l.Unlock(); done() }, true
}

// rlockShare takes a share's lock in shared mode: every writer of a share's bytes holds it, so
// none can recreate a directory RemoveShare is removing. Returns the release
// func.
func (f *FS) rlockShare(id string) func() {
	l, done := f.shareLocks.acquire(id)
	l.RLock()
	return func() { l.RUnlock(); done() }
}

// copyBufs pools 1 MB buffers for the multi-GB copy paths; the 32 KB
// io.Copy default costs measurable per-chunk overhead at that scale.
var copyBufs = sync.Pool{New: func() any { b := make([]byte, 1<<20); return &b }}

// CopyBuffer copies src into dst through a pooled 1 MB buffer. The wrappers
// hide WriterTo and ReaderFrom so io.CopyBuffer uses the buffer.
func CopyBuffer(dst io.Writer, src io.Reader) (int64, error) {
	bp := copyBufs.Get().(*[]byte)
	defer copyBufs.Put(bp)
	return io.CopyBuffer(struct{ io.Writer }{dst}, struct{ io.Reader }{src}, *bp)
}
