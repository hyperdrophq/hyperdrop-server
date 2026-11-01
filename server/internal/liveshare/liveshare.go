// Package liveshare holds shares relayed by their owner's client. A
// disconnected relay stays in memory for a short resume grace; nothing here
// touches disk, deliberately: the server relays and stores no file bytes. See
// docs/api.md § Live shares.
package liveshare

import (
	"errors"
	"sync"
	"time"

	"hyperdrop/server/internal/shareid"
)

const (
	defaultGrace        = 5 * time.Minute
	defaultOfflineAfter = 10 * time.Second
	defaultMaxPerOwner  = 3
	defaultMaxFiles     = 100000
	defaultAddressWait  = 30 * time.Second
)

var (
	ErrTooMany        = errors.New("too many live shares for this account")
	ErrResumeMismatch = errors.New("live share sources no longer match")
)

type File struct {
	Path  string
	Size  int64
	Mime  string
	MTime time.Time
	Slug  string // minted by Create
	// Key is the file's direct-link key, minted beside Slug and kept for the
	// file's life in the share.
	Key string
}

type Record struct {
	ID           string
	Name         string
	Owner        string
	Folder       bool
	PasswordHash string
	// PasswordGen is what a visitor's access cookie is signed over. Create
	// starts it at 1 and every password change moves it on, voiding the
	// cookies and site grants the previous password issued.
	PasswordGen int
	ZipSize     int64
	CreatedAt   time.Time
	Files       []File
	// Listing forces the file listing on a share of ONE file, which
	// /share/{id} otherwise redirects straight to the file. Redundant on a
	// share of several files, which lists by default.
	Listing bool
	// Media marks a gallery: /share/{id} opens the pictures. Mutually
	// exclusive with Listing.
	Media bool
	// Entry is the relpath /share/{id} opens as a web page, "" for none; it
	// names a file of the manifest and /site relays it and its assets off
	// the sharer's device. Mutually exclusive with Listing and Media.
	Entry string
	// ExpiresAt is when public links 404, the same clock a stored share
	// uses. Nil means the share lasts until the relay stops.
	ExpiresAt *time.Time
	// Visitors is how many distinct visitor tokens have read the share. The
	// tokens live on the registry's own state, never on a row: a live share
	// writes nothing to the volume.
	Visitors int
}

type Config struct {
	Grace        time.Duration    // 0 = 5 * time.Minute
	OfflineAfter time.Duration    // 0 = 10 * time.Second
	MaxPerOwner  int              // 0 = 3
	MaxVisitors  int              // 0 = 100000; tokens past it are not kept
	MaxFiles     int              // 0 = 100000; a Patch past it is refused
	AddressWait  time.Duration    // 0 = 30 s; how long NewJob waits for a place of the visitor's address
	NewID        func() string    // shareid.NewID
	NewSlug      func() string    // shareid.NewSlug
	NewFileKey   func() string    // shareid.NewFileKey
	Now          func() time.Time // tests inject a fake clock
}

type Registry struct {
	cfg Config

	mu     sync.Mutex
	shares map[string]*liveShare
	// keys maps each live file's key to its share and slug; every path that
	// adds, drops or ends a share's files keeps it in step under mu.
	keys map[string]fileRef
	// drained is closed by Drain and never replaced: a closed channel wins
	// every later select, so parked polls release and new ones never park.
	drained chan struct{}
}

type fileRef struct{ id, slug string }

// liveShare is the mutable server-side state around an immutable Record.
type liveShare struct {
	rec      Record
	lastSeen time.Time
	// parked counts polls currently held on this share. While one is parked
	// the share is online whatever lastSeen says.
	parked int
	// jobs holds the offers visitors have minted and the sharer has not
	// claimed yet.
	jobs *jobSet
	// visitors is the set of distinct visitor tokens Visit has recorded.
	visitors map[[32]byte]struct{}
}

func NewRegistry(cfg Config) *Registry {
	if cfg.Grace <= 0 {
		cfg.Grace = defaultGrace
	}
	if cfg.OfflineAfter <= 0 {
		cfg.OfflineAfter = defaultOfflineAfter
	}
	if cfg.MaxPerOwner <= 0 {
		cfg.MaxPerOwner = defaultMaxPerOwner
	}
	if cfg.MaxVisitors <= 0 {
		cfg.MaxVisitors = 100000
	}
	if cfg.MaxFiles <= 0 {
		cfg.MaxFiles = defaultMaxFiles
	}
	if cfg.AddressWait <= 0 {
		cfg.AddressWait = defaultAddressWait
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.NewFileKey == nil {
		cfg.NewFileKey = shareid.NewFileKey
	}
	return &Registry{cfg: cfg, shares: map[string]*liveShare{}, keys: map[string]fileRef{}, drained: make(chan struct{})}
}

// sweepLocked removes every share whose grace has expired. Called at the top of
// every public method rather than from a ticker: lazy expiry needs no
// goroutine and no Stop, and a 404 on read is exactly as good as a timely
// delete for state nobody is paying for.
func (g *Registry) sweepLocked() {
	now := g.cfg.Now()
	for id, s := range g.shares {
		expired := s.rec.ExpiresAt != nil && now.After(*s.rec.ExpiresAt)
		if expired || (s.parked == 0 && now.Sub(s.lastSeen) > g.cfg.Grace) {
			s.jobs.failAll("live-share-ended")
			g.forgetLocked(id)
		}
	}
}

// indexLocked records the keys of rec's files, and unindexLocked forgets
// them; forgetLocked drops a whole share with its keys.
func (g *Registry) indexLocked(rec Record) {
	for _, f := range rec.Files {
		if f.Key != "" {
			g.keys[f.Key] = fileRef{id: rec.ID, slug: f.Slug}
		}
	}
}

func (g *Registry) unindexLocked(rec Record) {
	for _, f := range rec.Files {
		delete(g.keys, f.Key)
	}
}

func (g *Registry) forgetLocked(id string) {
	if s, ok := g.shares[id]; ok {
		g.unindexLocked(s.rec)
		delete(g.shares, id)
	}
}

// ByFileKey resolves a direct-link key to its live share and the file's
// slug. A key of the wrong shape, an unknown key and a key whose share has
// ended all answer false.
func (g *Registry) ByFileKey(key string) (Record, string, bool) {
	if !shareid.ValidFileKey(key) {
		return Record{}, "", false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweepLocked()
	ref, ok := g.keys[key]
	if !ok {
		return Record{}, "", false
	}
	s, ok := g.shares[ref.id]
	if !ok {
		return Record{}, "", false
	}
	return s.rec, ref.slug, true
}

func (g *Registry) Create(rec Record) (Record, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweepLocked()
	n := 0
	for _, s := range g.shares {
		if s.rec.Owner == rec.Owner {
			n++
		}
	}
	if n >= g.cfg.MaxPerOwner {
		return Record{}, ErrTooMany
	}
	rec.ID = g.cfg.NewID()
	rec.CreatedAt = g.cfg.Now()
	rec.PasswordGen = 1
	for i := range rec.Files {
		rec.Files[i].Slug = g.cfg.NewSlug()
		rec.Files[i].Key = g.cfg.NewFileKey()
	}
	g.shares[rec.ID] = &liveShare{rec: rec, lastSeen: rec.CreatedAt, jobs: newJobSet()}
	g.indexLocked(rec)
	return rec, nil
}

// Resume reattaches a relay after its app/CLI process disappeared. The
// public ID, slugs and edited metadata stay exactly as they were. The newly
// expanded local manifest must describe the same bytes; otherwise serving a
// different tree behind an already-shared link would be a silent replacement.
func (g *Registry) Resume(id string, candidate Record) (Record, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweepLocked()
	s, ok := g.shares[id]
	if !ok || s.rec.Owner != candidate.Owner {
		return Record{}, ErrNoShare
	}
	if s.rec.Folder != candidate.Folder || s.rec.ZipSize != candidate.ZipSize ||
		!sameFiles(s.rec.Files, candidate.Files) {
		return Record{}, ErrResumeMismatch
	}
	s.lastSeen = g.cfg.Now()
	return s.rec, nil
}

func sameFiles(a, b []File) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Path != b[i].Path || a[i].Size != b[i].Size ||
			a[i].Mime != b[i].Mime || !a[i].MTime.Equal(b[i].MTime) {
			return false
		}
	}
	return true
}

func (g *Registry) Get(id string) (Record, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweepLocked()
	s, ok := g.shares[id]
	if !ok {
		return Record{}, false
	}
	return s.rec, true
}

// Visit records one visitor token on the share, once per token, up to
// cfg.MaxVisitors. An id the registry does not hold is ignored: the visitor
// was answered 404 and there is nothing to count.
func (g *Registry) Visit(id string, token [32]byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweepLocked()
	s, ok := g.shares[id]
	if !ok {
		return
	}
	if _, seen := s.visitors[token]; seen || len(s.visitors) >= g.cfg.MaxVisitors {
		return
	}
	if s.visitors == nil {
		s.visitors = map[[32]byte]struct{}{}
	}
	s.visitors[token] = struct{}{}
	s.rec.Visitors = len(s.visitors)
}

// Visitors answers the count Visit keeps, 0 for an id the registry does not hold.
func (g *Registry) Visitors(id string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweepLocked()
	if s, ok := g.shares[id]; ok {
		return s.rec.Visitors
	}
	return 0
}

func (g *Registry) Online(id string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweepLocked()
	s, ok := g.shares[id]
	if !ok {
		return false
	}
	return s.parked > 0 || g.cfg.Now().Sub(s.lastSeen) < g.cfg.OfflineAfter
}

func (g *Registry) MarkSeen(id string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if s, ok := g.shares[id]; ok {
		s.lastSeen = g.cfg.Now()
	}
}

// DeleteOwner ends every live share owner holds, failing their parked jobs,
// for an account that is being deleted: ownership is keyed by username, so a
// share left behind would pass to a new account created under the same name
// within the grace.
func (g *Registry) DeleteOwner(owner string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for id, s := range g.shares {
		if s.rec.Owner == owner {
			s.jobs.failAll("live-share-ended")
			g.forgetLocked(id)
		}
	}
}

func (g *Registry) Delete(id, owner string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	s, ok := g.shares[id]
	if !ok || s.rec.Owner != owner {
		return false
	}
	s.jobs.failAll("live-share-ended")
	g.forgetLocked(id)
	return true
}
