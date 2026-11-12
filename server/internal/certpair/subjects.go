package certpair

import (
	"context"
	"net"
	"sync"

	"github.com/caddyserver/certmagic"
)

// Subjects is the set of domains this process has put under certificate
// management, and the map from each one's file origin back to it.
//
// It is live rather than captured at boot: a domain enters management at boot,
// when a free name is claimed and when an operator sets one, so anything
// deciding whether a name belongs to this
// server has to ask at the moment it decides.
//
// The file origin is derived from an injected function for the same reason
// PairIssuer takes one: nothing below the API layer should hard-code the label
// uploaded bytes are served from.
type Subjects struct {
	fileOrigin func(string) string

	mu      sync.RWMutex
	managed map[string]struct{}
	origins map[string]string
}

func NewSubjects(fileOrigin func(string) string) *Subjects {
	return &Subjects{
		fileOrigin: fileOrigin,
		managed:    map[string]struct{}{},
		origins:    map[string]string{},
	}
}

// Add records domains as managed. An IP address is skipped: the IP certificate
// is a separate subject with no file origin. Names are recorded in the form a
// storage key spells them, so a key segment can be compared against them
// directly.
func (s *Subjects) Add(names ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, name := range names {
		if name == "" || net.ParseIP(name) != nil {
			continue
		}
		safe := certmagic.StorageKeys.Safe(name)
		if safe == "" {
			continue
		}
		s.managed[safe] = struct{}{}
		file := certmagic.StorageKeys.Safe(s.fileOrigin(name))
		if file == "" || file == safe {
			continue
		}
		s.origins[file] = safe
	}
}

// AppDomain answers the managed domain whose file origin is name, and false
// when there is none.
//
// A name that is itself a managed domain is never treated as another domain's
// file origin, which is what keeps a server whose own domain begins with the
// file label (files.example.com, say) addressing its own resources instead of
// example.com's.
func (s *Subjects) AppDomain(name string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, managed := s.managed[name]; managed {
		return "", false
	}
	app, ok := s.origins[name]
	return app, ok
}

// Subject is CertMagic's SubjectTransformer: it answers the subject an obtain,
// a renewal or a managed-certificate load should act on.
//
// A paired certificate's first name is the file origin for most domains (see
// FileOriginAlias for why), and CertMagic renews a cached certificate under
// that first name. The name it is handed decides the ACME order's identifiers,
// the storage lock and the identifier on every certificate event, so it is
// mapped back to the app domain here: without it a renewal would order a
// certificate for the file origin alone and report it under a name no operator
// can act on.
func (s *Subjects) Subject(_ context.Context, name string) string {
	if app, ok := s.AppDomain(certmagic.StorageKeys.Safe(name)); ok {
		return app
	}
	return name
}
