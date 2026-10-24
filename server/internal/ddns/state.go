// Package ddns holds the server's free-name address: the name it was given,
// the token that lets it move that name, and what the last attempt to do so
// did. The names service itself lives in names/ and is versioned separately.
package ddns

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"

	"hyperdrop/server/internal/fsatomic"
)

// Zone is where free names live. One constant, because a name and its FQDN
// must never disagree between the route, the updater and the log.
const Zone = "hyperdrop.link"

func FQDN(name string) string { return name + "." + Zone }

// nameShape is what the names service issues: 5 to 32 characters of
// lowercase letters, digits and hyphens, never starting or ending with one.
var nameShape = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{3,30})[a-z0-9]$`)

// ValidName reports whether name is a shape the names service issues.
// Checked here once so a name accepted at one call site and refused at
// another can never happen: PUT /api/ddns and the boot-time HYPERDROP_DDNS_NAME
// both call this single definition.
func ValidName(name string) bool {
	return nameShape.MatchString(name) && !strings.Contains(name, "--")
}

// State persists the machine connection and its last DNS observations. Account
// ownership lives in the names service and does not expire.
type State struct {
	Custom          *HTTPConfig  `json:"custom,omitempty"`
	Connectivity    Connectivity `json:"connectivity,omitempty"`
	Name            string       `json:"name"`
	Token           string       `json:"token"`
	Disconnected    bool         `json:"disconnected,omitempty"`
	Cancelled       bool         `json:"cancelled,omitempty"`
	Approved        bool         `json:"approved,omitempty"`
	Pending         bool         `json:"pending,omitempty"`
	Enrollment      *Enrollment  `json:"enrollment,omitempty"`
	ServerID        string       `json:"serverID,omitempty"`
	RetryAt         int64        `json:"retryAt,omitempty"`
	ManagedFailures int          `json:"managedFailures,omitempty"`
	LastUpdate      int64        `json:"lastUpdate,omitempty"`
	LastIP          string       `json:"lastIP,omitempty"`
	CustomLastProbe string       `json:"customLastProbe,omitempty"`
	LastProbe       string       `json:"lastProbe,omitempty"`
	LastError       string       `json:"lastError,omitempty"`
}

// tokenRefused reports whether the registry has refused the token on file.
// A refused token names no connection: the name has to be claimed again
// rather than heartbeat, or the server reports a name live while the
// registry holds no server for it.
func (st State) tokenRefused() bool {
	return st.LastError == ErrUnknownToken.Error() || st.LastError == ErrReleased.Error()
}

type Store struct {
	path string
	mu   sync.Mutex
	st   State
}

// Load reads the state, treating an absent file as "no name", which is the
// state every server that never took one is in.
//
// A file that does not parse is set aside as <path>.corrupt and the server
// starts with no name, like domain.Load: writes are atomic, so only disk
// damage gets here, and a free-name file must never crash-loop the share
// server. The set-aside copy keeps the name's token for an operator to
// recover by hand.
func Load(path string) (*Store, error) {
	s := &Store{path: path}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.st); err != nil {
		s.st = State{}
		aside := path + ".corrupt"
		if rerr := os.Rename(path, aside); rerr != nil {
			log.Printf("ddns: %s does not parse (%v) and could not be set aside (%v); starting with no free name", path, err, rerr)
		} else {
			log.Printf("ddns: %s does not parse (%v); set aside as %s, starting with no free name", path, err, aside)
		}
	}
	return s, nil
}

func (s *Store) Snapshot() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st
}

func (s *Store) Configured() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.Name != "" && s.st.Token != "" && !s.st.Pending
}

// BeginClaim durably stages the locally generated token before the central
// registry sees it. A lost response or process restart can therefore repeat
// the exact claim without losing the credential that authenticates its connection approval.
func (s *Store) BeginClaim(name, token, serverID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := State{Name: strings.ToLower(strings.TrimSpace(name)), Token: strings.TrimSpace(token),
		CustomLastProbe: s.st.LastProbe, Pending: true, ServerID: strings.TrimSpace(serverID), Custom: s.st.Custom, Connectivity: s.st.Connectivity}
	return s.commit(next)
}

func (s *Store) ConfirmClaim() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.st.Pending {
		return nil
	}
	next := s.st
	next.Pending = false
	next.Approved = false
	next.Custom = nil
	next.Connectivity = Connectivity{}
	next.Enrollment = nil
	next.ServerID = ""
	return s.commit(next)
}

// Set adopts a name and its token, discarding any earlier name's history:
// the last update of a name we no longer hold would misreport this one.
func (s *Store) Set(name, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := State{Name: strings.ToLower(strings.TrimSpace(name)), Token: strings.TrimSpace(token), Connectivity: s.st.Connectivity}
	return s.commit(next)
}

func (s *Store) Clear() error { return s.clear(false) }

func (s *Store) Disconnect() error { return s.clear(true) }

func (s *Store) clear(disconnected bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := State{Connectivity: s.st.Connectivity, Disconnected: disconnected}
	if s.st.Pending {
		next.Custom = s.st.Custom
		next.LastProbe = s.st.CustomLastProbe
	}
	return s.commit(next)
}

// Record stores the outcome of one attempt: ip is what the names service
// reported, probe is what this server's own address probe reported at the
// same tick. A failure never disturbs the last success, including
// LastProbe, because the warning in the app counts from that and the next
// tick's move comparison must still be against the last CONFIRMED probe.
func (s *Store) Record(ip, probe string, at int64, failure string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.Name == "" {
		return nil
	}
	next := s.st
	if failure != "" {
		next.LastError = failure
	} else {
		next.LastError = ""
		next.RetryAt = 0
		next.ManagedFailures = 0
		next.LastUpdate = at
		next.LastIP = ip
		next.LastProbe = probe
	}
	return s.commit(next)
}

// commit writes next to disk and, once it is there, makes it the state in
// memory. The caller holds s.mu.
func (s *Store) commit(next State) error {
	if err := s.write(next); err != nil {
		return err
	}
	s.st = next
	return nil
}

// write replaces the file atomically, so a crash mid-write cannot leave the
// token half on disk and the name unusable.
func (s *Store) write(next State) error {
	b, err := json.Marshal(next)
	if err != nil {
		return err
	}
	return fsatomic.Write(s.path, append(b, '\n'), 0o600)
}
