package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"hyperdrop/server/internal/ddns"
	"hyperdrop/server/internal/domain"
)

// ProxySource is one address that sent the server a forwarding header while
// it was not a trusted proxy.
type ProxySource struct {
	Addr     string `json:"addr"`
	Count    int    `json:"count"`
	LastSeen int64  `json:"lastSeen"`
	Kind     string `json:"kind"`
}

// AddressPending is an address change requested from DSM that the server has
// not carried out yet: Reason says what it waits for, and ApprovalURL, for a
// free name, is the live link that approves it.
type AddressPending struct {
	Address     string `json:"address"`
	Reason      string `json:"reason,omitempty"`
	ApprovalURL string `json:"approvalURL,omitempty"`
}

// Status is the small file a Synology package page reads while the server
// may be stopped (HYPERDROP_STATUS_FILE). The package start script writes
// lastError and at to the same file when it refuses to start.
type Status struct {
	Version        string          `json:"version"`
	StartedAt      int64           `json:"startedAt,omitempty"`
	LastError      string          `json:"lastError,omitempty"`
	At             int64           `json:"at,omitempty"`
	ProxySources   []ProxySource   `json:"proxySources,omitempty"`
	PublicProxy    int             `json:"publicProxyHeaders,omitempty"`
	MissingFiles   int             `json:"missingFiles,omitempty"`
	Reachable      *bool           `json:"reachable,omitempty"` // the outside port check's last answer; nil when unknown
	AddressPending *AddressPending `json:"addressPending,omitempty"`
}

// statusWriter keeps the status file current. It writes only when the
// marshalled JSON differs from what it wrote last, so an idle server never
// touches the disk. A nil writer does nothing.
type statusWriter struct {
	path string

	mu   sync.Mutex
	cur  Status
	last []byte
}

// newStatusWriter returns a writer for path, or nil when path is empty.
func newStatusWriter(path string) *statusWriter {
	if path == "" {
		return nil
	}
	return &statusWriter{path: path}
}

// Set replaces the whole status.
func (w *statusWriter) Set(s Status) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.cur = s
	w.flush()
}

// Current is a copy of the status; the zero Status on a nil writer.
func (w *statusWriter) Current() Status {
	if w == nil {
		return Status{}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	s := w.cur
	if s.AddressPending != nil {
		p := *s.AddressPending
		s.AddressPending = &p
	}
	return s
}

// Update applies fn to the current status and writes the result if it changed.
func (w *statusWriter) Update(fn func(*Status)) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	fn(&w.cur)
	w.flush()
}

// flush writes the current status through a temporary file in the same
// directory and a rename, mode 0600. Failures are ignored: the file is
// advisory.
func (w *statusWriter) flush() {
	b, err := json.Marshal(w.cur)
	if err != nil || bytes.Equal(b, w.last) {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(w.path), ".status-*")
	if err != nil {
		return
	}
	_, werr := tmp.Write(b)
	cerr := tmp.Close()
	if werr != nil || cerr != nil || os.Chmod(tmp.Name(), 0o600) != nil || os.Rename(tmp.Name(), w.path) != nil {
		os.Remove(tmp.Name())
		return
	}
	w.last = b
}

// listenRecording binds a TCP listener and, when that fails, records the
// reason in the status file for the package page to show.
func listenRecording(w *statusWriter, addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		msg := bindFailureText(addr, err)
		w.Update(func(s *Status) { s.LastError = msg; s.At = time.Now().Unix() })
	}
	return ln, err
}

// reachableFrom turns the port check's last verdicts into the status file's
// answer. HTTPS must be "ok" for true; a free name (under the ddns zone) also
// needs port 80 "ok", an own domain ignores port 80. It is false when a
// required port is closed or taken, and nil when nothing was probed or a
// required port's verdict is unknown.
func reachableFrom(host string, p domain.Ports, probed bool) *bool {
	if !probed {
		return nil
	}
	required := []string{p.HTTPS}
	if strings.HasSuffix(host, "."+ddns.Zone) {
		required = append(required, p.HTTP)
	}
	unknown := false
	for _, v := range required {
		switch v {
		case "closed", "taken":
			f := false
			return &f
		case "ok":
		default:
			unknown = true
		}
	}
	if unknown {
		return nil
	}
	t := true
	return &t
}

// reachableFromManager reads the domain manager's current host and last port
// verdicts.
func reachableFromManager(dom *domain.Manager) *bool {
	p, probed := dom.Ports()
	return reachableFrom(dom.Current(), p, probed)
}

// bindFailureText words a listen failure for the package page.
func bindFailureText(addr string, err error) string {
	port := addr
	if _, p, splitErr := net.SplitHostPort(addr); splitErr == nil {
		port = p
	}
	if errors.Is(err, syscall.EADDRINUSE) {
		return "Port " + port + " is already in use by another app."
	}
	return "HyperDrop could not open port " + port + ": " + strings.TrimSuffix(err.Error(), ".") + "."
}
