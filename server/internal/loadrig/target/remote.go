// Package target is the server under test and the client that drives it: a
// real server process on a generated volume, or a server named by URL.
package target

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"hyperdrop/server/internal/loadrig/report"
)

// Target is a server the rig drives.
type Target interface {
	BaseURL() string
	Info() report.ServerInfo
	// Memory is the server process's resident set read now (the last
	// sample once the process is gone) and the highest sample of the
	// current process, which Restart resets; ok is false for a server the
	// rig did not start.
	Memory() (current, peak int64, ok bool)
	// Log is every line the server logged since the target started, across
	// restarts; ok is false for a server the rig did not start.
	Log() (lines []string, ok bool)
	// WaitLog blocks until the current server process has logged a line
	// whose message, after the time the server puts first on every line,
	// begins with prefix, and returns that message.
	WaitLog(ctx context.Context, prefix string) (line string, err error)
	// Restart stops the server process and starts it again on the same
	// port and data directory. It returns the time from the new process
	// start until /api/health answers healthy. After an error the caller
	// must Close the target.
	Restart(ctx context.Context) (healthyAfter time.Duration, err error)
	// RestartKilled is Restart after SIGKILL instead of SIGTERM, so the
	// server gets no chance to shut down cleanly. A server the rig did not
	// start answers an error.
	RestartKilled(ctx context.Context) (healthyAfter time.Duration, err error)
	Alive() bool
	// Close stops a server the rig started (SIGTERM, then a kill after 30 s)
	// and answers how its process exited: nil for exit 0, the exit status
	// otherwise, and nil for a server the rig did not start. It never
	// deletes the data directory.
	Close() error
}

// healthTimeout bounds one /api/health request.
const healthTimeout = 10 * time.Second

// health reads GET /api/health: the version it reports, and an error when
// the server does not answer 200 with status "ok".
func health(ctx context.Context, base string) (version string, err error) {
	ctx, cancel := context.WithTimeout(ctx, healthTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/health", nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("health answered %d", resp.StatusCode)
	}
	var h struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		return "", err
	}
	if h.Status != "ok" {
		return "", fmt.Errorf("health status %q", h.Status)
	}
	return h.Version, nil
}

type remote struct{ base string }

// Remote is a server the rig did not start, named by its base URL. The rig
// reads from it and writes through its API as a client does (the upload,
// catchup and accounts scenarios create shares, pin them and sign in), but
// never floods, restarts or stops it: it has no memory, no log and no
// restart.
func Remote(baseURL string) Target { return &remote{base: strings.TrimRight(baseURL, "/")} }

func (r *remote) BaseURL() string { return r.base }

func (r *remote) Info() report.ServerInfo {
	v, _ := health(context.Background(), r.base)
	return report.ServerInfo{Version: v, BaseURL: r.base}
}

func (r *remote) Memory() (int64, int64, bool) { return 0, 0, false }
func (r *remote) Log() ([]string, bool)        { return nil, false }
func (r *remote) Alive() bool                  { _, err := health(context.Background(), r.base); return err == nil }
func (r *remote) Close() error                 { return nil }

func (r *remote) WaitLog(context.Context, string) (string, error) {
	return "", errors.New("a remote server's log is not available")
}

func (r *remote) Restart(context.Context) (time.Duration, error) {
	return 0, errors.New("a remote server cannot be restarted by the rig")
}

func (r *remote) RestartKilled(context.Context) (time.Duration, error) {
	return 0, errors.New("a server the rig did not start cannot be killed by the rig")
}
