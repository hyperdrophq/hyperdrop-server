package target

import (
	"bufio"
	"context"
	"debug/buildinfo"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"hyperdrop/server/internal/loadrig/report"
)

const (
	// stopLimit is how long a stopping server gets after SIGTERM before it
	// is killed.
	stopLimit = 30 * time.Second
	// sampleEvery is the pace of the memory sampler.
	sampleEvery = time.Second
	// AdminUser and AdminPassword seed the administrator a generated volume
	// lacks, since the server refuses to boot on a volume with none. On an
	// empty data directory they are the one account the server has.
	AdminUser     = "loadrig-admin"
	AdminPassword = "loadrig-admin-password"
	// maxLogLine is the longest log line the rig keeps whole.
	maxLogLine = 1 << 20
)

// BuildServer builds the server in moduleDir into outDir and answers the
// binary's path. The build stamps the commit it was made from into the
// binary, as go build does inside a repository, which is where StartLocal
// reads it.
func BuildServer(ctx context.Context, moduleDir, outDir string) (binary string, err error) {
	binary = filepath.Join(outDir, "hyperdrop-server")
	cmd := exec.CommandContext(ctx, "go", "build", "-o", binary, ".")
	cmd.Dir = moduleDir
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go build: %w\n%s", err, out)
	}
	return binary, nil
}

// binaryCommit is the commit a Go binary says it was built from, with
// "+dirty" when its tree had changes, or "" when it carries none.
func binaryCommit(binary string) string {
	info, err := buildinfo.ReadFile(binary)
	if err != nil {
		return ""
	}
	return vcsCommit(info.Settings)
}

func vcsCommit(settings []debug.BuildSetting) string {
	rev, modified := "", false
	for _, s := range settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	if rev != "" && modified {
		rev += "+dirty"
	}
	return rev
}

type local struct {
	binary, dataDir, addr, commit string

	mu    sync.Mutex
	cmd   *exec.Cmd
	done  chan struct{} // closed when the current process has exited and its log is read
	exit  error         // the current process's exit (cmd.Wait), set before done is closed
	lines []string
	since int   // index in lines where the current process's output begins
	peak  int64 // highest sample of the current process
	last  int64 // latest sample of the current process
	// version is what /api/health reported when the server first answered.
	version string
}

// StartLocal runs the server binary on dataDir, listening on a free loopback
// port, and returns once /api/health answers healthy. It waits as long as ctx
// allows, so the caller sets the bound; a server that exits first is an
// error carrying its last log lines. Everything the process
// logs is kept: the server writes each line to stderr as well as to its own
// log file.
//
// The server runs in a process group of its own, so a terminal's Ctrl-C
// does not reach it and Close is what stops it, and while it runs
// <dataDir>/loadrig-server.pid names it. StartLocal
// refuses a data directory whose pid file names a server still running.
func StartLocal(ctx context.Context, binary, dataDir string) (Target, error) {
	if err := checkPidFile(dataDir); err != nil {
		return nil, err
	}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	addr := l.Addr().String()
	l.Close()
	t := &local{binary: binary, dataDir: dataDir, addr: addr, commit: binaryCommit(binary)}
	if _, err := t.start(ctx); err != nil {
		t.Close()
		return nil, err
	}
	return t, nil
}

// serverEnv is the environment the rig starts the server with: environ
// without any HYPERDROP_ variable, so nothing set in the rig's own shell
// changes the server measured, and then the rig's own settings.
func serverEnv(environ []string, dataDir, addr string) []string {
	var env []string
	for _, kv := range environ {
		if !strings.HasPrefix(kv, "HYPERDROP_") {
			env = append(env, kv)
		}
	}
	return append(env,
		"HYPERDROP_ALLOW_PRIVATE=1",
		"HYPERDROP_PUSH_RELAY=",
		"HYPERDROP_SERVER_RELEASES=",
		"HYPERDROP_DATA="+dataDir,
		"HYPERDROP_HTTP_ADDR="+addr,
		"HYPERDROP_ADMIN_USER="+AdminUser,
		"HYPERDROP_ADMIN_PASSWORD="+AdminPassword,
	)
}

// start launches the process and waits for it to be healthy.
func (t *local) start(ctx context.Context) (time.Duration, error) {
	cmd := exec.Command(t.binary)
	cmd.Env = serverEnv(os.Environ(), t.dataDir, t.addr)
	cmd.SysProcAttr = serverProcAttr()
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return 0, err
	}
	began := time.Now()
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	pid := cmd.Process.Pid
	// The file is written before anything waits on the process, so the
	// removal that follows its exit always comes after it.
	if err := writePidFile(t.dataDir, pid, t.binary); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return 0, fmt.Errorf("record the server's pid: %w", err)
	}
	done := make(chan struct{})
	t.mu.Lock()
	t.cmd, t.done, t.since, t.exit = cmd, done, len(t.lines), nil
	t.peak, t.last = 0, 0
	t.mu.Unlock()
	go func() {
		defer close(done)
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 0, 64<<10), maxLogLine)
		for sc.Scan() {
			t.mu.Lock()
			t.lines = append(t.lines, sc.Text())
			t.mu.Unlock()
		}
		// A read error (a line over maxLogLine) must not leave the pipe
		// undrained: a full pipe blocks the server's next log write.
		io.Copy(io.Discard, stderr)
		err := cmd.Wait()
		t.mu.Lock()
		if t.cmd == cmd {
			t.exit = err
		}
		t.mu.Unlock()
		removePidFile(t.dataDir, pid)
	}()
	go t.sample(pid, done)

	for {
		if v, err := health(ctx, t.BaseURL()); err == nil {
			t.mu.Lock()
			t.version = v
			t.mu.Unlock()
			return time.Since(began), nil
		}
		select {
		case <-done:
			return 0, fmt.Errorf("server exited before it was healthy:\n%s", t.tail(20))
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (t *local) tail(n int) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	from := max(t.since, len(t.lines)-n)
	return strings.Join(t.lines[from:], "\n")
}

// sample keeps the peak resident set of pid until it exits.
func (t *local) sample(pid int, done <-chan struct{}) {
	tick := time.NewTicker(sampleEvery)
	defer tick.Stop()
	for {
		t.observeRSS(pid)
		select {
		case <-done:
			return
		case <-tick.C:
		}
	}
}

func (t *local) observeRSS(pid int) (int64, bool) {
	rss, ok := rssOf(pid)
	if !ok {
		return 0, false
	}
	t.mu.Lock()
	t.peak = max(t.peak, rss)
	t.last = rss
	t.mu.Unlock()
	return rss, true
}

func (t *local) BaseURL() string { return "http://" + t.addr }

func (t *local) Info() report.ServerInfo {
	t.mu.Lock()
	v := t.version
	t.mu.Unlock()
	return report.ServerInfo{Version: v, Commit: t.commit, BaseURL: t.BaseURL(), Local: true}
}

func (t *local) Memory() (current, peak int64, ok bool) {
	t.mu.Lock()
	cmd := t.cmd
	t.mu.Unlock()
	if cmd != nil && cmd.Process != nil && t.Alive() {
		t.observeRSS(cmd.Process.Pid)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.last, t.peak, true
}

func (t *local) Log() ([]string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.lines...), true
}

func (t *local) WaitLog(ctx context.Context, prefix string) (string, error) {
	next := -1
	for {
		t.mu.Lock()
		if next < 0 {
			next = t.since
		}
		for ; next < len(t.lines); next++ {
			if m := logMessage(t.lines[next]); strings.HasPrefix(m, prefix) {
				t.mu.Unlock()
				return m, nil
			}
		}
		done := t.done
		t.mu.Unlock()
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-done:
			// The process is gone; one last look at what it logged.
			t.mu.Lock()
			for ; next < len(t.lines); next++ {
				if m := logMessage(t.lines[next]); strings.HasPrefix(m, prefix) {
					t.mu.Unlock()
					return m, nil
				}
			}
			t.mu.Unlock()
			return "", fmt.Errorf("server exited without logging %q", prefix)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// logTimeLen is the length of the "2006/01/02 15:04:05 " every log line of
// the server starts with.
const logTimeLen = len("2006/01/02 15:04:05 ")

// logMessage is a log line without its leading time.
func logMessage(line string) string {
	if len(line) >= logTimeLen && line[4] == '/' && line[7] == '/' && line[10] == ' ' && line[13] == ':' && line[16] == ':' && line[19] == ' ' {
		return line[logTimeLen:]
	}
	return line
}

func (t *local) Alive() bool {
	t.mu.Lock()
	done := t.done
	t.mu.Unlock()
	if done == nil {
		return false
	}
	select {
	case <-done:
		return false
	default:
		return true
	}
}

// stop sends SIGTERM and waits for the process, killing it after stopLimit,
// and answers how the process exited: nil for exit 0.
func (t *local) stop() error {
	t.mu.Lock()
	cmd, done := t.cmd, t.done
	t.mu.Unlock()
	if cmd == nil || done == nil {
		return nil
	}
	select {
	case <-done:
	default:
		cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(stopLimit):
			cmd.Process.Kill()
			<-done
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.exit
}

// Restart stops the process and starts it again; after an error the caller
// must Close the target.
func (t *local) Restart(ctx context.Context) (time.Duration, error) {
	t.stop()
	return t.start(ctx)
}

// RestartKilled kills the process with SIGKILL, waits for it to be gone and
// starts it again; after an error the caller must Close the target.
func (t *local) RestartKilled(ctx context.Context) (time.Duration, error) {
	t.mu.Lock()
	cmd, done := t.cmd, t.done
	t.mu.Unlock()
	if cmd != nil && done != nil {
		cmd.Process.Kill()
		<-done
	}
	return t.start(ctx)
}

func (t *local) Close() error {
	return t.stop()
}
