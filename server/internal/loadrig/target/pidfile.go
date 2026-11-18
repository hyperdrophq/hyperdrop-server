package target

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"hyperdrop/server/internal/fsatomic"
)

// PidFileName is the file in the data directory that names the server
// process the rig started there, while it runs.
const PidFileName = "loadrig-server.pid"

// serverCommand is the start of the command name of a server the rig
// builds, as Linux reports it (the first 15 bytes).
const serverCommand = "hyperdrop-serve"

func pidPath(dataDir string) string { return filepath.Join(dataDir, PidFileName) }

// checkPidFile refuses a data directory whose pid file names a process that
// is alive and is a server: one an earlier run left running there. A file
// naming a dead process, or one that is not a server, is stale and is
// replaced at the next start. It never signals the process it names.
func checkPidFile(dataDir string) error {
	b, err := os.ReadFile(pidPath(dataDir))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	first, binary, _ := strings.Cut(string(b), "\n")
	pid, err := strconv.Atoi(strings.TrimSpace(first))
	if err != nil || pid <= 0 || !processAlive(pid) {
		return nil
	}
	name, err := processName(pid)
	if err == nil && !isServerName(name, strings.TrimSpace(binary)) {
		return nil
	}
	return fmt.Errorf("%s names process %d, which is running and may be a server an earlier run left on this volume: stop it, or remove the file if it is not one",
		pidPath(dataDir), pid)
}

// isServerName reports whether the command name of a process is that of a
// server binary at path binary, or of any binary named as the rig names the
// server, allowing for a name the system cut short.
func isServerName(name, binary string) bool {
	name = filepath.Base(name)
	if name == "" || name == "." {
		return false
	}
	want := filepath.Base(binary)
	return strings.HasPrefix(name, serverCommand) || name == want ||
		(len(name) >= len(serverCommand) && strings.HasPrefix(want, name))
}

// writePidFile records the server process pid started from binary. The file
// is replaced whole, so a reader never sees it empty or half written.
func writePidFile(dataDir string, pid int, binary string) error {
	return fsatomic.Write(pidPath(dataDir), []byte(fmt.Sprintf("%d\n%s\n", pid, binary)))
}

// removePidFile removes the pid file when it still names pid.
func removePidFile(dataDir string, pid int) {
	b, err := os.ReadFile(pidPath(dataDir))
	if err != nil {
		return
	}
	first, _, _ := strings.Cut(string(b), "\n")
	if strings.TrimSpace(first) == strconv.Itoa(pid) {
		os.Remove(pidPath(dataDir))
	}
}
