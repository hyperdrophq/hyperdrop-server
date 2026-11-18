//go:build unix

package target

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fakeServer is a script that stands in for a server: it never answers
// /api/health and lives until it is signalled.
func fakeServer(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hyperdrop-server")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexec sleep 60\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestTheServerRunsInItsOwnGroupAndItsPidFileLastsWhileItRuns starts a
// stand-in that never turns healthy, and holds it to a process group of its
// own and a pid file naming it until StartLocal gives up and stops it.
func TestTheServerRunsInItsOwnGroupAndItsPidFileLastsWhileItRuns(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type seen struct {
		pid, pgid int
		err       error
	}
	got := make(chan seen, 1)
	go func() {
		defer cancel()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if b, err := os.ReadFile(pidPath(dir)); err == nil {
				first, _, _ := strings.Cut(string(b), "\n")
				pid, err := strconv.Atoi(first)
				if err != nil {
					got <- seen{err: err}
					return
				}
				pgid, err := syscall.Getpgid(pid)
				got <- seen{pid, pgid, err}
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		got <- seen{err: errors.New("no pid file within 10 s")}
	}()
	if _, err := StartLocal(ctx, fakeServer(t), dir); !errors.Is(err, context.Canceled) {
		t.Fatalf("StartLocal = %v, want the cancellation", err)
	}
	s := <-got
	if s.err != nil {
		t.Fatal(s.err)
	}
	if s.pgid != s.pid || s.pgid == syscall.Getpgrp() {
		t.Fatalf("the server's group is %d, its pid %d, the rig's group %d", s.pgid, s.pid, syscall.Getpgrp())
	}
	if _, err := os.Stat(pidPath(dir)); !os.IsNotExist(err) {
		t.Fatalf("the pid file outlived the server it names: %v", err)
	}
	if processAlive(s.pid) {
		t.Fatalf("process %d still runs after StartLocal gave up", s.pid)
	}
}

func TestAPidFileNamingARunningServerIsRefusedAndAStaleOneIsNot(t *testing.T) {
	dir := t.TempDir()
	if err := checkPidFile(dir); err != nil {
		t.Fatalf("no pid file: %v", err)
	}

	dead := exec.Command("/bin/sh", "-c", "exit 0")
	if err := dead.Run(); err != nil {
		t.Fatal(err)
	}
	if err := writePidFile(dir, dead.Process.Pid, "/x/hyperdrop-server"); err != nil {
		t.Fatal(err)
	}
	if err := checkPidFile(dir); err != nil {
		t.Fatalf("a pid file naming a process that exited: %v", err)
	}

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := writePidFile(dir, os.Getpid(), "/x/hyperdrop-server"); err != nil {
		t.Fatal(err)
	}
	if err := checkPidFile(dir); err != nil {
		t.Fatalf("a pid file naming a running process that is not a server: %v", err)
	}

	if err := writePidFile(dir, os.Getpid(), self); err != nil {
		t.Fatal(err)
	}
	err = checkPidFile(dir)
	if err == nil || !strings.Contains(err.Error(), strconv.Itoa(os.Getpid())) {
		t.Fatalf("a pid file naming a running server: %v, want a refusal naming its pid", err)
	}
	if _, err := StartLocal(context.Background(), self, dir); err == nil || !strings.Contains(err.Error(), strconv.Itoa(os.Getpid())) {
		t.Fatalf("StartLocal on a volume a server still runs on: %v", err)
	}
	if !processAlive(os.Getpid()) {
		t.Fatal("the check touched the process it names")
	}
}

func TestServerNamesAllowForANameCutShort(t *testing.T) {
	for _, c := range []struct {
		name, binary string
		want         bool
	}{
		{"hyperdrop-serve", "/tmp/x/hyperdrop-server", true},
		{"/tmp/x/hyperdrop-server", "/elsewhere/hyperdrop-server", true},
		{"srv-before-fix", "/tmp/srv-before-fix", true},
		{"srv-before-fix-", "/tmp/srv-before-fix-1", true},
		{"bash", "/tmp/x/hyperdrop-server", false},
		{"", "/tmp/x/hyperdrop-server", false},
	} {
		if got := isServerName(c.name, c.binary); got != c.want {
			t.Errorf("isServerName(%q, %q) = %v, want %v", c.name, c.binary, got, c.want)
		}
	}
}
