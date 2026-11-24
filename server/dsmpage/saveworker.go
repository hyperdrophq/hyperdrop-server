package dsmpage

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// The change lock and the worker: the lock one change holds at a time, and the
// detached process that applies a change after the request has been answered.

// takeLock opens the lock file and takes it without waiting. busy is true
// when another change holds it.
func takeLock(path string) (f *os.File, busy bool, err error) {
	f, err = os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, false, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, true, nil
		}
		return nil, false, err
	}
	return f, false, nil
}

// lockHeld is true while a change holds the lock at path.
func lockHeld(path string) bool {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB)
	return errors.Is(err, syscall.EWOULDBLOCK)
}

// holdLock answers the lock the worker holds: the descriptor fd it
// inherited from the CGI when that is the lock file (marked close-on-exec,
// so neither the start script nor the server it starts keeps it), or else
// the lock taken here.
func holdLock(path string, fd uintptr) (*os.File, error) {
	var st syscall.Stat_t
	if fi, err := os.Lstat(path); err == nil && syscall.Fstat(int(fd), &st) == nil {
		if want, ok := fi.Sys().(*syscall.Stat_t); ok && fi.Mode().IsRegular() && want.Dev == st.Dev && want.Ino == st.Ino {
			syscall.CloseOnExec(int(fd))
			if err := syscall.Flock(int(fd), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
				return os.NewFile(fd, path), nil
			}
		}
	}
	f, busy, err := takeLock(path)
	if busy {
		return nil, pageError(busyText)
	}
	return f, err
}

// startWorker starts `bin dsmpage-apply job` in a session of its own, with
// no terminal, standard streams on /dev/null and the lock as fd 3, and
// does not wait for it.
func startWorker(bin, job string, lock *os.File) error {
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer null.Close()
	cmd := exec.Command(bin, "dsmpage-apply", job)
	cmd.Env = []string{"PATH=" + scriptPATH}
	cmd.Dir = "/"
	cmd.Stdin, cmd.Stdout, cmd.Stderr = null, null, null
	cmd.ExtraFiles = []*os.File{lock}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

// RunApply is `hyperdrop-server dsmpage-apply <job>`: the worker the CGI
// starts. It applies the job with the package's start-stop-status and
// answers 0 when the change was kept.
func RunApply(args []string) int {
	if os.Geteuid() == 0 {
		fmt.Fprintln(os.Stderr, "dsmpage-apply: refusing to run as root")
		return 1
	}
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: hyperdrop-server dsmpage-apply <job file>")
		return 2
	}
	p := newPage(Deps{})
	return p.work(args[0], 3, p.deps.Service, realClock{})
}

// work holds the lock (inherited as fd, or taken here) and applies the job.
// Without the lock nothing runs and the job is removed.
func (p *page) work(job string, fd uintptr, svc Service, clk Clock) int {
	lock, err := holdLock(p.lockPath(), fd)
	if err != nil {
		os.Remove(job)
		fmt.Fprintf(os.Stderr, "dsmpage-apply: %v\n", err)
		return 1
	}
	defer lock.Close()
	if res := p.apply(job, svc, clk); res.State != "done" {
		return 1
	}
	return 0
}
