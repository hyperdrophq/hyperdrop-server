package dsmpage

import (
	"context"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// On DSM 6 DSM's web server runs a package's CGI as root, and only root may
// run authenticate.cgi there. So a CGI that starts as root does three things
// before it serves anything: it checks that the program it runs is root's
// (DSM hands the program tree to the package user when it extracts a
// package, and postinst hands it back to root; a program the package user
// could write must never run as root), it asks DSM who is signed in, and it
// becomes the package user. Everything after that, every read and write and
// every program it starts, happens as the package user, exactly as on DSM 7,
// where DSM runs the CGI as the package user from the start.

// packageUser is the account the server and the page run as.
const packageUser = "hyperdrop"

var (
	errUnsafeInstall error = pageError("HyperDrop's page is not installed safely on this NAS: its program is not owned by root.")
	errCannotDrop    error = pageError("HyperDrop's page cannot run as the package user on this NAS.")
)

// rootStep is what the CGI does while it is still root, with every system
// call behind a field so a test runs it unprivileged.
type rootStep struct {
	Euid         func() int
	Exe          func() (string, error)
	Stat         func(path string) (uid int, mode os.FileMode, err error)
	Lookup       func(name string) (uid, gid int, err error)
	Setgroups    func([]int) error
	Setgid       func(int) error
	Setuid       func(int) error
	Authenticate func(ctx context.Context, env []string) (string, error)
}

// run does nothing when the process is not root. Otherwise it refuses with
// errUnsafeInstall unless the program and its directory are root's and
// writable by nobody else, asks DSM for the signed-in user when env carries
// the token header (the rule requireDSMAdmin applies; a request without the
// header is refused there and DSM is never asked), becomes the package user
// and sets d.Authenticate to answer that user from memory. A drop that does
// not take is errCannotDrop.
func (s rootStep) run(ctx context.Context, env []string, d *Deps) error {
	if s.Euid() != 0 {
		return nil
	}
	exe, err := s.Exe()
	if err != nil {
		return errUnsafeInstall
	}
	for _, path := range []string{exe, filepath.Dir(exe)} {
		uid, mode, err := s.Stat(path)
		if err != nil || uid != 0 || mode.Perm()&0o022 != 0 {
			return errUnsafeInstall
		}
	}
	dsmUser := ""
	if tokenIn(env) {
		actx, cancel := context.WithTimeout(ctx, commandTimeout)
		u, err := s.Authenticate(actx, env)
		cancel()
		if err == nil {
			dsmUser = u
		}
	}
	uid, gid, err := s.Lookup(packageUser)
	if err != nil {
		return errCannotDrop
	}
	if s.Setgroups([]int{gid}) != nil || s.Setgid(gid) != nil || s.Setuid(uid) != nil || s.Euid() == 0 {
		return errCannotDrop
	}
	d.Authenticate = func(context.Context, []string) (string, error) { return dsmUser, nil }
	return nil
}

// tokenIn answers whether the CGI environment carries a non-empty
// X-SYNO-TOKEN header.
func tokenIn(env []string) bool {
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "HTTP_X_SYNO_TOKEN="); ok {
			return v != ""
		}
	}
	return false
}

// realRootStep is the step over the real process and DSM.
func realRootStep() rootStep {
	return rootStep{
		Euid: os.Geteuid,
		Exe:  os.Executable,
		Stat: func(path string) (int, os.FileMode, error) {
			fi, err := os.Stat(path)
			if err != nil {
				return 0, 0, err
			}
			st, ok := fi.Sys().(*syscall.Stat_t)
			if !ok {
				return 0, 0, errUnsafeInstall
			}
			return int(st.Uid), fi.Mode(), nil
		},
		Lookup: func(name string) (int, int, error) {
			u, err := user.Lookup(name)
			if err != nil {
				return 0, 0, err
			}
			uid, err := strconv.Atoi(u.Uid)
			if err != nil {
				return 0, 0, err
			}
			gid, err := strconv.Atoi(u.Gid)
			return uid, gid, err
		},
		Setgroups: syscall.Setgroups,
		Setgid:    syscall.Setgid,
		Setuid:    syscall.Setuid,
		Authenticate: func(ctx context.Context, env []string) (string, error) {
			return runAuthenticate(ctx, authenticateCGI, env)
		},
	}
}

// serveRefusal answers every request with the step's one sentence.
func serveRefusal(err error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusInternalServerError, err.Error())
	})
}
