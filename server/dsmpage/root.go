package dsmpage

import (
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// On DSM 6 DSM's web server runs a package's CGI as root. So a CGI that
// starts as root does two things before it serves anything, and nothing
// else: it checks that the program it runs is root's (DSM hands the program
// tree to the package user when it extracts a package, and postinst hands it
// back to root; a program the package user could write must never run as
// root), and it becomes the package user. While root it only stats files: it
// runs no program and reads nothing of the request. Everything after that,
// the session check included (webapi.go), every read and write and every
// program it starts, happens as the package user, exactly as on DSM 7, where
// DSM runs the CGI as the package user from the start.

// packageUser is the account the server and the page run as.
const packageUser = "hyperdrop"

var (
	errUnsafeInstall error = pageError("HyperDrop's page is not installed safely on this NAS: its program is not owned by root.")
	errNoProgram     error = pageError("HyperDrop's page could not find its own program on this NAS.")
	errCannotDrop    error = pageError("HyperDrop's page cannot run as the package user on this NAS.")
)

// rootStep is what the CGI does while it is still root, with every system
// call behind a field so a test runs it unprivileged.
type rootStep struct {
	Euid      func() int
	Exe       func() (string, error)
	Stat      func(path string) (uid int, mode os.FileMode, err error)
	Lookup    func(name string) (uid, gid int, err error)
	Setgroups func([]int) error
	Setgid    func(int) error
	Setuid    func(int) error
}

// run does nothing when the process is not root. Otherwise it checks the
// program (checkProgram) and becomes the package user. The drop happens
// whatever the check found, so a refusal is answered by the package user
// too; a drop that does not take is errCannotDrop.
func (s rootStep) run() error {
	if s.Euid() != 0 {
		return nil
	}
	refusal := s.checkProgram()
	uid, gid, err := s.Lookup(packageUser)
	if err != nil || s.Setgroups([]int{gid}) != nil || s.Setgid(gid) != nil || s.Setuid(uid) != nil || s.Euid() == 0 {
		return errCannotDrop
	}
	return refusal
}

// checkProgram answers errNoProgram when the process cannot name its own
// program, and errUnsafeInstall unless the program, the directory holding
// it and the package's program tree above that (bin's parent, where the CGI
// script's folder sits too) are all root's and writable by nobody else: the
// package user could otherwise replace the program, or rename a directory
// on the way to it and plant another.
func (s rootStep) checkProgram() error {
	exe, err := s.Exe()
	if err != nil {
		return errNoProgram
	}
	bin := filepath.Dir(exe)
	for _, path := range []string{exe, bin, filepath.Dir(bin)} {
		uid, mode, err := s.Stat(path)
		if err != nil || uid != 0 || mode.Perm()&0o022 != 0 {
			return errUnsafeInstall
		}
	}
	return nil
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
	}
}

// serveRefusal serves the page and its assets as usual, since they hold no
// data, and answers every API call with the step's one sentence, which the
// page then shows.
func serveRefusal(err error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setHeaders(w.Header())
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		serveStatic(w, r)
	})
}
