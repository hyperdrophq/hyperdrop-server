package dsmpage

// The Storage tab. HyperDrop's data lives in a DSM shared folder, and DSM
// itself moves a shared folder to another volume (Control Panel, Shared
// Folder, Edit, Location). This page guides that move rather than doing it.
//
// DSM refuses to move a package's shared folder while it counts the package
// as running, and only a package start of its own points the package's link
// (/var/packages/hyperdrop/shares/<folder>) at the folder's new place. So the
// package is stopped and started by DSM itself: the page's script calls
// DSM's package control (SYNO.Core.Package.Control, the calls Package Center
// makes) with the administrator's own session, which the CGI, running as
// the package user, cannot do. The CGI keeps the move's record:
// POST /api/storage/stop records "stopped-for-move" before the page asks
// DSM to stop, POST /api/storage/stop-failed clears that hold when DSM did
// not stop, and POST /api/storage/start, sent once DSM has started the
// package, has the worker Save uses wait for HyperDrop as a Save does. All
// three take the lock Save holds. The start script resolves the folder
// through DSM's link at every start, so HyperDrop follows the folder to its
// new volume.

import (
	"net/http"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const (
	// stopForMoveJobKind and startJobKind are the last change's "job" for
	// the two halves of a move; startJobKind is also the worker's job kind.
	stopForMoveJobKind = "stop-for-move"
	startJobKind       = "start"

	stoppedForMoveState = "stopped-for-move"
	finishMoveText      = "Finish the move first: start HyperDrop on the Storage tab."
	runningAgainText    = "HyperDrop is running again."
	stoppedForMoveText  = "HyperDrop is stopped for a move."
	notStartedText      = "HyperDrop did not start. Open the log to see why."
)

// volumeDir matches the directory DSM mounts a volume on.
var volumeDir = regexp.MustCompile(`^volume[0-9]+$`)

// volumeOf answers the volume a resolved path lives on: its name ("/volume2")
// and the path of the volume's directory, or "" and the path itself when it
// names no volume.
func volumeOf(path string) (name, dir string) {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if volumeDir.MatchString(part) {
			return "/" + part, strings.Join(parts[:i+1], "/")
		}
	}
	return "", path
}

// moveHeld answers 409 and true while HyperDrop waits on a storage move.
func (p *page) moveHeld(w http.ResponseWriter) bool {
	if c := p.lastChange(); c != nil && c.HoldsMove {
		writeError(w, http.StatusConflict, finishMoveText)
		return true
	}
	return false
}

// startAfterMoveJob is the worker's job for the start after a move: Since is
// when HyperDrop stopped for it (or an earlier start failed), so a reason a
// start left in the status file before then is not this start's.
type startAfterMoveJob struct {
	Job   string `json:"job"`
	Since int64  `json:"since"`
}

// serveStorage answers where the data folder lives: {"folder", "path",
// "volume", "freeBytes", "available": true}; {"folder", "available": true,
// "locked": true, "text"} when the folder does not resolve; and
// {"available": false} for a package with no shared folder.
func (p *page) serveStorage(w http.ResponseWriter, r *http.Request, user string) {
	folder := readConf(p.deps.ConfPath)["SHARED_FOLDER"]
	if folder == "" {
		writeJSON(w, http.StatusOK, map[string]any{"available": false})
		return
	}
	dir, ok := p.dataDir(folder)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"folder": folder, "available": true, "locked": true, "text": lockedText})
		return
	}
	volume, volDir := volumeOf(dir)
	out := map[string]any{"folder": folder, "path": dir, "volume": volume, "available": true}
	var fs syscall.Statfs_t
	if syscall.Statfs(volDir, &fs) == nil {
		out["freeBytes"] = uint64(fs.Bavail) * uint64(fs.Bsize)
	}
	writeJSON(w, http.StatusOK, out)
}

// serveStopForMove records "stopped-for-move" under the lock and answers
// {"state": "stopped-for-move"}. It stops nothing: the page asks DSM to stop
// the package next, and the hold is in place before HyperDrop goes down, so
// no Save or admin rescue can start it during the move.
func (p *page) serveStopForMove(w http.ResponseWriter, r *http.Request, user string) {
	lock, ok := p.takeChangeLock(w)
	if !ok {
		return
	}
	defer lock.Close()
	c := p.record(LastChange{State: stoppedForMoveState, At: time.Now().Unix(), Job: stopForMoveJobKind})
	writeJSON(w, http.StatusOK, map[string]string{"state": c.State})
}

// serveStopFailed is the page's report that DSM did not confirm the stop
// (it refused, or its answer never arrived or could not be read), and
// answers the resulting state. A "stopped-for-move" hold becomes a failed
// stop, which holds nothing, only while a server still runs: with none
// running the stop may have happened after all, and the hold stays so
// nothing starts HyperDrop during a move. Any other last change is left as
// it is.
func (p *page) serveStopFailed(w http.ResponseWriter, r *http.Request, user string) {
	lock, ok := p.takeChangeLock(w)
	if !ok {
		return
	}
	defer lock.Close()
	state := ""
	if c := p.lastChange(); c != nil {
		state = c.State
		if c.State == stoppedForMoveState && c.Job == stopForMoveJobKind && p.deps.Service.Running() {
			state = p.record(LastChange{State: "failed", Reason: notStoppedText, At: time.Now().Unix(), Job: stopForMoveJobKind}).State
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"state": state})
}

// serveStartAfterMove starts the worker that waits for HyperDrop once the
// page has had DSM start the package.
func (p *page) serveStartAfterMove(w http.ResponseWriter, r *http.Request, user string) {
	since := time.Now().Unix()
	if c := p.lastChange(); c != nil && c.HoldsMove && c.At > 0 && c.At < since {
		since = c.At
	}
	p.startJob(w, startJobKind, startAfterMoveJob{Job: startJobKind, Since: since})
}

// StartAfterMove waits for the server DSM started as Save waits for the
// one it starts, and starts nothing itself. A server that does not come up
// leaves the change "failed" with the reason a start left in the status
// file at or after since, such as the start script's refusal of a folder
// DSM is still moving.
func (p *page) StartAfterMove(svc Service, clk Clock, since time.Time) LastChange {
	p.record(LastChange{State: "applying", At: clk.Now().Unix(), Job: startJobKind})
	if reason, ok := p.waitUp(svc, clk, since, notStartedText); !ok {
		return p.record(LastChange{State: "failed", Reason: reason, At: clk.Now().Unix(), Job: startJobKind})
	}
	return p.record(LastChange{State: "done", At: clk.Now().Unix(), Job: startJobKind})
}
