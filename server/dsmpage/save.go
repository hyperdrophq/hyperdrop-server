package dsmpage

// Save and restart. POST /api/settings validates the request and hands it to
// a worker (`hyperdrop-server dsmpage-apply <job>`) started in its own
// session, and answers 202 at once: stopping, starting and watching the
// server takes longer than DSM's web server lets a CGI run, and the worker
// outlives the request. One change runs at a time, under a lock the worker
// holds until it ends. The worker records its progress and outcome in
// last-change.json, which GET /api/state reports, because the server rewrites
// its own status file at every start.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"hyperdrop/server/internal/conffile"
	"hyperdrop/server/internal/ddns"
	"hyperdrop/server/internal/domain"
)

const (
	// settingsBodyLimit bounds the request body.
	settingsBodyLimit = 64 << 10
	// upLimit is how long a started server has to run and answer its
	// health check; upPoll is how often both are checked.
	upLimit = 60 * time.Second
	upPoll  = 2 * time.Second
	// lockTries and lockWait are how long a Save waits for a lock held
	// for a moment, about 100 ms.
	lockTries = 5
	lockWait  = 20 * time.Millisecond
	// healthTimeout bounds one health check.
	healthTimeout = 2 * time.Second
)

// The texts the page shows. The address, port and proxy refusals are the
// install wizard's (scripts/common validate_answers).
const (
	kindText       = "Choose a free HyperDrop address or your own domain."
	freeNameText   = "5-32 lowercase letters, digits and single hyphens, for example alice."
	domainText     = "A domain name, for example share.example.com."
	portText       = "A port is a number from 1 to 65535."
	samePortsText  = "The HTTPS and HTTP ports must be different."
	proxyText      = "Proxy address must be IP addresses separated by commas, for example 192.168.1.10 or 127.0.0.1."
	renameText     = "Change your free name in the HyperDrop app."
	badRequestText = "The request is not valid."
	busyText       = "Another change is being applied. Wait for it to finish."

	notStoppedText        = "HyperDrop could not be stopped, so nothing was changed."
	readConfText          = "HyperDrop could not read its settings file, so nothing was changed."
	writeConfText         = "HyperDrop could not save the new settings, so nothing was changed. Check free space on the volume."
	notStoppedRestoreText = "HyperDrop could not be stopped to put the previous settings back."
	restoreText           = "HyperDrop could not put the previous settings back. Check free space on the volume, then save again."
	exitedText            = "HyperDrop stopped as soon as it started. Open the log to see why."
	timeoutText           = "HyperDrop did not start in 60 seconds."
	interruptedText       = "The change was interrupted. Check the settings and save again."
	workerText            = "HyperDrop could not start applying the change."
)

// SettingsRequest is the body of POST /api/settings: the address (Kind
// "free" with the name before .hyperdrop.link, or "domain"), both ports and
// the proxy list ("" for no proxy).
type SettingsRequest struct {
	Kind      string `json:"kind"`
	Address   string `json:"address"`
	HTTPPort  int    `json:"httpPort"`
	HTTPSPort int    `json:"httpsPort"`
	Proxy     string `json:"proxy"`
}

// LastChange is last-change.json: the state of the last Save or admin
// rescue ("applying", "done", "undone" with the previous settings back,
// "stopped-for-move" while HyperDrop waits for its folder to be moved, or
// "failed"), why it was undone or failed or, for a done rescue, what it
// did, and when it started or ended. Job is "rescue" for an admin rescue,
// "stop-for-move" or "start" for the halves of a storage move and empty for
// a Save.
type LastChange struct {
	State  string `json:"state"`
	Reason string `json:"reason"`
	At     int64  `json:"at"`
	Job    string `json:"job,omitempty"`
}

// Text is the sentence the page shows for the change.
func (c LastChange) Text() string {
	switch c.State {
	case "applying":
		return "Applying your change…"
	case "done":
		if c.Reason != "" {
			return c.Reason
		}
		if c.Job == startJobKind {
			return runningAgainText
		}
		return "Saved."
	case stoppedForMoveState:
		return stoppedForMoveText
	case "undone":
		return "Last change undone: " + c.Reason
	}
	return "Change failed: " + c.Reason
}

// ChangeReport is the last change as GET /api/state reports it.
type ChangeReport struct {
	LastChange
	Text string `json:"text"`
	// HoldsMove is true while HyperDrop waits on a storage move: a Save or
	// an admin rescue would start it in the middle of DSM's copy.
	HoldsMove bool `json:"holdsMove,omitempty"`
}

// Service controls the package's server.
type Service interface {
	Stop() error
	Start() error
	Running() bool
	Healthy(ctx context.Context) bool
}

// Clock is the worker's time: Sleep waits between checks.
type Clock interface {
	Now() time.Time
	Sleep(time.Duration)
}

type realClock struct{}

func (realClock) Now() time.Time        { return time.Now() }
func (realClock) Sleep(d time.Duration) { time.Sleep(d) }

func (p *page) varPath(name string) string { return filepath.Join(p.deps.VarDir, name) }
func (p *page) lockPath() string           { return p.varPath(".dsmpage.lock") }
func (p *page) jobPath() string            { return p.varPath(".dsmpage-job.json") }
func (p *page) lastChangePath() string     { return p.varPath("last-change.json") }
func (p *page) requestPath() string        { return p.varPath("address-request") }

// serveSettings validates the request and starts the worker that applies it.
// The CGI closes its copy of the lock when it exits and never unlocks it:
// the worker holds the same lock through the descriptor it inherited.
func (p *page) serveSettings(w http.ResponseWriter, r *http.Request, user string) {
	if p.moveHeld(w) {
		return
	}
	req, err := decodeSettings(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, badRequestText)
		return
	}
	if msg := refusal(req, readConf(p.deps.ConfPath)); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	p.startJob(w, "", req)
}

// startJob takes the lock, writes job as the job file, records a change of
// kind as applying and starts the worker on it, answering 202, or 409 while
// another change holds the lock.
func (p *page) startJob(w http.ResponseWriter, kind string, job any) {
	lock, ok := p.takeChangeLock(w)
	if !ok {
		return
	}
	defer lock.Close()
	text, _ := json.Marshal(job)
	if err := conffile.Write(p.jobPath(), string(text)); err != nil {
		writeError(w, http.StatusInternalServerError, workerText)
		return
	}
	p.record(LastChange{State: "applying", At: time.Now().Unix(), Job: kind})
	if err := p.deps.StartWorker(p.jobPath(), lock); err != nil {
		os.Remove(p.jobPath())
		p.record(LastChange{State: "failed", Reason: workerText, At: time.Now().Unix(), Job: kind})
		writeError(w, http.StatusInternalServerError, workerText)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"state": "applying"})
}

// takeChangeLock takes the lock one change holds at a time, answering 409
// while another change holds it (or 500 when it cannot be opened) and false.
func (p *page) takeChangeLock(w http.ResponseWriter) (*os.File, bool) {
	// No var directory (a DSM 6 whose target names no volume) is nowhere to
	// write: refused before any path is composed, so nothing lands under a
	// relative name.
	if p.deps.VarDir == "" {
		writeError(w, http.StatusConflict, p.missingDataText())
		return nil, false
	}
	lock, busy, err := takeLock(p.lockPath())
	// The state poll holds the lock shared for a moment: wait that out.
	for try := 0; busy && try < lockTries; try++ {
		time.Sleep(lockWait)
		lock, busy, err = takeLock(p.lockPath())
	}
	if busy {
		writeError(w, http.StatusConflict, busyText)
		return nil, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, workerText)
		return nil, false
	}
	return lock, true
}

// decodeSettings reads the settings request.
func decodeSettings(w http.ResponseWriter, r *http.Request) (SettingsRequest, error) {
	var req SettingsRequest
	return req, decodeBody(w, r, &req)
}

// decodeBody reads exactly one JSON object of v's known fields from a body
// of at most settingsBodyLimit bytes.
func decodeBody(w http.ResponseWriter, r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, settingsBodyLimit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return errors.New("more than one JSON value")
	}
	return nil
}

// address is the request's address as the package spells it in
// address-request: "free <name>" or "domain <fqdn>", the domain lowercased.
func (req SettingsRequest) address() string {
	if req.Kind == "domain" {
		return "domain " + strings.ToLower(req.Address)
	}
	return "free " + req.Address
}

// confAddress is the conf's address in the same spelling, or "".
func confAddress(conf map[string]string) string {
	switch {
	case conf["DDNS_NAME"] != "":
		return "free " + conf["DDNS_NAME"]
	case conf["DOMAIN"] != "":
		return "domain " + conf["DOMAIN"]
	}
	return ""
}

// refusal answers why req cannot be saved over conf (the conf's values,
// keyed without HYPERDROP_), or "". Every value is held to what the
// package's validate_answers and the server at boot both accept, since the
// start script sources the conf.
func refusal(req SettingsRequest, conf map[string]string) string {
	switch req.Kind {
	case "free":
		// The wizard's rule and the names service's are one shape.
		if !ddns.ValidName(req.Address) {
			return freeNameText
		}
	case "domain":
		if !validDomain(req.Address) {
			return domainText
		}
	default:
		return kindText
	}
	for _, port := range []int{req.HTTPPort, req.HTTPSPort} {
		if port < 1 || port > 65535 {
			return portText
		}
	}
	if req.HTTPPort == req.HTTPSPort {
		return samePortsText
	}
	if msg := proxyRefusal(req.Proxy); msg != "" {
		return msg
	}
	if cur, want := confAddress(conf), req.address(); strings.HasPrefix(cur, "free ") && strings.HasPrefix(want, "free ") && cur != want {
		return renameText
	}
	return ""
}

// validDomain is the wizard's domain rule (letters, digits, dots and
// hyphens, at least one dot, no empty label or hyphen at a label's edge)
// and the server's own, outside the free-name zone.
func validDomain(d string) bool {
	if strings.Trim(d, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-") != "" {
		return false
	}
	d = strings.ToLower(d)
	return domain.Valid(d) && d != ddns.Zone && !ddns.InFreeZone(d)
}

// proxyRefusal answers proxyText unless v is empty or a list of addresses
// and CIDR ranges the server trusts: only the address characters, at least
// one item, and no item that trusts the whole internet.
func proxyRefusal(v string) string {
	if v == "" {
		return ""
	}
	if strings.Trim(v, "0123456789abcdefABCDEF.:/, ") != "" {
		return proxyText
	}
	prefixes, err := conffile.ParseTrustedProxies(v)
	if err != nil || len(prefixes) == 0 {
		return proxyText
	}
	return ""
}
