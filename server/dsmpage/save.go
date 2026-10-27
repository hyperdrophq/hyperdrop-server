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
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
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
	return domain.Valid(d) && d != ddns.Zone && !strings.HasSuffix(d, "."+ddns.Zone)
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

// apply reads and removes the job file, then runs it: an admin rescue or
// the wait after a storage move when its "job" says so, else a Save.
func (p *page) apply(job string, svc Service, clk Clock) LastChange {
	text, err := conffile.Read(job)
	os.Remove(job)
	var kind struct {
		Job string `json:"job"`
	}
	if err == nil {
		err = json.Unmarshal([]byte(text), &kind)
	}
	strict := func(v any) error {
		dec := json.NewDecoder(strings.NewReader(text))
		dec.DisallowUnknownFields()
		return dec.Decode(v)
	}
	if err == nil && kind.Job == startJobKind {
		var sj startAfterMoveJob
		if err = strict(&sj); err == nil {
			return p.StartAfterMove(svc, clk, time.Unix(sj.Since, 0))
		}
	}
	if err == nil && kind.Job == rescueJobKind {
		var rj rescueJob
		if err = strict(&rj); err == nil {
			return p.Rescue(rj.RescueRequest, svc, clk)
		}
	}
	var req SettingsRequest
	if err == nil {
		err = strict(&req)
	}
	if err != nil {
		return p.record(LastChange{State: "failed", Reason: workerText, At: clk.Now().Unix()})
	}
	return p.Save(req, svc, clk)
}

// Save applies req and answers the outcome, which it also records: it
// checks req against the conf before anything stops, stops the server,
// keeps the conf as hyperdrop.conf.prev and merges req into it (an address
// change goes to address-request, which the server carries out once the
// new address is proven), starts the server and waits up to a minute for
// it to run and answer its health check. A server that does not come up is
// stopped, the previous conf and address request are put back, and the
// server is started on them: the change is "undone", its reason the one the
// failed start left in the status file. When even that start fails, the
// change "failed".
func (p *page) Save(req SettingsRequest, svc Service, clk Clock) LastChange {
	conf := readConf(p.deps.ConfPath)
	if msg := refusal(req, conf); msg != "" {
		return p.record(LastChange{State: "failed", Reason: msg, At: clk.Now().Unix()})
	}
	p.record(LastChange{State: "applying", At: clk.Now().Unix()})
	failed := func(reason string) LastChange {
		return p.record(LastChange{State: "failed", Reason: reason, At: clk.Now().Unix()})
	}

	if err := svc.Stop(); err != nil {
		svc.Start()
		return failed(notStoppedText)
	}
	before, err := conffile.Read(p.deps.ConfPath)
	if err != nil {
		svc.Start()
		return failed(readConfText)
	}
	prevRequest, hadRequest := p.readRequest()
	restore := func() error {
		err := conffile.Write(p.deps.ConfPath, before)
		if hadRequest {
			return errors.Join(err, conffile.Write(p.requestPath(), prevRequest))
		}
		return errors.Join(err, removePlain(p.requestPath()))
	}
	if err := conffile.Write(p.deps.ConfPath+".prev", before); err != nil {
		svc.Start()
		return failed(writeConfText)
	}
	next := before
	for _, kv := range [][2]string{
		{"HYPERDROP_HTTP_ADDR", ":" + strconv.Itoa(req.HTTPPort)},
		{"HYPERDROP_HTTPS_ADDR", ":" + strconv.Itoa(req.HTTPSPort)},
		{"HYPERDROP_TRUSTED_PROXIES", strings.TrimSpace(req.Proxy)},
	} {
		next = conffile.SetText(next, kv[0], kv[1])
	}
	err = conffile.Write(p.deps.ConfPath, next)
	if err == nil {
		// As the upgrade wizard does: a new address is a request, and the
		// conf's own address makes a waiting request stale.
		if want := req.address(); want != confAddress(parseConf([]byte(before))) {
			err = conffile.Write(p.requestPath(), want+"\n")
		} else {
			err = removePlain(p.requestPath())
		}
	}
	if err != nil {
		if restore() != nil {
			svc.Start()
			return failed(restoreText)
		}
		svc.Start()
		return failed(writeConfText)
	}

	reason, ok := p.startAndWait(svc, clk)
	if ok {
		return p.record(LastChange{State: "done", At: clk.Now().Unix()})
	}
	if err := svc.Stop(); err != nil {
		return failed(notStoppedRestoreText)
	}
	if restore() != nil {
		svc.Start()
		return failed(restoreText)
	}
	if again, ok := p.startAndWait(svc, clk); !ok {
		return failed(again)
	}
	return p.record(LastChange{State: "undone", Reason: reason, At: clk.Now().Unix()})
}

// startAndWait starts the server and waits for it (waitUp). A server that
// is not running at a check has exited. On failure it answers the reason
// the start left in the status file, or what it saw.
func (p *page) startAndWait(svc Service, clk Clock) (string, bool) {
	since := clk.Now()
	if err := svc.Start(); err != nil {
		return p.startError(since, exitedText), false
	}
	return p.waitUp(svc, clk, since, exitedText)
}

// waitUp checks every upPoll, for up to upLimit, that the server runs and
// answers its health check. A server that is not running at a check is not
// waited for: the answer is the reason a start at or after since left in
// the status file, else notRunning.
func (p *page) waitUp(svc Service, clk Clock, since time.Time, notRunning string) (string, bool) {
	deadline := clk.Now().Add(upLimit)
	for {
		clk.Sleep(upPoll)
		if !svc.Running() {
			return p.startError(since, notRunning), false
		}
		ctx, cancel := context.WithTimeout(context.Background(), healthTimeout)
		healthy := svc.Healthy(ctx)
		cancel()
		if healthy {
			return "", true
		}
		if !clk.Now().Before(deadline) {
			return p.startError(since, timeoutText), false
		}
	}
}

// startError is the status file's lastError when the start at or after
// since wrote it, else fallback.
func (p *page) startError(since time.Time, fallback string) string {
	var st struct {
		LastError string `json:"lastError"`
		At        int64  `json:"at"`
	}
	if b, err := readCapped(p.deps.StatusPath); err == nil && json.Unmarshal(b, &st) == nil &&
		st.LastError != "" && st.At >= since.Unix() {
		return st.LastError
	}
	return fallback
}

// record writes c as last-change.json and answers it.
func (p *page) record(c LastChange) LastChange {
	b, _ := json.Marshal(c)
	conffile.Write(p.lastChangePath(), string(b)+"\n")
	return c
}

// lastChange reads last-change.json. A change still "applying" while no
// worker holds the lock was cut short and is reported as failed, and the
// job and the rescue's seed it may have left are removed, since either can
// hold a password.
func (p *page) lastChange() *ChangeReport {
	text, err := conffile.Read(p.lastChangePath())
	if err != nil {
		return nil
	}
	var c LastChange
	if json.Unmarshal([]byte(text), &c) != nil || c.State == "" {
		return nil
	}
	switch c.State {
	case "applying":
		if !lockHeld(p.lockPath()) {
			c.State, c.Reason = "failed", interruptedText
			if c.Job == rescueJobKind {
				c.Reason = interruptedRescueText
			}
			removePlain(p.jobPath())
			removePlain(p.seedPath())
		}
	case "done", "undone", "failed", stoppedForMoveState:
	default:
		return nil
	}
	held := c.State == stoppedForMoveState || (c.State == "failed" && (c.Job == startJobKind || c.Job == stopForMoveJobKind && c.Reason == interruptedText))
	return &ChangeReport{LastChange: c, Text: c.Text(), HoldsMove: held}
}

// readRequest reads a waiting address request, when there is one.
func (p *page) readRequest() (string, bool) {
	text, err := conffile.Read(p.requestPath())
	return text, err == nil
}

// requestLimit bounds address-request, as the server bounds it.
const requestLimit = 512

// pendingAddress is the address change waiting in address-request, read the
// way the server reads it at boot: a regular file of its own of at most
// requestLimit bytes, one line "free <name>" or "domain <fqdn>". Anything
// else is nil, and so is a request for the address conf already holds,
// which is stale.
func (p *page) pendingAddress(conf map[string]string) *Address {
	text, ok := p.readRequest()
	if !ok || len(text) > requestLimit {
		return nil
	}
	line, rest, _ := strings.Cut(text, "\n")
	if strings.TrimSpace(rest) != "" {
		return nil
	}
	kind, value, _ := strings.Cut(strings.TrimSpace(line), " ")
	switch kind {
	case "free":
		if ddns.ValidName(value) && confAddress(conf) != "free "+value {
			return &Address{"free", value}
		}
	case "domain":
		d := strings.TrimSuffix(strings.ToLower(value), ".")
		if domain.Valid(d) && d != ddns.Zone && !strings.HasSuffix(d, "."+ddns.Zone) && confAddress(conf) != "domain "+d {
			return &Address{"domain", d}
		}
	}
	return nil
}

// removePlain removes path when it is a regular file; a link or anything
// else there is left alone.
func removePlain(path string) error {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// scriptPATH is the PATH the worker and the start script run with.
const scriptPATH = "/usr/syno/sbin:/usr/syno/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// scriptService runs the package's start-stop-status as DSM does, with the
// facts its scripts read from DSM's environment.
type scriptService struct {
	p      *page
	script string
	client *http.Client
}

func newScriptService(p *page) *scriptService {
	return &scriptService{
		p:      p,
		script: p.deps.Script,
		client: &http.Client{
			Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Stop waits up to the script's own 30 seconds and its kill, Start for the
// script alone, which watches the server it starts for its first seconds
// and fails when it exits; the server runs on in the background.
func (s *scriptService) Stop() error  { return s.run("stop", 90*time.Second) }
func (s *scriptService) Start() error { return s.run("start", 60*time.Second) }

func (s *scriptService) run(arg string, limit time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.script, arg)
	cmd.Dir = "/"
	cmd.Env = []string{
		"PATH=" + scriptPATH,
		"SYNOPKG_PKGNAME=hyperdrop",
		"SYNOPKG_PKGDEST=" + packageTarget,
		"SYNOPKG_PKGVAR=" + s.p.deps.VarDir,
	}
	cmd.WaitDelay = time.Second
	return cmd.Run()
}

func (s *scriptService) Running() bool { return s.p.running() }

// Healthy is true when the server's plain-HTTP health route on loopback,
// on the port the conf names now, answers 200 with HyperDrop's own health
// document, which carries its serverID: another program answering on the
// port is not HyperDrop.
func (s *scriptService) Healthy(ctx context.Context) bool {
	port := portOf(readConf(s.p.deps.ConfPath)["HTTP_ADDR"])
	if port == 0 {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(port)+"/api/health", nil)
	if err != nil {
		return false
	}
	res, err := s.client.Do(req)
	if err != nil {
		return false
	}
	defer res.Body.Close()
	var health struct {
		ServerID string `json:"serverID"`
	}
	if res.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&health) != nil {
		return false
	}
	return health.ServerID != ""
}
