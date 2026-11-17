package dsmpage

import (
	"context"
	"encoding/json"
	"errors"
	"hyperdrop/server/internal/conffile"
	"hyperdrop/server/internal/ddns"
	"os"
	"strconv"
	"strings"
	"time"
)

// Applying a change: the job's dispatch, the Save state machine with its undo,
// the wait for the server to come up, and the files that record the outcome
// (last-change.json, address-request).

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
	req, ok := ddns.ParseAddressRequest(text)
	if !ok {
		return nil
	}
	kind := "domain"
	if req.Free {
		kind = "free"
	}
	if confAddress(conf) == kind+" "+req.Name {
		return nil
	}
	return &Address{kind, req.Name}
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
