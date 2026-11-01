package api

import (
	"context"
	"encoding/json"
	"slices"

	"hyperdrop/core/pushseal"
	"hyperdrop/core/updatenotice"
)

// sentUpdateKeys bounds the memory of reminders pushed: keys are per
// version, so the newest few are all that can recur.
const sentUpdateKeys = 32

// updateMemory is the server-update reminder keys already pushed, oldest
// first.
type updateMemory struct {
	Sent []string `json:"sent"`
}

// updatePass pushes each server-update reminder due now to every admin's
// devices, once (read each pass, so a demoted admin is not told; deliver
// reaches no suspended or expired account, PushTargets). The keys sent are
// recorded BEFORE sending, and a pass that meets the reminders for the
// first time (a new server, or one back from an absence) only records
// them, so a phone registering later is not told what was already due. It
// answers whether the reminders were recorded completely.
func (p *pusher) updatePass(ctx context.Context) (complete bool) {
	if p.updates == nil {
		return true
	}
	raw, stored, err := p.db.PushState(pushStateServer, pushStateUpdate)
	if err != nil {
		p.logEvery("update-state", "push: server-update memory: %v", err)
		return false
	}
	var mem updateMemory
	parsed := stored && json.Unmarshal([]byte(raw), &mem) == nil
	if !parsed {
		mem = updateMemory{}
	}
	// known is loadState's answer for the same row. What was sent is kept
	// whatever it is: an absence (amnesia) only stops this pass from
	// sending, and the reminders already pushed stay remembered, so they are
	// not pushed again when they are next due (a rebooted server reads its
	// manifest minutes after its first pass).
	known := parsed && !(p.amnesia && !p.recorded[pushStateServer])
	var fresh []updatenotice.Notice
	for _, n := range p.updates() {
		// A key still due moves to the end, so the bound below evicts
		// only keys no longer due.
		if i := slices.Index(mem.Sent, n.Key); i >= 0 {
			mem.Sent = slices.Delete(mem.Sent, i, i+1)
		} else {
			fresh = append(fresh, n)
		}
		mem.Sent = append(mem.Sent, n.Key)
	}
	if len(mem.Sent) > sentUpdateKeys {
		mem.Sent = mem.Sent[len(mem.Sent)-sentUpdateKeys:]
	}
	if mem.Sent == nil {
		mem.Sent = []string{}
	}
	var admins []string
	if known && len(fresh) > 0 {
		// Who to tell is read before the keys are recorded: without it,
		// record nothing, so the next pass sends the same reminders.
		var err error
		if admins, err = p.adminNames(); err != nil {
			p.logEvery("admins", "push: admins: %v", err)
			return false
		}
	}
	if !p.saveState(pushStateServer, pushStateUpdate, mem) {
		return false
	}
	if !known || len(fresh) == 0 {
		return true
	}
	for _, a := range admins {
		if ctx.Err() != nil {
			return true
		}
		if p.quiet(a) {
			continue
		}
		for _, n := range fresh {
			p.deliver(ctx, a, pushKindServerUpdate, "su-"+n.Key, updateMessage(n))
		}
	}
	return true
}

// updateMessage carries the server's own words: core/updatenotice writes
// them for any device.
func updateMessage(n updatenotice.Notice) pushseal.Message {
	return pushseal.Message{Title: n.Title, Body: n.Body, Thread: "server-update"}
}
