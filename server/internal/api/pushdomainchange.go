package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"hyperdrop/core/domainconn"
	"hyperdrop/core/pushseal"
)

// sentDomainChangeKeys bounds the memory of address changes pushed: the
// server lists no more than domainconn.ChangesKept at a time.
const sentDomainChangeKeys = 16

// domainChangePass pushes each address change not yet told to every admin's
// devices, once (admins read each pass, so a demoted admin is not told;
// deliver reaches no suspended or expired account). The keys are recorded
// BEFORE sending, and a pass that meets the changes for the first time (a
// new server, or one back from an absence) only records those older than
// pushAbsence and sends the newer ones. Unlike the
// reminders it never asks p.quiet: a computer in use must not silence the
// one warning an administrator who did not move the server needs. It answers
// whether the changes were recorded completely.
func (p *pusher) domainChangePass(ctx context.Context) (complete bool) {
	if p.domainChanges == nil {
		return true
	}
	raw, stored, err := p.db.PushState(pushStateServer, pushStateDomainChange)
	if err != nil {
		p.logEvery("domain-change-state", "push: domain-change memory: %v", err)
		return false
	}
	var mem sentKeys
	parsed := stored && json.Unmarshal([]byte(raw), &mem) == nil
	if !parsed {
		mem = sentKeys{}
	}
	known := parsed && !(p.amnesia && !p.recorded[pushStateServer])
	// Without trusted memory a change older than pushAbsence is backlog and
	// is only recorded; a newer one is news (a domain changed at boot, or
	// between boot and the first pass) and is sent. Memory stored but
	// unreadable sends nothing.
	unreadable := stored && !parsed
	now := p.now()
	var fresh []domainconn.ChangeNotice
	for _, n := range p.domainChanges() {
		if !mem.note(n.Key) && (known || !unreadable && now.Sub(n.At) <= pushAbsence) {
			fresh = append(fresh, n)
		}
	}
	admins, ok := p.recordSent(pushStateDomainChange, mem, sentDomainChangeKeys, len(fresh) > 0)
	if !ok {
		return false
	}
	if len(fresh) == 0 {
		return true
	}
	for _, a := range admins {
		if ctx.Err() != nil {
			return true
		}
		for _, n := range fresh {
			p.deliver(ctx, a, pushKindDomainChanged, domainChangeCollapse(n.Key), pushseal.Message{Title: n.Title, Body: n.Body, Thread: "domain-changed"})
		}
	}
	return true
}

// domainChangeCollapse is the push's collapse id, dc-<24 hex>: a SHA-256 of
// the change's key, stable per change and of a fixed length whatever the
// domain's, well inside the relay's 64 characters.
func domainChangeCollapse(key string) string {
	sum := sha256.Sum256([]byte("domainChanged\x00" + key))
	return "dc-" + hex.EncodeToString(sum[:12])
}
