package api

import (
	"context"

	"hyperdrop/core/domainconn"
	"hyperdrop/core/pushseal"
	"hyperdrop/server/internal/ddns"
)

// domainPass reads the server's free name and pushes a change into a
// problem, and the recovery after one, to every admin (read each pass, so a
// demoted admin is not told; deliver reaches no suspended or expired
// account, PushTargets). A state met for the
// first time (a new server, or one back from an absence) is only
// remembered. It answers whether the reading was recorded completely.
func (p *pusher) domainPass(ctx context.Context) (complete bool) {
	if p.domain == nil {
		return true
	}
	facts, fqdn := p.domain()
	cur := domainconn.Derive(facts, p.now())
	var mem domainconn.Memory
	known := p.loadState(pushStateServer, pushStateDomain, &mem)
	next, notice := domainconn.Next(mem, known, cur)
	var admins []string
	if notice != domainconn.NoNotice {
		// Who to tell is read before the reading is recorded: without it,
		// record nothing, so the next pass announces the same change.
		var err error
		if admins, err = p.adminNames(); err != nil {
			p.logEvery("admins", "push: admins: %v", err)
			return false
		}
	}
	if !p.saveState(pushStateServer, pushStateDomain, next) {
		return false
	}
	if notice == domainconn.NoNotice {
		return true
	}
	m := domainMessage(cur, notice, fqdn)
	for _, a := range admins {
		if ctx.Err() != nil {
			return true
		}
		if !p.quiet(a) {
			p.deliver(ctx, a, pushKindDomain, "dm-"+string(cur), m)
		}
	}
	return true
}

// domainMessage words the change for any device: the titles of
// DomainConnectionPresentation (HyperDropKit), and its bodies up to the
// sentence that names a screen of the Mac app, which a phone does not have.
func domainMessage(c domainconn.Connection, n domainconn.Notice, fqdn string) pushseal.Message {
	name := fqdn
	if name == "" {
		name = "Your free domain"
	}
	m := pushseal.Message{Thread: "domain"}
	switch {
	case n == domainconn.Recovered:
		m.Title = name + " is working again"
		m.Body = "This server keeps " + name + " pointed at itself again, so links using this address reach your files."
	case c == domainconn.Unauthorized:
		m.Title = name + " stopped working"
		m.Body = "This server lost permission to keep " + name + " pointed at it, so links using this address no longer reach your files."
	case c == domainconn.Silent:
		m.Title = name + " is not being kept up to date"
		m.Body = "This server has not refreshed " + name + " for over a day. If its internet address changes, links using it stop working."
	default:
		m.Title = name + " could not be updated"
		m.Body = "This server failed to update the address behind " + name + ". If its internet address changed, links using it stop working."
	}
	return m
}

// ddnsPublished reports a free name that is live for this server, not
// between names while a claim waits; GET /api/ddns reads it the same way.
func ddnsPublished(st ddns.State) bool { return st.Name != "" && !st.Pending }

// ddnsFacts reads the updater's state the way GET /api/ddns reports it.
func ddnsFacts(u *ddns.Updater) (domainconn.Facts, string) {
	st := u.Store().Snapshot()
	if !ddnsPublished(st) {
		return domainconn.Facts{Enrolling: st.Pending && st.Enrollment != nil, LastClaimError: u.LastClaimError()}, ""
	}
	return domainconn.Facts{Configured: true, LastUpdate: st.LastUpdate, LastError: st.LastError}, ddns.FQDN(st.Name)
}
