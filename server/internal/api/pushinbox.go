package api

import (
	"context"
	"log"
	"strconv"

	"hyperdrop/core/inboxannounce"
	"hyperdrop/core/pushseal"
)

// inboxPass runs inboxannounce over the owner's inboxes, the way a client
// runs it over its replica, and pushes each finished delivery. It answers
// whether some delivery is waiting on the clock, and whether the owner's
// state was read and recorded completely.
func (p *pusher) inboxPass(ctx context.Context, owner string) (pending, complete bool) {
	var st inboxannounce.State
	p.loadState(owner, pushStateInbox, &st)
	sums, err := p.db.InboxSummaries(owner)
	if err != nil {
		log.Printf("push: inboxes of %s: %v", owner, err)
		return false, false
	}
	complete = true
	settled := map[string]inboxannounce.LinkState{}
	var links []inboxannounce.Link
	for _, s := range sums {
		sum := inboxannounce.Summary{ID: s.ID, Notify: !s.NotifyOff}
		if s.SeenAt != nil {
			sum.SeenAt = *s.SeenAt
		}
		if s.Newest != nil {
			sum.Newest = *s.Newest
		}
		if ls, ok := inboxannounce.Settle(st, sum); ok {
			settled[s.ID] = ls
			continue
		}
		files, err := p.db.InboxFilesAfter(s.ID, st.Links[s.ID].Watermark)
		if err != nil {
			// Keep what was remembered; the next pass tries again. Settle
			// answered false, so the link is known.
			settled[s.ID] = st.Links[s.ID]
			complete = false
			continue
		}
		l := inboxannounce.Link{ID: s.ID, Name: s.Name, Notify: true, SeenAt: sum.SeenAt}
		for _, f := range files {
			l.Files = append(l.Files, inboxannounce.File{Path: f.Path, CommittedAt: f.CommittedAt, UploadedBy: f.UploadSession})
		}
		l.Incoming = p.incoming(s.ID)
		links = append(links, l)
	}
	next, out := inboxannounce.Evaluate(st, links, serverActivity, p.now())
	for id, ls := range settled {
		next.Links[id] = ls
	}
	pending = inboxannounce.Pending(next, links, serverActivity)
	send := len(out) > 0 && !p.quiet(owner)
	unseen := 0
	if send {
		// The count is part of every message and the phone's badge takes it
		// as is: without it, record nothing and send nothing, so the next
		// pass announces the same deliveries with a count.
		if unseen, err = p.unseenOf(owner); err != nil {
			p.logEvery("unseen "+owner, "push: unseen files of %s: %v", owner, err)
			return true, false
		}
	}
	if !p.saveState(owner, pushStateInbox, next) {
		return pending, false
	}
	if send {
		for _, a := range out {
			p.deliver(ctx, owner, pushKindInboxReceived, a.Key(), inboxMessage(a, unseen))
		}
	}
	return pending, complete
}

// inboxMessage words one delivery exactly as the apps' arrival banners do
// (InboxBannerText in HyperDropKit's InboxRules.swift, its twin): the
// inbox's name or "Files received", and the one file or the count. The
// banner's "Saving to" suffix names a folder on the device and is the
// device's to add.
func inboxMessage(a inboxannounce.Announcement, unseen int) pushseal.Message {
	title := a.LinkName
	if title == "" {
		title = "Files received"
	}
	body := "Received " + strconv.Itoa(a.Count) + " files"
	if a.Count == 1 && len(a.Files) > 0 {
		body = "Received " + a.Files[0]
	}
	return pushseal.Message{Title: title, Body: body, Thread: "inbox-" + a.LinkID, Unseen: unseen, Ref: a.LinkID}
}
