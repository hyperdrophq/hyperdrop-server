package api

import (
	"context"
	"strconv"
	"strings"

	"hyperdrop/core/pushseal"
	"hyperdrop/core/revokeannounce"
)

// revokePass runs revokeannounce over the owner's revoked sources and pushes
// each admin action once. The first pass for an owner only remembers:
// revokeannounce's replay window suits a new Mac, but a phone registering
// must not open with last month's revokes. It answers whether the owner's
// revokes were read and recorded completely.
func (p *pusher) revokePass(ctx context.Context, owner string) (complete bool) {
	var st revokeannounce.State
	known := p.loadState(owner, pushStateRevoke, &st)
	rows, err := p.revoked(owner)
	if err != nil {
		p.logEvery("revoked "+owner, "push: revoked folders of %s: %v", owner, err)
		return false
	}
	sources := make([]revokeannounce.Source, 0, len(rows))
	for _, r := range rows {
		sources = append(sources, revokeannounce.Source{ShareID: r.ShareID, ShareName: r.ShareName,
			Source: r.Source, At: r.At, Files: r.Files})
	}
	next, out := revokeannounce.Evaluate(st, sources, serverActivity, p.now())
	if !p.saveState(owner, pushStateRevoke, next) {
		return false
	}
	if !known || len(out) == 0 || p.quiet(owner) {
		return true
	}
	for _, a := range out {
		p.deliver(ctx, owner, pushKindAccessRevoked, "rv-"+strconv.FormatInt(a.At.Unix(), 10), revokeMessage(a))
	}
	return true
}

// revokeMessage words one admin action exactly as the Mac's banner does
// (NotificationKind.accessRevoked's title and RevokeNotifier.body, its
// twins). One share is the push's destination; several open no share.
func revokeMessage(a revokeannounce.Announcement) pushseal.Message {
	total := 0
	for _, s := range a.Shares {
		if s.Files != nil {
			total += *s.Files
		}
	}
	lost := "its files"
	if total > 0 {
		lost = grouped(total) + " files"
	}
	who := strconv.Itoa(len(a.Shares)) + " shares"
	ref := ""
	if len(a.Shares) == 1 {
		who, ref = a.Shares[0].Name, a.Shares[0].ID
	}
	what := "the folder"
	if len(a.Sources) > 1 {
		what = "the folders"
	}
	return pushseal.Message{Title: "Folder access removed", Thread: "revoked", Ref: ref,
		Body: strings.Join(a.Sources, ", ") + ": " + who + " lost " + lost + ". An admin removed " + what + " from your account."}
}

// grouped writes n with thousands separators, as CountText.grouped does.
func grouped(n int) string {
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}
