// Package inboxannounce decides which finished uploads a client should
// announce to its user. It is pure: no I/O, no clock, no platform. Every
// client (macOS today, Windows, Linux and mobile next) evaluates the same
// rules over the rows its replica already holds, so "one notification per
// sender" means the same thing everywhere rather than drifting one port at a
// time.
package inboxannounce

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"time"
)

// QuietWindow is how long a sender must be silent before their delivery counts as
// finished. The upload page sends strictly one file at a time, so the gap
// between two files of one delivery is a round trip, not a pause.
const QuietWindow = 3 * time.Second

// ActiveIdleLimit is how recently this device must have seen input to count as
// the one its owner is using.
const ActiveIdleLimit = 5 * time.Minute

// Link is one inbox as the replica holds it.
type Link struct {
	ID       string
	Name     string
	Notify   bool
	SeenAt   time.Time // zero when the owner has never marked it read
	Files    []File
	Incoming []Claim
}

// File is one committed file. CommittedAt is zero for an entry whose bytes
// have not landed, which is never announceable.
type File struct {
	Path        string
	CommittedAt time.Time
	UploadedBy  string
}

// Claim is one upload in flight, which is how a sender says "not done yet".
type Claim struct {
	Name string
	By   string
}

// Activity is what this device knows about its own user.
type Activity struct {
	OnConsole bool
	Idle      time.Duration
}

// Usable reports whether this device is the one the owner is at. A held
// announcement is never dropped, only deferred until this turns true, which
// is why a client re-evaluates when this verdict flips.
func (a Activity) Usable() bool { return a.OnConsole && a.Idle < ActiveIdleLimit }

// Announcement is one finished delivery: one sender's files in one link.
type Announcement struct {
	LinkID   string   `json:"linkID"`
	LinkName string   `json:"linkName"`
	Sender   string   `json:"sender,omitempty"`
	Files    []string `json:"files"`
	Count    int      `json:"count"`
}

// Key names this delivery for every device that announces it: the push and
// the phone's own banner carry it as the notification's identifier, so the
// later one replaces the earlier rather than repeating it. Two evaluators
// that group a delivery the same way agree on it; the first file is the
// oldest commit of the group, which a later file joining the group never
// changes. The inbox's id is hashed in, never written out: it is the
// anonymous upload link, and the push carries this key in the clear to the
// relay and to Apple. Share ids are random, so the hash cannot be undone.
func (a Announcement) Key() string {
	first := ""
	if len(a.Files) > 0 {
		first = a.Files[0]
	}
	sum := sha256.Sum256([]byte(a.LinkID + "\x00" + a.Sender + "\x00" + first))
	return "in-" + hex.EncodeToString(sum[:12])
}

// LinkState is one link's settled point. Watermark is the instant through
// which everything is settled; Announced holds paths committed AFTER it that
// are already announced, which is non-empty only while an older sender is
// still uploading.
type LinkState struct {
	Watermark time.Time `json:"watermark"`
	Announced []string  `json:"announced,omitempty"`
}

// State is what one device remembers between evaluations.
type State struct {
	Links map[string]LinkState `json:"links"`
}

// Evaluate folds the current links and this device's activity into the next
// state and the announcements to post right now. It is idempotent: called
// twice with the same inputs it announces once, because the state it returns
// records what was said.
func Evaluate(st State, links []Link, act Activity, now time.Time) (State, []Announcement) {
	next := State{Links: make(map[string]LinkState, len(links))}
	var out []Announcement
	for _, l := range links {
		prev, known := st.Links[l.ID]
		// Muted, or seen here for the first time: settle everything and say
		// nothing. Unmuting announces the future rather than replaying the
		// past, and a device meeting an existing link (a fresh install, an
		// upgrade, a dropped replica) must not open with a banner for every
		// delivery the link has ever received. A link created while this device
		// is watching is settled empty on the same pass, so its first real
		// arrival still announces.
		if !l.Notify || !known {
			next.Links[l.ID] = LinkState{Watermark: newest(l.Files)}
			continue
		}
		floor := floorOf(prev, l.SeenAt)
		// Settled = already announced by this device. Anything the owner has
		// since read elsewhere falls below the floor and drops out with it.
		settled := settledSet(prev)
		busy := make(map[string]bool, len(l.Incoming))
		for _, c := range l.Incoming {
			busy[c.By] = true
		}
		groups := map[string][]File{}
		var senders []string
		for _, f := range l.Files {
			if f.CommittedAt.IsZero() || !f.CommittedAt.After(floor) || settled[f.Path] {
				continue
			}
			if _, seen := groups[f.UploadedBy]; !seen {
				senders = append(senders, f.UploadedBy)
			}
			groups[f.UploadedBy] = append(groups[f.UploadedBy], f)
		}
		sort.Strings(senders)
		for _, s := range senders {
			g := groups[s]
			// Still uploading, still inside the quiet window, or this is not
			// the device the owner is at: hold. Holding costs nothing because
			// the next tick recomputes the group from scratch, merged with
			// whatever landed meanwhile.
			if busy[s] || now.Sub(newest(g)) < QuietWindow || !act.Usable() {
				continue
			}
			sort.Slice(g, func(i, j int) bool { return byCommit(g[i], g[j]) })
			names := make([]string, 0, len(g))
			for _, f := range g {
				names = append(names, f.Path)
				settled[f.Path] = true
			}
			out = append(out, Announcement{LinkID: l.ID, LinkName: l.Name,
				Sender: s, Files: names, Count: len(names)})
		}
		next.Links[l.ID] = advance(l.Files, floor, settled)
	}
	return next, out
}

// Summary is what a client knows of a link without reading its files:
// whether it notifies, when its owner last marked it read, and when its
// newest committed file landed (zero for none).
type Summary struct {
	ID     string
	Notify bool
	SeenAt time.Time
	Newest time.Time
}

// Settle answers the state Evaluate records for a link, and true, whenever
// the summary alone decides it: a muted link, a link met for the first time,
// and a link holding nothing committed after its floor announce nothing and
// hold nothing, so this state is Evaluate's whole verdict on them and Pending
// never counts them. False says the link has files to weigh, and it goes
// through Evaluate with its files. It is what lets a client read the files of
// only the links that received something, rather than every file of every
// link on every pass.
func Settle(st State, s Summary) (LinkState, bool) {
	prev, known := st.Links[s.ID]
	if !s.Notify || !known {
		return LinkState{Watermark: s.Newest}, true
	}
	floor := floorOf(prev, s.SeenAt)
	if s.Newest.After(floor) {
		return LinkState{}, false
	}
	return LinkState{Watermark: floor}, true
}

// Pending reports whether the CLOCK is what some link is waiting on. It is
// what lets a client stop ticking entirely when nothing is waiting: the quiet
// window needs a tick of its own to fire on, and a tick that can never
// produce anything is pure idle work.
//
// A device nobody is at is never waiting on the clock, however much is held:
// what releases those is the owner coming back, which the client reports.
func Pending(st State, links []Link, act Activity) bool {
	if !act.Usable() {
		return false
	}
	for _, l := range links {
		prev, known := st.Links[l.ID]
		if !l.Notify || !known {
			continue
		}
		floor, settled := floorOf(prev, l.SeenAt), settledSet(prev)
		for _, f := range l.Files {
			if !f.CommittedAt.IsZero() && f.CommittedAt.After(floor) && !settled[f.Path] {
				return true
			}
		}
	}
	return false
}

// floorOf is the instant below which a link's files are settled: its
// watermark, or the owner's last read when that is later.
func floorOf(prev LinkState, seenAt time.Time) time.Time {
	if seenAt.After(prev.Watermark) {
		return seenAt
	}
	return prev.Watermark
}

// settledSet is the set of paths this device already announced above the
// watermark.
func settledSet(prev LinkState) map[string]bool {
	settled := make(map[string]bool, len(prev.Announced))
	for _, p := range prev.Announced {
		settled[p] = true
	}
	return settled
}

// byCommit orders files by commit instant, then by path within one instant.
func byCommit(a, b File) bool {
	if a.CommittedAt.Equal(b.CommittedAt) {
		return a.Path < b.Path
	}
	return a.CommittedAt.Before(b.CommittedAt)
}

// advance moves the watermark through the leading run of fully settled commit
// instants and keeps the settled paths beyond it. Files sharing an instant
// advance only together: CommittedAt is truncated to the second server-side,
// so one settled and one unsettled file share an instant routinely, and
// advancing on the settled one would swallow its twin unannounced.
func advance(files []File, floor time.Time, settled map[string]bool) LinkState {
	var rest []File
	for _, f := range files {
		if !f.CommittedAt.IsZero() && f.CommittedAt.After(floor) {
			rest = append(rest, f)
		}
	}
	sort.Slice(rest, func(i, j int) bool { return byCommit(rest[i], rest[j]) })
	ls := LinkState{Watermark: floor}
	i := 0
	for i < len(rest) {
		j, all := i, true
		for j < len(rest) && rest[j].CommittedAt.Equal(rest[i].CommittedAt) {
			if !settled[rest[j].Path] {
				all = false
			}
			j++
		}
		if !all {
			break
		}
		ls.Watermark = rest[i].CommittedAt
		i = j
	}
	for ; i < len(rest); i++ {
		if settled[rest[i].Path] {
			ls.Announced = append(ls.Announced, rest[i].Path)
		}
	}
	return ls
}

// newest is the latest commit instant among files, zero for none.
func newest(files []File) time.Time {
	var t time.Time
	for _, f := range files {
		if f.CommittedAt.After(t) {
			t = f.CommittedAt
		}
	}
	return t
}
