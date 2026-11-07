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
// the one its owner is using. A computer reports once a minute while in use,
// so the limit covers one missed report.
const ActiveIdleLimit = 2 * time.Minute

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

// Usable reports whether this device is the one the owner is at. A delivery
// whose presence is unknown is held, never dropped, until this turns true,
// which is why a client re-evaluates when this verdict flips.
func (a Activity) Usable() bool { return a.OnConsole && a.Idle < ActiveIdleLimit }

// Presence is who of the account was at a computer at one instant, as the
// server answers it for the device asking. The zero value is unknown.
type Presence int

const (
	// PresenceUnknown: nobody can say (a failed read, the server's own
	// pusher). The device's own Activity decides.
	PresenceUnknown Presence = iota
	// PresenceSelf: this computer was the one in use.
	PresenceSelf
	// PresenceOther: another computer of the account was in use, and it is
	// the one that tells the owner.
	PresenceOther
	// PresenceNone: no computer of the account was in use, so every device
	// tells the owner.
	PresenceNone
)

// presenceAt is at(t), unknown when there is no at.
func presenceAt(at func(time.Time) Presence, t time.Time) Presence {
	if at == nil {
		return PresenceUnknown
	}
	return at(t)
}

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
//
// A finished delivery is decided by who was at a computer when its newest
// file landed, at(newest): this computer or none announces it now, whoever
// is at this one; another computer settles it here silently, for good; an
// unknown presence holds it until this device is Usable. Files the owner has
// read anywhere (the link's SeenAt) are below the floor and never announce.
func Evaluate(st State, links []Link, act Activity, now time.Time, at func(time.Time) Presence) (State, []Announcement) {
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
		for _, g := range openGroups(l, floor, settled) {
			// Still uploading or still inside the quiet window: hold. Holding
			// costs nothing because the next tick recomputes the group from
			// scratch, merged with whatever landed meanwhile.
			if g.busy || now.Sub(g.newest) < QuietWindow {
				continue
			}
			p := presenceAt(at, g.newest)
			if p == PresenceUnknown && !act.Usable() {
				continue
			}
			sort.Slice(g.files, func(i, j int) bool { return byCommit(g.files[i], g.files[j]) })
			names := make([]string, 0, len(g.files))
			for _, f := range g.files {
				names = append(names, f.Path)
				settled[f.Path] = true
			}
			if p == PresenceOther {
				continue
			}
			out = append(out, Announcement{LinkID: l.ID, LinkName: l.Name,
				Sender: g.sender, Files: names, Count: len(names)})
		}
		next.Links[l.ID] = advance(l.Files, floor, settled)
	}
	return next, out
}

// group is one sender's unsettled files in one link.
type group struct {
	sender string
	files  []File
	newest time.Time
	busy   bool // the sender still has an upload in flight
}

// openGroups answers a link's unsettled files above floor, one group per
// sender, in sender order.
func openGroups(l Link, floor time.Time, settled map[string]bool) []group {
	busy := make(map[string]bool, len(l.Incoming))
	for _, c := range l.Incoming {
		busy[c.By] = true
	}
	files := map[string][]File{}
	var senders []string
	for _, f := range l.Files {
		if f.CommittedAt.IsZero() || !f.CommittedAt.After(floor) || settled[f.Path] {
			continue
		}
		if _, seen := files[f.UploadedBy]; !seen {
			senders = append(senders, f.UploadedBy)
		}
		files[f.UploadedBy] = append(files[f.UploadedBy], f)
	}
	sort.Strings(senders)
	out := make([]group, 0, len(senders))
	for _, s := range senders {
		out = append(out, group{sender: s, files: files[s], newest: newest(files[s]), busy: busy[s]})
	}
	return out
}

// Candidates answers every instant Evaluate and then Pending ask at about
// for these inputs, each once and oldest first: the newest commit of each
// finished delivery, and on a device that is not Usable also of each one
// inside its quiet window. A commit after now (this device's clock behind
// the server's) is never one: it is held until the clock reaches it, which
// no presence read speeds up. A client asks the server about exactly these
// before it evaluates, and asks nothing when there are none.
func Candidates(st State, links []Link, act Activity, now time.Time) []time.Time {
	seen := map[int64]bool{}
	var out []time.Time
	for _, l := range links {
		prev, known := st.Links[l.ID]
		if !l.Notify || !known {
			continue
		}
		for _, g := range openGroups(l, floorOf(prev, l.SeenAt), settledSet(prev)) {
			if g.busy || g.newest.After(now) || (act.Usable() && now.Sub(g.newest) < QuietWindow) {
				continue
			}
			if k := g.newest.UnixNano(); !seen[k] {
				seen[k] = true
				out = append(out, g.newest)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Before(out[j]) })
	return out
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
// On a device nobody is at, only a delivery whose presence is known and
// whose newest commit is not after now waits on the clock (its quiet window
// closing is what releases it); a delivery of unknown presence waits for the
// owner to come back, which the client reports, a sender still uploading
// waits for the replica, and a commit after now waits for a later pass.
func Pending(st State, links []Link, act Activity, now time.Time, at func(time.Time) Presence) bool {
	for _, l := range links {
		prev, known := st.Links[l.ID]
		if !l.Notify || !known {
			continue
		}
		for _, g := range openGroups(l, floorOf(prev, l.SeenAt), settledSet(prev)) {
			if act.Usable() || (!g.busy && !g.newest.After(now) && presenceAt(at, g.newest) != PresenceUnknown) {
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
