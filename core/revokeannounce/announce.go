// Package revokeannounce decides which revoked server folders a client
// should tell its user about. Pure, like inboxannounce: every client reads
// the same rows its replica holds and reaches the same verdict.
package revokeannounce

import (
	"sort"
	"time"

	"hyperdrop/core/inboxannounce"
)

// ReplayWindow bounds how far back a device with no state announces: a Mac
// set up next month must not replay last quarter's revokes.
const ReplayWindow = 30 * 24 * time.Hour

// Source is one revoked source of one share, as the replica row reports it.
type Source struct {
	ShareID, ShareName, Source string
	At                         time.Time
	Files                      *int
}

// Key identifies one revoke: the same source revoked again later is a
// different key. Keys are compared as values, so At is always UTC and
// whole seconds (instant): a time.Time compares its location too, and the
// stored state reads an instant back in a different one.
type Key struct {
	ShareID string    `json:"share"`
	Source  string    `json:"source"`
	At      time.Time `json:"at"`
}

// State is what one device remembers between evaluations.
type State struct {
	Announced []Key `json:"announced"`
}

// Loss is one share's part of an announcement.
type Loss struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Source string `json:"source"`
	Files  *int   `json:"files,omitempty"`
}

// Announcement is one admin action: every source revoked at one instant,
// and every share that lost one of them.
type Announcement struct {
	At      time.Time `json:"at"`
	Sources []string  `json:"sources"`
	Shares  []Loss    `json:"shares"`
}

func keyOf(s Source) Key {
	return Key{ShareID: s.ShareID, Source: s.Source, At: instant(s.At)}
}

// instant is t as a Key holds it: UTC, whole seconds, no monotonic reading.
func instant(t time.Time) time.Time { return t.UTC().Truncate(time.Second) }

// Evaluate folds the revoked sources and this device's activity into the
// next state and the announcements due right now. Each admin action (every
// source revoked at one instant) is decided by who was at a computer then,
// at(instant), the rule inboxannounce.Evaluate applies to a delivery: this
// computer or none announces it now, whoever is at this one; another
// computer remembers it silently; an unknown presence holds it, said and
// remembered only once this device is Usable. A revoke older than
// ReplayWindow is remembered without being said; a key that is no longer
// revoked is forgotten.
func Evaluate(st State, revoked []Source, act inboxannounce.Activity, now time.Time,
	at func(time.Time) inboxannounce.Presence) (State, []Announcement) {
	seen := make(map[Key]bool, len(st.Announced))
	for _, k := range st.Announced {
		k.At = instant(k.At)
		seen[k] = true
	}
	present := make(map[Key]bool, len(revoked))
	groups := map[time.Time]*Announcement{}
	keys := map[time.Time][]Key{}
	grouped := map[Key]bool{}
	var order []time.Time
	for _, s := range revoked {
		k := keyOf(s)
		present[k] = true
		if seen[k] {
			continue
		}
		if s.At.Before(now.Add(-ReplayWindow)) {
			seen[k] = true
			continue
		}
		g := groups[k.At]
		if g == nil {
			g = &Announcement{At: k.At}
			groups[k.At] = g
			order = append(order, k.At)
		}
		if !grouped[k] {
			grouped[k] = true
			keys[k.At] = append(keys[k.At], k)
			g.Shares = append(g.Shares, Loss{ID: s.ShareID, Name: s.ShareName, Source: s.Source, Files: s.Files})
		}
	}
	sort.Slice(order, func(i, j int) bool { return order[i].Before(order[j]) })
	var out []Announcement
	decided := false
	for _, t := range order {
		p := inboxannounce.PresenceUnknown
		if at != nil {
			p = at(t)
		}
		if p == inboxannounce.PresenceUnknown && !act.Usable() {
			continue
		}
		decided = true
		for _, k := range keys[t] {
			seen[k] = true
		}
		if p == inboxannounce.PresenceOther {
			continue
		}
		g := groups[t]
		names := map[string]bool{}
		for _, d := range g.Shares {
			names[d.Source] = true
		}
		for n := range names {
			g.Sources = append(g.Sources, n)
		}
		sort.Strings(g.Sources)
		out = append(out, *g)
	}
	// A device nobody is at that decided nothing keeps its state as it was.
	if !act.Usable() && !decided {
		return st, nil
	}
	next := State{}
	for k := range seen {
		if present[k] {
			next.Announced = append(next.Announced, k)
		}
	}
	sort.Slice(next.Announced, func(i, j int) bool {
		a, b := next.Announced[i], next.Announced[j]
		if !a.At.Equal(b.At) {
			return a.At.Before(b.At)
		}
		return a.ShareID+a.Source < b.ShareID+b.Source
	})
	return next, out
}

// Candidates answers every instant Evaluate asks at about for these inputs,
// each once and oldest first: the instant of each admin action this device
// has not settled, inside ReplayWindow and not after now (this device's
// clock behind the server's). A client asks the server
// about exactly these before it evaluates, and asks nothing when there are
// none.
func Candidates(st State, revoked []Source, now time.Time) []time.Time {
	seen := make(map[Key]bool, len(st.Announced))
	for _, k := range st.Announced {
		k.At = instant(k.At)
		seen[k] = true
	}
	asked := map[time.Time]bool{}
	var out []time.Time
	for _, s := range revoked {
		k := keyOf(s)
		if seen[k] || s.At.Before(now.Add(-ReplayWindow)) || s.At.After(now) || asked[k.At] {
			continue
		}
		asked[k.At] = true
		out = append(out, k.At)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Before(out[j]) })
	return out
}
