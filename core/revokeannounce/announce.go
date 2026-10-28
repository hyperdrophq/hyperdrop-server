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
// next state and the announcements due right now. Nothing is said, and
// nothing remembered, on a device nobody is at; a revoke older than
// ReplayWindow is remembered without being said; a key that is no longer
// revoked is forgotten.
func Evaluate(st State, revoked []Source, act inboxannounce.Activity, now time.Time) (State, []Announcement) {
	if !act.Usable() {
		return st, nil
	}
	seen := make(map[Key]bool, len(st.Announced))
	for _, k := range st.Announced {
		k.At = instant(k.At)
		seen[k] = true
	}
	present := make(map[Key]bool, len(revoked))
	groups := map[time.Time]*Announcement{}
	var order []time.Time
	for _, s := range revoked {
		k := keyOf(s)
		present[k] = true
		if seen[k] {
			continue
		}
		seen[k] = true
		if s.At.Before(now.Add(-ReplayWindow)) {
			continue
		}
		g := groups[k.At]
		if g == nil {
			g = &Announcement{At: k.At}
			groups[k.At] = g
			order = append(order, k.At)
		}
		g.Shares = append(g.Shares, Loss{ID: s.ShareID, Name: s.ShareName, Source: s.Source, Files: s.Files})
	}
	sort.Slice(order, func(i, j int) bool { return order[i].Before(order[j]) })
	var out []Announcement
	for _, at := range order {
		g := groups[at]
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
