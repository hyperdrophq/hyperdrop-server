package revokeannounce

import (
	"encoding/json"
	"testing"
	"time"

	"hyperdrop/core/inboxannounce"
)

var usable = inboxannounce.Activity{OnConsole: true, Idle: time.Minute}

func at(s string) time.Time { t, _ := time.Parse(time.RFC3339, s); return t }

func unknown(time.Time) inboxannounce.Presence { return inboxannounce.PresenceUnknown }

func always(p inboxannounce.Presence) func(time.Time) inboxannounce.Presence {
	return func(time.Time) inboxannounce.Presence { return p }
}

func TestOneAnnouncementPerAdminAction(t *testing.T) {
	now := at("2026-09-23T12:00:00Z")
	two := 2
	revoked := []Source{
		{ShareID: "d1", ShareName: "Wedding", Source: "photo/2024", At: at("2026-09-23T11:00:00Z"), Files: &two},
		{ShareID: "d2", ShareName: "Trip", Source: "photo/2024", At: at("2026-09-23T11:00:00Z")},
		{ShareID: "d3", ShareName: "Old", Source: "video", At: at("2026-09-22T09:00:00Z")},
	}
	st, out := Evaluate(State{}, revoked, usable, now, unknown)
	if len(out) != 2 {
		t.Fatalf("announcements = %+v, want one per instant", out)
	}
	if out[0].At != at("2026-09-22T09:00:00Z") || out[1].Sources[0] != "photo/2024" || len(out[1].Shares) != 2 {
		t.Fatalf("order or grouping wrong: %+v", out)
	}
	if len(st.Announced) != 3 {
		t.Fatalf("state = %+v", st)
	}
	if _, again := Evaluate(st, revoked, usable, now, unknown); len(again) != 0 {
		t.Fatal("announced twice")
	}
}

func TestAFirstRunAnnouncesRecentRevokesOnly(t *testing.T) {
	now := at("2026-09-23T12:00:00Z")
	revoked := []Source{
		{ShareID: "d1", ShareName: "Old", Source: "photo", At: now.Add(-ReplayWindow - time.Hour)},
		{ShareID: "d2", ShareName: "New", Source: "photo", At: now.Add(-time.Hour)},
	}
	st, out := Evaluate(State{}, revoked, usable, now, unknown)
	if len(out) != 1 || out[0].Shares[0].ID != "d2" {
		t.Fatalf("announced %+v, want the recent one alone", out)
	}
	if len(st.Announced) != 2 {
		t.Fatal("the stale revoke must be remembered as announced, or it fires the day the window moves")
	}
}

func TestNothingSpeaksOnAMacNobodyIsAt(t *testing.T) {
	revoked := []Source{{ShareID: "d1", Source: "photo", At: at("2026-09-23T11:00:00Z")}}
	st, out := Evaluate(State{}, revoked, inboxannounce.Activity{}, at("2026-09-23T12:00:00Z"), unknown)
	if len(out) != 0 || len(st.Announced) != 0 {
		t.Fatalf("idle Mac spoke: %+v %+v", out, st)
	}
}

func TestARestoreForgetsTheKeySoALaterRevokeAnnouncesAgain(t *testing.T) {
	now := at("2026-09-23T12:00:00Z")
	first := []Source{{ShareID: "d1", Source: "photo", At: at("2026-09-23T11:00:00Z")}}
	st, _ := Evaluate(State{}, first, usable, now, unknown)
	st, _ = Evaluate(st, nil, usable, now, unknown)
	if len(st.Announced) != 0 {
		t.Fatalf("restored key kept: %+v", st)
	}
	_, out := Evaluate(st, []Source{{ShareID: "d1", Source: "photo", At: at("2026-09-23T11:30:00Z")}}, usable, now, unknown)
	if len(out) != 1 {
		t.Fatal("the second revoke was not announced")
	}
}

// A revoke is one instant whatever location its time carries: the state is
// stored as JSON, which reads an offset-0 time back as UTC and another
// offset as a fixed zone, so a key compared by its time.Time value would
// announce the same revoke again on every evaluation.
func TestARevokeIsTheSameInstantInEveryLocation(t *testing.T) {
	now := at("2026-09-23T12:00:00Z")
	for _, loc := range []*time.Location{time.FixedZone("GMT", 0), time.FixedZone("ICT", 7*3600), time.UTC} {
		t.Run(loc.String(), func(t *testing.T) {
			revoked := []Source{{ShareID: "d1", Source: "photo", At: at("2026-09-23T11:00:00.5Z").In(loc)}}
			st, out := Evaluate(State{}, revoked, usable, now, unknown)
			if len(out) != 1 {
				t.Fatalf("announced %d, want 1", len(out))
			}
			raw, err := json.Marshal(st)
			if err != nil {
				t.Fatal(err)
			}
			var stored State
			if err := json.Unmarshal(raw, &stored); err != nil {
				t.Fatal(err)
			}
			for _, in := range []*time.Location{loc, time.UTC, time.FixedZone("EST", -5*3600)} {
				moved := []Source{{ShareID: "d1", Source: "photo", At: revoked[0].At.In(in)}}
				if _, again := Evaluate(stored, moved, usable, now, unknown); len(again) != 0 {
					t.Fatalf("stored in %s, read in %s: announced again", loc, in)
				}
			}
		})
	}
}

// A revoke follows the arrivals' rule, by the instant the admin revoked:
// another computer in use then settles it here silently, nobody or this
// computer in use announces it whoever is at this one now, and a presence
// nobody can answer holds it until the owner is at this computer.
func TestTheRevokeFollowsTheSameRule(t *testing.T) {
	now := at("2026-09-23T12:00:00Z")
	when := at("2026-09-23T11:00:00Z")
	revoked := []Source{{ShareID: "d1", ShareName: "Wedding", Source: "photo", At: when}}
	idle := inboxannounce.Activity{}
	var asked []time.Time
	other := func(t time.Time) inboxannounce.Presence { asked = append(asked, t); return inboxannounce.PresenceOther }
	st, out := Evaluate(State{}, revoked, usable, now, other)
	if len(out) != 0 || len(st.Announced) != 1 {
		t.Fatalf("another computer in use: out %+v state %+v, want settled silently", out, st)
	}
	if len(asked) != 1 || !asked[0].Equal(when) {
		t.Fatalf("asked presence at %v, want the revoke's instant", asked)
	}
	if _, out = Evaluate(st, revoked, usable, now, always(inboxannounce.PresenceNone)); len(out) != 0 {
		t.Fatalf("a settled revoke announced later: %+v", out)
	}
	for _, p := range []inboxannounce.Presence{inboxannounce.PresenceNone, inboxannounce.PresenceSelf} {
		st, out := Evaluate(State{}, revoked, idle, now, always(p))
		if len(out) != 1 || len(st.Announced) != 1 {
			t.Fatalf("%v on an idle computer: out %+v state %+v, want announced", p, out, st)
		}
	}
	st, out = Evaluate(State{}, revoked, idle, now, unknown)
	if len(out) != 0 || len(st.Announced) != 0 {
		t.Fatalf("unknown on an idle computer: out %+v state %+v, want held", out, st)
	}
	if _, out = Evaluate(st, revoked, usable, now, unknown); len(out) != 1 {
		t.Fatalf("held revoke on return = %+v", out)
	}
	if c := Candidates(State{}, revoked, now); len(c) != 1 || !c[0].Equal(when) {
		t.Fatalf("candidates = %v, want the revoke's instant", c)
	}
	if c := Candidates(st, nil, now); len(c) != 0 {
		t.Fatalf("candidates = %v with nothing revoked", c)
	}
}

// A revoke after this computer's clock asks no presence.
func TestARevokeAfterTheLocalClockAsksNoPresence(t *testing.T) {
	now := at("2026-09-23T12:00:00Z")
	revoked := []Source{{ShareID: "d1", Source: "photo", At: now.Add(time.Minute)}}
	if c := Candidates(State{}, revoked, now); len(c) != 0 {
		t.Fatalf("candidates = %v for a revoke after now", c)
	}
}
