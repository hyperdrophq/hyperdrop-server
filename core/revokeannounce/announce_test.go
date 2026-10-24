package revokeannounce

import (
	"encoding/json"
	"testing"
	"time"

	"hyperdrop/core/inboxannounce"
)

var usable = inboxannounce.Activity{OnConsole: true, Idle: time.Minute}

func at(s string) time.Time { t, _ := time.Parse(time.RFC3339, s); return t }

func TestOneAnnouncementPerAdminAction(t *testing.T) {
	now := at("2026-09-23T12:00:00Z")
	two := 2
	revoked := []Source{
		{ShareID: "d1", ShareName: "Wedding", Source: "photo/2024", At: at("2026-09-23T11:00:00Z"), Files: &two},
		{ShareID: "d2", ShareName: "Trip", Source: "photo/2024", At: at("2026-09-23T11:00:00Z")},
		{ShareID: "d3", ShareName: "Old", Source: "video", At: at("2026-09-22T09:00:00Z")},
	}
	st, out := Evaluate(State{}, revoked, usable, now)
	if len(out) != 2 {
		t.Fatalf("announcements = %+v, want one per instant", out)
	}
	if out[0].At != at("2026-09-22T09:00:00Z") || out[1].Sources[0] != "photo/2024" || len(out[1].Shares) != 2 {
		t.Fatalf("order or grouping wrong: %+v", out)
	}
	if len(st.Announced) != 3 {
		t.Fatalf("state = %+v", st)
	}
	if _, again := Evaluate(st, revoked, usable, now); len(again) != 0 {
		t.Fatal("announced twice")
	}
}

func TestAFirstRunAnnouncesRecentRevokesOnly(t *testing.T) {
	now := at("2026-09-23T12:00:00Z")
	revoked := []Source{
		{ShareID: "d1", ShareName: "Old", Source: "photo", At: now.Add(-ReplayWindow - time.Hour)},
		{ShareID: "d2", ShareName: "New", Source: "photo", At: now.Add(-time.Hour)},
	}
	st, out := Evaluate(State{}, revoked, usable, now)
	if len(out) != 1 || out[0].Shares[0].ID != "d2" {
		t.Fatalf("announced %+v, want the recent one alone", out)
	}
	if len(st.Announced) != 2 {
		t.Fatal("the stale revoke must be remembered as announced, or it fires the day the window moves")
	}
}

func TestNothingSpeaksOnAMacNobodyIsAt(t *testing.T) {
	revoked := []Source{{ShareID: "d1", Source: "photo", At: at("2026-09-23T11:00:00Z")}}
	st, out := Evaluate(State{}, revoked, inboxannounce.Activity{}, at("2026-09-23T12:00:00Z"))
	if len(out) != 0 || len(st.Announced) != 0 {
		t.Fatalf("idle Mac spoke: %+v %+v", out, st)
	}
}

func TestARestoreForgetsTheKeySoALaterRevokeAnnouncesAgain(t *testing.T) {
	now := at("2026-09-23T12:00:00Z")
	first := []Source{{ShareID: "d1", Source: "photo", At: at("2026-09-23T11:00:00Z")}}
	st, _ := Evaluate(State{}, first, usable, now)
	st, _ = Evaluate(st, nil, usable, now)
	if len(st.Announced) != 0 {
		t.Fatalf("restored key kept: %+v", st)
	}
	_, out := Evaluate(st, []Source{{ShareID: "d1", Source: "photo", At: at("2026-09-23T11:30:00Z")}}, usable, now)
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
			st, out := Evaluate(State{}, revoked, usable, now)
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
				if _, again := Evaluate(stored, moved, usable, now); len(again) != 0 {
					t.Fatalf("stored in %s, read in %s: announced again", loc, in)
				}
			}
		})
	}
}
