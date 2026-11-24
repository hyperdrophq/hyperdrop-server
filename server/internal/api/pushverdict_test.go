package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"hyperdrop/core/inboxannounce"
	"hyperdrop/core/revokeannounce"
)

// serverVerdictDigest is the SHA-256 of every verdict serverVerdictWalk
// records. The walk feeds inboxannounce and revokeannounce exactly what the
// pusher feeds them (serverActivity, serverPresence), so it names every push
// the server decides over the walk.
const serverVerdictDigest = "a573280cbf01084ef74c8870b6672adb7a3d4de652a04a6d8a554a8a11fa3bdf"

// serverVerdictWalk evaluates every combination of mute, first meeting,
// watermark, read mark, files on either side of the floor, a sender still
// uploading and the quiet window, twice in a row as the pusher's passes do,
// and the revoke rule over first runs, repeats, stale and restored revokes,
// and answers each verdict as one JSON line.
func serverVerdictWalk(
	inbox func(inboxannounce.State, []inboxannounce.Link, time.Time) (inboxannounce.State, []inboxannounce.Announcement),
	pending func(inboxannounce.State, []inboxannounce.Link, time.Time) bool,
	revoke func(revokeannounce.State, []revokeannounce.Source, time.Time) (revokeannounce.State, []revokeannounce.Announcement),
) [][]byte {
	t0 := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	file := func(p, by string, s int) inboxannounce.File {
		return inboxannounce.File{Path: p, CommittedAt: at(s), UploadedBy: by}
	}
	fileSets := [][]inboxannounce.File{
		nil,
		{file("a", "S1", 0)},
		{file("a", "S1", 0), file("b", "S2", 10)},
		{file("a", "S1", 10), file("b", "S1", 10)},
		{file("a", "S1", 0), file("b", "S1", 9), file("c", "S2", 9)},
		{file("a", "S1", 20)},
	}
	states := []*inboxannounce.LinkState{
		nil,
		{},
		{Watermark: at(0)},
		{Watermark: at(10)},
		{Watermark: at(0), Announced: []string{"b"}},
		{Watermark: at(30)},
	}
	seens := []time.Time{{}, at(5), at(10), at(25)}
	incomings := [][]inboxannounce.Claim{nil, {{Name: "c", By: "S1"}}}
	nows := []time.Time{at(11), at(12), at(60)}
	var lines [][]byte
	record := func(v any) {
		b, err := json.Marshal(v)
		if err != nil {
			panic(err)
		}
		lines = append(lines, b)
	}
	for _, notify := range []bool{true, false} {
		for _, files := range fileSets {
			for _, prev := range states {
				for _, seen := range seens {
					for _, inc := range incomings {
						l := inboxannounce.Link{ID: "L1", Name: "share", Notify: notify, SeenAt: seen, Files: files, Incoming: inc}
						for _, now := range nows {
							st := inboxannounce.State{Links: map[string]inboxannounce.LinkState{}}
							if prev != nil {
								st.Links["L1"] = *prev
							}
							next, out := inbox(st, []inboxannounce.Link{l}, now)
							again, more := inbox(next, []inboxannounce.Link{l}, now.Add(time.Minute))
							record([]any{next, out, pending(next, []inboxannounce.Link{l}, now), again, more,
								pending(again, []inboxannounce.Link{l}, now.Add(time.Minute))})
						}
					}
				}
			}
		}
	}
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	two := 2
	sources := [][]revokeannounce.Source{
		nil,
		{{ShareID: "d1", ShareName: "Wedding", Source: "photo/2024", At: now.Add(-time.Hour), Files: &two},
			{ShareID: "d2", ShareName: "Trip", Source: "photo/2024", At: now.Add(-time.Hour)},
			{ShareID: "d3", ShareName: "Old", Source: "video", At: now.Add(-25 * time.Hour)}},
		{{ShareID: "d1", ShareName: "Old", Source: "photo", At: now.Add(-revokeannounce.ReplayWindow - time.Hour)},
			{ShareID: "d2", ShareName: "New", Source: "photo", At: now.Add(-time.Minute)}},
	}
	for _, first := range sources {
		for _, second := range sources {
			st, out := revoke(revokeannounce.State{}, first, now)
			again, more := revoke(st, second, now.Add(time.Minute))
			record([]any{st, out, again, more})
		}
	}
	return lines
}

func digestOf(lines [][]byte) string {
	h := sha256.New()
	for _, l := range lines {
		h.Write(l)
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// The server's push decisions do not depend on presence: it passes
// inboxannounce and revokeannounce a presence that is always unknown, which
// leaves their verdict to serverActivity alone, and the digest pins every
// verdict the walk records.
func TestTheServersEvaluateIsUnchanged(t *testing.T) {
	lines := serverVerdictWalk(
		func(st inboxannounce.State, links []inboxannounce.Link, now time.Time) (inboxannounce.State, []inboxannounce.Announcement) {
			return inboxannounce.Evaluate(st, links, serverActivity, now, serverPresence)
		},
		func(st inboxannounce.State, links []inboxannounce.Link, now time.Time) bool {
			return inboxannounce.Pending(st, links, serverActivity, now, serverPresence)
		},
		func(st revokeannounce.State, revoked []revokeannounce.Source, now time.Time) (revokeannounce.State, []revokeannounce.Announcement) {
			return revokeannounce.Evaluate(st, revoked, serverActivity, now, serverPresence)
		},
	)
	for _, at := range []time.Time{{}, time.Now()} {
		if p := serverPresence(at); p != inboxannounce.PresenceUnknown {
			t.Fatalf("the server's presence answers %v, want unknown", p)
		}
	}
	if got := digestOf(lines); got != serverVerdictDigest {
		t.Fatalf("the server's verdicts digest to %s over %d verdicts, want %s", got, len(lines), serverVerdictDigest)
	}
}
