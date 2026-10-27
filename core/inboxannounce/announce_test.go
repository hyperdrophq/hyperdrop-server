package inboxannounce

import (
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)

func active() Activity { return Activity{OnConsole: true, Idle: time.Second} }

func link(files []File, incoming []Claim) Link {
	return Link{ID: "L1", Name: "share", Notify: true, Files: files, Incoming: incoming}
}

// known marks links this device has already met. Evaluate settles a link it
// is seeing for the first time without announcing, so a test that wants an
// announcement has to have met the link, exactly as a running client has.
func known(ids ...string) State {
	st := State{Links: map[string]LinkState{}}
	for _, id := range ids {
		st.Links[id] = LinkState{}
	}
	return st
}

func file(path, by string, at time.Time) File {
	return File{Path: path, CommittedAt: at, UploadedBy: by}
}

// One sender, one file, quiet: one announcement naming it.
func TestOneSenderOneFile(t *testing.T) {
	l := link([]File{file("a.txt", "S1", t0)}, nil)
	_, out := Evaluate(known("L1"), []Link{l}, active(), t0.Add(5*time.Second))
	if len(out) != 1 || out[0].Count != 1 || out[0].Sender != "S1" || out[0].LinkID != "L1" {
		t.Fatalf("out = %+v", out)
	}
	if len(out[0].Files) != 1 || out[0].Files[0] != "a.txt" {
		t.Fatalf("files = %+v", out[0].Files)
	}
	if out[0].LinkName != "share" {
		t.Fatalf("link name = %q", out[0].LinkName)
	}
}

// Announced once, never again: the state carries what was said.
func TestAnnouncedOnce(t *testing.T) {
	l := link([]File{file("a.txt", "S1", t0)}, nil)
	st, out := Evaluate(known("L1"), []Link{l}, active(), t0.Add(5*time.Second))
	if len(out) != 1 {
		t.Fatalf("first pass = %+v", out)
	}
	if _, out = Evaluate(st, []Link{l}, active(), t0.Add(10*time.Second)); len(out) != 0 {
		t.Fatalf("second pass announced again: %+v", out)
	}
}

// The sender is still uploading: nothing is announced yet, however long the
// files already committed have been sitting there.
func TestSenderStillUploadingIsNotAnnounced(t *testing.T) {
	l := link([]File{file("a.txt", "S1", t0)}, []Claim{{Name: "b.txt", By: "S1"}})
	if _, out := Evaluate(known("L1"), []Link{l}, active(), t0.Add(time.Hour)); len(out) != 0 {
		t.Fatalf("announced mid-delivery: %+v", out)
	}
}

// The gap between two files of one delivery is a round trip, not a pause.
func TestQuietWindowNotElapsed(t *testing.T) {
	l := link([]File{file("a.txt", "S1", t0)}, nil)
	if _, out := Evaluate(known("L1"), []Link{l}, active(), t0.Add(time.Second)); len(out) != 0 {
		t.Fatalf("announced inside the quiet window: %+v", out)
	}
}

// One sender's whole delivery is ONE announcement, not one per file.
func TestOneSenderManyFilesIsOneAnnouncement(t *testing.T) {
	l := link([]File{
		file("a.txt", "S1", t0),
		file("b.txt", "S1", t0.Add(time.Second)),
		file("c.txt", "S1", t0.Add(2*time.Second)),
	}, nil)
	_, out := Evaluate(known("L1"), []Link{l}, active(), t0.Add(10*time.Second))
	if len(out) != 1 || out[0].Count != 3 {
		t.Fatalf("out = %+v", out)
	}
}

// Two senders are two announcements: that is the whole point of the token.
func TestTwoSendersAreTwoAnnouncements(t *testing.T) {
	l := link([]File{
		file("a.txt", "S1", t0),
		file("b.txt", "S2", t0.Add(time.Second)),
	}, nil)
	_, out := Evaluate(known("L1"), []Link{l}, active(), t0.Add(10*time.Second))
	if len(out) != 2 {
		t.Fatalf("out = %+v", out)
	}
}

// The interleaving trap: S1's newer file is announced while S2 is still
// uploading an OLDER one. The watermark must not swallow S2's file.
func TestAnOlderSenderStillUploadingIsNotSwallowed(t *testing.T) {
	early, late := t0, t0.Add(10*time.Second)
	l := link([]File{file("slow.txt", "S2", early), file("fast.txt", "S1", late)},
		[]Claim{{Name: "slow2.txt", By: "S2"}})
	st, out := Evaluate(known("L1"), []Link{l}, active(), late.Add(5*time.Second))
	if len(out) != 1 || out[0].Sender != "S1" {
		t.Fatalf("first pass = %+v", out)
	}
	// S2 finishes: its earlier file must still be announced, and S1's must
	// not repeat.
	l.Incoming = nil
	l.Files = append(l.Files, file("slow2.txt", "S2", late.Add(time.Second)))
	_, out = Evaluate(st, []Link{l}, active(), late.Add(30*time.Second))
	if len(out) != 1 || out[0].Sender != "S2" || out[0].Count != 2 {
		t.Fatalf("second pass = %+v", out)
	}
}

// Files committed in the same second, one settled and one not, must not let
// the watermark swallow the unsettled one. CommittedAt is truncated to the
// second server-side, so ties are ordinary, not exotic.
func TestTiedTimestampsDoNotSwallow(t *testing.T) {
	l := link([]File{file("a.txt", "S1", t0), file("b.txt", "S2", t0)},
		[]Claim{{Name: "b2.txt", By: "S2"}})
	st, out := Evaluate(known("L1"), []Link{l}, active(), t0.Add(10*time.Second))
	if len(out) != 1 || out[0].Sender != "S1" {
		t.Fatalf("first pass = %+v", out)
	}
	l.Incoming = nil
	_, out = Evaluate(st, []Link{l}, active(), t0.Add(20*time.Second))
	if len(out) != 1 || out[0].Sender != "S2" || out[0].Files[0] != "b.txt" {
		t.Fatalf("second pass = %+v", out)
	}
}

// Away from the Mac: hold, do not post. Everything that landed meanwhile is
// one announcement when the owner returns.
func TestHeldWhileIdleThenAnnouncedOnReturn(t *testing.T) {
	l := link([]File{file("a.txt", "S1", t0)}, nil)
	idle := Activity{OnConsole: true, Idle: time.Hour}
	st, out := Evaluate(known("L1"), []Link{l}, idle, t0.Add(10*time.Second))
	if len(out) != 0 {
		t.Fatalf("announced while away: %+v", out)
	}
	l.Files = append(l.Files, file("b.txt", "S1", t0.Add(time.Minute)))
	_, out = Evaluate(st, []Link{l}, active(), t0.Add(2*time.Minute))
	if len(out) != 1 || out[0].Count != 2 {
		t.Fatalf("on return = %+v", out)
	}
}

// A locked or fast-user-switched session is not the Mac the owner is at.
func TestOffConsoleHolds(t *testing.T) {
	l := link([]File{file("a.txt", "S1", t0)}, nil)
	_, out := Evaluate(known("L1"), []Link{l}, Activity{OnConsole: false}, t0.Add(10*time.Second))
	if len(out) != 0 {
		t.Fatalf("announced off console: %+v", out)
	}
}

// Read on another device: the shared watermark silences this one, which is
// what stops a second Mac telling you about files you already looked at.
func TestSeenElsewhereIsNeverAnnounced(t *testing.T) {
	l := link([]File{file("a.txt", "S1", t0)}, nil)
	l.SeenAt = t0.Add(time.Minute)
	_, out := Evaluate(known("L1"), []Link{l}, active(), t0.Add(2*time.Minute))
	if len(out) != 0 {
		t.Fatalf("announced what was already read: %+v", out)
	}
}

// A held announcement that the owner reads elsewhere is dropped, not posted
// late: that is the cross-device dismissal the shared watermark buys.
func TestHeldThenSeenElsewhereIsDropped(t *testing.T) {
	l := link([]File{file("a.txt", "S1", t0)}, nil)
	st, out := Evaluate(known("L1"), []Link{l}, Activity{OnConsole: true, Idle: time.Hour},
		t0.Add(10*time.Second))
	if len(out) != 0 {
		t.Fatalf("announced while away: %+v", out)
	}
	l.SeenAt = t0.Add(time.Minute)
	if _, out = Evaluate(st, []Link{l}, active(), t0.Add(2*time.Minute)); len(out) != 0 {
		t.Fatalf("posted a banner for what was read elsewhere: %+v", out)
	}
}

// Muted means muted, and unmuting later must not replay history.
func TestMutedLinkNeverAnnounces(t *testing.T) {
	l := link([]File{file("a.txt", "S1", t0)}, nil)
	l.Notify = false
	st, out := Evaluate(known("L1"), []Link{l}, active(), t0.Add(10*time.Second))
	if len(out) != 0 {
		t.Fatalf("muted link announced: %+v", out)
	}
	l.Notify = true
	if _, out = Evaluate(st, []Link{l}, active(), t0.Add(20*time.Second)); len(out) != 0 {
		t.Fatalf("unmuting replayed history: %+v", out)
	}
}

// A sender with no cookie is one group, not one group per file: a curl user
// uploading three files is told about once.
func TestCookielessSendersGroupTogether(t *testing.T) {
	l := link([]File{file("a.txt", "", t0), file("b.txt", "", t0.Add(time.Second))}, nil)
	_, out := Evaluate(known("L1"), []Link{l}, active(), t0.Add(10*time.Second))
	if len(out) != 1 || out[0].Count != 2 || out[0].Sender != "" {
		t.Fatalf("out = %+v", out)
	}
}

// A file with no commit time has not landed; it is not announceable.
func TestUncommittedFilesAreIgnored(t *testing.T) {
	l := link([]File{{Path: "a.txt", UploadedBy: "S1"}}, nil)
	if _, out := Evaluate(known("L1"), []Link{l}, active(), t0.Add(time.Hour)); len(out) != 0 {
		t.Fatalf("announced an uncommitted file: %+v", out)
	}
}

// Several links each announce their own, and a link's state is its own.
func TestLinksAreIndependent(t *testing.T) {
	a := Link{ID: "A", Name: "one", Notify: true, Files: []File{file("a.txt", "S1", t0)}}
	b := Link{ID: "B", Name: "two", Notify: true, Files: []File{file("b.txt", "S1", t0)}}
	st, out := Evaluate(known("A", "B"), []Link{a, b}, active(), t0.Add(10*time.Second))
	if len(out) != 2 {
		t.Fatalf("out = %+v", out)
	}
	if len(st.Links) != 2 {
		t.Fatalf("state = %+v", st.Links)
	}
}

// The settled prefix collapses into the watermark rather than growing a list
// forever: a link that has received a thousand files carries no per-file
// state once they are all announced.
func TestSettledStateCollapsesIntoTheWatermark(t *testing.T) {
	var files []File
	for i := range 50 {
		files = append(files, file(string(rune('a'+i))+".txt", "S1", t0.Add(time.Duration(i)*time.Second)))
	}
	l := link(files, nil)
	st, out := Evaluate(known("L1"), []Link{l}, active(), t0.Add(time.Hour))
	if len(out) != 1 || out[0].Count != 50 {
		t.Fatalf("out = %+v", out)
	}
	if got := st.Links["L1"]; len(got.Announced) != 0 || !got.Watermark.Equal(t0.Add(49*time.Second)) {
		t.Fatalf("state = %+v, want an empty list and the newest instant", got)
	}
}

// Nothing waiting means the client has no reason to look at the clock, which
// is what keeps an idle account from doing periodic work forever.
func TestPendingIsFalseWithNothingWaiting(t *testing.T) {
	if Pending(State{}, nil, active()) {
		t.Fatal("pending with no links")
	}
	l := link([]File{file("a.txt", "S1", t0)}, nil)
	st, out := Evaluate(known("L1"), []Link{l}, active(), t0.Add(10*time.Second))
	if len(out) != 1 {
		t.Fatalf("out = %+v", out)
	}
	if Pending(st, []Link{l}, active()) {
		t.Fatal("pending after everything was announced")
	}
}

// A delivery inside its quiet window, and one held because nobody is here, are
// both reasons to keep ticking.
func TestPendingWhileWaiting(t *testing.T) {
	l := link([]File{file("a.txt", "S1", t0)}, nil)
	if !Pending(known("L1"), []Link{l}, active()) {
		t.Fatal("not pending with an unannounced file")
	}
	st, _ := Evaluate(known("L1"), []Link{l}, Activity{OnConsole: true, Idle: time.Hour},
		t0.Add(10*time.Second))
	if !Pending(st, []Link{l}, active()) {
		t.Fatal("not pending while held")
	}
}

// A muted link is never waiting for anything.
func TestPendingIgnoresMutedLinks(t *testing.T) {
	l := link([]File{file("a.txt", "S1", t0)}, nil)
	l.Notify = false
	if Pending(known("L1"), []Link{l}, active()) {
		t.Fatal("a muted link reported as pending")
	}
}

// A device meeting a link for the first time settles it silently. Otherwise a
// fresh install, an upgrade, or a dropped replica opens with a banner for
// every delivery the link has ever received.
func TestFirstEncounterAnnouncesNothing(t *testing.T) {
	l := link([]File{file("old1.txt", "S1", t0), file("old2.txt", "S2", t0)}, nil)
	st, out := Evaluate(State{}, []Link{l}, active(), t0.Add(time.Hour))
	if len(out) != 0 {
		t.Fatalf("announced history on first sight: %+v", out)
	}
	// And the future still announces.
	l.Files = append(l.Files, file("new.txt", "S3", t0.Add(2*time.Hour)))
	_, out = Evaluate(st, []Link{l}, active(), t0.Add(3*time.Hour))
	if len(out) != 1 || out[0].Files[0] != "new.txt" {
		t.Fatalf("second pass = %+v, want only the new file", out)
	}
}

// A link created while this device is watching is settled empty on the pass
// that first sees it, so its first real arrival is still announced.
func TestNewLinkStillAnnouncesItsFirstDelivery(t *testing.T) {
	empty := link(nil, nil)
	st, out := Evaluate(State{}, []Link{empty}, active(), t0)
	if len(out) != 0 {
		t.Fatalf("an empty new link announced: %+v", out)
	}
	filled := link([]File{file("a.txt", "S1", t0.Add(time.Minute))}, nil)
	_, out = Evaluate(st, []Link{filled}, active(), t0.Add(2*time.Minute))
	if len(out) != 1 || out[0].Count != 1 {
		t.Fatalf("first delivery = %+v, want one announcement", out)
	}
}

// summaryOf is what a client's index holds of l.
func summaryOf(l Link) Summary {
	return Summary{ID: l.ID, Notify: l.Notify, SeenAt: l.SeenAt, Newest: newest(l.Files)}
}

// Whenever Settle decides a link from its summary, Evaluate over the whole
// link agrees exactly: the same state, no announcement, and nothing Pending.
// Walked over every combination of mute, first meeting, read watermark,
// announced paths, files on either side of the floor, a sender still
// uploading, the owner's presence and the quiet window.
func TestSettleAgreesWithEvaluate(t *testing.T) {
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	fileSets := [][]File{
		nil,
		{file("a", "S1", at(0))},
		{file("a", "S1", at(0)), file("b", "S2", at(10))},
		{file("a", "S1", at(10)), file("b", "S1", at(10))},
		{file("a", "S1", at(20))},
	}
	states := []*LinkState{
		nil,
		{},
		{Watermark: at(0)},
		{Watermark: at(10)},
		{Watermark: at(0), Announced: []string{"b"}},
		{Watermark: at(30)},
	}
	seens := []time.Time{{}, at(5), at(10), at(25)}
	incomings := [][]Claim{nil, {{Name: "c", By: "S1"}}}
	acts := []Activity{active(), {OnConsole: true, Idle: time.Hour}}
	nows := []time.Time{at(11), at(60)}
	decided, weighed := 0, 0
	for _, notify := range []bool{true, false} {
		for _, files := range fileSets {
			for _, prev := range states {
				for _, seen := range seens {
					for _, inc := range incomings {
						l := Link{ID: "L1", Name: "share", Notify: notify, SeenAt: seen, Files: files, Incoming: inc}
						st := State{Links: map[string]LinkState{}}
						if prev != nil {
							st.Links["L1"] = *prev
						}
						got, ok := Settle(st, summaryOf(l))
						if !ok {
							weighed++
							continue
						}
						decided++
						for _, act := range acts {
							for _, now := range nows {
								next, out := Evaluate(st, []Link{l}, act, now)
								want := next.Links["L1"]
								if len(out) != 0 || !want.Watermark.Equal(got.Watermark) ||
									len(want.Announced) != 0 || len(got.Announced) != 0 {
									t.Fatalf("link %+v state %+v: Settle = %+v, Evaluate = %+v announcing %+v",
										l, prev, got, want, out)
								}
								if Pending(next, []Link{l}, act) {
									t.Fatalf("link %+v state %+v: settled yet Pending", l, prev)
								}
							}
						}
					}
				}
			}
		}
	}
	if decided == 0 || weighed == 0 {
		t.Fatalf("decided %d, weighed %d: the walk must cover both answers", decided, weighed)
	}
}

// A link with an arrival after its floor is never settled from its summary,
// whatever the watermark or read mark says below it.
func TestSettleWeighsAnArrivalAfterTheFloor(t *testing.T) {
	st := State{Links: map[string]LinkState{"L1": {Watermark: t0}}}
	s := Summary{ID: "L1", Notify: true, SeenAt: t0.Add(time.Second), Newest: t0.Add(2 * time.Second)}
	if _, ok := Settle(st, s); ok {
		t.Fatal("an arrival after the floor was settled unread")
	}
}

func TestAKeyNamesOneDeliveryAndFitsACollapseID(t *testing.T) {
	a := Announcement{LinkID: "Ab3dE5gH9k", Sender: "hdv-1", Files: []string{"a.pdf", "b.pdf"}, Count: 2}
	k := a.Key()
	if !strings.HasPrefix(k, "in-") || len(k) != 27 || strings.Contains(k, "Ab3dE5gH9k") {
		t.Fatalf("key %q: want in- and 24 hex, never the inbox's id", k)
	}
	for _, c := range k {
		if !(c == '-' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			t.Fatalf("key %q holds %q", k, c)
		}
	}
	same := Announcement{LinkID: "Ab3dE5gH9k", Sender: "hdv-1", Files: []string{"a.pdf"}, Count: 1}
	if same.Key() != k {
		t.Fatal("the key depends on more than the inbox, the sender and the first file")
	}
	other := Announcement{LinkID: "Ab3dE5gH9k", Sender: "hdv-2", Files: []string{"a.pdf"}}
	if other.Key() == k {
		t.Fatal("two senders share a key")
	}
	elsewhere := Announcement{LinkID: "Zz3dE5gH9k", Sender: "hdv-1", Files: []string{"a.pdf"}}
	if elsewhere.Key() == k {
		t.Fatal("two inboxes share a key")
	}
	if (Announcement{LinkID: "Ab3dE5gH9k"}).Key() == (Announcement{LinkID: "Zz3dE5gH9k"}).Key() {
		t.Fatal("two inboxes' keys without files agree")
	}
}
