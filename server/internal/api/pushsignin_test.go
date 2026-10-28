package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"hyperdrop/core/signinannounce"
	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/pushrelay"
)

// settle waits for every delivery sendSoon started.
func (p *pusher) settle() { p.sends.Wait() }

// signedInComputer mints alice a computer her phone (the rig's token)
// approved, and answers the account, the computer's raw token and the
// sign-in as the poll handler announces it.
func (r *pushRig) signedInComputer(label string) (metadb.User, string, signinannounce.SignIn) {
	r.t.Helper()
	u, err := r.hd.db.User("alice")
	if err != nil {
		r.t.Fatal(err)
	}
	approver := tokenNamed(u, metadb.TokenHash(r.tok))
	u, raw, err := r.hd.db.MintDesktopSignIn("alice", approver.ID, desktopSignInLabelPrefix+label, "windows", "m", time.Now())
	if err != nil {
		r.t.Fatal(err)
	}
	tok := tokenNamed(u, metadb.TokenHash(raw))
	return u, raw, signinannounce.SignIn{TokenID: tok.ID, Label: label, Platform: tok.ClientPlatform,
		ApprovedBy: tok.ApprovedByLabel, Username: u.Username, At: tok.CreatedAt}
}

func (r *pushRig) announce(u metadb.User, s signinannounce.SignIn) []pushrelay.Message {
	r.hd.announceDeviceSignedIn(u, s.TokenID, s)
	r.hd.push.settle()
	return r.relay.take()
}

// A planted computer's console activity cannot silence the alarm about
// itself: the push goes out while a computer of the account is in use.
func TestDeviceSignedInIgnoresQuiet(t *testing.T) {
	r := newPushRig(t)
	mac, err := r.hd.db.MintToken("alice", "mac")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.hd.db.UserByToken(mac, metadb.ClientInfo{Version: "1.0.1", Platform: "macos"}); err != nil {
		t.Fatal(err)
	}
	minuteAgo := time.Now().Add(-time.Minute)
	if err := r.hd.db.SetConsoleActivity(metadb.TokenHash(mac), &minuteAgo); err != nil {
		t.Fatal(err)
	}
	if !r.hd.push.quiet("alice") {
		t.Fatal("the rig's Mac does not quiet the account")
	}
	u, _, s := r.signedInComputer("Office PC")
	sent := r.announce(u, s)
	if len(sent) != 1 {
		t.Fatalf("sent %d while a computer of the account was in use, want 1", len(sent))
	}
	m := r.open(sent[0])
	title, body := signinannounce.Words(s)
	if m.Kind != pushKindDeviceSignedIn || m.Title != title || m.Body != body || m.Tag != "entry-1" ||
		m.TokenID != s.TokenID || m.Label != "Office PC" || m.Platform != "windows" || m.ApprovedBy != "test" ||
		m.Username != "alice" || m.At != s.At.UTC().Format(time.RFC3339) || m.Thread != "device-signed-in" || m.Ref != "" {
		t.Fatalf("message %+v", m)
	}
	if m.Body != `"Office PC" (Windows) signed in to alice, approved by test. If this wasn't you, sign it out.` {
		t.Fatalf("body %q", m.Body)
	}
	if sent[0].CollapseID == "" || sent[0].CollapseID == "si-"+s.TokenID {
		t.Fatalf("collapse %q: present, and never the token id in the clear", sent[0].CollapseID)
	}
}

// Every other registered device of the account hears about the computer;
// the computer itself, registered or not, does not.
func TestDeviceSignedInSkipsTheNewComputer(t *testing.T) {
	r := newPushRig(t)
	tablet, err := r.hd.db.MintToken("alice", "tablet")
	if err != nil {
		t.Fatal(err)
	}
	r.register(tablet, "entry-2")
	u, raw, s := r.signedInComputer("Office PC")
	r.register(raw, "entry-3")
	sent := r.announce(u, s)
	var tags []string
	for _, m := range sent {
		tags = append(tags, r.open(m).Tag)
	}
	slices.Sort(tags)
	if !slices.Equal(tags, []string{"entry-1", "entry-2"}) {
		t.Fatalf("sent to %v, want the phone and the tablet and never the new computer", tags)
	}
}

// The announcement is recorded before it is sent: nothing goes out while
// the record cannot be written, and a sign-in recorded once is never sent
// again.
func TestDeviceSignedInIsRecordedBeforeItIsSent(t *testing.T) {
	r := newPushRig(t)
	u, _, s := r.signedInComputer("Office PC")
	write := r.hd.push.setState
	r.hd.push.setState = func(owner, kind, value string) error {
		if kind == pushStateSignIn {
			return errInjected
		}
		return write(owner, kind, value)
	}
	if sent := r.announce(u, s); len(sent) != 0 {
		t.Fatalf("sent %d with no record", len(sent))
	}
	r.hd.push.setState = write
	u2, _, s2 := r.signedInComputer("Laptop")
	if sent := r.announce(u2, s2); len(sent) != 1 || r.open(sent[0]).TokenID != s2.TokenID {
		t.Fatalf("once recorded: %d", len(sent))
	}
	if sent := r.announce(u2, s2); len(sent) != 0 {
		t.Fatal("one sign-in pushed twice")
	}
}

// A poll answered while the server drains finds the pusher stopped: the
// sign-in is recorded as owed, not as announced, and the next pusher sends
// it once.
func TestASignInDuringShutdownIsSentByTheNextPusher(t *testing.T) {
	r := newPushRig(t)
	u, _, s := r.signedInComputer("Office PC")
	r.hd.push.stop()
	if sent := r.announce(u, s); len(sent) != 0 {
		t.Fatalf("a stopped pusher sent %d", len(sent))
	}
	next := r.restart()
	next.start()
	next.settle()
	next.stop()
	sent := r.relay.take()
	if len(sent) != 1 || r.open(sent[0]).TokenID != s.TokenID {
		t.Fatalf("the next pusher sent %d, want the owed sign-in once", len(sent))
	}
	again := r.restart()
	again.start()
	again.settle()
	again.stop()
	if sent := r.relay.take(); len(sent) != 0 {
		t.Fatalf("a sign-in the relay took was sent again by a later pusher: %d", len(sent))
	}
}

// stalledRelay holds every send until its context ends, as a relay that
// has not answered yet when the server drains.
type stalledRelay struct{ entered chan struct{} }

func (s stalledRelay) Send(ctx context.Context, _ pushrelay.Message) error {
	s.entered <- struct{}{}
	<-ctx.Done()
	return ctx.Err()
}

// A send the drain cancels before the relay answered leaves the sign-in
// owed, and the next pusher sends it.
func TestASignInSendCancelledByShutdownIsSentByTheNextPusher(t *testing.T) {
	r := newPushRig(t)
	u, _, s := r.signedInComputer("Office PC")
	stalled := stalledRelay{entered: make(chan struct{}, 1)}
	r.hd.push.relay = stalled
	r.hd.announceDeviceSignedIn(u, s.TokenID, s)
	<-stalled.entered
	r.hd.push.stop()
	next := r.restart()
	next.start()
	next.settle()
	next.stop()
	if sent := r.relay.take(); len(sent) != 1 || r.open(sent[0]).TokenID != s.TokenID {
		t.Fatalf("the next pusher sent %d, want the cancelled sign-in once", len(sent))
	}
}

// A computer signed out before its owed alarm went out is no alarm: the
// next pusher sends nothing for it and forgets it.
func TestOwedSignInForARevokedTokenIsDroppedUnsent(t *testing.T) {
	r := newPushRig(t)
	u, _, s := r.signedInComputer("Office PC")
	r.hd.push.stop()
	if sent := r.announce(u, s); len(sent) != 0 {
		t.Fatalf("a stopped pusher sent %d", len(sent))
	}
	if m, _ := r.hd.push.loadSignIns("alice"); len(m.Owed) != 1 {
		t.Fatalf("owed %+v, want the sign-in", m.Owed)
	}
	if err := r.hd.db.RevokeToken("alice", s.TokenID); err != nil {
		t.Fatal(err)
	}
	next := r.restart()
	next.resumeSignIns()
	next.settle()
	if sent := r.relay.take(); len(sent) != 0 {
		t.Fatalf("sent %d about a computer already signed out", len(sent))
	}
	if m, _ := next.loadSignIns("alice"); len(m.Owed) != 0 {
		t.Fatalf("still owed after resume: %+v", m.Owed)
	}
}

// A sign-in whose computer cannot be looked up (a database error) is
// neither sent nor dropped: it stays owed, and goes out once the lookup
// answers that the computer is still signed in.
func TestOwedSignInStaysOwedWhenItsTokenCannotBeLookedUp(t *testing.T) {
	r := newPushRig(t)
	u, _, s := r.signedInComputer("Office PC")
	r.hd.push.stop()
	r.announce(u, s)
	next := r.restart()
	next.tokenLive = func(string, string, time.Time) (string, bool, error) {
		return "", false, errors.New("database is locked")
	}
	next.resumeSignIns()
	next.settle()
	if sent := r.relay.take(); len(sent) != 0 {
		t.Fatalf("sent %d about a computer that could not be looked up", len(sent))
	}
	if m, _ := next.loadSignIns("alice"); len(m.Owed) != 1 || m.Owed[0].TokenID != s.TokenID {
		t.Fatalf("owed after a failed lookup: %+v, want the sign-in", m.Owed)
	}
	next.tokenLive = r.hd.db.TokenLive
	next.resumeSignIns()
	next.settle()
	if sent := r.relay.take(); len(sent) != 1 {
		t.Fatalf("sent %d once the lookup answered, want 1", len(sent))
	}
}

// A relay that refuses the message for the device (a 4xx) has answered
// about it: the sign-in counts as announced and is never sent again.
func TestASignInTheRelayRefusedIsNotSentAgain(t *testing.T) {
	r := newPushRig(t)
	r.relay.answer = func(pushrelay.Message) error { return &pushrelay.Error{Status: 400, Code: "bad-handle"} }
	u, _, s := r.signedInComputer("Office PC")
	if sent := r.announce(u, s); len(sent) != 1 {
		t.Fatalf("sent %d", len(sent))
	}
	r.relay.answer = nil
	r.ahead += signInRetryMost
	if sent := r.sweep(); len(sent) != 0 {
		t.Fatalf("the sweep sent a refused sign-in again: %d", len(sent))
	}
	next := r.restart()
	next.start()
	next.settle()
	next.stop()
	if sent := r.relay.take(); len(sent) != 0 {
		t.Fatalf("a refused sign-in was sent again: %d", len(sent))
	}
}

// sweep runs the pusher's slow pass and answers what it sent.
func (r *pushRig) sweep() []pushrelay.Message {
	r.hd.push.sweep(context.Background())
	r.hd.push.settle()
	return r.relay.take()
}

// A send the relay did not answer about the device (a 5xx, a transport
// error) leaves the sign-in owed: the sweep sends it again once the wait
// after the failure has passed, and once the relay answers, never again.
func TestASignInTheRelayDidNotAnswerIsSentAgainOnTheSweep(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"503", &pushrelay.Error{Status: 503, Code: "relay-unavailable"}},
		{"dial failure", fmt.Errorf("pushrelay: %w", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newPushRig(t)
			r.relay.answer = func(pushrelay.Message) error { return tc.err }
			u, _, s := r.signedInComputer("Office PC")
			if sent := r.announce(u, s); len(sent) != 1 {
				t.Fatalf("sent %d", len(sent))
			}
			r.relay.answer = nil
			if sent := r.sweep(); len(sent) != 0 {
				t.Fatalf("the sweep sent %d before the wait passed", len(sent))
			}
			r.ahead += signInRetryFirst
			sent := r.sweep()
			if len(sent) != 1 || r.open(sent[0]).TokenID != s.TokenID {
				t.Fatalf("the sweep after the wait sent %d, want the owed sign-in once", len(sent))
			}
			r.ahead += signInRetryMost
			if sent := r.sweep(); len(sent) != 0 {
				t.Fatalf("a sign-in the relay took was sent again: %d", len(sent))
			}
		})
	}
}

// Each send that leaves a device unanswered waits longer before the next,
// up to signInRetryMost, and the sign-in is never sent past
// signinannounce.Window.
func TestOwedSignInsBackOffWithinTheWindow(t *testing.T) {
	if got := []time.Duration{signInRetryAfter(1), signInRetryAfter(2), signInRetryAfter(3), signInRetryAfter(30)}; !slices.Equal(got,
		[]time.Duration{signInRetryFirst, 2 * signInRetryFirst, 4 * signInRetryFirst, signInRetryMost}) {
		t.Fatalf("waits %v", got)
	}
	r := newPushRig(t)
	r.relay.answer = func(pushrelay.Message) error { return &pushrelay.Error{Status: 503} }
	u, _, s := r.signedInComputer("Office PC")
	r.announce(u, s)
	r.ahead += signInRetryFirst
	if sent := r.sweep(); len(sent) != 1 {
		t.Fatalf("second try sent %d", len(sent))
	}
	r.ahead += signInRetryFirst
	if sent := r.sweep(); len(sent) != 0 {
		t.Fatalf("the third try came %v after the second, before its doubled wait", signInRetryFirst)
	}
	r.ahead += signInRetryFirst
	if sent := r.sweep(); len(sent) != 1 {
		t.Fatalf("third try sent %d", len(sent))
	}
	r.ahead += signinannounce.Window
	if sent := r.sweep(); len(sent) != 0 {
		t.Fatalf("a sign-in past the window was sent: %d", len(sent))
	}
	m, _ := r.hd.push.loadSignIns("alice")
	if len(m.Owed) != 0 {
		t.Fatalf("a sign-in past the window is still owed: %+v", m.Owed)
	}
}

// A retry goes only to the devices the relay did not answer about.
func TestASignInRetryGoesOnlyToTheUnansweredDevices(t *testing.T) {
	r := newPushRig(t)
	tablet, err := r.hd.db.MintToken("alice", "tablet")
	if err != nil {
		t.Fatal(err)
	}
	r.register(tablet, "entry-2")
	r.relay.answer = func(m pushrelay.Message) error {
		if m.Handle == strings.Repeat("2", 32) {
			return &pushrelay.Error{Status: 503}
		}
		return nil
	}
	u, _, s := r.signedInComputer("Office PC")
	if sent := r.announce(u, s); len(sent) != 2 {
		t.Fatalf("first send reached %d devices, want 2", len(sent))
	}
	r.relay.answer = nil
	r.ahead += signInRetryFirst
	sent := r.sweep()
	if len(sent) != 1 || r.open(sent[0]).Tag != "entry-2" {
		t.Fatalf("the retry sent %d, want the tablet alone", len(sent))
	}
}

// A device the relay calls gone has been answered about: the sign-in is
// announced, the handle dropped, and nothing is sent again.
func TestASignInToAGoneDeviceIsFinished(t *testing.T) {
	r := newPushRig(t)
	r.relay.answer = func(pushrelay.Message) error { return pushrelay.ErrGone }
	u, _, s := r.signedInComputer("Office PC")
	if sent := r.announce(u, s); len(sent) != 1 {
		t.Fatalf("sent %d", len(sent))
	}
	m, _ := r.hd.push.loadSignIns("alice")
	if len(m.Owed) != 0 || !slices.Contains(m.Announced, s.TokenID) {
		t.Fatalf("memory %+v, want the sign-in announced", m)
	}
	if targets, _ := r.hd.db.PushTargets("alice"); len(targets) != 0 {
		t.Fatalf("the gone device is still registered: %d", len(targets))
	}
	r.relay.answer = nil
	r.register(r.tok, "entry-1")
	r.ahead += signInRetryMost
	if sent := r.sweep(); len(sent) != 0 {
		t.Fatalf("a sign-in to a gone device was sent again: %d", len(sent))
	}
}

// A device mutes only the kinds metadb.PushKinds lists; deviceSignedIn is
// never one of them, so no registration can turn it off.
func TestDeviceSignedInCannotBeMuted(t *testing.T) {
	if slices.Contains(metadb.PushKinds, pushKindDeviceSignedIn) {
		t.Fatal("deviceSignedIn is a kind a device may mute")
	}
	h, _ := pushAPI(t)
	_, key := phoneKey(t)
	rec := doReq(t, h, "PUT", "/api/me/push", testToken, pushBody(testRelay, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", key, "entry-1", pushKindDeviceSignedIn))
	if rec.Code != 400 {
		t.Fatalf("muting deviceSignedIn: %d %s, want 400", rec.Code, rec.Body)
	}
}

// The computer's poll that collects its token announces the sign-in to the
// account's other devices.
func TestTheDesktopPollAnnouncesTheSignIn(t *testing.T) {
	r := newPushRig(t)
	f := webFixture{h: r.hd.routes(), hd: r.hd, db: r.hd.db, aliceDevice: r.tok}
	s := approvedDesktop(t, f)
	rec, out := pollDesktop(t, f, s)
	if rec.Code != 200 || out.Token == "" {
		t.Fatalf("poll: %d %s", rec.Code, rec.Body)
	}
	r.hd.push.settle()
	sent := r.relay.take()
	if len(sent) != 1 {
		t.Fatalf("sent %d, want 1", len(sent))
	}
	u, err := r.hd.db.User("alice")
	if err != nil {
		t.Fatal(err)
	}
	computer := tokenNamed(u, metadb.TokenHash(out.Token))
	m := r.open(sent[0])
	if m.Kind != pushKindDeviceSignedIn || m.TokenID != computer.ID || m.Label != "Work Mac" || m.Platform != "macos" ||
		m.Body != `"Work Mac" (macOS) signed in to alice, approved by test. If this wasn't you, sign it out.` {
		t.Fatalf("message %+v", m)
	}
}

// With push off the poll still signs the computer in.
func TestTheDesktopPollSignsInWithPushOff(t *testing.T) {
	f := newWebFixture(t, false)
	if f.hd.push != nil {
		t.Fatal("the web fixture has push on")
	}
	if rec, out := pollDesktop(t, f, approvedDesktop(t, f)); rec.Code != 200 || out.Token == "" {
		t.Fatalf("poll: %d %s", rec.Code, rec.Body)
	}
}
