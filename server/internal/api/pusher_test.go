package api

import (
	"context"
	"crypto/ecdh"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"hyperdrop/core/inboxannounce"
	"hyperdrop/core/pushseal"
	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/pushrelay"
)

// fakeRelay records every send and answers what answer says (nil = 200).
type fakeRelay struct {
	mu     sync.Mutex
	sent   []pushrelay.Message
	answer func(pushrelay.Message) error
}

func (f *fakeRelay) Send(_ context.Context, m pushrelay.Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, m)
	if f.answer != nil {
		return f.answer(m)
	}
	return nil
}

func (f *fakeRelay) take() []pushrelay.Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.sent
	f.sent = nil
	return out
}

// pushRig is a server with push on, alice with one registered phone, and a
// clock the test moves ahead of the real one (commits are stamped with the
// real time).
type pushRig struct {
	t      *testing.T
	hd     *handler
	relay  *fakeRelay
	phone  *ecdh.PrivateKey
	tok    string // alice's phone token
	ahead  time.Duration
	claims []inboxannounce.Claim
}

func newPushRig(t *testing.T) *pushRig {
	t.Helper()
	hd := newHandler(testBackend(t), "2.0.0", testDomain(t), nil, Deployment{PushRelay: testRelay})
	r := &pushRig{t: t, hd: hd, relay: &fakeRelay{}}
	r.adopt(hd.push)
	r.tok = seedUser(t, hd.db, "alice")
	r.phone, _ = phoneKey(t)
	r.register(r.tok, "entry-1")
	return r
}

// adopt points p at the rig's relay, clock and claims.
func (r *pushRig) adopt(p *pusher) {
	p.relay = r.relay
	p.now = func() time.Time { return time.Now().Add(r.ahead) }
	p.incoming = func(string) []inboxannounce.Claim { return r.claims }
}

// restart is a new pusher on the same volume, the way a new process starts
// one: it reads the heartbeat first.
func (r *pushRig) restart() *pusher {
	p := newPusher(r.hd.db, r.relay, testRelay)
	r.adopt(p)
	p.resume()
	return p
}

func (r *pushRig) register(tok, tag string, muted ...string) {
	r.t.Helper()
	if err := r.hd.db.SetPush(metadb.TokenHash(tok), metadb.PushRegistration{Relay: testRelay,
		Handle: strings.Repeat(tag[len(tag)-1:], 32), PublicKey: r.phone.PublicKey().Bytes(), Tag: tag, Muted: muted}); err != nil {
		r.t.Fatal(err)
	}
}

func (r *pushRig) inbox(name string) string {
	r.t.Helper()
	d, err := r.hd.db.CreateShare(metadb.CreateOptions{Name: name, Owner: "alice", Inbox: true})
	if err != nil {
		r.t.Fatal(err)
	}
	return d.ID
}

// arrive commits one file from sender into the inbox, as an upload does:
// the bytes first, then the row.
func (r *pushRig) arrive(id, path, sender string) {
	r.t.Helper()
	if _, err := r.hd.fs.Write(id, path, strings.NewReader("x")); err != nil {
		r.t.Fatal(err)
	}
	c, err := r.hd.fs.Commit(id, path, 1, nil)
	if err != nil {
		r.t.Fatal(err)
	}
	if _, err := r.hd.db.CommitFile(metadb.CommitInput{ShareID: id, Path: path, Size: c.Size, SHA256: c.SHA256,
		Mime: c.Mime, UploadSession: sender}); err != nil {
		r.t.Fatal(err)
	}
}

func (r *pushRig) pass() []pushrelay.Message {
	return r.passOf(r.hd.push)
}

func (r *pushRig) passOf(p *pusher) []pushrelay.Message {
	p.pass(context.Background())
	return r.relay.take()
}

func (r *pushRig) open(m pushrelay.Message) pushseal.Message {
	r.t.Helper()
	msg, err := pushseal.Open(r.phone, m.Ciphertext)
	if err != nil {
		r.t.Fatal(err)
	}
	return msg
}

func TestADeliveryIsPushedOnceAfterTheQuietWindow(t *testing.T) {
	r := newPushRig(t)
	id := r.inbox("Band photos")
	if sent := r.pass(); len(sent) != 0 {
		t.Fatalf("an empty inbox pushed %d", len(sent))
	}
	r.arrive(id, "a.jpg", "s1")
	r.arrive(id, "b.jpg", "s1")
	if sent := r.pass(); len(sent) != 0 {
		t.Fatal("pushed inside the quiet window")
	}
	if !r.hd.push.waiting() {
		t.Fatal("a delivery inside its quiet window is not waiting on the clock")
	}
	r.ahead = inboxannounce.QuietWindow + time.Second
	sent := r.pass()
	if len(sent) != 1 {
		t.Fatalf("sent %d, want 1", len(sent))
	}
	m := r.open(sent[0])
	want := pushseal.Message{V: 1, Kind: "inboxReceived", Title: "Band photos", Body: "Received 2 files",
		Thread: "inbox-" + id, Tag: "entry-1", Unseen: 2, Ref: id}
	if m != want {
		t.Fatalf("message %+v, want %+v", m, want)
	}
	key := inboxannounce.Announcement{LinkID: id, Sender: "s1", Files: []string{"a.jpg"}}.Key()
	if sent[0].CollapseID != key || sent[0].Handle != strings.Repeat("1", 32) {
		t.Fatalf("collapse %q handle %q", sent[0].CollapseID, sent[0].Handle)
	}
	if again := r.pass(); len(again) != 0 {
		t.Fatal("the same delivery was pushed twice")
	}
	if r.hd.push.waiting() {
		t.Fatal("still waiting on the clock with everything announced")
	}
}

func TestOneFileIsNamedAndTwoSendersAreTwoPushes(t *testing.T) {
	r := newPushRig(t)
	id := r.inbox("Client uploads")
	r.pass()
	r.arrive(id, "brief-v2.docx", "s1")
	r.arrive(id, "scan.pdf", "s2")
	r.ahead = inboxannounce.QuietWindow + time.Second
	sent := r.pass()
	if len(sent) != 2 {
		t.Fatalf("sent %d, want one per sender", len(sent))
	}
	bodies := []string{r.open(sent[0]).Body, r.open(sent[1]).Body}
	a, b := "Received brief-v2.docx", "Received scan.pdf"
	if !(bodies[0] == a && bodies[1] == b) && !(bodies[1] == a && bodies[0] == b) {
		t.Fatalf("bodies %v", bodies)
	}
}

func TestAnUnnamedInboxIsTitledLikeTheBanner(t *testing.T) {
	m := inboxMessage(inboxannounce.Announcement{LinkID: "Ab3dE5gH9k", Files: []string{"a.pdf"}, Count: 1}, 3)
	want := pushseal.Message{Title: "Files received", Body: "Received a.pdf", Thread: "inbox-Ab3dE5gH9k", Unseen: 3, Ref: "Ab3dE5gH9k"}
	if m != want {
		t.Fatalf("message %+v, want %+v", m, want)
	}
}

// The push words a delivery as the apps' arrival banner does
// (TestTheInboxWordsAreTheBannersWords pins these to core/judge).
func TestTheInboxWords(t *testing.T) {
	unnamed := inboxMessage(inboxannounce.Announcement{Files: []string{"x"}, Count: 1}, 0)
	many := inboxMessage(inboxannounce.Announcement{LinkName: "n", Files: []string{"x", "y"}, Count: 2}, 0)
	one := inboxMessage(inboxannounce.Announcement{LinkName: "n", Files: []string{"x"}, Count: 1}, 0)
	if unnamed.Title != "Files received" || many.Body != "Received 2 files" || one.Body != "Received x" {
		t.Fatalf("server words %q / %q / %q", unnamed.Title, many.Body, one.Body)
	}
}

func TestAFirstRegistrationReplaysNothing(t *testing.T) {
	r := newPushRig(t)
	if err := r.hd.db.ClearPush(metadb.TokenHash(r.tok)); err != nil {
		t.Fatal(err)
	}
	id := r.inbox("Box")
	r.arrive(id, "old.pdf", "s1")
	r.ahead = time.Hour
	r.pass() // nobody registered: nothing evaluated, nothing remembered
	r.register(r.tok, "entry-1")
	if sent := r.pass(); len(sent) != 0 {
		t.Fatalf("a phone registering later received %d old deliveries", len(sent))
	}
	r.arrive(id, "new.pdf", "s2")
	r.ahead = time.Hour + inboxannounce.QuietWindow
	if sent := r.pass(); len(sent) != 1 || r.open(sent[0]).Body != "Received new.pdf" {
		t.Fatalf("the first new delivery after registering: %d", len(sent))
	}
}

// Suspending an account (or letting it expire) cuts its phone off: a
// delivery while suspended is never pushed, then or after re-enabling.
func TestASuspendedOrExpiredOwnerIsPushedNothing(t *testing.T) {
	for _, c := range []struct {
		name      string
		off, back metadb.Settings
	}{
		{"suspended", metadb.Settings{Disabled: new(true)}, metadb.Settings{Disabled: new(false)}},
		{"expired", metadb.Settings{AccountExpiresAt: new(time.Now().Add(-time.Minute))},
			metadb.Settings{ClearAccountExpiry: true}},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newPushRig(t)
			id := r.inbox("Box")
			r.pass()
			if _, err := r.hd.db.UpdateUser("alice", c.off); err != nil {
				t.Fatal(err)
			}
			r.arrive(id, "while-off.pdf", "s1")
			r.ahead = inboxannounce.QuietWindow + time.Second
			if sent := r.pass(); len(sent) != 0 {
				t.Fatalf("pushed %d to an account that is %s", len(sent), c.name)
			}
			if _, err := r.hd.db.UpdateUser("alice", c.back); err != nil {
				t.Fatal(err)
			}
			if sent := r.pass(); len(sent) != 0 {
				t.Fatalf("re-enabling replayed %d deliveries made while %s", len(sent), c.name)
			}
			r.arrive(id, "after.pdf", "s2")
			r.ahead = 2 * (inboxannounce.QuietWindow + time.Second)
			if sent := r.pass(); len(sent) != 1 || r.open(sent[0]).Body != "Received after.pdf" {
				t.Fatalf("after re-enabling: %d", len(sent))
			}
		})
	}
}

func TestAnAccountThatUnregistersIsForgottenAtOnce(t *testing.T) {
	r := newPushRig(t)
	id := r.inbox("Box")
	r.pass()
	if _, ok, _ := r.hd.db.PushState("alice", pushStateInbox); !ok {
		t.Fatal("the pass remembered nothing")
	}
	if err := r.hd.db.ClearPush(metadb.TokenHash(r.tok)); err != nil {
		t.Fatal(err)
	}
	r.pass()
	if _, ok, _ := r.hd.db.PushState("alice", pushStateInbox); ok {
		t.Fatal("an account with no device kept its memory past the next pass")
	}
	r.arrive(id, "while-off.pdf", "s1")
	r.ahead = time.Hour
	r.pass()
	r.register(r.tok, "entry-1")
	if sent := r.pass(); len(sent) != 0 {
		t.Fatalf("re-registering replayed %d deliveries made while unregistered", len(sent))
	}
}

func TestARestartPushesNothingTwice(t *testing.T) {
	r := newPushRig(t)
	id := r.inbox("Box")
	r.hd.push.sweep(context.Background())
	r.arrive(id, "a.pdf", "s1")
	r.ahead = inboxannounce.QuietWindow + time.Second
	if sent := r.pass(); len(sent) != 1 {
		t.Fatalf("sent %d", len(sent))
	}
	r.hd.push.sweep(context.Background())
	restarted := r.restart()
	if restarted.amnesia {
		t.Fatal("a restart inside the heartbeat bound distrusted the memory")
	}
	if sent := r.passOf(restarted); len(sent) != 0 {
		t.Fatalf("a restarted server pushed %d again", len(sent))
	}
}

func TestAShortRestartStillAnnouncesWhatArrivedMeanwhile(t *testing.T) {
	r := newPushRig(t)
	id := r.inbox("Box")
	r.hd.push.sweep(context.Background())
	r.arrive(id, "a.pdf", "s1") // lands while the process is down
	r.ahead = pushSweep
	restarted := r.restart()
	if sent := r.passOf(restarted); len(sent) != 1 || r.open(sent[0]).Body != "Received a.pdf" {
		t.Fatalf("after a short restart: %d", len(sent))
	}
}

func TestAPusherBackFromALongAbsenceReplaysNothing(t *testing.T) {
	r := newPushRig(t)
	id := r.inbox("Box")
	r.hd.push.sweep(context.Background())
	// Another server (a rolled-back release) serves the volume for a while;
	// arrivals land that this pusher never saw.
	r.arrive(id, "while-away-1.pdf", "s1")
	r.arrive(id, "while-away-2.pdf", "s2")
	r.ahead = pushAbsence + time.Minute
	back := r.restart()
	if sent := r.passOf(back); len(sent) != 0 {
		t.Fatalf("back from a long absence, pushed %d old deliveries", len(sent))
	}
	r.arrive(id, "new.pdf", "s3")
	r.ahead += inboxannounce.QuietWindow + time.Second
	if sent := r.passOf(back); len(sent) != 1 || r.open(sent[0]).Body != "Received new.pdf" {
		t.Fatalf("the first delivery after coming back: %d", len(sent))
	}
	// No heartbeat at all reads the same way.
	if err := r.hd.db.SetPushState(pushStateServer, pushStateAlive, "not a number"); err != nil {
		t.Fatal(err)
	}
	if !r.restart().amnesia {
		t.Fatal("an unreadable heartbeat was trusted")
	}
}

func TestAnUploadInFlightHoldsItsSendersDelivery(t *testing.T) {
	r := newPushRig(t)
	id := r.inbox("Box")
	r.pass()
	r.arrive(id, "a.pdf", "s1")
	r.claims = []inboxannounce.Claim{{Name: "b.pdf", By: "s1"}}
	r.ahead = inboxannounce.QuietWindow + time.Second
	if sent := r.pass(); len(sent) != 0 {
		t.Fatal("pushed while the sender was still uploading")
	}
	r.claims = nil
	r.arrive(id, "b.pdf", "s1")
	r.ahead = 2*inboxannounce.QuietWindow + time.Second
	if sent := r.pass(); len(sent) != 1 || r.open(sent[0]).Body != "Received 2 files" {
		t.Fatalf("after the upload: %d", len(sent))
	}
}

func TestAMutedKindIsNeverSentToThatDevice(t *testing.T) {
	r := newPushRig(t)
	r.register(r.tok, "entry-1", "inboxReceived")
	other, err := r.hd.db.MintToken("alice", "ipad")
	if err != nil {
		t.Fatal(err)
	}
	r.register(other, "entry-2")
	id := r.inbox("Box")
	r.pass()
	r.arrive(id, "a.pdf", "s1")
	r.ahead = inboxannounce.QuietWindow + time.Second
	sent := r.pass()
	if len(sent) != 1 || r.open(sent[0]).Tag != "entry-2" {
		t.Fatalf("sent %d (want only the unmuted device)", len(sent))
	}
}

func TestEveryRegisteredDeviceIsSentTo(t *testing.T) {
	r := newPushRig(t)
	for _, tag := range []string{"entry-2", "entry-3"} {
		tok, err := r.hd.db.MintToken("alice", tag)
		if err != nil {
			t.Fatal(err)
		}
		r.register(tok, tag)
	}
	id := r.inbox("Box")
	r.pass()
	r.arrive(id, "a.pdf", "s1")
	r.ahead = inboxannounce.QuietWindow + time.Second
	tags := map[string]bool{}
	for _, m := range r.pass() {
		tags[r.open(m).Tag] = true
	}
	if len(tags) != 3 {
		t.Fatalf("tags %v, want all three devices", tags)
	}
}

func TestAnInboxThatDoesNotNotifyStaysQuiet(t *testing.T) {
	r := newPushRig(t)
	id := r.inbox("Box")
	if _, err := r.hd.db.UpdateShare(id, metadb.UpdateOptions{SetNotify: true, Notify: false}); err != nil {
		t.Fatal(err)
	}
	r.pass()
	r.arrive(id, "a.pdf", "s1")
	r.ahead = inboxannounce.QuietWindow + time.Second
	if sent := r.pass(); len(sent) != 0 {
		t.Fatal("a muted inbox pushed")
	}
}

func TestADeliveryWhileTheMacIsInUseIsSettledNotHeld(t *testing.T) {
	r := newPushRig(t)
	mac, err := r.hd.db.MintToken("alice", "mac")
	if err != nil {
		t.Fatal(err)
	}
	h := metadb.TokenHash(mac)
	if _, err := r.hd.db.UserByToken(mac, metadb.ClientInfo{Version: "1.0.1", Platform: "macos"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := r.hd.db.SetConsoleActivity(h, &now); err != nil {
		t.Fatal(err)
	}
	id := r.inbox("Box")
	r.pass()
	r.arrive(id, "a.pdf", "s1")
	r.ahead = inboxannounce.QuietWindow + time.Second
	if sent := r.pass(); len(sent) != 0 {
		t.Fatal("pushed while the Mac was in use")
	}
	if err := r.hd.db.SetConsoleActivity(h, nil); err != nil {
		t.Fatal(err)
	}
	r.ahead = time.Hour
	if sent := r.pass(); len(sent) != 0 {
		t.Fatal("the delivery the Mac announced was pushed once the Mac went idle")
	}
}

func TestARelayOutageKeepsTheRegistration(t *testing.T) {
	r := newPushRig(t)
	r.relay.answer = func(pushrelay.Message) error { return &pushrelay.Error{Status: 502, Code: "apns-unavailable"} }
	id := r.inbox("Box")
	r.pass()
	r.arrive(id, "a.pdf", "s1")
	r.ahead = inboxannounce.QuietWindow + time.Second
	if sent := r.pass(); len(sent) != 1 {
		t.Fatalf("sent %d", len(sent))
	}
	if _, ok, _ := r.hd.db.PushOf(metadb.TokenHash(r.tok)); !ok {
		t.Fatal("an outage dropped the registration")
	}
}

func TestAGoneHandleIsDropped(t *testing.T) {
	r := newPushRig(t)
	r.relay.answer = func(pushrelay.Message) error { return pushrelay.ErrGone }
	id := r.inbox("Box")
	r.pass()
	r.arrive(id, "a.pdf", "s1")
	r.ahead = inboxannounce.QuietWindow + time.Second
	r.pass()
	if _, ok, _ := r.hd.db.PushOf(metadb.TokenHash(r.tok)); ok {
		t.Fatal("a handle the relay called gone is still registered")
	}
}

func TestARegistrationWithAnotherRelayIsSkipped(t *testing.T) {
	r := newPushRig(t)
	if err := r.hd.db.SetPush(metadb.TokenHash(r.tok), metadb.PushRegistration{Relay: "https://old-relay.test",
		Handle: strings.Repeat("9", 32), PublicKey: r.phone.PublicKey().Bytes(), Tag: "entry-1"}); err != nil {
		t.Fatal(err)
	}
	id := r.inbox("Box")
	r.pass()
	r.arrive(id, "a.pdf", "s1")
	r.ahead = inboxannounce.QuietWindow + time.Second
	if sent := r.pass(); len(sent) != 0 {
		t.Fatal("sent through a registration made with another relay")
	}
}

func TestPushOffBuildsNoPusher(t *testing.T) {
	hd := newHandler(testBackend(t), "2.0.0", testDomain(t), nil, Deployment{})
	if hd.push != nil {
		t.Fatal("a server with push off built a pusher")
	}
	srv := NewServer(testBackend(t), "2.0.0", testDomain(t), nil, Deployment{})
	srv.Drain()
}

func TestTheServingProcessStartsThePusherAndDrainStopsIt(t *testing.T) {
	srv := NewServer(testBackend(t), "2.0.0", testDomain(t), nil, Deployment{PushRelay: testRelay})
	p := srv.h.push
	if p == nil || p.done == nil {
		t.Fatal("the serving process did not start the pusher")
	}
	finished := make(chan struct{})
	go func() {
		srv.Drain()
		srv.Drain()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("Drain did not stop the pusher")
	}
	select {
	case <-p.done:
	default:
		t.Fatal("the pusher's loop still runs after Drain")
	}
}

var errInjected = errors.New("injected failure")

func TestAFailedStateWriteSendsNothingAndNeverRepeats(t *testing.T) {
	r := newPushRig(t)
	id := r.inbox("Box")
	r.pass()
	r.arrive(id, "a.pdf", "s1")
	r.ahead = inboxannounce.QuietWindow + time.Second
	write := r.hd.push.setState
	r.hd.push.setState = func(string, string, string) error { return errInjected }
	for i := range 3 {
		if sent := r.pass(); len(sent) != 0 {
			t.Fatalf("pass %d sent %d while the state could not be recorded", i, len(sent))
		}
	}
	r.hd.push.setState = write
	if sent := r.pass(); len(sent) != 1 {
		t.Fatalf("once recording works, sent %d, want the delivery once", len(sent))
	}
	if sent := r.pass(); len(sent) != 0 {
		t.Fatal("the delivery was sent again")
	}
}

func TestAnUnreadableCountHoldsTheDeliveryRatherThanSendingZero(t *testing.T) {
	r := newPushRig(t)
	id := r.inbox("Box")
	r.pass()
	r.arrive(id, "a.pdf", "s1")
	r.ahead = inboxannounce.QuietWindow + time.Second
	count := r.hd.push.unseenOf
	r.hd.push.unseenOf = func(string) (int, error) { return 0, errInjected }
	if sent := r.pass(); len(sent) != 0 {
		t.Fatalf("sent %d without a count", len(sent))
	}
	if !r.hd.push.waiting() {
		t.Fatal("a delivery held for its count is not retried on the tick")
	}
	r.hd.push.unseenOf = count
	sent := r.pass()
	if len(sent) != 1 || r.open(sent[0]).Unseen != 1 {
		t.Fatalf("after the count reads again: %d", len(sent))
	}
}

func TestAnOwnerNotRecordedAfterAnAbsenceStaysUnknown(t *testing.T) {
	r := newPushRig(t)
	bobTok := seedUser(t, r.hd.db, "bob")
	r.register(bobTok, "entry-2")
	box := r.inbox("Box")
	bobBox, err := r.hd.db.CreateShare(metadb.CreateOptions{Name: "Bob's", Owner: "bob", Inbox: true})
	if err != nil {
		t.Fatal(err)
	}
	r.hd.push.sweep(context.Background())
	r.arrive(box, "away-a.pdf", "s1")
	r.arrive(bobBox.ID, "away-b.pdf", "s1")
	r.ahead = pushAbsence + time.Minute
	back := r.restart()
	write := back.setState
	back.setState = func(owner, kind, value string) error {
		if owner == "alice" {
			return errInjected
		}
		return write(owner, kind, value)
	}
	if sent := r.passOf(back); len(sent) != 0 {
		t.Fatalf("back from an absence, sent %d", len(sent))
	}
	if !back.amnesia {
		t.Fatal("the absence was forgotten although alice was never recorded")
	}
	back.setState = write
	if sent := r.passOf(back); len(sent) != 0 {
		t.Fatalf("alice's absence window replayed: %d", len(sent))
	}
	if back.amnesia {
		t.Fatal("still distrusting memory after every owner was recorded")
	}
	r.arrive(box, "new-a.pdf", "s2")
	r.arrive(bobBox.ID, "new-b.pdf", "s2")
	r.ahead += inboxannounce.QuietWindow + time.Second
	bodies := map[string]bool{}
	for _, m := range r.passOf(back) {
		bodies[r.open(m).Body] = true
	}
	if len(bodies) != 2 || !bodies["Received new-a.pdf"] || !bodies["Received new-b.pdf"] {
		t.Fatalf("after the absence: %v", bodies)
	}
}

func TestAStoppingPusherSendsNothingMore(t *testing.T) {
	r := newPushRig(t)
	other, err := r.hd.db.MintToken("alice", "ipad")
	if err != nil {
		t.Fatal(err)
	}
	r.register(other, "entry-2")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.hd.push.deliver(ctx, "alice", pushKindInboxReceived, "in-x", pushseal.Message{Title: "t", Body: "b"})
	if sent := r.relay.take(); len(sent) != 0 {
		t.Fatalf("a cancelled pusher sent %d", len(sent))
	}
}
