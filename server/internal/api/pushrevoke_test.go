package api

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"hyperdrop/core/domainconn"
	"hyperdrop/core/revokeannounce"
	"hyperdrop/server/internal/ddns"
	"hyperdrop/server/internal/metadb"
)

func TestARevokeIsPushedOnceAndAFirstPassAnnouncesNothing(t *testing.T) {
	r := newPushRig(t)
	two := 2
	var revoked []metadb.RevokedSource
	r.hd.push.revoked = func(string) ([]metadb.RevokedSource, error) { return revoked, nil }
	revoked = []metadb.RevokedSource{{ShareID: "d1", ShareName: "Old", Source: "video", At: time.Now().Add(-time.Hour)}}
	if sent := r.pass(); len(sent) != 0 {
		t.Fatal("a revoke that existed before the first pass was pushed")
	}
	at := time.Now().Truncate(time.Second)
	revoked = append(revoked,
		metadb.RevokedSource{ShareID: "d2", ShareName: "Wedding", Source: "photo/2024", At: at, Files: &two},
		metadb.RevokedSource{ShareID: "d3", ShareName: "Trip", Source: "photo/2024", At: at})
	sent := r.pass()
	if len(sent) != 1 {
		t.Fatalf("sent %d, want one per admin action", len(sent))
	}
	m := r.open(sent[0])
	if m.Kind != "accessRevoked" || m.Title != "Folder access removed" ||
		m.Body != "photo/2024: 2 shares lost 2 files. An admin removed the folder from your account." ||
		m.Thread != "revoked" || m.Ref != "" {
		t.Fatalf("message %+v", m)
	}
	if sent[0].CollapseID != "rv-"+strconv.FormatInt(at.Unix(), 10) {
		t.Fatalf("collapse %q", sent[0].CollapseID)
	}
	if again := r.pass(); len(again) != 0 {
		t.Fatal("pushed twice")
	}
}

func TestARevokeMessageNamesOneShare(t *testing.T) {
	m := revokeMessage(revokeannounce.Announcement{Sources: []string{"video"},
		Shares: []revokeannounce.Loss{{ID: "d1", Name: "Holiday", Source: "video"}}})
	if m.Body != "video: Holiday lost its files. An admin removed the folder from your account." || m.Ref != "d1" {
		t.Fatalf("%+v", m)
	}
}

func TestARevokeIsHeldUntilItsStateIsRecorded(t *testing.T) {
	r := newPushRig(t)
	var revoked []metadb.RevokedSource
	r.hd.push.revoked = func(string) ([]metadb.RevokedSource, error) { return revoked, nil }
	r.pass()
	revoked = []metadb.RevokedSource{{ShareID: "d1", ShareName: "Holiday", Source: "video", At: time.Now()}}
	write := r.hd.push.setState
	r.hd.push.setState = func(owner, kind, value string) error {
		if kind == pushStateRevoke {
			return errInjected
		}
		return write(owner, kind, value)
	}
	for i := 0; i < 3; i++ {
		if sent := r.pass(); len(sent) != 0 {
			t.Fatalf("pass %d sent %d while the revoke could not be recorded", i, len(sent))
		}
	}
	r.hd.push.setState = write
	if sent := r.pass(); len(sent) != 1 || r.open(sent[0]).Ref != "d1" {
		t.Fatalf("once recorded: %d", len(sent))
	}
	if sent := r.pass(); len(sent) != 0 {
		t.Fatal("pushed twice")
	}
}

func TestARevokeWhileTheMacIsInUseIsRecordedNotPushed(t *testing.T) {
	r := newPushRig(t)
	var revoked []metadb.RevokedSource
	r.hd.push.revoked = func(string) ([]metadb.RevokedSource, error) { return revoked, nil }
	r.pass()
	mac, err := r.hd.db.MintToken("alice", "mac")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.hd.db.UserByToken(mac, metadb.ClientInfo{Version: "1.0.1", Platform: "macos"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := r.hd.db.SetConsoleActivity(metadb.TokenHash(mac), &now); err != nil {
		t.Fatal(err)
	}
	revoked = []metadb.RevokedSource{{ShareID: "d1", ShareName: "Holiday", Source: "video", At: now}}
	if sent := r.pass(); len(sent) != 0 {
		t.Fatal("pushed while the Mac was in use")
	}
	if err := r.hd.db.SetConsoleActivity(metadb.TokenHash(mac), nil); err != nil {
		t.Fatal(err)
	}
	r.ahead = time.Hour
	if sent := r.pass(); len(sent) != 0 {
		t.Fatal("the revoke the Mac announced was pushed once the Mac went idle")
	}
}

func TestTheDomainIsPushedToAdminsOnTheChangeAndTheRecovery(t *testing.T) {
	r := newPushRig(t) // alice is a user; the seeded admin registers below
	r.register(testToken, "entry-a")
	facts := domainconn.Facts{Configured: true, LastUpdate: time.Now().Unix()}
	r.hd.push.domain = func() (domainconn.Facts, string) { return facts, "box.hyperdrop.link" }
	if sent := r.pass(); len(sent) != 0 {
		t.Fatal("a state met for the first time was announced")
	}
	facts.LastError = "write DNS: budget"
	sent := r.pass()
	if len(sent) != 1 {
		t.Fatalf("sent %d, want the admin's device only", len(sent))
	}
	m := r.open(sent[0])
	if m.Kind != "domain" || m.Tag != "entry-a" || m.Title != "box.hyperdrop.link could not be updated" || m.Thread != "domain" {
		t.Fatalf("message %+v", m)
	}
	if again := r.pass(); len(again) != 0 {
		t.Fatal("an unchanged problem was pushed again")
	}
	facts.LastError = ""
	sent = r.pass()
	if len(sent) != 1 || r.open(sent[0]).Title != "box.hyperdrop.link is working again" {
		t.Fatalf("recovery: %d", len(sent))
	}
}

// Who is told of the domain is read each pass: an admin suspended or
// demoted since registering is told nothing.
func TestTheDomainSkipsASuspendedOrDemotedAdmin(t *testing.T) {
	for _, c := range []struct {
		name string
		s    metadb.Settings
	}{
		{"suspended", metadb.Settings{Disabled: new(true)}},
		{"expired", metadb.Settings{AccountExpiresAt: new(time.Now().Add(-time.Minute))}},
		{"demoted", metadb.Settings{Role: new(metadb.RoleUser)}},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newPushRig(t)
			if _, err := r.hd.db.CreateUser("bob", "bob-pw", metadb.RoleAdmin, metadb.Settings{}); err != nil {
				t.Fatal(err)
			}
			bob, err := r.hd.db.MintToken("bob", "phone")
			if err != nil {
				t.Fatal(err)
			}
			r.register(bob, "entry-b")
			facts := domainconn.Facts{Configured: true, LastUpdate: time.Now().Unix()}
			r.hd.push.domain = func() (domainconn.Facts, string) { return facts, "" }
			r.pass()
			if _, err := r.hd.db.UpdateUser("bob", c.s); err != nil {
				t.Fatal(err)
			}
			facts.LastError = "x"
			if sent := r.pass(); len(sent) != 0 {
				t.Fatalf("an admin who is %s was sent %d", c.name, len(sent))
			}
		})
	}
}

func TestAMutedDomainKindStaysQuiet(t *testing.T) {
	r := newPushRig(t)
	r.register(testToken, "entry-a", "domain")
	facts := domainconn.Facts{Configured: true, LastUpdate: time.Now().Unix()}
	r.hd.push.domain = func() (domainconn.Facts, string) { return facts, "" }
	r.pass()
	facts.LastError = "x"
	if sent := r.pass(); len(sent) != 0 {
		t.Fatal("a muted kind was sent")
	}
}

func TestDomainWordsAreDeviceNeutral(t *testing.T) {
	for _, c := range []domainconn.Connection{domainconn.Unauthorized, domainconn.Silent, domainconn.Failing} {
		m := domainMessage(c, domainconn.Problem, "")
		if !strings.HasPrefix(m.Title, "Your free domain") || strings.Contains(m.Body, "Open Servers") {
			t.Errorf("%s: %+v", c, m)
		}
	}
}

// Back from an absence, a revoke and a domain problem that happened while
// another server served the volume are remembered, never pushed.
func TestAnAbsenceReplaysNoRevokeAndNoDomainChange(t *testing.T) {
	r := newPushRig(t)
	r.register(testToken, "entry-a")
	var revoked []metadb.RevokedSource
	facts := domainconn.Facts{Configured: true, LastUpdate: time.Now().Unix()}
	seams := func(p *pusher) {
		p.revoked = func(string) ([]metadb.RevokedSource, error) { return revoked, nil }
		p.domain = func() (domainconn.Facts, string) { return facts, "box.hyperdrop.link" }
	}
	seams(r.hd.push)
	r.hd.push.sweep(context.Background())
	revoked = []metadb.RevokedSource{{ShareID: "d1", ShareName: "Holiday", Source: "video", At: time.Now()}}
	facts.LastError = "write DNS: budget"
	r.ahead = pushAbsence + time.Minute
	back := r.restart()
	seams(back)
	if sent := r.passOf(back); len(sent) != 0 {
		t.Fatalf("back from an absence, pushed %d", len(sent))
	}
	if back.amnesia {
		t.Fatal("every owner and the domain were recorded, yet the absence holds")
	}
	facts.LastError = ""
	if sent := r.passOf(back); len(sent) != 1 || r.open(sent[0]).Title != "box.hyperdrop.link is working again" {
		t.Fatalf("the recovery after coming back: %d", len(sent))
	}
}

// The domain's reading counts toward "recorded completely": a reading that
// could not be written keeps the absence in force.
func TestAnUnrecordedDomainKeepsTheAbsence(t *testing.T) {
	r := newPushRig(t)
	facts := domainconn.Facts{Configured: true, LastUpdate: time.Now().Unix()}
	r.hd.push.sweep(context.Background())
	r.ahead = pushAbsence + time.Minute
	back := r.restart()
	back.domain = func() (domainconn.Facts, string) { return facts, "" }
	write := back.setState
	back.setState = func(owner, kind, value string) error {
		if kind == pushStateDomain {
			return errInjected
		}
		return write(owner, kind, value)
	}
	r.passOf(back)
	if !back.amnesia {
		t.Fatal("the absence ended although the domain was never recorded")
	}
	back.setState = write
	r.passOf(back)
	if back.amnesia {
		t.Fatal("the absence holds after everything was recorded")
	}
}

// While an owner is still unrecorded after an absence the heartbeat is not
// written, so a restart in that time distrusts the memory again.
func TestTheHeartbeatWaitsForEveryOwnerAfterAnAbsence(t *testing.T) {
	r := newPushRig(t)
	r.hd.push.sweep(context.Background())
	before, _, _ := r.hd.db.PushState(pushStateServer, pushStateAlive)
	r.ahead = pushAbsence + time.Minute
	back := r.restart()
	back.revoked = func(string) ([]metadb.RevokedSource, error) { return nil, errInjected }
	back.sweep(context.Background())
	if now, _, _ := r.hd.db.PushState(pushStateServer, pushStateAlive); now != before {
		t.Fatalf("heartbeat written (%s, was %s) while alice was unrecorded", now, before)
	}
	if !r.restart().amnesia {
		t.Fatal("a restart trusted alice's state from before the absence")
	}
	back.revoked = r.hd.db.RevokedSources
	back.sweep(context.Background())
	if now, _, _ := r.hd.db.PushState(pushStateServer, pushStateAlive); now == before {
		t.Fatal("no heartbeat after every owner was recorded")
	}
	if r.restart().amnesia {
		t.Fatal("a restart right after a complete sweep distrusted the memory")
	}
}

func TestARecurringFailureIsLoggedOncePerInterval(t *testing.T) {
	r := newPushRig(t)
	p := r.hd.push
	p.logEvery("k", "push: test %d", 1)
	first := p.logged["k"]
	r.ahead = pushLogEvery / 2
	p.logEvery("k", "push: test %d", 2)
	if p.logged["k"] != first {
		t.Fatal("logged again inside the interval")
	}
	r.ahead = pushLogEvery + time.Second
	p.logEvery("k", "push: test %d", 3)
	if p.logged["k"] == first {
		t.Fatal("not logged again after the interval")
	}
}

func TestDDNSFactsReadTheUpdatersState(t *testing.T) {
	st, err := ddns.Load(filepath.Join(t.TempDir(), "ddns"))
	if err != nil {
		t.Fatal(err)
	}
	u := ddns.NewUpdater(st, &ddns.Client{}, nil)
	if f, name := ddnsFacts(u); f != (domainconn.Facts{}) || name != "" {
		t.Fatalf("no name: %+v %q", f, name)
	}
	if err := st.BeginClaim("box01", "token", "server"); err != nil {
		t.Fatal(err)
	}
	if f, name := ddnsFacts(u); f.Configured || name != "" {
		t.Fatalf("a pending claim read as published: %+v %q", f, name)
	}
	if err := st.ConfirmClaim(); err != nil {
		t.Fatal(err)
	}
	if err := st.Record("203.0.113.7", "203.0.113.7", 1_900_000_000, ""); err != nil {
		t.Fatal(err)
	}
	if err := st.Record("", "", 1_900_000_100, "write DNS: budget"); err != nil {
		t.Fatal(err)
	}
	f, name := ddnsFacts(u)
	if f != (domainconn.Facts{Configured: true, LastUpdate: 1_900_000_000, LastError: "write DNS: budget"}) || name != "box01."+ddns.Zone {
		t.Fatalf("published: %+v %q", f, name)
	}
}

// The push words a revoke as the Mac's banner does
// (TestTheRevokeWordsAreTheMacsWords pins these to RevokeNotifier), counts
// grouped with a comma.
func TestTheRevokeWords(t *testing.T) {
	n := 12480
	one := 1
	many := revokeMessage(revokeannounce.Announcement{Sources: []string{"a", "b"}, Shares: []revokeannounce.Loss{
		{ID: "d1", Name: "x", Source: "a", Files: &n}, {ID: "d2", Name: "y", Source: "b", Files: &one}}})
	if many.Title != "Folder access removed" ||
		many.Body != "a, b: 2 shares lost 12,481 files. An admin removed the folders from your account." {
		t.Fatalf("server words %+v", many)
	}
	for in, want := range map[int]string{0: "0", 999: "999", 1000: "1,000", 1234567: "1,234,567"} {
		if got := grouped(in); got != want {
			t.Errorf("grouped(%d) = %q", in, got)
		}
	}
}
