package api

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"hyperdrop/core/domainconn"
	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/pushrelay"
)

// domainChangeRig rigs the seeded admin and a second one, each with a device, beside
// alice (a user with a device).
func domainChangeRig(t *testing.T) *pushRig {
	t.Helper()
	r := newPushRig(t)
	r.register(testToken, "entry-a")
	if _, err := r.hd.db.CreateUser("root2", "root2-pw", metadb.RoleAdmin, metadb.Settings{}); err != nil {
		t.Fatal(err)
	}
	tok, err := r.hd.db.MintToken("root2", "test")
	if err != nil {
		t.Fatal(err)
	}
	r.register(tok, "entry-b")
	return r
}

func aChange(to string) domainconn.ChangeNotice {
	return domainconn.NoticeOf(domainconn.Change{From: "old.example", To: to, At: time.Now()})
}

func tagsOf(r *pushRig, sent []pushrelay.Message) map[string]bool {
	out := map[string]bool{}
	for _, m := range sent {
		out[r.open(m).Tag] = true
	}
	return out
}

func TestADomainChangeIsPushedToEveryAdminOnce(t *testing.T) {
	r := domainChangeRig(t)
	var notices []domainconn.ChangeNotice
	r.hd.push.domainChanges = func() []domainconn.ChangeNotice { return notices }
	r.pass()
	n := aChange("new.example")
	notices = []domainconn.ChangeNotice{n}
	sent := r.pass()
	if len(sent) != 2 {
		t.Fatalf("sent %d, want one per admin device", len(sent))
	}
	if tags := tagsOf(r, sent); !tags["entry-a"] || !tags["entry-b"] || tags["entry-1"] {
		t.Fatalf("sent to %v, want both admins and not the user", tags)
	}
	m := r.open(sent[0])
	if m.Kind != "domainChanged" || m.Title != n.Title || m.Body != n.Body ||
		m.Thread != "domain-changed" || sent[0].CollapseID != domainChangeCollapse(n.Key) {
		t.Fatalf("message %+v collapse %q", m, sent[0].CollapseID)
	}
	if again := r.pass(); len(again) != 0 {
		t.Fatal("a domain change was pushed twice")
	}
}

func TestADomainChangeIsPushedWhileTheAdminsComputerIsActive(t *testing.T) {
	r := domainChangeRig(t)
	var notices []domainconn.ChangeNotice
	r.hd.push.domainChanges = func() []domainconn.ChangeNotice { return notices }
	r.pass()
	mac, err := r.hd.db.MintToken(metadb.DefaultAdminName, "mac")
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
	if active, _ := r.hd.db.DesktopActiveSince(metadb.DefaultAdminName, now.Add(-time.Minute)); !active {
		t.Fatal("the rig's computer is not in use")
	}
	notices = []domainconn.ChangeNotice{aChange("new.example")}
	if sent := r.pass(); len(sent) != 2 {
		t.Fatalf("sent %d, want both admins told despite the active computer", len(sent))
	}
}

func changeAt(to string, at time.Time) domainconn.ChangeNotice {
	return domainconn.NoticeOf(domainconn.Change{From: "old.example", To: to, At: at})
}

func TestDomainChangesListedBeforeThePushersFirstPassAreNotPushed(t *testing.T) {
	r := domainChangeRig(t)
	n := changeAt("new.example", time.Now().Add(-3*24*time.Hour))
	r.hd.push.domainChanges = func() []domainconn.ChangeNotice { return []domainconn.ChangeNotice{n} }
	if sent := r.pass(); len(sent) != 0 {
		t.Fatalf("the first pass pushed %d changes it only had to record", len(sent))
	}
	var mem domainChangeMemory
	if !r.hd.push.loadState(pushStateServer, pushStateDomainChange, &mem) || len(mem.Sent) != 1 {
		t.Fatalf("recorded %v", mem.Sent)
	}
	if sent := r.pass(); len(sent) != 0 {
		t.Fatal("a recorded change was pushed later")
	}
}

func TestARecentDomainChangeIsPushedOnTheFirstPassAfterAnAbsence(t *testing.T) {
	r := domainChangeRig(t)
	r.hd.push.domainChanges = func() []domainconn.ChangeNotice { return nil }
	r.pass()
	stale := strconv.FormatInt(time.Now().Add(-3*24*time.Hour).Unix(), 10)
	if err := r.hd.db.SetPushState(pushStateServer, pushStateAlive, stale); err != nil {
		t.Fatal(err)
	}
	p := r.restart()
	if !p.amnesia {
		t.Fatal("a pusher back from three days off trusts its memory")
	}
	recent := changeAt("recent.example", time.Now().Add(-time.Minute))
	old := changeAt("old.example", time.Now().Add(-3*24*time.Hour))
	p.domainChanges = func() []domainconn.ChangeNotice { return []domainconn.ChangeNotice{old, recent} }
	sent := r.passOf(p)
	if len(sent) != 2 {
		t.Fatalf("sent %d, want the recent change once per admin device", len(sent))
	}
	for _, m := range sent {
		if got := r.open(m); got.Body != recent.Body {
			t.Fatalf("pushed %q, want only the recent change", got.Body)
		}
	}
	if again := r.passOf(p); len(again) != 0 {
		t.Fatalf("a recorded change was pushed again: %d", len(again))
	}
}

func TestUnreadableDomainChangeMemorySendsNothing(t *testing.T) {
	r := domainChangeRig(t)
	if err := r.hd.db.SetPushState(pushStateServer, pushStateDomainChange, "not json"); err != nil {
		t.Fatal(err)
	}
	recent := changeAt("recent.example", time.Now().Add(-time.Minute))
	r.hd.push.domainChanges = func() []domainconn.ChangeNotice { return []domainconn.ChangeNotice{recent} }
	if sent := r.pass(); len(sent) != 0 {
		t.Fatalf("unreadable memory pushed %d", len(sent))
	}
}

func TestAMuteOfDomainChangedIsRefused(t *testing.T) {
	h, _ := pushAPI(t)
	_, key := phoneKey(t)
	rec := doReq(t, h, "PUT", "/api/me/push", testToken, pushBody(testRelay, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", key, "entry-1", pushKindDomainChanged))
	if rec.Code != 400 {
		t.Fatalf("muting domainChanged: %d %s, want 400", rec.Code, rec.Body)
	}
}

// relayCollapseID is the names relay's rule for a collapse id.
var relayCollapseID = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)

func TestADomainChangeToALongNameHasACollapseIDTheRelayTakes(t *testing.T) {
	r := domainChangeRig(t)
	var notices []domainconn.ChangeNotice
	r.hd.push.domainChanges = func() []domainconn.ChangeNotice { return notices }
	r.pass()
	long := strings.Repeat("a", 48) + ".example.com"
	if len(long) != 60 {
		t.Fatalf("domain is %d characters, want 60", len(long))
	}
	n := aChange(long)
	notices = []domainconn.ChangeNotice{n}
	sent := r.pass()
	if len(sent) != 2 {
		t.Fatalf("sent %d, want one per admin device", len(sent))
	}
	id := sent[0].CollapseID
	if !relayCollapseID.MatchString(id) || sent[1].CollapseID != id {
		t.Fatalf("collapse ids %q and %q, want one the relay takes for both", id, sent[1].CollapseID)
	}
	if again := domainChangeCollapse(n.Key); again != id {
		t.Fatalf("collapse id %q then %q for one change", id, again)
	}
	if other := domainChangeCollapse(aChange(long + "x").Key); other == id {
		t.Fatal("two changes share a collapse id")
	}
}
