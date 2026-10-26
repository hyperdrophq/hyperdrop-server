package domainconn

import (
	"testing"
	"time"
)

func TestDeriveFollowsTheServersOwnFacts(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	fresh := now.Add(-time.Hour).Unix()
	stale := now.Add(-CheckInWindow - time.Second).Unix()
	cases := []struct {
		name string
		f    Facts
		want Connection
	}{
		{"nothing", Facts{}, None},
		{"pending", Facts{Enrolling: true}, PendingApproval},
		{"not yet approved", Facts{Enrolling: true, LastClaimError: "Sign in to approve this free domain"}, PendingApproval},
		{"publication held", Facts{Enrolling: true, LastClaimError: "The free hyperdrop.link address pool is full right now."}, Waiting},
		{"unknown token", Facts{Configured: true, LastUpdate: fresh, LastError: "ddns: the names service does not know this token"}, Unauthorized},
		{"released", Facts{Configured: true, LastUpdate: fresh, LastError: "ddns: the name has been released"}, Unauthorized},
		{"other failure", Facts{Configured: true, LastUpdate: fresh, LastError: "write DNS: budget"}, Failing},
		{"never checked in", Facts{Configured: true}, Silent},
		{"silent", Facts{Configured: true, LastUpdate: stale}, Silent},
		{"connected", Facts{Configured: true, LastUpdate: fresh}, Connected},
	}
	for _, c := range cases {
		if got := Derive(c.f, now); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// The Mac's rule (ServerHealthMonitor), except that a first reading is only
// remembered: speak when the state changes INTO one that needs attention,
// and once more when it is connected again after an announced problem.
func TestNextSpeaksOnAProblemAndOnTheRecoveryAfterIt(t *testing.T) {
	m, n := Next(Memory{}, false, Failing)
	if n != NoNotice || m != (Memory{State: Failing, Attention: true}) {
		t.Fatalf("first meeting: %v %+v", n, m)
	}
	if _, n := Next(m, true, Failing); n != NoNotice {
		t.Fatal("an unchanged problem spoke again")
	}
	m, n = Next(Memory{State: Connected}, true, Silent)
	if n != Problem || !m.Attention {
		t.Fatalf("into a problem: %v %+v", n, m)
	}
	m, n = Next(m, true, Connected)
	if n != Recovered || m.Attention {
		t.Fatalf("recovery: %v %+v", n, m)
	}
	if _, n := Next(Memory{State: PendingApproval}, true, Connected); n != NoNotice {
		t.Fatal("an approval the person made themselves was announced as a recovery")
	}
	if _, n := Next(Memory{State: Connected}, true, Waiting); n != NoNotice {
		t.Fatal("waiting to publish is not an alarm")
	}
}

func TestLabelsAreTheSharedVocabulary(t *testing.T) {
	want := map[Connection]string{None: "No domain", PendingApproval: "Waiting for approval",
		Connected: "Connected", Unauthorized: "Not connected", Silent: "Not checking in",
		Failing: "DNS update failing", Waiting: "Waiting to publish"}
	for c, label := range want {
		if c.Label() != label {
			t.Errorf("%s: %q", c, c.Label())
		}
	}
}
