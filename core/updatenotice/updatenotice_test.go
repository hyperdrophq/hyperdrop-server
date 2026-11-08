package updatenotice

import (
	"strings"
	"testing"
)

func keys(ns []Notice) string {
	var k []string
	for _, n := range ns {
		k = append(k, n.Key)
	}
	return strings.Join(k, ",")
}

func TestNothingIsDueWhileCurrentOrUpdatingItself(t *testing.T) {
	if got := Due(Facts{Running: "1.1.0", Latest: "1.1.0", SelfUpdate: Off}); got != nil {
		t.Fatalf("current: %v", got)
	}
	if got := Due(Facts{Running: "1.0.1", Latest: "1.1.0", SelfUpdate: On}); got != nil {
		t.Fatalf("updating itself: %v", got)
	}
	if got := Due(Facts{Running: "1.0.1", SelfUpdate: Off}); got != nil {
		t.Fatalf("no manifest read yet: %v", got)
	}
}

func TestACompatibleReleaseGetsOneNotice(t *testing.T) {
	got := Due(Facts{Running: "1.1.0", Latest: "1.1.1", SelfUpdate: Off})
	if len(got) != 1 {
		t.Fatalf("%v", got)
	}
	want := Notice{Key: "release:1.1.1", Title: "Server update available",
		Body: "HyperDrop Server 1.1.1 is out. Automatic updates are off: update it with Update Server in HyperDrop, or turn them back on."}
	if got[0] != want {
		t.Fatalf("%+v", got[0])
	}
}

func TestEachStateNamesItsOwnWayToUpdate(t *testing.T) {
	for state, want := range map[string]string{
		NAS:    "Update HyperDrop in Package Center on the NAS.",
		Manual: "This server cannot install updates on its own: update it with Update Server in HyperDrop.",
		Off:    "Automatic updates are off: update it with Update Server in HyperDrop, or turn them back on.",
	} {
		got := Due(Facts{Running: "1.1.0", Latest: "1.1.1", SelfUpdate: state})
		if len(got) != 1 || !strings.HasSuffix(got[0].Body, want) {
			t.Errorf("%s: %+v", state, got)
		}
	}
}

func TestAFailureLeadsAndKeepsItsOwnKey(t *testing.T) {
	f := Facts{Running: "1.0.1", Latest: "1.1.0", SelfUpdate: Failed,
		FailedVersion: "1.1.0", FailedReason: "the signature is not from a HyperDrop release key."}
	got := Due(f)
	if keys(got) != "failed:1.1.0" {
		t.Fatalf("%v", keys(got))
	}
	if got[0].Title != "The server could not update itself" ||
		got[0].Body != "HyperDrop Server 1.1.0 did not install: the signature is not from a HyperDrop release key. "+
			"Update it with Update Server in HyperDrop." {
		t.Fatalf("%+v", got[0])
	}
	long := Due(Facts{Running: "1.1.0", Latest: "1.1.1", SelfUpdate: Failed, FailedVersion: "1.1.1",
		FailedReason: strings.Repeat("x", 500)})
	if n := len(long[0].Body); n > 300 {
		t.Fatalf("a long reason makes a %d-byte body", n)
	}
}

// No reminder names a date or says apps stop working: that is the version
// window's verdict, not the update's.
func TestNoReminderCarriesADeadline(t *testing.T) {
	for _, f := range []Facts{
		{Running: "1.2.0", Latest: "1.3.0", SelfUpdate: Off},
		{Running: "1.2.0", Latest: "1.3.0", SelfUpdate: NAS},
		{Running: "1.2.0", Latest: "1.3.0", SelfUpdate: Failed, FailedVersion: "1.2.9"},
	} {
		for _, n := range Due(f) {
			if strings.Contains(n.Body, "stop working") || strings.Contains(n.Title, " by ") || strings.HasPrefix(n.Key, "due") {
				t.Errorf("%+v", n)
			}
		}
	}
}

func TestAFailedCompatibleReleaseIsAnnouncedOnce(t *testing.T) {
	got := Due(Facts{Running: "1.3.0", Latest: "1.3.1", SelfUpdate: Failed, FailedVersion: "1.3.1",
		FailedReason: "the download did not match its checksum"})
	if keys(got) != "failed:1.3.1" {
		t.Fatalf("%v", keys(got))
	}
	// A failure of an OLDER release than the newest still leaves the newest announced.
	got = Due(Facts{Running: "1.3.0", Latest: "1.3.2", SelfUpdate: Failed, FailedVersion: "1.3.1"})
	if keys(got) != "failed:1.3.1,release:1.3.2" {
		t.Fatalf("%v", keys(got))
	}
}

// A box that rolled a failed update back restarts without having read the
// manifest: the failure is announced all the same.
func TestAFailureIsAnnouncedBeforeTheManifestIsRead(t *testing.T) {
	got := Due(Facts{Running: "1.3.0", SelfUpdate: Failed, FailedVersion: "1.3.1",
		FailedReason: "the installer did not bring it up"})
	if keys(got) != "failed:1.3.1" ||
		got[0].Body != "HyperDrop Server 1.3.1 did not install: the installer did not bring it up. Update it with Update Server in HyperDrop." {
		t.Fatalf("%+v", got)
	}
	if got := Due(Facts{Running: "1.3.1", SelfUpdate: Failed, FailedVersion: "1.3.1"}); got != nil {
		t.Fatalf("a failure of the running version: %v", got)
	}
}
