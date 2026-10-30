package api

import (
	"strconv"
	"testing"
	"time"

	"hyperdrop/core/updatenotice"
)

func TestAServerUpdateReminderIsPushedOnceToAdmins(t *testing.T) {
	r := newPushRig(t) // alice is a user; the seeded admin registers below
	r.register(testToken, "entry-a")
	notices := []updatenotice.Notice{{Key: "release:1.1.1", Title: "Server update available", Body: "b"}}
	r.hd.push.updates = func() []updatenotice.Notice { return notices }
	if sent := r.pass(); len(sent) != 0 {
		t.Fatal("the first pass announced a reminder that was already due")
	}
	notices = append(notices, updatenotice.Notice{Key: "failed:1.1.1", Title: "The server could not update itself", Body: "f"})
	sent := r.pass()
	if len(sent) != 1 {
		t.Fatalf("sent %d, want the admin's one device", len(sent))
	}
	m := r.open(sent[0])
	if m.Kind != "serverUpdate" || m.Title != "The server could not update itself" || m.Body != "f" ||
		m.Thread != "server-update" || m.Tag != "entry-a" || sent[0].CollapseID != "su-failed:1.1.1" {
		t.Fatalf("message %+v collapse %q", m, sent[0].CollapseID)
	}
	if again := r.pass(); len(again) != 0 {
		t.Fatal("a reminder was pushed twice")
	}
	notices = nil // the box updated: nothing due
	if again := r.pass(); len(again) != 0 {
		t.Fatal("pushed with nothing due")
	}
}

func TestAMutedServerUpdateKindStaysQuiet(t *testing.T) {
	r := newPushRig(t)
	r.register(testToken, "entry-a", "serverUpdate")
	var notices []updatenotice.Notice
	r.hd.push.updates = func() []updatenotice.Notice { return notices }
	r.pass()
	notices = []updatenotice.Notice{{Key: "release:1.1.1", Title: "t", Body: "b"}}
	if sent := r.pass(); len(sent) != 0 {
		t.Fatal("a muted kind was sent")
	}
}

// Who to tell is read before the reminder is recorded: when the admins
// cannot be read, nothing is recorded and the next pass sends it.
func TestAReminderWaitsForTheAdminsToBeReadable(t *testing.T) {
	r := newPushRig(t)
	r.register(testToken, "entry-a")
	var notices []updatenotice.Notice
	r.hd.push.updates = func() []updatenotice.Notice { return notices }
	r.pass()
	notices = []updatenotice.Notice{{Key: "release:1.1.1", Title: "t", Body: "b"}}
	read := r.hd.push.adminNames
	r.hd.push.adminNames = func() ([]string, error) { return nil, errInjected }
	for i := range 3 {
		if sent := r.pass(); len(sent) != 0 {
			t.Fatalf("pass %d sent %d without the admins", i, len(sent))
		}
	}
	var mem updateMemory
	if !r.hd.push.loadState(pushStateServer, pushStateUpdate, &mem) || len(mem.Sent) != 0 {
		t.Fatalf("recorded %v while the admins could not be read", mem.Sent)
	}
	r.hd.push.adminNames = read
	if sent := r.pass(); len(sent) != 1 {
		t.Fatalf("once the admins read, sent %d, want the reminder once", len(sent))
	}
	if sent := r.pass(); len(sent) != 0 {
		t.Fatal("the reminder was sent again")
	}
}

// An absence stops the first pass after it from sending, never from
// remembering: a reminder pushed before a long outage is not pushed again
// when it falls due once more after the manifest is read again.
func TestAnAbsenceDoesNotRepeatAReminder(t *testing.T) {
	r := newPushRig(t)
	r.register(testToken, "entry-a")
	notices := []updatenotice.Notice{}
	r.hd.push.updates = func() []updatenotice.Notice { return notices }
	r.pass()
	notices = []updatenotice.Notice{{Key: "release:1.1.1", Title: "t", Body: "b"}}
	if sent := r.pass(); len(sent) != 1 {
		t.Fatalf("sent %d, want the reminder once", len(sent))
	}
	stale := time.Now().Add(-2 * pushAbsence).Unix()
	if err := r.hd.db.SetPushState(pushStateServer, pushStateAlive, strconv.FormatInt(stale, 10)); err != nil {
		t.Fatal(err)
	}
	back := r.restart()
	if !back.amnesia {
		t.Fatal("a stale heartbeat was trusted")
	}
	back.updates = r.hd.push.updates
	notices = nil // the manifest is not read yet
	if sent := r.passOf(back); len(sent) != 0 {
		t.Fatalf("the pass after the absence sent %d", len(sent))
	}
	if back.amnesia {
		t.Fatal("the absence did not end")
	}
	notices = []updatenotice.Notice{{Key: "release:1.1.1", Title: "t", Body: "b"}}
	if sent := r.passOf(back); len(sent) != 0 {
		t.Fatal("a reminder pushed before the absence was pushed again")
	}
	notices = append(notices, updatenotice.Notice{Key: "failed:1.1.2", Title: "t7", Body: "b7"})
	if sent := r.passOf(back); len(sent) != 1 || r.open(sent[0]).Title != "t7" {
		t.Fatal("a new reminder after the absence was not pushed once")
	}
}

// A key still due is never evicted by the bound, however many newer keys
// come and go.
func TestAStillDueReminderOutlivesTheBound(t *testing.T) {
	r := newPushRig(t)
	r.register(testToken, "entry-a")
	live := updatenotice.Notice{Key: "release:1.1.1", Title: "t", Body: "b"}
	notices := []updatenotice.Notice{live}
	r.hd.push.updates = func() []updatenotice.Notice { return notices }
	r.pass()
	for i := range sentUpdateKeys + 4 {
		key := "k" + strconv.Itoa(i)
		notices = []updatenotice.Notice{live, {Key: key, Title: "n", Body: "b"}}
		sent := r.pass()
		if len(sent) != 1 || r.open(sent[0]).Title != "n" || sent[0].CollapseID != "su-"+key {
			t.Fatalf("pass %d sent %d, want only the new %s", i, len(sent), key)
		}
	}
	notices = []updatenotice.Notice{live}
	if sent := r.pass(); len(sent) != 0 {
		t.Fatal("a still-due reminder was evicted and pushed again")
	}
}
