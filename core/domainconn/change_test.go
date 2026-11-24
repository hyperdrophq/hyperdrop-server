package domainconn

import (
	"testing"
	"time"
)

func TestRecordChangeKeepsTheNewestEightOfTheLastWeek(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	var list []Change
	list = RecordChange(list, Change{To: "old.example", At: now.Add(-8 * 24 * time.Hour)}, now)
	if len(list) != 0 {
		t.Fatalf("an 8-day-old change was kept: %v", list)
	}
	for i := 0; i < 10; i++ {
		list = RecordChange(list, Change{To: "d.example", At: now.Add(time.Duration(i-10) * time.Hour)}, now)
	}
	if len(list) != ChangesKept {
		t.Fatalf("kept %d, want %d", len(list), ChangesKept)
	}
	if !list[0].At.Equal(now.Add(-8*time.Hour)) || !list[7].At.Equal(now.Add(-1*time.Hour)) {
		t.Errorf("not the newest eight, oldest first: %v", list)
	}
}

func TestChangesShownDropsAWeekOldChange(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	got := ChangesShown([]Change{
		{To: "a", At: now.Add(-ChangeShownFor)},
		{To: "b", At: now.Add(-ChangeShownFor + time.Minute)},
	}, now)
	if len(got) != 1 || got[0].To != "b" {
		t.Errorf("got %v", got)
	}
}

func TestTheNoticeKeyIsStablePerChange(t *testing.T) {
	at := time.Unix(1_900_000_000, 5)
	c := Change{From: "a.example", To: "b.example", At: at}
	if NoticeOf(c).Key != NoticeOf(c).Key {
		t.Error("key not stable")
	}
	if NoticeOf(c).Key != "domain:1900000000000000005:b.example" {
		t.Errorf("key %q", NoticeOf(c).Key)
	}
	if NoticeOf(Change{To: "b.example", At: at.Add(time.Second)}).Key == NoticeOf(c).Key {
		t.Error("another time shares a key")
	}
}

func TestTheNoticeWordsAMoveAndAFirstAddress(t *testing.T) {
	at := time.Unix(1_900_000_000, 0)
	move := NoticeOf(Change{From: "a.example", To: "b.example", At: at})
	if move.Title != "Your server's address changed" {
		t.Errorf("title %q", move.Title)
	}
	if move.Body != "This HyperDrop server moved from a.example to b.example, and HyperDrop apps follow it to the new address. If no administrator of this server made this change, change your password now: that signs out every other device." {
		t.Errorf("move body %q", move.Body)
	}
	first := NoticeOf(Change{To: "b.example", At: at})
	if first.Body != "This HyperDrop server now uses b.example as its address, and HyperDrop apps follow it there. If no administrator of this server made this change, change your password now: that signs out every other device." {
		t.Errorf("first body %q", first.Body)
	}
}
