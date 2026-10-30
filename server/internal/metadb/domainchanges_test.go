package metadb

import (
	"fmt"
	"testing"
	"time"

	"hyperdrop/core/domainconn"
)

func TestRecordDomainChangeKeepsTheBoundedList(t *testing.T) {
	db := openTest(t)
	now := time.Now()
	for i := 0; i < 9; i++ {
		at := now.Add(time.Duration(i) * time.Minute)
		c := domainconn.Change{From: fmt.Sprintf("d%d.example.com", i), To: fmt.Sprintf("d%d.example.com", i+1), At: at}
		if err := db.RecordDomainChange(c, at); err != nil {
			t.Fatal(err)
		}
	}
	got, err := db.DomainChanges(now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != domainconn.ChangesKept || got[0].From != "d1.example.com" || got[len(got)-1].To != "d9.example.com" {
		t.Fatalf("kept %+v", got)
	}
	if got, err := db.DomainChanges(now.Add(8 * 24 * time.Hour)); err != nil || len(got) != 0 {
		t.Fatalf("after a week and more: %+v, %v", got, err)
	}
}

func TestAnUnreadableDomainChangesValueReadsAsNone(t *testing.T) {
	db := openTest(t)
	if err := db.SetSetting(domainChangesSetting, "{not json"); err != nil {
		t.Fatal(err)
	}
	if got, err := db.DomainChanges(time.Now()); err != nil || len(got) != 0 {
		t.Fatalf("%+v, %v", got, err)
	}
	now := time.Now()
	if err := db.RecordDomainChange(domainconn.Change{To: "a.example.com", At: now}, now); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.DomainChanges(now); len(got) != 1 {
		t.Fatalf("%+v", got)
	}
}
