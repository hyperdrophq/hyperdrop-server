package metadb

import (
	"testing"
	"time"
)

func TestTheIntegrityScanRecordReadsBack(t *testing.T) {
	db := openTest(t)
	if _, ok, err := db.LastIntegrityScan(); ok || err != nil {
		t.Fatalf("a fresh volume: ok=%v err=%v, want no record", ok, err)
	}
	s := IntegrityScan{At: at.Add(123 * time.Nanosecond), Files: 5800, Missing: 2}
	if err := db.RecordIntegrityScan(s); err != nil {
		t.Fatal(err)
	}
	got, ok, err := db.LastIntegrityScan()
	if err != nil || !ok || !got.At.Equal(s.At) || got.Files != s.Files || got.Missing != s.Missing {
		t.Fatalf("LastIntegrityScan = %+v, %v, %v; want %+v", got, ok, err, s)
	}
	var raw string
	if err := db.r.QueryRow(`SELECT value FROM meta WHERE key = 'integrity_scan'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if want := `{"at":1789819200000000123,"files":5800,"missing":2}`; raw != want {
		t.Fatalf("stored %s, want %s", raw, want)
	}
	next := IntegrityScan{At: at.Add(time.Hour), Files: 5801}
	if err := db.RecordIntegrityScan(next); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := db.LastIntegrityScan(); !got.At.Equal(next.At) || got.Missing != 0 {
		t.Fatalf("after a second record: %+v, want %+v", got, next)
	}
}

// An unreadable record reads as none, which owes a scan.
func TestAnUnreadableIntegrityRecordReadsAsNone(t *testing.T) {
	db := openTest(t)
	if _, err := db.w.Exec(`INSERT INTO meta(key, value) VALUES('integrity_scan', 'not json')`); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := db.LastIntegrityScan(); ok || err != nil {
		t.Fatalf("ok=%v err=%v, want no record and no error", ok, err)
	}
}
