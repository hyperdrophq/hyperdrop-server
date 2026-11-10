package sharefs

import (
	"testing"
	"time"
)

// A part nobody touched for the abandoned window is the stalled sweep's, and
// it stops being charged even when no removal told the ledger.
func TestAPartPastTheAbandonedWindowIsNotCharged(t *testing.T) {
	f := openTest(t)
	f.ChargePart(testID, "a.bin", "bob", 600)
	if got := f.StagedBytes("bob"); got != 600 {
		t.Fatalf("charged %d, want 600", got)
	}
	f.AbandonedWindow = time.Nanosecond
	time.Sleep(time.Millisecond)
	if got := f.StagedBytes("bob"); got != 0 {
		t.Fatalf("charged %d past the window, want 0", got)
	}
}

func TestDiscardReleasesAPartsCharge(t *testing.T) {
	f := openTest(t)
	f.ChargePart(testID, "a.bin", "bob", 600)
	if got := f.PartCharge(testID, "a.bin"); got != 600 {
		t.Fatalf("PartCharge = %d, want 600", got)
	}
	f.Discard(testID, "a.bin")
	if got := f.StagedBytes("bob"); got != 0 {
		t.Fatalf("charged %d after the discard", got)
	}
}
