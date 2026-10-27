package housekeep

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"hyperdrop/server/internal/metadb"
)

// seal makes shares/ unreadable, so any step that walks it fails loudly.
func seal(t *testing.T, x *fixture) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	shares := filepath.Join(x.dir, "shares")
	if err := os.Chmod(shares, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(shares, 0o755) })
}

// A quiet volume: three shares with content, one expiring in a month, one
// with a scheduled change far off, nothing pending, nothing staged.
func quietVolume(t *testing.T, x *fixture) {
	t.Helper()
	month := x.now.Add(30 * 24 * time.Hour)
	a := x.share(t, metadb.CreateOptions{Name: "a", ExpiresAt: &month})
	b := x.share(t, metadb.CreateOptions{Name: "b"})
	c := x.share(t, metadb.CreateOptions{Name: "c"})
	for _, d := range []metadb.Share{a, b, c} {
		x.upload(t, d.ID, "f", "content")
	}
	if _, err := x.db.Schedule(b.ID, metadb.Scheduled{Kind: metadb.ScheduledExpiry, ApplyAt: month, ExpiresAt: &month}); err != nil {
		t.Fatal(err)
	}
	// One warm-up pass, so the journal retention and optimize have run once.
	x.pass(x.now)
}

func TestAnIdlePassNeverTouchesTheSharesTree(t *testing.T) {
	x := setup(t)
	quietVolume(t, x)
	seal(t, x)
	// Lines reports every count and every failure, so an empty one means the
	// pass neither did work nor reached shares/.
	res := x.pass(x.now.Add(time.Hour))
	if len(res.Lines()) != 0 {
		t.Fatalf("an idle pass has nothing to log: %v", res.Lines())
	}
}

func TestASealedTreeIsDetectedWhenAStepDoesReadIt(t *testing.T) {
	x := setup(t)
	quietVolume(t, x)
	seal(t, x)
	// The boot pass is the one reader of shares/ by design; under the seal
	// it must fail, which proves the seal is real and the idle test above
	// is not passing vacuously.
	if _, err := x.fs.Orphans(func(string) bool { return true }); err == nil {
		t.Fatal("Orphans read a sealed shares/ without error")
	}
	// A sweep that finds a candidate does read the disk: an expired share
	// under the seal surfaces as an error, not as a silent success.
	past := x.now.Add(-time.Hour)
	d := x.share(t, metadb.CreateOptions{Name: "expired", ExpiresAt: &past})
	_ = d
	res := x.pass(x.now)
	if res.ExpiredErr == nil {
		t.Fatalf("removing an expired share's directory under the seal must fail: %+v", res)
	}
}
