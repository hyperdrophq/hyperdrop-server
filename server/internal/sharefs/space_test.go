package sharefs

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func fixedDisk(free, total int64) func(string) (int64, int64, error) {
	return func(string) (int64, int64, error) { return free, total, nil }
}

func TestSpaceReportsTheDiskAndTheReserve(t *testing.T) {
	f := openTest(t)
	f.DiskSpace = fixedDisk(40, 100)
	f.ReservePercent = 10
	s, err := f.Space()
	if err != nil || s.Total != 100 || s.Free != 40 || s.Used != 60 || s.Reserve != 10 {
		t.Fatalf("Space = %+v, %v", s, err)
	}
	f.DiskSpace = fixedDisk(1<<40, 8<<40) // 8 TiB disk: the 1 GiB floor is below 10 percent, so the percentage wins
	if s, _ := f.Space(); s.Reserve != (8<<40)/10 {
		t.Fatalf("reserve on a big disk = %d", s.Reserve)
	}
	f.ReservePercent = 1
	f.DiskSpace = fixedDisk(1<<40, 8<<40) // 1 percent of 8 TiB is 80 GiB, above the floor
	if s, _ := f.Space(); s.Reserve != (8<<40)/100 {
		t.Fatalf("reserve = %d", s.Reserve)
	}
	f.DiskSpace = fixedDisk(1<<30, 10<<30) // 10 GiB disk at 1 percent: the 1 GiB floor applies
	if s, _ := f.Space(); s.Reserve != reserveFloorBytes {
		t.Fatalf("floor not applied: %d", s.Reserve)
	}
	f.ReservePercent = 0
	if s, _ := f.Space(); s.Reserve != 0 {
		t.Fatal("0 disables the reserve")
	}
}

// The default reserve is a flat 1 GiB whatever the disk's size, at most a
// quarter of a small disk.
func TestTheFlatReserveIsOneGiB(t *testing.T) {
	f := openTest(t)
	f.ReservePercent = FlatReserve
	for _, c := range []struct{ total, want int64 }{
		{8 << 40, 1 << 30},   // 8 TiB
		{4 << 40, 1 << 30},   // 4 TiB
		{100 << 30, 1 << 30}, // 100 GiB
		{2 << 30, 512 << 20}, // a 2 GiB volume keeps a quarter
	} {
		f.DiskSpace = fixedDisk(c.total/2, c.total)
		if s, err := f.Space(); err != nil || s.Reserve != c.want {
			t.Errorf("reserve on %d bytes = %d, want %d (%v)", c.total, s.Reserve, c.want, err)
		}
	}
}

func TestReserveAdmitsAgainstFreeMinusOtherHoldsAndTheReserve(t *testing.T) {
	f := openTest(t)
	f.DiskSpace = fixedDisk(100, 1000)
	f.ReservePercent = 10 // reserve 100 on a small disk (no floor below 4 GiB)
	if err := f.Reserve("abcdefghjk", 0); err != nil {
		t.Fatalf("zero bytes: %v", err)
	}
	if err := f.Reserve("abcdefghjk", 1); !errors.Is(err, ErrNoSpace) {
		t.Fatalf("nothing usable above the reserve: %v", err)
	}
	f.DiskSpace = fixedDisk(160, 1000) // usable 60
	if err := f.Reserve("abcdefghjk", 40); err != nil {
		t.Fatal(err)
	}
	err := f.Reserve("abcdefghjm", 30)
	if !errors.Is(err, ErrNoSpace) || !strings.Contains(err.Error(), "already promised") {
		t.Fatalf("other holds count: %v", err)
	}
	if err := f.Reserve("abcdefghjk", 60); err != nil {
		t.Fatal("re-reserving replaces the share's own hold, which is not counted against itself")
	}
	f.ConsumeReservation("abcdefghjk", 50)
	if err := f.Reserve("abcdefghjm", 50); err != nil {
		t.Fatalf("consumed bytes free the hold: %v", err)
	}
	f.ReleaseReservation("abcdefghjm")
	f.ConsumeReservation("abcdefghjk", 10)
	f.resMu.Lock()
	n := len(f.reservations)
	f.resMu.Unlock()
	if n != 0 {
		t.Fatalf("a hold consumed to zero is deleted; %d left", n)
	}
	f.DiskSpace = func(string) (int64, int64, error) { return 0, 0, errors.New("probe failed") }
	if err := f.Reserve("abcdefghjk", 1<<40); err != nil {
		t.Fatalf("a failing probe never blocks: %v", err)
	}
}

// admit is AdmitWrite with the hold given straight back, for the checks that
// only ask whether a write fits.
func admit(f *FS, id string, bytes int64) error {
	h, err := f.AdmitWrite(id, bytes)
	h.Release()
	return err
}

func TestAdmitWriteAndIdleSweep(t *testing.T) {
	f := openTest(t)
	f.DiskSpace = fixedDisk(150, 1000)
	f.ReservePercent = 10
	if err := admit(f, "abcdefghjk", 50); err != nil {
		t.Fatalf("fits: %v", err)
	}
	if err := admit(f, "abcdefghjk", 51); !errors.Is(err, ErrDiskFull) {
		t.Fatalf("dips into the reserve: %v", err)
	}
	if err := admit(f, "abcdefghjk", 1<<62); !errors.Is(err, ErrDiskFull) {
		t.Fatalf("a size near the int64 bound: %v", err)
	}
	if err := f.Reserve("abcdefghjm", 30); err != nil {
		t.Fatal(err)
	}
	if err := admit(f, "abcdefghjk", 25); !errors.Is(err, ErrDiskFull) {
		t.Fatalf("another share's hold counts: %v", err)
	}
	if err := admit(f, "abcdefghjm", 50); err != nil {
		t.Fatalf("a share's own hold does not count against it: %v", err)
	}
	if err := admit(f, "abcdefghjk", -1); err != nil {
		t.Fatalf("unknown size skips the check: %v", err)
	}
	f.ReservePercent = 0
	if err := admit(f, "abcdefghjk", 1<<40); err != nil {
		t.Fatalf("no reserve, no check: %v", err)
	}
	f.resMu.Lock()
	r := f.reservations["abcdefghjm"]
	r.lastActivity = time.Now().Add(-2 * reservationIdle)
	f.reservations["abcdefghjm"] = r
	f.resMu.Unlock()
	f.TouchReservation("nothere")
	if n := f.SweepReservations(); n != 1 {
		t.Fatalf("swept %d", n)
	}
	if err := f.Reserve("abcdefghjk", 1); err != nil {
		t.Fatal(err)
	}
	f.TouchReservation("abcdefghjk")
	if n := f.SweepReservations(); n != 0 {
		t.Fatalf("a touched hold survives: swept %d", n)
	}
}

// chunkReader yields one chunk per Read and pauses between them, so a test
// can tell that the clock moved while a copy was running.
type chunkReader struct{ chunks []string }

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(c.chunks) == 0 {
		return 0, io.EOF
	}
	time.Sleep(time.Millisecond)
	n := copy(p, c.chunks[0])
	c.chunks = c.chunks[1:]
	return n, nil
}

func TestACopyInProgressKeepsItsReservationAlive(t *testing.T) {
	f := openTest(t)
	// Every chunk refreshes the hold, which is what the interval bounds in
	// production and what makes the refresh observable here.
	restore := touchInterval
	t.Cleanup(func() { touchInterval = restore })
	touchInterval = 0
	for _, tc := range []struct {
		name string
		copy func(r io.Reader) error
	}{
		{"Write", func(r io.Reader) error { _, err := f.Write(testID, "w", r); return err }},
	} {
		if err := f.Reserve(testID, 1<<20); err != nil {
			t.Fatal(err)
		}
		f.resMu.Lock()
		before := f.reservations[testID].lastActivity
		f.resMu.Unlock()
		if err := tc.copy(&chunkReader{chunks: []string{"ab", "cd", "ef"}}); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		f.resMu.Lock()
		after := f.reservations[testID].lastActivity
		f.resMu.Unlock()
		if !after.After(before) {
			t.Fatalf("%s left the hold untouched since %v", tc.name, before)
		}
		f.ReleaseReservation(testID)
	}
}

// Writes admitted together cannot each pass on free space the others are
// about to fill: every admitted write holds what it may still write until it
// is released, shrinking as its bytes land (the probe sees those), and a
// write into a reserved share is covered by the reservation instead.
func TestAdmittedWritesHoldTheirBytesUntilReleased(t *testing.T) {
	f := openTest(t)
	f.DiskSpace = fixedDisk(150, 1000) // 50 usable above the reserve of 100
	f.ReservePercent = 10
	first, err := f.AdmitWrite("abcdefghjk", 40)
	if err != nil {
		t.Fatal(err)
	}
	if err := admit(f, "abcdefghjm", 20); !errors.Is(err, ErrDiskFull) {
		t.Fatalf("a second write past what the first holds: %v", err)
	}
	if err := admit(f, "abcdefghjk", 20); !errors.Is(err, ErrDiskFull) {
		t.Fatalf("a second write into the same share: %v", err)
	}
	if _, err := io.Copy(io.Discard, first.Reader(strings.NewReader(strings.Repeat("x", 30)))); err != nil {
		t.Fatal(err)
	}
	f.DiskSpace = fixedDisk(120, 1000) // the 30 landed
	if err := admit(f, "abcdefghjm", 10); err != nil {
		t.Fatalf("the first write holds only what it has left: %v", err)
	}
	if err := admit(f, "abcdefghjm", 11); !errors.Is(err, ErrDiskFull) {
		t.Fatalf("past what is left: %v", err)
	}
	first.Release()
	if err := admit(f, "abcdefghjm", 20); err != nil {
		t.Fatalf("after the release: %v", err)
	}
	if err := f.Reserve("abcdefghjk", 10); err != nil {
		t.Fatal(err)
	}
	covered, err := f.AdmitWrite("abcdefghjk", 10)
	if err != nil {
		t.Fatal(err)
	}
	defer covered.Release()
	if err := admit(f, "abcdefghjm", 10); err != nil {
		t.Fatalf("a write inside a reservation is counted once: %v", err)
	}
	if err := admit(f, "abcdefghjm", 11); !errors.Is(err, ErrDiskFull) {
		t.Fatalf("past the reservation: %v", err)
	}
	var nilHold *WriteHold
	nilHold.Release()
	if nilHold.Reader(strings.NewReader("x")) == nil {
		t.Fatal("a nil hold passes the reader through")
	}
}
