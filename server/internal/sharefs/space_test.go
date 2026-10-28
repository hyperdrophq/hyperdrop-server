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

// ownerOf names a distinct account for each share, for the checks that are
// not about what one account may hold.
func ownerOf(id string) string { return "owner-" + id }

// reserved is the share's reservation budget, 0 for none.
func reserved(f *FS, id string) int64 {
	f.resMu.Lock()
	defer f.resMu.Unlock()
	return f.reservations[id].bytes
}

func TestReserveAdmitsAgainstFreeMinusOtherHoldsAndTheReserve(t *testing.T) {
	f := openTest(t)
	f.DiskSpace = fixedDisk(100, 1000)
	f.ReservePercent = 10 // reserve 100 on a small disk (no floor below 4 GiB)
	if err := f.Reserve("abcdefghjk", "alice", 0); err != nil {
		t.Fatalf("zero bytes: %v", err)
	}
	if err := f.Reserve("abcdefghjk", "alice", 1); !errors.Is(err, ErrNoSpace) {
		t.Fatalf("nothing usable above the reserve: %v", err)
	}
	f.DiskSpace = fixedDisk(160, 1000) // usable 60, so one account holds at most 30
	if err := f.Reserve("abcdefghjk", "alice", 25); err != nil {
		t.Fatal(err)
	}
	err := f.Reserve("abcdefghjm", "bob", 40)
	if !errors.Is(err, ErrNoSpace) || !strings.Contains(err.Error(), "already promised") {
		t.Fatalf("other holds count: %v", err)
	}
	if err := f.Reserve("abcdefghjk", "alice", 60); err != nil {
		t.Fatal("re-reserving replaces the share's own reservation, which is not counted against itself")
	}
	if got := reserved(f, "abcdefghjk"); got != 30 {
		t.Fatalf("a reservation past the account's half is clamped to it: %d", got)
	}
	if err := f.Reserve("abcdefghjm", "bob", 30); err != nil {
		t.Fatalf("another account's half: %v", err)
	}
	if err := f.Reserve("abcdefghjn", "carol", 1); !errors.Is(err, ErrNoSpace) {
		t.Fatalf("nothing left: %v", err)
	}
	f.ReleaseReservation("abcdefghjm")
	if got := reserved(f, "abcdefghjm"); got != 0 {
		t.Fatalf("released: %d", got)
	}
	f.DiskSpace = func(string) (int64, int64, error) { return 0, 0, errors.New("probe failed") }
	f.ReleaseReservation("abcdefghjk")
	if err := f.Reserve("abcdefghjk", "alice", 1<<40); err != nil || reserved(f, "abcdefghjk") != 0 {
		t.Fatalf("a failing probe never blocks and records nothing: %v, %d", err, reserved(f, "abcdefghjk"))
	}
}

// admit is AdmitWrite with the hold given straight back, for the checks that
// only ask whether a write fits. Each share writes as its own account.
func admit(f *FS, id string, bytes int64) error {
	h, err := f.AdmitWrite(id, ownerOf(id), bytes)
	h.Release()
	return err
}

func TestAdmitWriteAndIdleSweep(t *testing.T) {
	f := openTest(t)
	f.DiskSpace = fixedDisk(150, 1000) // 50 usable, so one account holds at most 25
	f.ReservePercent = 10
	if err := admit(f, "abcdefghjk", 25); err != nil {
		t.Fatalf("fits: %v", err)
	}
	if err := admit(f, "abcdefghjk", 26); !errors.Is(err, ErrNoSpace) || errors.Is(err, ErrDiskFull) {
		t.Fatalf("past the account's half: %v", err)
	}
	if err := admit(f, "abcdefghjk", 51); !errors.Is(err, ErrDiskFull) {
		t.Fatalf("dips into the reserve: %v", err)
	}
	if err := admit(f, "abcdefghjk", 1<<62); !errors.Is(err, ErrDiskFull) {
		t.Fatalf("a size near the int64 bound: %v", err)
	}
	if err := f.Reserve("abcdefghjm", ownerOf("abcdefghjm"), 20); err != nil {
		t.Fatal(err)
	}
	if err := admit(f, "abcdefghjk", 31); !errors.Is(err, ErrDiskFull) {
		t.Fatalf("another share's reservation counts: %v", err)
	}
	if err := admit(f, "abcdefghjm", 25); err != nil {
		t.Fatalf("a write drawing on its own reservation: %v", err)
	}
	if err := admit(f, "abcdefghjk", -1); err != nil {
		t.Fatalf("unknown size skips the check: %v", err)
	}
	f.ReservePercent = 0
	if err := admit(f, "abcdefghjk", 1<<40); err != nil {
		t.Fatalf("no reserve, no check: %v", err)
	}
	age(f, "abcdefghjm", 2*reservationIdle)
	f.landed("nothere", reservationProgress)
	if n := f.SweepReservations(); n != 1 {
		t.Fatalf("swept %d", n)
	}
	if err := f.Reserve("abcdefghjk", "alice", 1); err != nil {
		t.Fatal(err)
	}
	age(f, "abcdefghjk", reservationIdle-time.Minute)
	f.landed("abcdefghjk", reservationProgress)
	age(f, "abcdefghjk", reservationIdle-time.Minute)
	if n := f.SweepReservations(); n != 0 {
		t.Fatalf("a reservation that earned its life survives: swept %d", n)
	}
	age(f, "abcdefghjk", 2*time.Minute)
	f.landed("abcdefghjk", reservationProgress)
	f.resMu.Lock()
	_, kept := f.reservations["abcdefghjk"]
	f.resMu.Unlock()
	if kept {
		t.Fatal("progress revived a reservation past reservationIdle")
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

// lastActivity reads a reservation's last refresh.
func lastActivity(f *FS, id string) time.Time {
	f.resMu.Lock()
	defer f.resMu.Unlock()
	return f.reservations[id].lastActivity
}

func TestBytesIntoAFreshPartRenewAReservation(t *testing.T) {
	f := openTest(t)
	// Two bytes earn a refresh here, as reservationProgress bytes do in
	// production, so the copy's six bytes refresh the reservation.
	restore := reservationProgress
	t.Cleanup(func() { reservationProgress = restore })
	reservationProgress = 2
	if err := f.Reserve(testID, "alice", 1<<20); err != nil {
		t.Fatal(err)
	}
	age(f, testID, 10*time.Minute)
	before := lastActivity(f, testID)
	if _, err := f.Write(testID, "w", &chunkReader{chunks: []string{"ab", "cd", "ef"}}); err != nil {
		t.Fatal(err)
	}
	if after := lastActivity(f, testID); !after.After(before) {
		t.Fatalf("Write left the reservation untouched since %v", before)
	}
}

// Writes admitted together cannot each pass on free space the others are
// about to fill: every admitted write holds its window until it is
// released, shrinking as its bytes land (the probe sees those), and a write
// drawing on its share's reservation holds what it drew instead.
func TestAdmittedWritesHoldTheirBytesUntilReleased(t *testing.T) {
	f := openTest(t)
	f.DiskSpace = fixedDisk(200, 1000) // 100 usable above the reserve of 100
	f.ReservePercent = 10
	first, err := f.AdmitWrite("abcdefghjk", "alice", 40)
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.AdmitWrite("abcdefghjm", "bob", 40)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Release()
	if err := admit(f, "abcdefghjn", 21); !errors.Is(err, ErrDiskFull) {
		t.Fatalf("a third write past what the two hold: %v", err)
	}
	if err := admit(f, "abcdefghjn", 20); err != nil {
		t.Fatalf("what is left: %v", err)
	}
	if _, err := io.Copy(io.Discard, first.Reader(strings.NewReader(strings.Repeat("x", 30)))); err != nil {
		t.Fatal(err)
	}
	f.DiskSpace = fixedDisk(170, 1000) // the 30 landed
	if err := admit(f, "abcdefghjn", 20); err != nil {
		t.Fatalf("the first write holds only what it has left: %v", err)
	}
	if err := admit(f, "abcdefghjn", 21); !errors.Is(err, ErrDiskFull) {
		t.Fatalf("past what is left: %v", err)
	}
	first.Release()
	if err := admit(f, "abcdefghjn", 30); err != nil {
		t.Fatalf("after the release: %v", err)
	}
	if err := f.Reserve("abcdefghjk", "alice", 10); err != nil {
		t.Fatal(err)
	}
	covered, err := f.AdmitWrite("abcdefghjk", "alice", 10)
	if err != nil {
		t.Fatal(err)
	}
	defer covered.Release()
	if err := admit(f, "abcdefghjn", 20); err != nil {
		t.Fatalf("a write inside a reservation is counted once: %v", err)
	}
	if err := admit(f, "abcdefghjn", 21); !errors.Is(err, ErrDiskFull) {
		t.Fatalf("past the reservation: %v", err)
	}
	var nilHold *WriteHold
	nilHold.Release()
	if nilHold.Reader(strings.NewReader("x")) == nil {
		t.Fatal("a nil hold passes the reader through")
	}
}
