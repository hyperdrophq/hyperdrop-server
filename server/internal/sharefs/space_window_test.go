package sharefs

import (
	"bytes"
	"errors"
	"io"
	"math"
	"strings"
	"testing"
	"time"
)

const (
	mib int64 = 1 << 20
	gib int64 = 1 << 30
)

// held reads a hold's drawn budget, window and what it has left, under the
// lock the reader writes them under.
func held(h *WriteHold) (covered, window, left int64) {
	h.f.resMu.Lock()
	defer h.f.resMu.Unlock()
	return h.covered, h.held, h.left
}

// promised is what every upload holds.
func promised(f *FS) int64 {
	f.resMu.Lock()
	defer f.resMu.Unlock()
	return f.promisedLocked("")
}

// ledger is what one account holds.
func ledger(f *FS, owner string) int64 {
	f.resMu.Lock()
	defer f.resMu.Unlock()
	return f.ledgerLocked(owner, "")
}

// age moves a reservation's last refresh back by d.
func age(f *FS, id string, d time.Duration) {
	f.resMu.Lock()
	r := f.reservations[id]
	r.lastActivity = r.lastActivity.Add(-d)
	f.reservations[id] = r
	f.resMu.Unlock()
}

// hasDigit reports whether a refusal names a figure.
func hasDigit(s string) bool { return strings.ContainsAny(s, "0123456789") }

// bigDisk is 10 GiB usable above the flat 1 GiB reserve.
func bigDisk(f *FS) {
	f.DiskSpace = fixedDisk(11*gib, 100*gib)
	f.ReservePercent = FlatReserve
}

func TestAHoldPromisesAtMostTheWindow(t *testing.T) {
	f := openTest(t)
	bigDisk(f)
	h, err := f.AdmitWrite("abcdefghjk", "alice", 9*gib)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Release()
	if _, w, left := held(h); w != defaultWriteWindow || left != 9*gib {
		t.Fatalf("held %d with %d left, want the %d window of 9 GiB", w, left, defaultWriteWindow)
	}
	if p := promised(f); p != defaultWriteWindow {
		t.Fatalf("promised %d, want one window", p)
	}
	small, err := f.AdmitWrite("abcdefghjm", "bob", 10)
	if err != nil {
		t.Fatal(err)
	}
	defer small.Release()
	if _, w, _ := held(small); w != 10 {
		t.Fatalf("a write below the window holds its size: %d", w)
	}
}

// Two writes of 9 GiB in progress on a disk with 10 GiB usable leave room
// for a third: each promises one window, not what it has left.
func TestTwoLargeWritesInProgressDoNotBlockAThird(t *testing.T) {
	f := openTest(t)
	bigDisk(f)
	for _, id := range []string{"abcdefghjk", "abcdefghjm"} {
		h, err := f.AdmitWrite(id, ownerOf(id), 9*gib)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		defer h.Release()
	}
	if err := admit(f, "abcdefghjn", 100*mib); err != nil {
		t.Fatalf("a 100 MiB write beside two dripping 9 GiB ones: %v", err)
	}
	if err := f.Reserve("abcdefghjn", "carol", 100*mib); err != nil {
		t.Fatalf("a 100 MiB reservation beside them: %v", err)
	}
}

// The whole write must still fit the disk as it stands: only what it holds
// against others is a window.
func TestAWriteLargerThanUsableSpaceIsRefusedAtAdmission(t *testing.T) {
	f := openTest(t)
	bigDisk(f)
	if err := admit(f, "abcdefghjk", 10*gib+1); !errors.Is(err, ErrDiskFull) {
		t.Fatalf("one byte past usable: %v", err)
	}
	if err := admit(f, "abcdefghjk", 10*gib); err != nil {
		t.Fatalf("exactly usable: %v", err)
	}
	h, err := f.AdmitWrite("abcdefghjk", "alice", 9*gib)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Release()
	if err := admit(f, "abcdefghjm", 10*gib-defaultWriteWindow+1); !errors.Is(err, ErrDiskFull) {
		t.Fatalf("past usable less the other write's window: %v", err)
	}
}

func TestTheReaderAdmitsTheNextWindowAsBytesLand(t *testing.T) {
	f := openTest(t)
	f.WriteWindow = 10
	f.DiskSpace = fixedDisk(150, 1000) // 50 usable above the reserve of 100
	f.ReservePercent = 10
	h, err := f.AdmitWrite("abcdefghjk", "alice", 25)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Release()
	r := h.Reader(strings.NewReader(strings.Repeat("x", 25)))
	buf := make([]byte, 64)
	n, err := r.Read(buf)
	if err != nil || n != 10 {
		t.Fatalf("a read stops at the window: %d %v", n, err)
	}
	if _, w, left := held(h); w != 0 || left != 15 {
		t.Fatalf("after one window: held %d, left %d", w, left)
	}
	if n, err := r.Read(buf); err != nil || n != 10 {
		t.Fatalf("the second window: %d %v", n, err)
	}
	if n, err := r.Read(buf); err != nil || n != 5 {
		t.Fatalf("the last window is what is left: %d %v", n, err)
	}
	if _, w, left := held(h); w != 0 || left != 0 {
		t.Fatalf("landed: held %d, left %d", w, left)
	}
	if n, err := r.Read(buf); n != 0 || err != io.EOF {
		t.Fatalf("past the end: %d %v", n, err)
	}
}

// A window other uploads leave no room for fails the read, with a refusal
// that names no figure.
func TestARefusedWindowFailsTheRead(t *testing.T) {
	f := openTest(t)
	f.WriteWindow = 10
	f.DiskSpace = fixedDisk(150, 1000) // 50 usable
	f.ReservePercent = 10
	h, err := f.AdmitWrite("abcdefghjk", "alice", 40)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Release()
	r := h.Reader(strings.NewReader(strings.Repeat("x", 40)))
	if _, err := io.ReadFull(r, make([]byte, 10)); err != nil {
		t.Fatal(err)
	}
	// The window is spent, so two other accounts may reserve all but 5.
	if err := f.Reserve("abcdefghjm", "bob", 25); err != nil {
		t.Fatal(err)
	}
	if err := f.Reserve("abcdefghjn", "carol", 20); err != nil {
		t.Fatal(err)
	}
	_, err = r.Read(make([]byte, 10))
	if !errors.Is(err, ErrNoSpace) || hasDigit(err.Error()) {
		t.Fatalf("a window past what is left: %v", err)
	}
	f.ReleaseReservation("abcdefghjn")
	if n, err := r.Read(make([]byte, 10)); err != nil || n != 10 {
		t.Fatalf("once the space is back: %d %v", n, err)
	}
	f.DiskSpace = func(string) (int64, int64, error) { return 0, 0, errors.New("probe failed") }
	if n, err := r.Read(make([]byte, 10)); err != nil || n != 10 {
		t.Fatalf("a failing probe never blocks: %d %v", n, err)
	}
}

// A refused window fails Write like any read error, and its part goes.
func TestARefusedWindowFailsTheWrite(t *testing.T) {
	f := openTest(t)
	f.WriteWindow = 10
	f.DiskSpace = fixedDisk(150, 1000)
	f.ReservePercent = 10
	h, err := f.AdmitWrite(testID, "alice", 20)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Release()
	body := &chunkReader{chunks: []string{strings.Repeat("x", 10), strings.Repeat("x", 10)}}
	// The disk fills from elsewhere while the first window lands.
	gate := &hookReader{r: body, after: 10, hook: func() { f.DiskSpace = fixedDisk(105, 1000) }}
	if _, err := f.Write(testID, "w", h.Reader(gate)); !errors.Is(err, ErrNoSpace) {
		t.Fatalf("Write = %v, want ErrNoSpace", err)
	}
	if n, err := f.PartSize(testID, "w"); err != nil || n != 0 {
		t.Fatalf("the part stayed: %d %v", n, err)
	}
}

// hookReader runs hook once after bytes have passed through it.
type hookReader struct {
	r     io.Reader
	after int
	seen  int
	hook  func()
}

func (h *hookReader) Read(p []byte) (int, error) {
	n, err := h.r.Read(p)
	h.seen += n
	if h.hook != nil && h.seen >= h.after {
		h.hook()
		h.hook = nil
	}
	return n, err
}

// A reservation lives while its share's uploads newly land
// reservationProgress bytes per reservationIdle; a slower one is swept and
// stops counting.
func TestAReservationIsEarnedByProgress(t *testing.T) {
	restore := reservationProgress
	t.Cleanup(func() { reservationProgress = restore })
	reservationProgress = 100
	f := openTest(t)
	f.DiskSpace = fixedDisk(1150, 10000) // 150 usable above the reserve of 1000
	f.ReservePercent = 10
	for _, tc := range []struct {
		name  string
		body  int
		alive bool
	}{
		{"below the rate", 99, false},
		{"at the rate", 100, true},
	} {
		if err := f.Reserve(testID, "alice", 100); err != nil {
			t.Fatal(err)
		}
		age(f, testID, 10*time.Minute)
		if _, err := f.Write(testID, "w", strings.NewReader(strings.Repeat("x", tc.body))); err != nil {
			t.Fatal(err)
		}
		age(f, testID, 6*time.Minute)
		err := f.Reserve("abcdefghjm", "bob", 100)
		if tc.alive && !errors.Is(err, ErrNoSpace) {
			t.Fatalf("%s: the reservation stopped counting: %v", tc.name, err)
		}
		if !tc.alive && err != nil {
			t.Fatalf("%s: an unearned reservation still counts: %v", tc.name, err)
		}
		f.ReleaseReservation("abcdefghjm")
		swept := f.SweepReservations()
		if want := map[bool]int{true: 0, false: 1}[tc.alive]; swept != want {
			t.Fatalf("%s: swept %d, want %d", tc.name, swept, want)
		}
		f.ReleaseReservation(testID)
	}
}

// Only bytes the part's ranges did not hold yet are progress: a re-sent
// range renews nothing, and a resumed chunk earns its unseen tail.
func TestResendingARangeRenewsNothing(t *testing.T) {
	restore := reservationProgress
	t.Cleanup(func() { reservationProgress = restore })
	reservationProgress = 10
	f := openTest(t)
	if err := f.Reserve(testID, "alice", 1<<20); err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("x"), 20)
	put := func(start, end int64) {
		t.Helper()
		if _, err := f.WriteRange(testID, "big.bin", bytes.NewReader(data[start:end]), Range{start, end}, 20, "session-a", nil); err != nil {
			t.Fatalf("range %d-%d: %v", start, end, err)
		}
	}
	renewed := func() bool { return time.Since(lastActivity(f, testID)) < time.Minute }
	age(f, testID, 10*time.Minute)
	put(0, 10)
	if !renewed() {
		t.Fatal("ten new bytes did not renew")
	}
	age(f, testID, 10*time.Minute)
	put(0, 10)
	if renewed() {
		t.Fatal("a re-sent range renewed the reservation")
	}
	put(5, 15)
	if renewed() {
		t.Fatal("five new bytes renewed a reservation that needs ten")
	}
	put(15, 20)
	if !renewed() {
		t.Fatal("the resumed tails' ten new bytes did not renew")
	}
}

// Repeated whole-disk reservations from one account hold at most half the
// usable space: the rest stays for everyone else.
func TestRepeatedWholeDiskReservationsLeaveOthersHalf(t *testing.T) {
	f := openTest(t)
	bigDisk(f)
	if err := f.Reserve("abcdefghjk", "alice", 10*gib); err != nil {
		t.Fatalf("the first: %v", err)
	}
	if got := reserved(f, "abcdefghjk"); got != 5*gib {
		t.Fatalf("clamped to %d, want the half", got)
	}
	if err := f.Reserve("abcdefghjm", "alice", 10*gib); !errors.Is(err, ErrNoSpace) {
		t.Fatalf("a second whole-disk reservation does not fit: %v", err)
	}
	if err := f.Reserve("abcdefghjn", "alice", 5*gib); err != nil || reserved(f, "abcdefghjn") != 0 {
		t.Fatalf("a reservation past the account's half is clamped, never refused: %v, %d", err, reserved(f, "abcdefghjn"))
	}
	if got := ledger(f, "alice"); got != 5*gib {
		t.Fatalf("alice holds %d", got)
	}
	if err := f.Reserve("abcdefghjp", "bob", 5*gib); err != nil || reserved(f, "abcdefghjp") != 5*gib {
		t.Fatalf("another account's half: %v", err)
	}
}

// One account's writes in progress, across all its shares, hold at most
// half the usable space; another account keeps the other half.
func TestOneAccountsWritesHoldAtMostHalf(t *testing.T) {
	f := openTest(t)
	f.DiskSpace = fixedDisk(2*gib, 100*gib) // 1 GiB usable
	f.ReservePercent = FlatReserve
	ids := []string{"abcdefgh01", "abcdefgh02", "abcdefgh03", "abcdefgh04", "abcdefgh05",
		"abcdefgh06", "abcdefgh07", "abcdefgh08", "abcdefgh09"}
	for i, id := range ids {
		h, err := f.AdmitWrite(id, "alice", 100*mib)
		if i < 8 {
			if err != nil {
				t.Fatalf("write %d: %v", i, err)
			}
			defer h.Release()
			continue
		}
		if !errors.Is(err, ErrNoSpace) || hasDigit(err.Error()) {
			h.Release()
			t.Fatalf("a window past the account's half: %v", err)
		}
	}
	if got := ledger(f, "alice"); got != gib/2 {
		t.Fatalf("alice holds %d", got)
	}
	h, err := f.AdmitWrite("abcdefgh10", "bob", gib/2)
	if err != nil {
		t.Fatalf("another account's write of half: %v", err)
	}
	h.Release()
}

// A write draws on its share's reservation at admission, and what the
// reservation cannot cover holds windows everyone sees: a 1-byte
// reservation hides nothing.
func TestAWriteDrawsOnItsReservation(t *testing.T) {
	f := openTest(t)
	bigDisk(f)
	if err := f.Reserve("abcdefghjk", "alice", 1); err != nil {
		t.Fatal(err)
	}
	h, err := f.AdmitWrite("abcdefghjk", "alice", 9*gib)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Release()
	if c, w, _ := held(h); c != 1 || w != defaultWriteWindow {
		t.Fatalf("drew %d and holds %d", c, w)
	}
	if got := reserved(f, "abcdefghjk"); got != 0 {
		t.Fatalf("the reservation has %d left", got)
	}
	if p := promised(f); p != defaultWriteWindow+1 {
		t.Fatalf("promised %d", p)
	}
	if err := admit(f, "abcdefghjm", 10*gib-defaultWriteWindow); !errors.Is(err, ErrDiskFull) {
		t.Fatalf("the stream past the reservation is visible: %v", err)
	}
	if err := admit(f, "abcdefghjm", 10*gib-defaultWriteWindow-1); err != nil {
		t.Fatalf("what is left: %v", err)
	}

	// An honest upload reserving less than half draws its files from the
	// reservation and holds nothing more.
	if err := f.Reserve("abcdefghjn", "carol", 300*mib); err != nil {
		t.Fatal(err)
	}
	before := promised(f)
	for i := 0; i < 3; i++ {
		file, err := f.AdmitWrite("abcdefghjn", "carol", 100*mib)
		if err != nil {
			t.Fatalf("file %d: %v", i, err)
		}
		defer file.Release()
		if _, w, _ := held(file); w != 0 {
			t.Fatalf("file %d holds a window of %d inside its reservation", i, w)
		}
	}
	if reserved(f, "abcdefghjn") != 0 || promised(f) != before {
		t.Fatalf("the files moved %d out of the reservation and changed the promise to %d from %d",
			300*mib-reserved(f, "abcdefghjn"), promised(f), before)
	}
}

// A write that fails gives back what it drew and did not land.
func TestAFailedWriteRefundsItsDraw(t *testing.T) {
	f := openTest(t)
	f.DiskSpace = fixedDisk(1000, 1000)
	f.ReservePercent = 10 // 900 usable
	if err := f.Reserve(testID, "alice", 100); err != nil {
		t.Fatal(err)
	}
	h, err := f.AdmitWrite(testID, "alice", 60)
	if err != nil {
		t.Fatal(err)
	}
	if got := reserved(f, testID); got != 40 {
		t.Fatalf("drew %d", 100-got)
	}
	if _, err := io.CopyN(io.Discard, h.Reader(strings.NewReader(strings.Repeat("x", 60))), 20); err != nil {
		t.Fatal(err)
	}
	h.Release()
	if got := reserved(f, testID); got != 80 {
		t.Fatalf("after the failed write the reservation has %d, want 80", got)
	}
	h.Release()
	if got := reserved(f, testID); got != 80 {
		t.Fatalf("a second release refunded again: %d", got)
	}
}

// Strangers' windows together promise at most half the usable space, so the
// owner's own writes and reservations keep the other half, and the system
// reserve is never promised.
func TestAnonymousWritesHoldAtMostHalfTheUsableSpace(t *testing.T) {
	f := openTest(t)
	f.DiskSpace = fixedDisk(2*gib, 100*gib) // 1 GiB usable above the flat 1 GiB
	f.ReservePercent = FlatReserve
	var anon []*WriteHold
	for i := 0; i < int(gib/2/defaultWriteWindow); i++ {
		h, err := f.AdmitAnonymousWrite("abcdefghjk", 100*mib)
		if err != nil {
			t.Fatalf("anonymous write %d: %v", i, err)
		}
		defer h.Release()
		anon = append(anon, h)
	}
	if h, err := f.AdmitAnonymousWrite("abcdefghjm", 100*mib); !errors.Is(err, ErrNoSpace) || hasDigit(err.Error()) {
		h.Release()
		t.Fatalf("a window past half the usable space: %v", err)
	}
	if got := ledger(f, ""); got != 0 {
		t.Fatalf("strangers' writes are charged to an account: %d", got)
	}
	owner, err := f.AdmitWrite("abcdefghjn", "alice", gib/2)
	if err != nil {
		t.Fatalf("the owner's write of half the usable space: %v", err)
	}
	defer owner.Release()
	room := gib - gib/2 - defaultWriteWindow
	if err := f.Reserve("abcdefghjp", "bob", room+1); !errors.Is(err, ErrNoSpace) {
		t.Fatalf("a reservation into the system reserve: %v", err)
	}
	if err := f.Reserve("abcdefghjp", "bob", room); err != nil {
		t.Fatalf("a reservation of what is left: %v", err)
	}
	if p := promised(f); p != gib {
		t.Fatalf("promised %d, want exactly the usable space", p)
	}
	f.ReleaseReservation("abcdefghjp")

	// A spent anonymous window is admitted again only within the half.
	r := anon[0].Reader(strings.NewReader(strings.Repeat("x", int(100*mib))))
	if _, err := io.CopyN(io.Discard, r, defaultWriteWindow); err != nil {
		t.Fatal(err)
	}
	late, err := f.AdmitAnonymousWrite("abcdefghjm", defaultWriteWindow)
	if err != nil {
		t.Fatalf("the spent window's room: %v", err)
	}
	defer late.Release()
	if _, err := r.Read(make([]byte, 1)); !errors.Is(err, ErrNoSpace) {
		t.Fatalf("the next anonymous window past the half: %v", err)
	}
	late.Release()
	if n, err := r.Read(make([]byte, 1)); err != nil || n != 1 {
		t.Fatalf("once the half has room: %d %v", n, err)
	}
	if err := admit(f, "abcdefghjq", room); err != nil {
		t.Fatalf("a signed-in write is not held to the anonymous half: %v", err)
	}
}

// A stranger's window is what is left, at most the write window and the
// anonymous room, so a file that fits in the half is not refused for being
// larger than the room left for one window.
func TestAStrangersWindowShrinksToTheAnonymousRoom(t *testing.T) {
	f := openTest(t)
	f.DiskSpace = fixedDisk(gib+100*mib, 100*gib) // 100 MiB usable, 50 MiB for strangers
	f.ReservePercent = FlatReserve
	h, err := f.AdmitAnonymousWrite("abcdefghjk", 60*mib)
	if err != nil {
		t.Fatalf("a 60 MiB file on a 50 MiB half: %v", err)
	}
	defer h.Release()
	if _, w, _ := held(h); w != 50*mib {
		t.Fatalf("window %d, want the 50 MiB room", w)
	}
	if h2, err := f.AdmitAnonymousWrite("abcdefghjm", mib); !errors.Is(err, ErrNoSpace) {
		h2.Release()
		t.Fatalf("no anonymous room left: %v", err)
	}
	if err := admit(f, "abcdefghjm", 50*mib); err != nil {
		t.Fatalf("the owner's half: %v", err)
	}
	if h3, err := f.AdmitAnonymousWrite("abcdefghjn", 101*mib); !errors.Is(err, ErrDiskFull) {
		h3.Release()
		t.Fatalf("a file larger than the disk: %v", err)
	}
}

// A write larger than its share's clamped reservation starts on the drawn
// budget while the account has no room for a window, and asks for the
// window once that budget has landed: the reservation is already the
// account's, so the write is never refused for holding it.
func TestAWriteLargerThanItsClampedReservationIsAdmitted(t *testing.T) {
	f := openTest(t)
	f.DiskSpace = fixedDisk(1100, 10000) // 100 usable above the reserve of 1000, 50 per account
	f.ReservePercent = 10
	if err := f.Reserve("abcdefghjk", "alice", 70); err != nil || reserved(f, "abcdefghjk") != 50 {
		t.Fatalf("clamped to %d: %v", reserved(f, "abcdefghjk"), err)
	}
	h, err := f.AdmitWrite("abcdefghjk", "alice", 70)
	if err != nil {
		t.Fatalf("the whole size beside its clamped reservation: %v", err)
	}
	defer h.Release()
	if c, w, _ := held(h); c != 50 || w != 0 {
		t.Fatalf("drew %d and holds %d", c, w)
	}
	if got := ledger(f, "alice"); got != 50 {
		t.Fatalf("alice holds %d, want her half once", got)
	}
	r := h.Reader(strings.NewReader(strings.Repeat("x", 70)))
	if n, err := io.Copy(io.Discard, r); err != nil || n != 70 {
		t.Fatalf("the write lands %d: %v", n, err)
	}
}

// Two shares of one account: the second's reservation is clamped below its
// file, and the file still lands, its window waiting for its budget.
func TestASecondShareLargerThanItsClampLands(t *testing.T) {
	f := openTest(t)
	f.DiskSpace = fixedDisk(1100, 10000) // 100 usable, 50 per account
	f.ReservePercent = 10
	if err := f.Reserve("abcdefghjk", "alice", 30); err != nil {
		t.Fatal(err)
	}
	if err := f.Reserve("abcdefghjm", "alice", 40); err != nil || reserved(f, "abcdefghjm") != 20 {
		t.Fatalf("the second share clamped to %d: %v", reserved(f, "abcdefghjm"), err)
	}
	h, err := f.AdmitWrite("abcdefghjm", "alice", 40)
	if err != nil {
		t.Fatalf("the second share's file: %v", err)
	}
	defer h.Release()
	if n, err := io.Copy(io.Discard, h.Reader(strings.NewReader(strings.Repeat("x", 40)))); err != nil || n != 40 {
		t.Fatalf("the second file lands %d: %v", n, err)
	}
	// A write with no budget of its own still meets the account's half.
	if h2, err := f.AdmitWrite("abcdefghjn", "alice", 21); !errors.Is(err, ErrNoSpace) {
		h2.Release()
		t.Fatalf("a window past the account's half: %v", err)
	}
}

// A body into a fresh part earns its reservation while it lands, not only
// once it ends, so a long one keeps the reservation alive mid-body.
func TestALongBodyRenewsItsReservationMidBody(t *testing.T) {
	restore := reservationProgress
	t.Cleanup(func() { reservationProgress = restore })
	reservationProgress = 2
	f := openTest(t)
	if err := f.Reserve(testID, "alice", 1<<20); err != nil {
		t.Fatal(err)
	}
	age(f, testID, 14*time.Minute)
	body := &midBodyCheck{chunks: []string{"ab", "cd", "ef"}, check: func() time.Duration {
		return time.Since(lastActivity(f, testID))
	}}
	if _, err := f.Write(testID, "w", body); err != nil {
		t.Fatal(err)
	}
	if body.seen > time.Minute {
		t.Fatalf("mid-body the reservation was last renewed %v ago", body.seen)
	}
}

// midBodyCheck yields its chunks and, on its last one, records check(): the
// state while the body is still landing.
type midBodyCheck struct {
	chunks []string
	check  func() time.Duration
	seen   time.Duration
}

func (m *midBodyCheck) Read(p []byte) (int, error) {
	if len(m.chunks) == 0 {
		return 0, io.EOF
	}
	if len(m.chunks) == 1 {
		m.seen = m.check()
	}
	n := copy(p, m.chunks[0])
	m.chunks = m.chunks[1:]
	return n, nil
}

// A failing probe records no reservation, whatever size a client asks for,
// so no sum of reservations can pass the int64 bound; the sums stop at it
// in any case.
func TestReservationsCannotOverflowThePromise(t *testing.T) {
	f := openTest(t)
	f.ReservePercent = 10
	f.DiskSpace = func(string) (int64, int64, error) { return 0, 0, errors.New("probe failed") }
	for _, id := range []string{"abcdefghjk", "abcdefghjm"} {
		if err := f.Reserve(id, "alice", math.MaxInt64); err != nil || reserved(f, id) != 0 {
			t.Fatalf("%s: %v, %d", id, err, reserved(f, id))
		}
	}
	if p := promised(f); p != 0 {
		t.Fatalf("promised %d", p)
	}
	f.resMu.Lock()
	for _, id := range []string{"abcdefghjk", "abcdefghjm"} {
		f.reservations[id] = reservation{owner: "alice", bytes: math.MaxInt64/2 + 1, lastActivity: time.Now()}
	}
	f.resMu.Unlock()
	if p := promised(f); p != math.MaxInt64 {
		t.Fatalf("the sum wrapped to %d", p)
	}
	if l := ledger(f, "alice"); l != math.MaxInt64 {
		t.Fatalf("the ledger wrapped to %d", l)
	}
}

// A write admitted on its drawn budget alone meets the account's half at its
// first window: if the account has filled its half meanwhile, that window is
// refused, which is the one gate after a small draw.
func TestAWriteOnItsBudgetAloneIsRefusedAtItsFirstWindow(t *testing.T) {
	f := openTest(t)
	f.DiskSpace = fixedDisk(1100, 10000) // 100 usable, 50 per account
	f.ReservePercent = 10
	if err := f.Reserve("abcdefghjk", "alice", 10); err != nil {
		t.Fatal(err)
	}
	h, err := f.AdmitWrite("abcdefghjk", "alice", 60)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Release()
	if c, w, _ := held(h); c != 10 || w != 0 {
		t.Fatalf("drew %d and holds %d, want the budget alone", c, w)
	}
	// The account fills its half while the budget lands.
	if err := f.Reserve("abcdefghjm", "alice", 50); err != nil || reserved(f, "abcdefghjm") != 40 {
		t.Fatalf("the second reservation clamped to %d: %v", reserved(f, "abcdefghjm"), err)
	}
	r := h.Reader(strings.NewReader(strings.Repeat("x", 60)))
	if n, err := io.ReadFull(r, make([]byte, 10)); err != nil || n != 10 {
		t.Fatalf("the drawn budget: %d %v", n, err)
	}
	_, err = r.Read(make([]byte, 10))
	if !errors.Is(err, ErrNoSpace) || hasDigit(err.Error()) {
		t.Fatalf("the first window past the account's half: %v", err)
	}
}
