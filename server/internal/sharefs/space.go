package sharefs

import (
	"fmt"
	"io"
	"log"
	"math"
	"syscall"
	"time"

	"hyperdrop/server/internal/bytefmt"
)

const (
	// reservationIdle: a reservation whose share has not landed
	// reservationProgress bytes in this long is dropped by the housekeeping
	// sweep and stops counting against other uploads, so neither a crashed
	// client nor a trickling one can pin space.
	reservationIdle = 15 * time.Minute
	// reserveFloorBytes is the flat reserve, and the floor under a
	// percentage one on disks above 4 GiB: logs, package caches and journal
	// growth do not scale with disk size.
	reserveFloorBytes int64 = 1 << 30
)

// FlatReserve as ReservePercent keeps a flat reserveFloorBytes free, at most
// a quarter of the disk, whatever the disk's size. It is the server's
// default: a percentage of a large disk holds back far more than the system
// needs.
const FlatReserve = -1

const (
	// defaultWriteWindow is the most an admitted write promises other
	// uploads at once: its next bytes, admitted again window by window as
	// they land (FS.WriteWindow overrides it).
	defaultWriteWindow int64 = 64 << 20
	// minWindow is the smallest window a write is given while more than
	// that is left to land: below it the room is taken as full, so a crowded
	// pool cannot turn one upload into a probe per byte.
	minWindow int64 = 1 << 20
)

// reservationProgress is what a share's uploads must newly land per
// reservationIdle to keep its reservation live. A variable so a test can
// lower it.
var reservationProgress int64 = 64 << 20

// reservation is a share's budget for the upload its creation announced. A
// write admitted into the share draws on it at once, and what it cannot
// cover holds rolling windows like any other write.
type reservation struct {
	// owner is the account whose ledger the reservation is charged to.
	owner string
	// bytes is what is left to draw.
	bytes int64
	// lastActivity is when the reservation was made or last earned its
	// life: reservationProgress new bytes landing since the previous
	// refresh.
	lastActivity time.Time
	// landed counts the new bytes landed since lastActivity.
	landed int64
}

func (r reservation) live() bool { return time.Since(r.lastActivity) <= reservationIdle }

// writeWindow is the FS's window.
func (f *FS) writeWindow() int64 {
	if f.WriteWindow > 0 {
		return f.WriteWindow
	}
	return defaultWriteWindow
}

// statfsSpace reads the filesystem stats for dir. Field widths differ
// between darwin and Linux, hence the explicit conversions.
func statfsSpace(dir string) (free, total int64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, 0, err
	}
	bsize := int64(st.Bsize)
	return int64(st.Bavail) * bsize, int64(st.Blocks) * bsize, nil
}

// Space is the disk holding the data directory.
type Space struct {
	Total, Used, Free int64
	// Reserve is the bytes kept free for the system: 1 GiB (FlatReserve),
	// or the larger of the configured percentage and, on disks above 4 GiB,
	// the 1 GiB floor.
	Reserve int64
}

// Space reports the disk. The caller adds what the shares hold from the
// database's counters.
func (f *FS) Space() (Space, error) {
	free, total, err := f.DiskSpace(f.dataDir)
	if err != nil {
		return Space{}, err
	}
	return Space{Total: total, Used: total - free, Free: free, Reserve: f.systemReserve(total)}, nil
}

// systemReserve is the bytes kept free for the system.
func (f *FS) systemReserve(total int64) int64 {
	if f.ReservePercent == FlatReserve {
		return min(reserveFloorBytes, total/4)
	}
	if f.ReservePercent <= 0 {
		return 0
	}
	r := total * int64(f.ReservePercent) / 100
	if total > 4*reserveFloorBytes && r < reserveFloorBytes {
		r = reserveFloorBytes
	}
	return r
}

// errHeld is the refusal of a window other uploads' promises leave no room
// for. Like the two below it names no figure, since strangers and guests
// read it; the figures go to the server log (refusalNote).
var errHeld = fmt.Errorf("%w: other uploads in progress hold the space this upload needs next; try again in a while", ErrNoSpace)

// errAccountHeld refuses a signed-in window past the account's half.
var errAccountHeld = fmt.Errorf("%w: this account's uploads in progress already hold as much of the server's free space as one account may; try again once they land", ErrNoSpace)

// errAnonHeld refuses a stranger's window past the anonymous half.
var errAnonHeld = fmt.Errorf("%w: uploads to inboxes in progress hold as much of the server's free space as they may; try again in a while", ErrNoSpace)

// liveReservationLocked is the share's reservation while it is live. One
// past reservationIdle that the sweep has not reached yet is deleted here,
// never revived. The caller holds resMu.
func (f *FS) liveReservationLocked(shareID string) (reservation, bool) {
	r, ok := f.reservations[shareID]
	if ok && !r.live() {
		delete(f.reservations, shareID)
		return reservation{}, false
	}
	return r, ok
}

// promisedLocked is what uploads hold right now, apart from the reservation
// of except ("" for none): every live reservation's budget plus what every
// write still landing holds, its drawn budget and its window. The caller
// holds resMu.
func (f *FS) promisedLocked(except string) int64 {
	var sum int64
	for id, r := range f.reservations {
		if id != except && r.live() {
			sum = addSat(sum, r.bytes)
		}
	}
	for h := range f.holds {
		sum = addSat(sum, addSat(h.covered, h.held))
	}
	return sum
}

// addSat adds two non-negative sizes, stopping at the int64 bound rather
// than wrapping: every size here is bounded by a disk probe, and a sum that
// wrapped negative would read as room.
func addSat(a, b int64) int64 {
	if a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

// ledgerLocked is what one account holds against everyone else: its live
// reservations' budgets, less the reservation of except, plus what its
// signed-in writes still landing hold. Strangers' writes into the account's
// inboxes are the anonymous pool's, never the account's. The caller holds
// resMu.
func (f *FS) ledgerLocked(owner, except string) int64 {
	var sum int64
	for id, r := range f.reservations {
		if id != except && r.owner == owner && r.live() {
			sum = addSat(sum, r.bytes)
		}
	}
	for h := range f.holds {
		if !h.anon && h.owner == owner {
			sum = addSat(sum, addSat(h.covered, h.held))
		}
	}
	return sum
}

// anonHeldLocked is what strangers' writes hold. The caller holds resMu.
func (f *FS) anonHeldLocked() int64 {
	var sum int64
	for h := range f.holds {
		if h.anon {
			sum = addSat(sum, h.held)
		}
	}
	return sum
}

// Reserve admits an upload of bytes for the owner's share against the disk:
// the whole upload must fit free space minus what other uploads in
// progress hold minus the system reserve. What is recorded is clamped to
// the owner's room: one account holds at most half the usable space (free
// minus the system reserve) across all its reservations and writes, so the
// clamp never refuses, and a reservation clamped to nothing records none.
// Re-reserving replaces the share's existing reservation. A failing probe
// never blocks and records nothing: every write is then admitted on its
// own, and the write itself fails if the disk is truly full.
//
// The sum of other holds and the recording of this one happen under ONE
// resMu hold: as separate steps, two creations racing into the last usable
// bytes each sum "nothing promised yet" and are both admitted. The disk
// probe stays outside the lock; a syscall's answer does not change with it.
func (f *FS) Reserve(shareID, owner string, bytes int64) error {
	if bytes <= 0 {
		return nil
	}
	if f.DiskSpace == nil {
		return nil
	}
	free, total, err := f.DiskSpace(f.dataDir)
	if err != nil {
		return nil
	}
	f.resMu.Lock()
	defer f.resMu.Unlock()
	usableDisk := free - f.systemReserve(total)
	promised := f.promisedLocked(shareID)
	usable := usableDisk - promised
	if bytes > usable {
		if promised > 0 {
			return fmt.Errorf("%w: it has %s usable right now (%s already promised to other uploads in progress) and this upload needs %s",
				ErrNoSpace, fmtBytes(max(usable, 0)), fmtBytes(promised), fmtBytes(bytes))
		}
		return fmt.Errorf("%w: it has %s usable and this upload needs %s. Free up space, or move to a bigger server",
			ErrNoSpace, fmtBytes(max(usable, 0)), fmtBytes(bytes))
	}
	keep := min(bytes, max(half(usableDisk)-f.ledgerLocked(owner, shareID), 0))
	if keep <= 0 {
		delete(f.reservations, shareID)
		return nil
	}
	f.reservations[shareID] = reservation{owner: owner, bytes: keep, lastActivity: time.Now()}
	return nil
}

// WriteHold is one admitted write still landing. What it promises other
// uploads is what it drew from its share's reservation (covered) and a
// window of the rest (held, at most the FS's write window), never all it
// has left: an upload that stalls or trickles holds one window, not the
// disk. The free-space probe already reflects the bytes it has written, so
// covered and then the window shrink by them as they pass through Reader,
// and the next window is admitted against a fresh probe when both are
// spent. A nil hold (a write no check applied to) is valid and holds
// nothing.
type WriteHold struct {
	f       *FS
	shareID string
	// owner is the account whose ledger the hold is charged to, "" for a
	// stranger's write.
	owner string
	// anon marks a write from a stranger (a Receive Inbox upload), whose
	// windows together stay within half the usable space.
	anon bool
	// left is the bytes still to land; covered is what is still unlanded of
	// what the write drew from the reservation; held is the window promised
	// now.
	left, covered, held int64
}

// AdmitWrite admits the owner's write of a known size into the share
// against the disk: the whole write must fit free space minus the system
// reserve minus what other uploads hold, so an upload that can never fit is
// refused at once. The write draws on the share's live reservation up to
// its size, and holds a window of what that does not cover within the
// owner's room: one account holds at most half the usable space (free minus
// the system reserve) across its reservations and writes. A room too small
// for a window refuses a write that draws nothing with ErrNoSpace; a write
// that draws a budget is admitted on that budget alone, and its first
// window is checked against the account's room when the budget has been
// read (nextWindow), refused there with ErrNoSpace. The sums and the
// recording happen under one resMu hold, so parallel writes cannot each pass
// on a free space the others are about to fill. A negative size means
// unknown and skips the check; a failing probe never blocks.
func (f *FS) AdmitWrite(shareID, owner string, bytes int64) (*WriteHold, error) {
	return f.admitWrite(shareID, owner, bytes, false)
}

// AdmitAnonymousWrite is AdmitWrite for a stranger's write: it draws on no
// reservation and is charged to no account, and its windows and every other
// anonymous write's together promise at most half the usable space, at
// admission and at each window, so dripping inbox uploads cannot crowd out
// the owner's own.
func (f *FS) AdmitAnonymousWrite(shareID string, bytes int64) (*WriteHold, error) {
	return f.admitWrite(shareID, "", bytes, true)
}

func (f *FS) admitWrite(shareID, owner string, bytes int64, anon bool) (*WriteHold, error) {
	if bytes < 0 || f.DiskSpace == nil {
		return nil, nil
	}
	free, total, err := f.DiskSpace(f.dataDir)
	if err != nil {
		return nil, nil
	}
	var note string
	defer func() {
		if note != "" {
			log.Print(note)
		}
	}()
	f.resMu.Lock()
	defer f.resMu.Unlock()
	usable := free - f.systemReserve(total)
	if bytes > usable-f.promisedLocked(shareID) {
		return nil, f.diskFullErr()
	}
	h := &WriteHold{f: f, shareID: shareID, owner: owner, anon: anon, left: bytes}
	var r reservation
	haveRes := false
	if !anon {
		r, haveRes = f.liveReservationLocked(shareID)
		if haveRes {
			h.covered = min(bytes, r.bytes)
		}
	}
	// A write that draws on its reservation starts on that budget alone
	// when its pool has no room for a window yet: the budget is already
	// the account's, and the window is asked for again, against the pool,
	// once the drawn bytes have landed and left the ledger.
	window, err := h.windowLocked(usable)
	if err != nil && h.covered > 0 {
		window, err = 0, nil
	}
	if err != nil {
		note = f.refusalNote(h, usable)
		return nil, err
	}
	if haveRes {
		r.bytes -= h.covered
		f.reservations[shareID] = r
	}
	h.held = window
	f.holds[h] = struct{}{}
	return h, nil
}

// half is the most one pool may promise of usable bytes: the anonymous
// pool, or any one account.
func half(usable int64) int64 {
	usable = max(usable, 0)
	return usable - usable/2
}

// windowLocked is the window the hold may take next on usable bytes: what
// is left past its drawn budget, at most the write window and the room its
// pool has left (the anonymous pool's, or the account's). A room under
// minWindow, or under what is left when less is left, refuses it. The
// caller holds resMu, and the hold's own window is spent or not yet
// recorded.
func (h *WriteHold) windowLocked(usable int64) (int64, error) {
	f := h.f
	want := min(h.left-h.covered, f.writeWindow())
	if want <= 0 {
		return 0, nil
	}
	room, refusal := half(usable)-f.ledgerLocked(h.owner, ""), errAccountHeld
	if h.anon {
		room, refusal = half(usable)-f.anonHeldLocked(), errAnonHeld
	}
	if room < min(want, minWindow) {
		return 0, refusal
	}
	return min(want, room), nil
}

// refusalNote is the log line with the figures behind a refused window,
// which the refusal itself never names. The caller holds resMu and logs
// the line once it has let go of it.
func (f *FS) refusalNote(h *WriteHold, usable int64) string {
	pool, held := "account", f.ledgerLocked(h.owner, "")
	if h.anon {
		pool, held = "anonymous", f.anonHeldLocked()
	}
	return fmt.Sprintf("disk: refused a write window in share %s: %d bytes left to land, %d usable, %d promised, %d held by the %s pool",
		h.shareID, h.left, usable, f.promisedLocked(""), held, pool)
}

// Reader passes r through, spending the hold's drawn budget and then its
// window by the bytes read, and admitting the next window before reading
// past it. A refused window fails the read with an error wrapping
// ErrNoSpace.
func (h *WriteHold) Reader(r io.Reader) io.Reader {
	if h == nil {
		return r
	}
	return holdReader{r: r, h: h}
}

// Release ends the hold, whether the write landed or failed. What it drew
// from the reservation and Reader did not read goes back to the
// reservation while that is live, so a failed write leaves the budget for
// its retry.
func (h *WriteHold) Release() {
	if h == nil {
		return
	}
	f := h.f
	f.resMu.Lock()
	defer f.resMu.Unlock()
	if _, ok := f.holds[h]; !ok {
		return
	}
	delete(f.holds, h)
	if h.covered > 0 {
		if r, ok := f.liveReservationLocked(h.shareID); ok {
			r.bytes += h.covered
			f.reservations[h.shareID] = r
		}
		h.covered = 0
	}
}

// nextWindow admits the hold's next window against a fresh probe: it must
// fit what the disk has usable less every promise, and the account's or the
// anonymous room. The probe runs outside resMu, the sum and the record under
// it. A failing probe never blocks.
func (h *WriteHold) nextWindow() error {
	free, total, err := h.f.DiskSpace(h.f.dataDir)
	h.f.resMu.Lock()
	if err != nil {
		h.held = min(h.left, h.f.writeWindow())
		h.f.resMu.Unlock()
		return nil
	}
	usable := free - h.f.systemReserve(total)
	window, werr := h.windowLocked(usable)
	if werr == nil && window > usable-h.f.promisedLocked("") {
		werr = errHeld
	}
	if werr != nil {
		note := h.f.refusalNote(h, usable)
		h.f.resMu.Unlock()
		log.Print(note)
		return werr
	}
	h.held = window
	h.f.resMu.Unlock()
	return nil
}

type holdReader struct {
	r io.Reader
	h *WriteHold
}

func (t holdReader) Read(p []byte) (int, error) {
	f := t.h.f
	f.resMu.Lock()
	allowed, left := t.h.covered+t.h.held, t.h.left
	f.resMu.Unlock()
	if allowed == 0 && left > 0 {
		if err := t.h.nextWindow(); err != nil {
			return 0, err
		}
		f.resMu.Lock()
		allowed = t.h.held
		f.resMu.Unlock()
	}
	// A read never runs past what the hold may write now. Once nothing is
	// left to land, a read goes on uncapped: all it can find is an overrun
	// the caller refuses.
	if allowed > 0 && int64(len(p)) > allowed {
		p = p[:allowed]
	}
	n, err := t.r.Read(p)
	if n > 0 {
		f.resMu.Lock()
		spent := int64(n)
		c := min(spent, t.h.covered)
		t.h.covered -= c
		t.h.held = max(t.h.held-(spent-c), 0)
		t.h.left = max(t.h.left-spent, 0)
		f.resMu.Unlock()
	}
	return n, err
}

// landingReader credits each read's bytes to the share's reservation as
// they arrive, so a body into a fresh part that takes longer than
// reservationIdle keeps the reservation while it lands at the rate.
type landingReader struct {
	r  io.Reader
	f  *FS
	id string
}

func (l landingReader) Read(p []byte) (int, error) {
	n, err := l.r.Read(p)
	l.f.landed(l.id, int64(n))
	return n, err
}

// landing wraps a body bound for a fresh part, every byte of which is new.
func (f *FS) landing(id string, r io.Reader) io.Reader { return landingReader{r: r, f: f, id: id} }

// landed records new bytes of the share's uploads: bytes into a fresh part,
// or the bytes of a range the part's ranges did not hold yet. Rewritten
// bytes never count. The reservation's life is refreshed only once
// reservationProgress new bytes have landed since the previous refresh, so
// an upload too slow to earn it loses the reservation after reservationIdle
// and goes on with each write admitted on its own. A reservation already
// past reservationIdle is deleted, never revived.
func (f *FS) landed(shareID string, bytes int64) {
	if bytes <= 0 {
		return
	}
	f.resMu.Lock()
	defer f.resMu.Unlock()
	r, ok := f.liveReservationLocked(shareID)
	if !ok {
		return
	}
	if r.landed += bytes; r.landed >= reservationProgress {
		r.lastActivity, r.landed = time.Now(), 0
	}
	f.reservations[shareID] = r
}

// ReleaseReservation releases a share's reservation.
func (f *FS) ReleaseReservation(shareID string) {
	f.resMu.Lock()
	delete(f.reservations, shareID)
	f.resMu.Unlock()
}

// SweepReservations drops the reservations past reservationIdle and reports
// how many went.
func (f *FS) SweepReservations() int {
	f.resMu.Lock()
	defer f.resMu.Unlock()
	n := 0
	for id, r := range f.reservations {
		if !r.live() {
			delete(f.reservations, id)
			n++
		}
	}
	return n
}

// fmtBytes renders a size the way a person reads one: decimal units,
// matching the app's own formatter, so a refusal and the app agree on the
// number.
func fmtBytes(b int64) string { return bytefmt.Decimal(b) }
