package sharefs

import (
	"fmt"
	"io"
	"syscall"
	"time"

	"hyperdrop/server/internal/bytefmt"
)

const (
	// reservationIdle: a hold with no upload activity this long is dropped
	// by the housekeeping sweep, so a crashed client cannot pin space.
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

type reservation struct {
	bytes        int64
	lastActivity time.Time
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

// reservedByOthersLocked is reservedByOthers for a caller holding resMu.
func (f *FS) reservedByOthersLocked(shareID string) int64 {
	var sum int64
	for id, r := range f.reservations {
		if id != shareID && time.Since(r.lastActivity) <= reservationIdle {
			sum += r.bytes
		}
	}
	return sum
}

// Reserve admits an upload of bytes for the share against the disk: free
// space minus what other uploads in progress were promised minus the
// system reserve. Re-reserving replaces the share's existing hold. A failing
// probe never blocks; the write itself fails if the disk is truly full.
//
// The sum of other holds and the recording of this one happen under ONE
// resMu hold: as separate steps, two creations racing into the last usable
// bytes each sum "nothing promised yet" and are both admitted. The disk
// probe stays outside the lock; a syscall's answer does not change with it.
func (f *FS) Reserve(shareID string, bytes int64) error {
	if bytes <= 0 {
		return nil
	}
	haveProbe := false
	var free, total int64
	if f.DiskSpace != nil {
		if fr, tot, err := f.DiskSpace(f.dataDir); err == nil {
			free, total, haveProbe = fr, tot, true
		}
	}
	f.resMu.Lock()
	defer f.resMu.Unlock()
	if haveProbe {
		promised := f.promisedLocked(shareID)
		usable := free - promised - f.systemReserve(total)
		if bytes > usable {
			if promised > 0 {
				return fmt.Errorf("%w: it has %s usable right now (%s already promised to other uploads in progress) and this upload needs %s",
					ErrNoSpace, fmtBytes(max(usable, 0)), fmtBytes(promised), fmtBytes(bytes))
			}
			return fmt.Errorf("%w: it has %s usable and this upload needs %s. Free up space, or move to a bigger server",
				ErrNoSpace, fmtBytes(max(usable, 0)), fmtBytes(bytes))
		}
	}
	f.reservations[shareID] = reservation{bytes: bytes, lastActivity: time.Now()}
	return nil
}

// WriteHold is one admitted write still landing: what it may yet write,
// counted against every other write's admission until it is released. The
// free-space probe already reflects the bytes it has written, so its hold
// shrinks by them as they pass through Reader. A nil hold (a write no check
// applied to) is valid and holds nothing.
type WriteHold struct {
	f       *FS
	shareID string
	left    int64
}

// AdmitWrite admits a write of a known size into the share against the disk:
// free space minus the system reserve, minus other shares' reservations and
// the other writes still landing, all summed and this write's hold recorded
// under one resMu hold, so parallel writes cannot each pass on a free space
// the others are about to fill. A write into a share that holds a live
// reservation is covered by it and holds nothing extra for the others. A
// negative size means unknown and skips the check; a failing probe never
// blocks.
func (f *FS) AdmitWrite(shareID string, bytes int64) (*WriteHold, error) {
	if f.ReservePercent == 0 || bytes < 0 || f.DiskSpace == nil {
		return nil, nil
	}
	free, total, err := f.DiskSpace(f.dataDir)
	if err != nil {
		return nil, nil
	}
	f.resMu.Lock()
	defer f.resMu.Unlock()
	if bytes > free-f.systemReserve(total)-f.promisedLocked(shareID) {
		return nil, f.diskFullErr()
	}
	h := &WriteHold{f: f, shareID: shareID, left: bytes}
	f.holds[h] = struct{}{}
	return h, nil
}

// promisedLocked is what other uploads may still write: the other shares'
// live reservations, plus the bytes left to land of every write held outside
// a reserved share, whichever share it writes. The caller holds resMu.
func (f *FS) promisedLocked(shareID string) int64 {
	sum := f.reservedByOthersLocked(shareID)
	for h := range f.holds {
		if r, ok := f.reservations[h.shareID]; ok && time.Since(r.lastActivity) <= reservationIdle {
			continue
		}
		sum += h.left
	}
	return sum
}

// Reader passes r through, shrinking the hold by the bytes read.
func (h *WriteHold) Reader(r io.Reader) io.Reader {
	if h == nil {
		return r
	}
	return holdReader{r: r, h: h}
}

// Release ends the hold, whether the write landed or failed.
func (h *WriteHold) Release() {
	if h == nil {
		return
	}
	h.f.resMu.Lock()
	delete(h.f.holds, h)
	h.f.resMu.Unlock()
}

type holdReader struct {
	r io.Reader
	h *WriteHold
}

func (t holdReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if n > 0 {
		t.h.f.resMu.Lock()
		t.h.left = max(t.h.left-int64(n), 0)
		t.h.f.resMu.Unlock()
	}
	return n, err
}

// TouchReservation marks upload activity so a live upload's hold never
// expires under it.
func (f *FS) TouchReservation(shareID string) {
	f.resMu.Lock()
	if r, ok := f.reservations[shareID]; ok {
		r.lastActivity = time.Now()
		f.reservations[shareID] = r
	}
	f.resMu.Unlock()
}

// touchInterval bounds how often a running copy refreshes its share's
// reservation: often enough that a body streaming for hours keeps its hold,
// rarely enough that the refresh costs nothing.
var touchInterval = time.Minute

// reservationToucher refreshes the share's reservation as bytes flow through
// it, so a long body cannot have its hold swept mid-copy.
type reservationToucher struct {
	r    io.Reader
	f    *FS
	id   string
	last time.Time
}

func (t *reservationToucher) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if now := time.Now(); now.Sub(t.last) >= touchInterval {
		t.f.TouchReservation(t.id)
		t.last = now
	}
	return n, err
}

// touching wraps a body so the share's hold is refreshed while it copies.
func (f *FS) touching(id string, r io.Reader) io.Reader {
	return &reservationToucher{r: r, f: f, id: id, last: time.Now()}
}

// ConsumeReservation shrinks a share's hold by bytes that have landed on
// disk, so committed files are not double-counted, on disk and in the hold,
// against other uploads' admission. The hold is deleted at 0.
func (f *FS) ConsumeReservation(shareID string, bytes int64) {
	if bytes <= 0 {
		return
	}
	f.resMu.Lock()
	defer f.resMu.Unlock()
	r, ok := f.reservations[shareID]
	if !ok {
		return
	}
	if r.bytes -= bytes; r.bytes <= 0 {
		delete(f.reservations, shareID)
		return
	}
	r.lastActivity = time.Now()
	f.reservations[shareID] = r
}

// ReleaseReservation releases a share's hold.
func (f *FS) ReleaseReservation(shareID string) {
	f.resMu.Lock()
	delete(f.reservations, shareID)
	f.resMu.Unlock()
}

// SweepReservations shares idle holds and reports how many went.
func (f *FS) SweepReservations() int {
	f.resMu.Lock()
	defer f.resMu.Unlock()
	n := 0
	for id, r := range f.reservations {
		if time.Since(r.lastActivity) > reservationIdle {
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
