package sharefs

import (
	"errors"
	"testing"
)

func inodes(free, total int64, err error) func(string) (int64, int64, error) {
	return func(string) (int64, int64, error) { return free, total, err }
}

// One account's tiny files must not run the disk out of inodes for everyone, so
// writes stop while the system still has room to work, as they do for bytes.
func TestAWriteStopsAtTheInodeReserve(t *testing.T) {
	f := openTest(t)
	f.DiskSpace = func(string) (int64, int64, error) { return 1 << 40, 2 << 40, nil }
	for _, tc := range []struct {
		free, total int64
		refused     bool
	}{
		{100, 100, false},
		{6, 100, false},
		{5, 100, true},
		{2, 100, true},
		{0, 100, true},
		{51_000, 1_000_000, false},
		{49_000, 1_000_000, true},
	} {
		f.InodeSpace = inodes(tc.free, tc.total, nil)
		hold, err := f.AdmitWrite(testID, "alice", 10)
		hold.Release()
		if got := errors.Is(err, ErrDiskFull); got != tc.refused {
			t.Errorf("%d of %d free: %v, refused want %v", tc.free, tc.total, err, tc.refused)
		}
		anon, err := f.AdmitAnonymousWrite(testID, 10)
		anon.Release()
		if got := errors.Is(err, ErrDiskFull); got != tc.refused {
			t.Errorf("anonymous, %d of %d free: %v, refused want %v", tc.free, tc.total, err, tc.refused)
		}
	}
}

// A filesystem with no fixed inode count, or a probe that fails, blocks nothing:
// the write itself fails if the disk is truly full.
func TestAnUnknownInodeCountBlocksNothing(t *testing.T) {
	f := openTest(t)
	f.DiskSpace = func(string) (int64, int64, error) { return 1 << 40, 2 << 40, nil }
	for _, probe := range []func(string) (int64, int64, error){inodes(0, 0, nil), inodes(0, 0, errors.New("no"))} {
		f.InodeSpace = probe
		hold, err := f.AdmitWrite(testID, "alice", 10)
		if err != nil {
			t.Fatalf("refused: %v", err)
		}
		hold.Release()
	}
}

// The real probe answers on this system, and the volume under a test has room.
func TestTheRealInodeProbeAdmitsAWrite(t *testing.T) {
	f := openTest(t)
	f.DiskSpace = func(string) (int64, int64, error) { return 1 << 40, 2 << 40, nil }
	hold, err := f.AdmitWrite(testID, "alice", 10)
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
	hold.Release()
}
