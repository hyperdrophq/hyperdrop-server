package sharefs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// payload is n deterministic bytes that differ at every offset a test cuts.
func payload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i/251)
	}
	return b
}

func sum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func write(t *testing.T, f *FS, data []byte, rg Range, session string) RangeState {
	t.Helper()
	st, err := f.WriteRange(testID, "big.bin", bytes.NewReader(data[rg.Start:rg.End]), rg,
		int64(len(data)), session, nil)
	if err != nil {
		t.Fatalf("WriteRange(%v): %v", rg, err)
	}
	return st
}

func storedBytes(t *testing.T, f *FS, rel string) []byte {
	t.Helper()
	fh, _, err := f.Open(testID, rel)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	b, err := io.ReadAll(fh)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRangesInAnyOrderCompleteThePart(t *testing.T) {
	f := openTest(t)
	data := payload(30)
	if st := write(t, f, data, Range{20, 30}, "s1"); st.Complete || len(st.Missing) != 1 || st.Missing[0] != (Range{0, 20}) {
		t.Fatalf("after the tail: %+v", st)
	}
	if st := write(t, f, data, Range{0, 10}, "s1"); st.Complete || st.Prefix != 10 || st.Missing[0] != (Range{10, 20}) {
		t.Fatalf("after the head: %+v", st)
	}
	st := write(t, f, data, Range{10, 20}, "s1")
	if !st.Complete || st.Received != 30 {
		t.Fatalf("after the middle: %+v", st)
	}
	c, err := f.CommitRanged(testID, "big.bin", 30, "s1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Size != 30 || c.SHA256 != sum(data) {
		t.Fatalf("committed %+v, want size 30 sha %s", c, sum(data))
	}
	if got := storedBytes(t, f, "big.bin"); !bytes.Equal(got, data) {
		t.Fatalf("stored %v", got)
	}
	for _, ext := range []string{"", partSessionExt, partRangesExt} {
		if exists(filepath.Join(shareDir(f, testID), partRel("big.bin")+ext)) {
			t.Errorf("staging %q left behind after the commit", ext)
		}
	}
}

func TestParallelRangesAllLand(t *testing.T) {
	f := openTest(t)
	const chunk, chunks = 4096, 16
	data := payload(chunk * chunks)
	var wg sync.WaitGroup
	complete := make(chan bool, chunks)
	for i := range chunks {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rg := Range{int64(i * chunk), int64((i + 1) * chunk)}
			st, err := f.WriteRange(testID, "big.bin", bytes.NewReader(data[rg.Start:rg.End]), rg,
				int64(len(data)), "s1", nil)
			if err != nil {
				t.Errorf("chunk %d: %v", i, err)
			}
			complete <- st.Complete
		}(i)
	}
	wg.Wait()
	close(complete)
	n := 0
	for c := range complete {
		if c {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d chunks saw the upload complete, want exactly the last one", n)
	}
	c, err := f.CommitRanged(testID, "big.bin", int64(len(data)), "s1", nil)
	if err != nil || c.SHA256 != sum(data) {
		t.Fatalf("commit %+v %v", c, err)
	}
}

func TestAnOverlappingRangeRewritesTheSameBytes(t *testing.T) {
	f := openTest(t)
	data := payload(20)
	write(t, f, data, Range{0, 12}, "s1")
	write(t, f, data, Range{8, 20}, "s1")
	st := write(t, f, data, Range{0, 12}, "s1")
	if !st.Complete || st.Received != 20 {
		t.Fatalf("%+v", st)
	}
	if c, err := f.CommitRanged(testID, "big.bin", 20, "s1", nil); err != nil || c.SHA256 != sum(data) {
		t.Fatalf("commit %+v %v", c, err)
	}
}

func TestABodyLongerThanItsRangeRecordsNothing(t *testing.T) {
	f := openTest(t)
	data := payload(20)
	_, err := f.WriteRange(testID, "big.bin", bytes.NewReader(data[0:11]), Range{0, 10}, 20, "s1", nil)
	if !errors.Is(err, ErrBadRequest) {
		t.Fatalf("err = %v, want a bad request", err)
	}
	if st, ok := f.PartRanges(testID, "big.bin", "s1"); !ok || st.Received != 0 {
		t.Fatalf("recorded %+v", st)
	}
}

func TestAShortBodyRecordsWhatLanded(t *testing.T) {
	f := openTest(t)
	data := payload(20)
	st, err := f.WriteRange(testID, "big.bin", bytes.NewReader(data[0:6]), Range{0, 10}, 20, "s1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if st.Received != 6 || st.Missing[0] != (Range{6, 20}) {
		t.Fatalf("%+v", st)
	}
}

func TestANewSessionDiscardsTheRangedPart(t *testing.T) {
	f := openTest(t)
	data := payload(20)
	write(t, f, data, Range{0, 10}, "s1")
	st := write(t, f, data, Range{10, 20}, "s2")
	if st.Received != 10 || st.Missing[0] != (Range{0, 10}) {
		t.Fatalf("the new session kept the old one's bytes: %+v", st)
	}
	if _, ok := f.PartRanges(testID, "big.bin", "s1"); ok {
		t.Fatal("the old session still has a part")
	}
}

func TestOnCreateRunsOnceForAFreshPartBeforeItsBytes(t *testing.T) {
	f := openTest(t)
	data := payload(20)
	calls := 0
	onCreate := func() error {
		calls++
		if exists(filepath.Join(shareDir(f, testID), partRel("big.bin"))) {
			t.Error("the part existed before onCreate ran")
		}
		return nil
	}
	for _, rg := range []Range{{0, 10}, {10, 20}} {
		if _, err := f.WriteRange(testID, "big.bin", bytes.NewReader(data[rg.Start:rg.End]), rg, 20, "s1", onCreate); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("onCreate ran %d times", calls)
	}
}

// The one crash a ranged write can leave: the bytes are synced into the part
// and the process dies before the range is recorded. The range must read as
// missing, and sending it again must commit the right file.
func TestARangeIsRecordedOnlyAfterItsBytesSync(t *testing.T) {
	f := openTest(t)
	data := payload(20)
	write(t, f, data, Range{0, 10}, "s1")
	crash := errors.New("crash")
	beforeRecord = func() error { return crash }
	_, err := f.WriteRange(testID, "big.bin", bytes.NewReader(data[10:20]), Range{10, 20}, 20, "s1", nil)
	beforeRecord = nil
	if !errors.Is(err, crash) {
		t.Fatalf("err = %v", err)
	}
	st, ok := f.PartRanges(testID, "big.bin", "s1")
	if !ok || st.Complete || st.Missing[0] != (Range{10, 20}) {
		t.Fatalf("after the crash: %+v %v", st, ok)
	}
	if st := write(t, f, data, Range{10, 20}, "s1"); !st.Complete {
		t.Fatalf("after the retry: %+v", st)
	}
	if c, err := f.CommitRanged(testID, "big.bin", 20, "s1", nil); err != nil || c.SHA256 != sum(data) {
		t.Fatalf("commit %+v %v", c, err)
	}
}

func TestCommitRangedRefusesAPartWithGaps(t *testing.T) {
	f := openTest(t)
	data := payload(20)
	write(t, f, data, Range{0, 10}, "s1")
	if _, err := f.CommitRanged(testID, "big.bin", 20, "s1", nil); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("err = %v, want a bad request", err)
	}
	if _, err := f.CommitRanged(testID, "big.bin", 20, "other", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another session's commit: err = %v, want not found", err)
	}
}

func TestPartSizeCountsReceivedBytes(t *testing.T) {
	f := openTest(t)
	data := payload(30)
	write(t, f, data, Range{20, 30}, "s1")
	if n, err := f.PartSize(testID, "big.bin"); err != nil || n != 10 {
		t.Fatalf("PartSize = %d %v, want 10 (the sparse file is 30 long)", n, err)
	}
}

func TestRangedStateSurvivesAReopen(t *testing.T) {
	dir := t.TempDir()
	f, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	data := payload(20)
	write(t, f, data, Range{0, 10}, "s1")
	again, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := again.PartRanges(testID, "big.bin", "s1")
	if !ok || st.Received != 10 {
		t.Fatalf("after a restart: %+v %v", st, ok)
	}
}

func TestRemoveFileTakesTheRangesSidecar(t *testing.T) {
	f := openTest(t)
	write(t, f, payload(20), Range{0, 10}, "s1")
	if err := f.RemoveFile(testID, "big.bin"); err != nil {
		t.Fatal(err)
	}
	if exists(filepath.Join(shareDir(f, testID), partRel("big.bin")+partRangesExt)) {
		t.Fatal("the ranges sidecar outlived its part")
	}
}

// Review Focus 1: a part the stalled sweep removed while its upload was
// delayed. The next chunk of the SAME session starts a fresh part, and what
// the swept part held reads as missing again.
func TestARangedPartRemovedMidUploadStartsAgainUnderTheSameSession(t *testing.T) {
	f := openTest(t)
	data := payload(30)
	write(t, f, data, Range{0, 10}, "s1")
	if err := f.RemoveFile(testID, "big.bin"); err != nil {
		t.Fatal(err)
	}
	st := write(t, f, data, Range{10, 20}, "s1")
	if st.Received != 10 || len(st.Missing) != 2 || st.Missing[0] != (Range{0, 10}) {
		t.Fatalf("%+v", st)
	}
}

func TestBootRemovesAnOrphanRangesSidecar(t *testing.T) {
	f := openTest(t)
	write(t, f, payload(20), Range{0, 10}, "s1")
	root := filepath.Join(shareDir(f, testID), partsDirName)
	part := filepath.Join(shareDir(f, testID), partRel("big.bin"))
	if err := os.Remove(part); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "x.part.ranges.tmp"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Orphans(func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(root)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), partRangesExt) || strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("boot left %s", e.Name())
		}
	}
}

// A chunk whose part another session replaced while it copied must not be
// recorded into the new part's sidecar: its bytes went to the old part.
func TestAChunkIntoAReplacedPartIsRefused(t *testing.T) {
	f := openTest(t)
	data := payload(20)
	write(t, f, data, Range{0, 10}, "s1")
	beforeRecord = func() error {
		beforeRecord = nil
		write(t, f, data, Range{0, 10}, "s2")
		return nil
	}
	_, err := f.WriteRange(testID, "big.bin", bytes.NewReader(data[10:20]), Range{10, 20}, 20, "s1", nil)
	beforeRecord = nil
	if !errors.Is(err, ErrPartChanged) {
		t.Fatalf("err = %v, want ErrPartChanged", err)
	}
	st, ok := f.PartRanges(testID, "big.bin", "s2")
	if !ok || st.Received != 10 || st.Missing[0] != (Range{10, 20}) {
		t.Fatalf("the new session's part: %+v %v", st, ok)
	}
}

func TestADifferentTotalUnderTheSameSessionDiscardsThePart(t *testing.T) {
	f := openTest(t)
	data := payload(30)
	write(t, f, data[:20], Range{0, 10}, "s1")
	st := write(t, f, data, Range{20, 30}, "s1")
	if st.Total != 30 || st.Received != 10 || st.Missing[0] != (Range{0, 20}) {
		t.Fatalf("the part kept the other total's bytes: %+v", st)
	}
}

func TestWriteRangeDiscardsAPartWriteStaged(t *testing.T) {
	f := openTest(t)
	data := payload(20)
	if _, err := f.Write(testID, "big.bin", bytes.NewReader(data[:10])); err != nil {
		t.Fatal(err)
	}
	st := write(t, f, data, Range{10, 20}, "s1")
	if st.Received != 10 || st.Missing[0] != (Range{0, 10}) {
		t.Fatalf("the bytes Write staged were adopted: %+v", st)
	}
}

// The same session restarting the path under another total replaces the part
// too; only the part's identity tells the two apart, so this is the case the
// open descriptor guards (a closed one could free the inode for reuse).
func TestAChunkIntoAPartTheSameSessionRestartedIsRefused(t *testing.T) {
	f := openTest(t)
	data := payload(30)
	write(t, f, data[:20], Range{0, 10}, "s1")
	beforeRecord = func() error {
		beforeRecord = nil
		write(t, f, data, Range{0, 10}, "s1")
		return nil
	}
	_, err := f.WriteRange(testID, "big.bin", bytes.NewReader(data[10:20]), Range{10, 20}, 20, "s1", nil)
	beforeRecord = nil
	if !errors.Is(err, ErrPartChanged) {
		t.Fatalf("err = %v, want ErrPartChanged", err)
	}
	st, ok := f.PartRanges(testID, "big.bin", "s1")
	if !ok || st.Total != 30 || st.Received != 10 {
		t.Fatalf("the restarted part: %+v %v", st, ok)
	}
}

func TestAWriteOverARangedPartDiscardsIt(t *testing.T) {
	f := openTest(t)
	data := payload(20)
	write(t, f, data, Range{10, 20}, "s1")
	if n, err := f.Write(testID, "big.bin", bytes.NewReader(data[:5])); err != nil || n != 5 {
		t.Fatalf("Write over a ranged part = %d %v", n, err)
	}
	if _, ok := f.PartRanges(testID, "big.bin", "s1"); ok {
		t.Fatal("the ranges sidecar survived a Write")
	}
	if n, _ := f.PartSize(testID, "big.bin"); n != 5 {
		t.Fatalf("part size %d, want 5", n)
	}
}

// Commit is the commit of a part Write staged whole (a batch entry, an inbox
// upload, an empty file); a ranged part's holes are only checked by
// CommitRanged, so Commit never takes one, even one whose sparse length is
// the expected size.
func TestCommitRefusesARangedPart(t *testing.T) {
	f := openTest(t)
	data := payload(20)
	write(t, f, data, Range{10, 20}, "s1")
	if _, err := f.Commit(testID, "big.bin", 20, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Commit of a ranged part = %v, want ErrNotFound", err)
	}
	if st, ok := f.PartRanges(testID, "big.bin", "s1"); !ok || st.Received != 10 {
		t.Fatalf("the ranged part was disturbed: %+v %v", st, ok)
	}
}

// A chunk still arriving counts what it has written so far, so a 32 MiB
// chunk does not read as nothing until its last byte syncs; once recorded
// it counts once, through the sidecar.
func TestPartSizeCountsAChunkStillArriving(t *testing.T) {
	f := openTest(t)
	data := payload(3000)
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		_, err := f.WriteRange(testID, "big.bin", pr, Range{0, 2000}, int64(len(data)), "s1", nil)
		done <- err
	}()
	if _, err := pw.Write(data[:700]); err != nil {
		t.Fatal(err)
	}
	waitPartSize(t, f, 700)
	if _, err := pw.Write(data[700:2000]); err != nil {
		t.Fatal(err)
	}
	pw.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if n, err := f.PartSize(testID, "big.bin"); err != nil || n != 2000 {
		t.Fatalf("PartSize after the chunk = %d %v, want 2000", n, err)
	}
}

// A chunk sent again over bytes already recorded never takes the count
// past the file's size.
func TestPartSizeNeverPassesTheTotal(t *testing.T) {
	f := openTest(t)
	data := payload(1000)
	write(t, f, data, Range{0, 1000}, "s1")
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		_, err := f.WriteRange(testID, "big.bin", pr, Range{0, 1000}, int64(len(data)), "s1", nil)
		done <- err
	}()
	if _, err := pw.Write(data[:600]); err != nil {
		t.Fatal(err)
	}
	waitPartSize(t, f, 1000)
	pw.Close()
	<-done
}

// waitPartSize polls PartSize until it reports want, failing after a second.
func waitPartSize(t *testing.T, f *FS, want int64) {
	t.Helper()
	var n int64
	for i := 0; i < 200; i++ {
		var err error
		if n, err = f.PartSize(testID, "big.bin"); err != nil {
			t.Fatal(err)
		}
		if n == want {
			return
		}
		if n > want {
			t.Fatalf("PartSize = %d, past %d", n, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("PartSize = %d, want %d while the chunk is arriving", n, want)
}

// A range that would leave the upload holding more than MaxRanges disjoint
// ranges is refused and recorded nowhere; one that joins two of them is fine.
func TestARangedUploadHoldsAtMostMaxRanges(t *testing.T) {
	defer func(n int) { MaxRanges = n }(MaxRanges)
	MaxRanges = 16
	f := openTest(t)
	total := int64(2*MaxRanges + 2)
	for i := int64(0); i < int64(MaxRanges); i++ {
		if _, err := f.WriteRange(testID, "r.bin", strings.NewReader("x"), Range{2 * i, 2*i + 1}, total, "session", nil); err != nil {
			t.Fatalf("range %d: %v", i, err)
		}
	}
	if _, err := f.WriteRange(testID, "r.bin", strings.NewReader("x"), Range{total - 2, total - 1}, total, "session", nil); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("one range past the bound = %v, want ErrBadRequest", err)
	}
	st, err := f.WriteRange(testID, "r.bin", strings.NewReader("x"), Range{1, 2}, total, "session", nil)
	if err != nil || len(st.Missing) != MaxRanges-1 {
		t.Fatalf("a range joining two = %v, %d missing", err, len(st.Missing))
	}
}
