package hevctag

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

// box lays one ISO box out: a 32-bit length, the four-letter type, the
// payload. Enough to build the shape the scan walks, and no more.
func testBox(typ string, parts ...[]byte) []byte {
	var body []byte
	for _, p := range parts {
		body = append(body, p...)
	}
	out := make([]byte, 8, 8+len(body))
	binary.BigEndian.PutUint32(out, uint32(8+len(body)))
	copy(out[4:], typ)
	return append(out, body...)
}

// sampleDescription wraps sample entries the way stsd does: a version byte,
// three flag bytes, then the entry count.
func sampleDescription(entries ...[]byte) []byte {
	head := []byte{0, 0, 0, 0, 0, 0, 0, byte(len(entries))}
	return testBox("stsd", append([][]byte{head}, entries...)...)
}

// movieFile builds a file whose video track carries `entryType`, with the
// four letters ALSO sitting in the picture data, where they are not a tag.
func movieFile(entryType string) []byte {
	entry := testBox(entryType, bytes.Repeat([]byte{0x11}, 20))
	moov := testBox("moov",
		testBox("trak", testBox("mdia", testBox("minf", testBox("stbl", sampleDescription(entry))))))
	mdat := testBox("mdat", []byte("....hev1....picture bytes...."))
	return append(append(testBox("ftyp", []byte("isommp41avc1")), moov...), mdat...)
}

// The scan answers the sample entry's type field and nothing else: the same
// four letters in the picture data are bytes that happen to spell it.
func TestTheScanFindsHEV1OnlyWhereItIsASampleEntryType(t *testing.T) {
	file := movieFile(HEV1)
	offs := Offsets(bytes.NewReader(file))
	if len(offs) != 1 {
		t.Fatalf("offsets = %v, want exactly the sample entry's", offs)
	}
	if got := string(file[offs[0] : offs[0]+4]); got != HEV1 {
		t.Fatalf("offset %d points at %q, want %q", offs[0], got, HEV1)
	}
	if offs[0] > int64(bytes.Index(file, []byte("mdat"))) {
		t.Fatalf("offset %d is inside the picture data", offs[0])
	}
}

func TestTheScanFindsNothingToRewriteInAnHVC1File(t *testing.T) {
	if offs := Offsets(bytes.NewReader(movieFile(HVC1))); len(offs) != 0 {
		t.Fatalf("offsets = %v, want none: the file is already playable", offs)
	}
}

func TestTheScanAnswersNothingForBytesThatAreNotAMovie(t *testing.T) {
	if offs := Offsets(bytes.NewReader([]byte("not a movie, just some bytes"))); len(offs) != 0 {
		t.Fatalf("offsets = %v, want none", offs)
	}
}

// The reader is where the file is read from, so it must leave the position it
// was handed: ServeContent seeks for its own reasons and the scan runs first.
func TestTheScanLeavesTheReaderWhereItFoundIt(t *testing.T) {
	rs := bytes.NewReader(movieFile(HEV1))
	if _, err := rs.Seek(11, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	Offsets(rs)
	at, err := rs.Seek(0, io.SeekCurrent)
	if err != nil {
		t.Fatal(err)
	}
	if at != 11 {
		t.Fatalf("reader left at %d, want 11", at)
	}
}

// Whatever window is read gets the same answer, including one that splits the
// four letters across two reads.
func TestTheReaderPatchesATagSplitAcrossReads(t *testing.T) {
	file := movieFile(HEV1)
	offs := Offsets(bytes.NewReader(file))
	at := offs[0]
	r := Reader(bytes.NewReader(file), offs)
	if _, err := r.Seek(at-2, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	first := make([]byte, 4)
	if _, err := io.ReadFull(r, first); err != nil {
		t.Fatal(err)
	}
	second := make([]byte, 4)
	if _, err := io.ReadFull(r, second); err != nil {
		t.Fatal(err)
	}
	got := string(first[2:]) + string(second[:2])
	if got != HVC1 {
		t.Fatalf("tag across two reads = %q, want %q", got, HVC1)
	}
}

// A seek to the middle of the file must not patch at the wrong place: the
// offsets are the FILE's, not the read's.
func TestTheReaderPatchesNothingOutsideTheTag(t *testing.T) {
	file := movieFile(HEV1)
	offs := Offsets(bytes.NewReader(file))
	r := Reader(bytes.NewReader(file), offs)
	mdat := int64(bytes.Index(file, []byte("mdat")))
	if _, err := r.Seek(mdat, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, file[mdat:]) {
		t.Fatal("the picture data changed; only the sample entry's type may be rewritten")
	}
}

// Read whole, the file differs from the original in exactly four bytes.
func TestTheReaderRewritesFourBytesAndKeepsTheLength(t *testing.T) {
	file := movieFile(HEV1)
	offs := Offsets(bytes.NewReader(file))
	got, err := io.ReadAll(Reader(bytes.NewReader(file), offs))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(file) {
		t.Fatalf("length = %d, want %d", len(got), len(file))
	}
	differ := 0
	for i := range got {
		if got[i] != file[i] {
			differ++
		}
	}
	// `hev1` and `hvc1` share their first and last byte.
	if differ != 2 {
		t.Fatalf("%d bytes changed, want the two that differ inside one tag", differ)
	}
	if string(got[offs[0]:offs[0]+4]) != HVC1 {
		t.Fatalf("tag = %q, want %q", got[offs[0]:offs[0]+4], HVC1)
	}
}

func TestOnlyAContainerThatCanHoldTheTagIsScanned(t *testing.T) {
	for _, name := range []string{"clip.mp4", "clip.MP4", "clip.m4v", "clip.mov"} {
		if !Applies(name) {
			t.Fatalf("%q holds sample entries and should be scanned", name)
		}
	}
	for _, name := range []string{"clip.mkv", "song.mp3", "notes.txt", "page.html"} {
		if Applies(name) {
			t.Fatalf("%q was offered to the scan", name)
		}
	}
}

// countingReader counts the bytes a scan reads.
type countingReader struct {
	*bytes.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.Reader.Read(p)
	c.n += n
	return n, err
}

// The scan reads box headers where they sit, never a payload: a movie header
// of many megabytes (a long recording's sample tables, or a file built to be
// expensive) costs the same few bytes as a small one.
func TestTheScanReadsHeadersNotTheMovieHeader(t *testing.T) {
	entry := testBox(HEV1, bytes.Repeat([]byte{0x11}, 20))
	tables := testBox("stsz", make([]byte, 16<<20))
	moov := testBox("moov",
		testBox("trak", testBox("mdia", testBox("minf",
			testBox("stbl", sampleDescription(entry), tables)))),
		testBox("udta", make([]byte, 8<<20)))
	file := append(testBox("ftyp", []byte("isommp41avc1")), moov...)
	r := &countingReader{Reader: bytes.NewReader(file)}
	offs := Offsets(r)
	if len(offs) != 1 || string(file[offs[0]:offs[0]+4]) != HEV1 {
		t.Fatalf("offsets = %v, want the one sample entry", offs)
	}
	if r.n > 4<<10 {
		t.Fatalf("the scan read %d bytes of a %d-byte file", r.n, len(file))
	}
}

// A 64-bit box length is honoured on the way down, and a length that runs past
// its parent ends the walk instead of reading outside it.
func TestTheScanFollowsLargeSizesAndStopsAtOverruns(t *testing.T) {
	entry := testBox(HEV1, bytes.Repeat([]byte{0x11}, 20))
	stbl := testBox("stbl", sampleDescription(entry))
	trak := testBox("trak", testBox("mdia", testBox("minf", stbl)))
	// moov with a 16-byte header: size 1, then the 64-bit length.
	large := make([]byte, 16, 16+len(trak))
	binary.BigEndian.PutUint32(large, 1)
	copy(large[4:], "moov")
	binary.BigEndian.PutUint64(large[8:], uint64(16+len(trak)))
	large = append(large, trak...)
	file := append(testBox("ftyp", []byte("isom")), large...)
	offs := Offsets(bytes.NewReader(file))
	if len(offs) != 1 || string(file[offs[0]:offs[0]+4]) != HEV1 {
		t.Fatalf("offsets = %v, want the one sample entry under a 64-bit moov", offs)
	}

	overrun := testBox("moov", trak)
	binary.BigEndian.PutUint32(overrun[8:], uint32(len(trak)+100)) // trak claims more than moov holds
	file = append(testBox("ftyp", []byte("isom")), overrun...)
	if offs := Offsets(bytes.NewReader(file)); len(offs) != 0 {
		t.Fatalf("offsets = %v, want none from a box that overruns its parent", offs)
	}
}
