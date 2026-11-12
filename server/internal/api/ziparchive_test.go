package api

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"hash"
	"hash/crc32"
	"io"
	"math/rand"
	"strconv"
	"testing"
	"time"
)

var zipTestTime = time.Date(2026, 11, 6, 13, 14, 15, 0, time.UTC)

// zipTestFile is one file of a test archive: its bytes, or size zeros when body is nil.
type zipTestFile struct {
	name string
	body []byte
	size int64
}

func (f zipTestFile) length() int64 {
	if f.body != nil {
		return int64(len(f.body))
	}
	return f.size
}

// zeroReader is a file of n zeros that takes no memory.
type zeroReader struct{ pos, n int64 }

func (z *zeroReader) Read(p []byte) (int, error) {
	if z.pos >= z.n {
		return 0, io.EOF
	}
	m := int(min(int64(len(p)), z.n-z.pos))
	clear(p[:m])
	z.pos += int64(m)
	return m, nil
}

func (z *zeroReader) Seek(off int64, whence int) (int64, error) {
	if whence != io.SeekStart {
		return 0, errors.New("only from the start")
	}
	z.pos = off
	return off, nil
}

func (z *zeroReader) Close() error { return nil }

type bytesFile struct{ *bytes.Reader }

func (bytesFile) Close() error { return nil }

// zipTestSource serves files and records what it was asked for.
type zipTestSource struct {
	files    []zipTestFile
	opened   []int
	measured map[int]uint32
	openErr  error
}

func (s *zipTestSource) open(i int) (io.ReadSeekCloser, error) {
	if s.openErr != nil {
		return nil, s.openErr
	}
	s.opened = append(s.opened, i)
	if s.files[i].body != nil {
		return bytesFile{bytes.NewReader(s.files[i].body)}, nil
	}
	return &zeroReader{n: s.files[i].size}, nil
}

func (s *zipTestSource) measuredCRC(i int, crc uint32) {
	if s.measured == nil {
		s.measured = map[int]uint32{}
	}
	s.measured[i] = crc
}

func zipTestArchive(files []zipTestFile) *zipArchive {
	entries := make([]zipFile, len(files))
	for i, f := range files {
		entries[i] = zipFile{name: f.name, size: f.length(), modified: zipTestTime}
	}
	return newZipArchive(entries)
}

// zipWriterBytes writes files through archive/zip, the format recipients' tools have
// always been handed.
func zipWriterBytes(t *testing.T, w io.Writer, files []zipTestFile) {
	t.Helper()
	zw := zip.NewWriter(w)
	for i, f := range files {
		dst, err := zw.CreateHeader(&zip.FileHeader{Name: f.name, Method: zip.Store, Modified: zipTestTime})
		if err != nil {
			t.Fatal(err)
		}
		src, _ := (&zipTestSource{files: files}).open(i)
		if _, err := io.Copy(dst, src); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}

func zipArchiveBytes(t *testing.T, a *zipArchive, files []zipTestFile, from, to int64) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := a.writeRange(context.Background(), &b, from, to, &zipTestSource{files: files}); err != nil {
		t.Fatalf("writeRange(%d, %d): %v", from, to, err)
	}
	return b.Bytes()
}

var zipSampleFiles = []zipTestFile{
	{name: "a.txt", body: []byte("alpha")},
	{name: "empty.bin", body: []byte{}},
	{name: "sub/b.txt", body: bytes.Repeat([]byte("bravo "), 900)},
	{name: "sub/café – наме 日本語.txt", body: []byte("unicode")},
	{name: "sub/tilde~and\\back.txt", body: []byte("needs the UTF-8 flag")},
	{name: "z.bin", body: bytes.Repeat([]byte{0, 1, 2, 3, 4, 5, 6, 7}, 20000)},
}

// What a recipient's unzip reads is what archive/zip writes, byte for byte.
func TestTheArchiveIsWhatArchiveZipWrites(t *testing.T) {
	var want bytes.Buffer
	zipWriterBytes(t, &want, zipSampleFiles)
	a := zipTestArchive(zipSampleFiles)
	if a.total != int64(want.Len()) {
		t.Fatalf("total %d, archive/zip wrote %d", a.total, want.Len())
	}
	got := zipArchiveBytes(t, a, zipSampleFiles, 0, a.total-1)
	if !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("bytes differ from archive/zip (%d and %d long)", len(got), want.Len())
	}
}

// zeroRunHash hashes what is written with runs of zeros reduced to their length, so
// two writers chunking the same many-gigabyte stream differently hash alike.
type zeroRunHash struct {
	h     hash.Hash
	zeros int64
	total int64
}

func (z *zeroRunHash) flushRun() {
	if z.zeros > 0 {
		z.h.Write([]byte("zeros:" + strconv.FormatInt(z.zeros, 10) + ";"))
		z.zeros = 0
	}
}

func (z *zeroRunHash) Write(p []byte) (int, error) {
	z.total += int64(len(p))
	rest := p
	for len(rest) > 0 {
		if rest[0] == 0 {
			n := 1
			for n < len(rest) && rest[n] == 0 {
				n++
			}
			z.zeros += int64(n)
			rest = rest[n:]
			continue
		}
		z.flushRun()
		n := 1
		for n < len(rest) && rest[n] != 0 {
			n++
		}
		z.h.Write(rest[:n])
		rest = rest[n:]
	}
	return len(p), nil
}

// The sizes at which zip64 records begin, in a file and in an offset, are archive/zip's.
func TestBigArchivesAreWhatArchiveZipWrites(t *testing.T) {
	if testing.Short() {
		t.Skip("reads several gigabytes of zeros")
	}
	const max32 = int64(1<<32 - 1)
	for name, files := range map[string][]zipTestFile{
		"below the line":    {{name: "a", size: max32 - 1}, {name: "after", body: []byte("x")}},
		"on the line":       {{name: "a", size: max32}, {name: "after", body: []byte("x")}},
		"past the line":     {{name: "a", size: max32 + 1}, {name: "after", body: []byte("x")}},
		"offset past it":    {{name: "a", size: max32 - 1000}, {name: "b", size: 2000}, {name: "c", body: []byte("x")}},
		"directory crosses": {{name: "a", size: max32 - 200}, {name: "b", body: []byte("x")}},
	} {
		t.Run(name, func(t *testing.T) {
			want := &zeroRunHash{h: sha256.New()}
			zipWriterBytes(t, want, files)
			want.flushRun()
			a := zipTestArchive(files)
			if a.total != want.total {
				t.Fatalf("total %d, archive/zip wrote %d", a.total, want.total)
			}
			got := &zeroRunHash{h: sha256.New()}
			if err := a.writeRange(context.Background(), got, 0, a.total-1, &zipTestSource{files: files}); err != nil {
				t.Fatal(err)
			}
			got.flushRun()
			if !bytes.Equal(got.h.Sum(nil), want.h.Sum(nil)) || got.total != want.total {
				t.Fatalf("bytes differ from archive/zip (%d and %d long)", got.total, want.total)
			}
		})
	}
}

// Past 65,534 entries the end records change, with no file large at all.
func TestArchivesOfManyFilesAreWhatArchiveZipWrites(t *testing.T) {
	for _, n := range []int{0xFFFE, 0xFFFF, 0x10000} {
		files := make([]zipTestFile, n)
		for i := range files {
			files[i] = zipTestFile{name: "f" + strconv.Itoa(i), body: []byte{}}
		}
		var want bytes.Buffer
		zipWriterBytes(t, &want, files)
		a := zipTestArchive(files)
		if got := zipArchiveBytes(t, a, files, 0, a.total-1); !bytes.Equal(got, want.Bytes()) {
			t.Fatalf("%d files: bytes differ from archive/zip", n)
		}
	}
}

func TestAnArchiveOfNothingIsAValidZip(t *testing.T) {
	a := zipTestArchive(nil)
	got := zipArchiveBytes(t, a, nil, 0, a.total-1)
	if _, err := zip.NewReader(bytes.NewReader(got), int64(len(got))); err != nil {
		t.Fatal(err)
	}
}

// Whatever a resume starts from, and however much a stored CRC already says, the bytes
// are the ones the whole archive holds there: a mistake is a corrupt archive its
// recipient finds only when extracting.
func TestEveryRangeIsThatPartOfTheArchive(t *testing.T) {
	var full bytes.Buffer
	zipWriterBytes(t, &full, zipSampleFiles)
	want := full.Bytes()
	total := int64(len(want))

	known := zipTestArchive(zipSampleFiles)
	for i := range known.files {
		known.files[i].crc, known.files[i].hasCRC = crc32.ChecksumIEEE(zipSampleFiles[i].body), true
	}
	check := func(from, to int64) {
		t.Helper()
		// A fresh archive each time: a request measures into its own.
		if got := zipArchiveBytes(t, zipTestArchive(zipSampleFiles), zipSampleFiles, from, to); !bytes.Equal(got, want[from:to+1]) {
			t.Fatalf("unmeasured %d-%d: bytes differ", from, to)
		}
		if got := zipArchiveBytes(t, known, zipSampleFiles, from, to); !bytes.Equal(got, want[from:to+1]) {
			t.Fatalf("measured %d-%d: bytes differ", from, to)
		}
	}
	// Every start in the structures, stepping through the long bodies.
	for from := int64(0); from < total; {
		check(from, total-1)
		if from < 7000 || total-from < 7000 || (from > 12000 && from < 13000) {
			from++
		} else {
			from += 257
		}
	}
	rng := rand.New(rand.NewSource(1))
	for range 3000 {
		from := rng.Int63n(total)
		check(from, from+rng.Int63n(total-from))
	}
}

// Parts stitched back together, cut anywhere, extract with every CRC good.
func TestStitchedRangesExtract(t *testing.T) {
	a := zipTestArchive(zipSampleFiles)
	rng := rand.New(rand.NewSource(2))
	for range 200 {
		var stitched bytes.Buffer
		for from := int64(0); from < a.total; {
			to := min(a.total-1, from+rng.Int63n(a.total/3+1))
			stitched.Write(zipArchiveBytes(t, zipTestArchive(zipSampleFiles), zipSampleFiles, from, to))
			from = to + 1
		}
		zr, err := zip.NewReader(bytes.NewReader(stitched.Bytes()), int64(stitched.Len()))
		if err != nil {
			t.Fatal(err)
		}
		if len(zr.File) != len(zipSampleFiles) {
			t.Fatalf("%d entries", len(zr.File))
		}
		for i, f := range zr.File {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatalf("%s: %v", f.Name, err)
			}
			if !bytes.Equal(body, zipSampleFiles[i].body) {
				t.Fatalf("%s: wrong bytes", f.Name)
			}
		}
	}
}

func TestAWholeStreamMeasuresEveryFile(t *testing.T) {
	a := zipTestArchive(zipSampleFiles)
	src := &zipTestSource{files: zipSampleFiles}
	if err := a.writeRange(context.Background(), io.Discard, 0, a.total-1, src); err != nil {
		t.Fatal(err)
	}
	for i, f := range zipSampleFiles {
		if f.length() == 0 {
			continue
		}
		if got, ok := src.measured[i]; !ok || got != crc32.ChecksumIEEE(f.body) {
			t.Errorf("%s: measured %x, %v", f.name, got, ok)
		}
	}
}

// A stream cut part way through measured the files it finished, which is what makes the
// resume that follows cheap.
func TestAStreamCutOffStillMeasuredWhatItFinished(t *testing.T) {
	a := zipTestArchive(zipSampleFiles)
	src := &zipTestSource{files: zipSampleFiles}
	cutAt := a.files[3].at + 10
	err := a.writeRange(context.Background(), &failingAfter{left: cutAt}, 0, a.total-1, src)
	if !errors.Is(err, errZipTestCut) {
		t.Fatalf("= %v", err)
	}
	if _, ok := src.measured[2]; !ok {
		t.Error("the file finished before the cut was not measured")
	}
	if _, ok := src.measured[3]; ok {
		t.Error("a file not finished was reported measured")
	}
}

var errZipTestCut = errors.New("cut")

type failingAfter struct{ left int64 }

func (f *failingAfter) Write(p []byte) (int, error) {
	if int64(len(p)) > f.left {
		n := f.left
		f.left = 0
		return int(n), errZipTestCut
	}
	f.left -= int64(len(p))
	return len(p), nil
}

// A file the range does not reach is not opened: a resume near the end of a measured
// share costs only what it sends.
func TestAResumeOpensOnlyWhatItSends(t *testing.T) {
	a := zipTestArchive(zipSampleFiles)
	for i := range a.files {
		a.files[i].crc, a.files[i].hasCRC = crc32.ChecksumIEEE(zipSampleFiles[i].body), true
	}
	src := &zipTestSource{files: zipSampleFiles}
	if err := a.writeRange(context.Background(), io.Discard, a.files[5].at+40, a.total-1, src); err != nil {
		t.Fatal(err)
	}
	if len(src.opened) != 1 || src.opened[0] != 5 {
		t.Fatalf("opened %v", src.opened)
	}
}

// Asking for the directory alone still has to name every file's CRC: an unmeasured one
// is read then, and kept.
func TestTheDirectoryMeasuresWhatItNames(t *testing.T) {
	a := zipTestArchive(zipSampleFiles)
	src := &zipTestSource{files: zipSampleFiles}
	if err := a.writeRange(context.Background(), io.Discard, a.dirAt, a.total-1, src); err != nil {
		t.Fatal(err)
	}
	for i, f := range zipSampleFiles {
		if f.length() > 0 {
			if _, ok := src.measured[i]; !ok {
				t.Errorf("%s not measured", f.name)
			}
		}
	}
}

func TestARangeInsideAFileMeasuresNothing(t *testing.T) {
	a := zipTestArchive(zipSampleFiles)
	src := &zipTestSource{files: zipSampleFiles}
	start := a.files[5].at + 1000
	if err := a.writeRange(context.Background(), io.Discard, start, start+500, src); err != nil {
		t.Fatal(err)
	}
	if len(src.measured) != 0 {
		t.Fatalf("measured %v", src.measured)
	}
}

// Measuring reads a whole file before anything is sent, so a client gone stops it.
func TestMeasuringStopsWhenTheClientLeaves(t *testing.T) {
	a := zipTestArchive(zipSampleFiles)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := a.writeRange(ctx, io.Discard, a.dirAt, a.total-1, &zipTestSource{files: zipSampleFiles})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("= %v", err)
	}
}

func TestAFileThatCannotBeOpenedEndsTheStream(t *testing.T) {
	a := zipTestArchive(zipSampleFiles)
	boom := errors.New("gone")
	if err := a.writeRange(context.Background(), io.Discard, 0, a.total-1, &zipTestSource{files: zipSampleFiles, openErr: boom}); !errors.Is(err, boom) {
		t.Fatalf("= %v", err)
	}
}

// A file shorter than its row must fail the stream: padding on would corrupt every
// offset after it.
func TestAFileShorterThanItsRowEndsTheStream(t *testing.T) {
	files := []zipTestFile{{name: "a", body: []byte("abc")}}
	a := newZipArchive([]zipFile{{name: "a", size: 10, modified: zipTestTime}})
	if err := a.writeRange(context.Background(), io.Discard, 0, a.total-1, &zipTestSource{files: files}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("= %v", err)
	}
}
