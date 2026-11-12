package api

import (
	"context"
	"encoding/binary"
	"hash/crc32"
	"io"
	"sort"
	"time"
	"unicode/utf8"
)

// A share's stored files make one fixed archive: the same files always produce the
// same bytes at the same offsets, so a download cut off can continue from where it
// stopped. Each file's CRC-32 travels in the data descriptor after its bytes and again
// in the central directory, and neither changes the layout, so every offset and the
// total are known from names and sizes alone, before any file is read. The format is
// byte for byte what archive/zip writes for store-mode entries (a test holds the two
// together), zip64 included.
const (
	zipLocalHeaderLen  = 30
	zipDirHeaderLen    = 46
	zipExtTimeLen      = 9
	zipDescriptorLen   = 16
	zipDescriptor64Len = 24
	zip64EndLen        = 56
	zip64LocatorLen    = 20
	zipEndLen          = 22
	zipMax16           = 1<<16 - 1
	zipMax32           = 1<<32 - 1
	zipVersion20       = 20
	zipVersion45       = 45
	zipFlagDescriptor  = 0x8
	zipFlagUTF8        = 0x800
)

// zipFile is one entry of a zipArchive. name is the name inside the archive, and crc,
// when hasCRC, what a stream measured earlier.
type zipFile struct {
	name     string
	size     int64
	modified time.Time
	crc      uint32
	hasCRC   bool
	at       int64 // where its local header starts
}

// zipSource hands a stream the files of its archive. open opens entry i's bytes, and
// measuredCRC reports the CRC of those bytes, read in full, for the next stream.
type zipSource interface {
	open(i int) (io.ReadSeekCloser, error)
	measuredCRC(i int, crc uint32)
}

// zipArchive is the layout of one archive, and the CRCs known to one stream of it.
type zipArchive struct {
	files  []zipFile
	dirAt  int64
	dirLen int64
	total  int64
	zip64  bool
}

// newZipArchive lays files out in the order given.
func newZipArchive(files []zipFile) *zipArchive {
	a := &zipArchive{files: files}
	var pos, dirLen int64
	for i := range files {
		f := &files[i]
		f.at = pos
		// An empty file's CRC needs no reading.
		f.hasCRC = f.hasCRC || f.size == 0
		pos += f.localLen() + f.size + f.descriptorLen()
		dirLen += f.dirLen()
		a.zip64 = a.zip64 || f.dirZip64Len() > 0
	}
	a.dirAt, a.dirLen = pos, dirLen
	a.zip64 = a.zip64 || len(files) >= zipMax16 || dirLen >= zipMax32 || pos >= zipMax32
	a.total = pos + dirLen + zipEndLen
	if a.zip64 {
		a.total += zip64EndLen + zip64LocatorLen
	}
	return a
}

func (f *zipFile) localLen() int64 { return zipLocalHeaderLen + int64(len(f.name)) + zipExtTimeLen }

func (f *zipFile) descriptorLen() int64 {
	if f.size > zipMax32 {
		return zipDescriptor64Len
	}
	return zipDescriptorLen
}

// dirZip64Len is the length of the entry's zip64 extra in the directory: the fields
// that reach the 32-bit limit, and none when no field does.
func (f *zipFile) dirZip64Len() int64 {
	var n int64
	if f.size >= zipMax32 {
		n += 16 // the uncompressed and compressed sizes
	}
	if f.at >= zipMax32 {
		n += 8
	}
	if n == 0 {
		return 0
	}
	return 4 + n
}

func (f *zipFile) dirLen() int64 {
	return zipDirHeaderLen + int64(len(f.name)) + zipExtTimeLen + f.dirZip64Len()
}

// flags are the bits both headers carry. A name a legacy reader would misread is
// marked UTF-8, on the rule archive/zip uses.
func (f *zipFile) flags() uint16 {
	flags := uint16(zipFlagDescriptor)
	if zipNameNeedsUTF8(f.name) {
		flags |= zipFlagUTF8
	}
	return flags
}

func zipNameNeedsUTF8(s string) bool {
	require := false
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		if r < 0x20 || r > 0x7d || r == 0x5c {
			if !utf8.ValidRune(r) || (r == utf8.RuneError && size == 1) {
				return false
			}
			require = true
		}
	}
	return require
}

func (f *zipFile) dosTime() (date, clock uint16) {
	t := f.modified
	return uint16(t.Day() + int(t.Month())<<5 + (t.Year()-1980)<<9),
		uint16(t.Second()/2 + t.Minute()<<5 + t.Hour()<<11)
}

func appendZipExtTime(b []byte, t time.Time) []byte {
	b = binary.LittleEndian.AppendUint16(b, 0x5455)
	b = binary.LittleEndian.AppendUint16(b, 5)
	b = append(b, 1)
	return binary.LittleEndian.AppendUint32(b, uint32(t.Unix()))
}

func (f *zipFile) localHeader(b []byte) []byte {
	date, clock := f.dosTime()
	b = binary.LittleEndian.AppendUint32(b, 0x04034b50)
	b = binary.LittleEndian.AppendUint16(b, zipVersion20)
	b = binary.LittleEndian.AppendUint16(b, f.flags())
	b = binary.LittleEndian.AppendUint16(b, 0) // store
	b = binary.LittleEndian.AppendUint16(b, clock)
	b = binary.LittleEndian.AppendUint16(b, date)
	b = append(b, make([]byte, 12)...) // the CRC and sizes, in the descriptor instead
	b = binary.LittleEndian.AppendUint16(b, uint16(len(f.name)))
	b = binary.LittleEndian.AppendUint16(b, zipExtTimeLen)
	b = append(b, f.name...)
	return appendZipExtTime(b, f.modified)
}

func (f *zipFile) descriptor(b []byte) []byte {
	b = binary.LittleEndian.AppendUint32(b, 0x08074b50)
	b = binary.LittleEndian.AppendUint32(b, f.crc)
	if f.size > zipMax32 {
		b = binary.LittleEndian.AppendUint64(b, uint64(f.size))
		return binary.LittleEndian.AppendUint64(b, uint64(f.size))
	}
	b = binary.LittleEndian.AppendUint32(b, uint32(f.size))
	return binary.LittleEndian.AppendUint32(b, uint32(f.size))
}

func (f *zipFile) dirEntry(b []byte) []byte {
	date, clock := f.dosTime()
	version := uint16(zipVersion20)
	extra := f.dirZip64Len()
	if extra > 0 {
		version = zipVersion45
	}
	b = binary.LittleEndian.AppendUint32(b, 0x02014b50)
	b = binary.LittleEndian.AppendUint16(b, zipVersion20)
	b = binary.LittleEndian.AppendUint16(b, version)
	b = binary.LittleEndian.AppendUint16(b, f.flags())
	b = binary.LittleEndian.AppendUint16(b, 0) // store
	b = binary.LittleEndian.AppendUint16(b, clock)
	b = binary.LittleEndian.AppendUint16(b, date)
	b = binary.LittleEndian.AppendUint32(b, f.crc)
	b = binary.LittleEndian.AppendUint32(b, uint32(min(f.size, zipMax32)))
	b = binary.LittleEndian.AppendUint32(b, uint32(min(f.size, zipMax32)))
	b = binary.LittleEndian.AppendUint16(b, uint16(len(f.name)))
	b = binary.LittleEndian.AppendUint16(b, uint16(zipExtTimeLen+extra))
	b = append(b, make([]byte, 10)...) // comment length, disk, internal and external attributes
	b = binary.LittleEndian.AppendUint32(b, uint32(min(f.at, zipMax32)))
	b = append(b, f.name...)
	b = appendZipExtTime(b, f.modified)
	if extra > 0 {
		b = binary.LittleEndian.AppendUint16(b, 0x0001)
		b = binary.LittleEndian.AppendUint16(b, uint16(extra-4))
		if f.size >= zipMax32 {
			b = binary.LittleEndian.AppendUint64(b, uint64(f.size))
			b = binary.LittleEndian.AppendUint64(b, uint64(f.size))
		}
		if f.at >= zipMax32 {
			b = binary.LittleEndian.AppendUint64(b, uint64(f.at))
		}
	}
	return b
}

// endRecords is everything after the directory.
func (a *zipArchive) endRecords() []byte {
	b := make([]byte, 0, zip64EndLen+zip64LocatorLen+zipEndLen)
	records, dirEnd := uint64(len(a.files)), a.dirAt+a.dirLen
	if a.zip64 {
		b = binary.LittleEndian.AppendUint32(b, 0x06064b50)
		b = binary.LittleEndian.AppendUint64(b, zip64EndLen-12)
		b = binary.LittleEndian.AppendUint16(b, zipVersion45)
		b = binary.LittleEndian.AppendUint16(b, zipVersion45)
		b = binary.LittleEndian.AppendUint64(b, 0) // this disk, the directory's disk
		b = binary.LittleEndian.AppendUint64(b, records)
		b = binary.LittleEndian.AppendUint64(b, records)
		b = binary.LittleEndian.AppendUint64(b, uint64(a.dirLen))
		b = binary.LittleEndian.AppendUint64(b, uint64(a.dirAt))
		b = binary.LittleEndian.AppendUint32(b, 0x07064b50)
		b = binary.LittleEndian.AppendUint32(b, 0)
		b = binary.LittleEndian.AppendUint64(b, uint64(dirEnd))
		b = binary.LittleEndian.AppendUint32(b, 1)
	}
	b = binary.LittleEndian.AppendUint32(b, 0x06054b50)
	b = binary.LittleEndian.AppendUint32(b, 0) // this disk, the directory's disk
	b = binary.LittleEndian.AppendUint16(b, uint16(min(records, zipMax16)))
	b = binary.LittleEndian.AppendUint16(b, uint16(min(records, zipMax16)))
	b = binary.LittleEndian.AppendUint32(b, uint32(min(a.dirLen, zipMax32)))
	b = binary.LittleEndian.AppendUint32(b, uint32(min(a.dirAt, zipMax32)))
	return binary.LittleEndian.AppendUint16(b, 0) // no comment
}

// zipRangeOut writes the part of the archive between from and to, inclusive.
type zipRangeOut struct {
	w        io.Writer
	from, to int64
}

func (o *zipRangeOut) put(at int64, b []byte) error {
	end := at + int64(len(b))
	if end <= o.from || at > o.to {
		return nil
	}
	if at < o.from {
		b = b[o.from-at:]
	}
	if end > o.to+1 {
		b = b[:int64(len(b))-(end-o.to-1)]
	}
	_, err := o.w.Write(b)
	return err
}

// writeRange writes bytes from to to of the archive, both inclusive. It opens only the
// files the range reaches, and reads more than it sends only to measure a CRC the range
// has to carry and no stream has measured: a descriptor's file in full, or for the
// directory every file not sent here.
func (a *zipArchive) writeRange(ctx context.Context, w io.Writer, from, to int64, src zipSource) error {
	o := &zipRangeOut{w: w, from: from, to: to}
	first := sort.Search(len(a.files), func(i int) bool {
		f := &a.files[i]
		return f.at+f.localLen()+f.size+f.descriptorLen() > from
	})
	var buf []byte
	for i := first; i < len(a.files) && a.files[i].at <= to; i++ {
		f := &a.files[i]
		buf = f.localHeader(buf[:0])
		if err := o.put(f.at, buf); err != nil {
			return err
		}
		if err := a.writeData(ctx, o, i, src); err != nil {
			return err
		}
		if dataEnd := f.at + f.localLen() + f.size; to >= dataEnd {
			buf = f.descriptor(buf[:0])
			if err := o.put(dataEnd, buf); err != nil {
				return err
			}
		}
	}
	if to < a.dirAt {
		return nil
	}
	at := a.dirAt
	for i := range a.files {
		f := &a.files[i]
		n := f.dirLen()
		if at+n > from && at <= to {
			if !f.hasCRC {
				if err := a.measure(ctx, i, src); err != nil {
					return err
				}
			}
			buf = f.dirEntry(buf[:0])
			if err := o.put(at, buf); err != nil {
				return err
			}
		}
		at += n
	}
	return o.put(at, a.endRecords())
}

// writeData sends the part of file i's bytes the range holds, and leaves its CRC known
// when the range holds its descriptor.
func (a *zipArchive) writeData(ctx context.Context, o *zipRangeOut, i int, src zipSource) error {
	f := &a.files[i]
	dataAt := f.at + f.localLen()
	dataEnd := dataAt + f.size
	wantData := o.from < dataEnd && o.to >= dataAt
	wantDescriptor := o.from < dataEnd+f.descriptorLen() && o.to >= dataEnd
	if !wantData && (f.hasCRC || !wantDescriptor) {
		return nil
	}
	start := max(0, min(o.from-dataAt, f.size))
	stop := max(0, min(o.to+1-dataAt, f.size))
	// Whole bytes passing by are measured for nothing extra; a prefix is read only for
	// a descriptor this range must send.
	measuring := !f.hasCRC && (wantDescriptor || (start == 0 && stop == f.size))
	file, err := src.open(i)
	if err != nil {
		return err
	}
	defer file.Close()
	dst := io.Writer(o.w)
	sum := crc32.NewIEEE()
	if measuring {
		if err := zipCopyExact(ctx, sum, file, start); err != nil {
			return err
		}
		dst = io.MultiWriter(o.w, sum)
	} else if start > 0 {
		if _, err := file.Seek(start, io.SeekStart); err != nil {
			return err
		}
	}
	if err := zipCopyExact(ctx, dst, file, stop-start); err != nil {
		return err
	}
	if measuring {
		f.crc, f.hasCRC = sum.Sum32(), true
		src.measuredCRC(i, f.crc)
	}
	return nil
}

// measure reads file i whole for its CRC alone.
func (a *zipArchive) measure(ctx context.Context, i int, src zipSource) error {
	f := &a.files[i]
	file, err := src.open(i)
	if err != nil {
		return err
	}
	defer file.Close()
	sum := crc32.NewIEEE()
	if err := zipCopyExact(ctx, sum, file, f.size); err != nil {
		return err
	}
	f.crc, f.hasCRC = sum.Sum32(), true
	src.measuredCRC(i, f.crc)
	return nil
}

// zipCopyExact copies exactly n bytes, a chunk at a time, stopping when ctx ends: a
// file shorter than its row must not end the stream as if it were whole.
func zipCopyExact(ctx context.Context, dst io.Writer, src io.Reader, n int64) error {
	bp := zipCopyBufs.Get().(*[]byte)
	defer zipCopyBufs.Put(bp)
	for n > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		chunk := (*bp)[:min(n, int64(len(*bp)))]
		if _, err := io.ReadFull(src, chunk); err != nil {
			if err == io.EOF {
				return io.ErrUnexpectedEOF
			}
			return err
		}
		if _, err := dst.Write(chunk); err != nil {
			return err
		}
		n -= int64(len(chunk))
	}
	return nil
}
