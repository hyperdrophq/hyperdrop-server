package hevctag

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

// wideBox is a box header carrying a 64-bit size.
func wideBox(typ string, size uint64) []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint32(b, 1)
	copy(b[4:], typ)
	binary.BigEndian.PutUint64(b[8:], size)
	return b
}

func smallBox(typ string, body []byte) []byte {
	b := make([]byte, 8, 8+len(body))
	binary.BigEndian.PutUint32(b, uint32(8+len(body)))
	copy(b[4:], typ)
	return append(b, body...)
}

// The bytes of a video are whatever was uploaded: every offset the scan
// answers is inside the file, and the retagging reader serves its length.
func FuzzOffsets(f *testing.F) {
	f.Add(smallBox("ftyp", []byte("isom")))
	f.Add(append(smallBox("ftyp", nil), smallBox("moov", smallBox("trak", smallBox("mdia", nil)))...))
	// A 64-bit size that overflows once the offset of its box is added.
	f.Add(append(smallBox("ftyp", nil), smallBox("moov", append(smallBox("free", nil), wideBox("trak", 1<<63-1)...))...))
	f.Add(append(smallBox("ftyp", nil), wideBox("moov", 1<<63-1)...))
	f.Add(append(smallBox("ftyp", nil), wideBox("mdat", 1<<63-1)...))
	f.Add(wideBox("moov", 1<<64-1))
	f.Fuzz(func(t *testing.T, data []byte) {
		rs := bytes.NewReader(data)
		offs := Offsets(rs)
		for _, o := range offs {
			if o < 0 || o+4 > int64(len(data)) {
				t.Fatalf("offset %d is outside a file of %d bytes", o, len(data))
			}
		}
		out, err := io.ReadAll(Reader(rs, offs))
		if err != nil || len(out) != len(data) {
			t.Fatalf("the retagged file is %d bytes (%v), the file %d", len(out), err, len(data))
		}
	})
}
