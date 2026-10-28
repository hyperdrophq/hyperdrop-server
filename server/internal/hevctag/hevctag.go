// Package hevctag rewrites an MP4's `hev1` HEVC sample entry to `hvc1` as the
// file is served.
//
// The two sample-entry types describe the SAME bitstream: `hvc1` keeps its
// parameter sets in the `hvcC` box, `hev1` also allows them in the stream.
// Apple's decoders and every browser play `hvc1` and refuse `hev1` outright,
// so a camera that writes `hev1` (Hikvision and most NVRs do) reaches a
// viewer as a player with sound and no picture. The names are the same
// length, so every offset in the file, every Range answer's length and the
// file on disk are exactly what they were, and no picture byte is touched.
//
// `core/api/hevctag.go` answers the same question for the app's loopback
// preview, over Range reads of a remote file. core/api is not one of the pure
// core packages the server may import (server/pureimports_test.go), so the
// server keeps its own scan. The two are pinned by the same fixtures and the
// same expectations: a change to what one finds owes the same change to the
// other.
package hevctag

import (
	"encoding/binary"
	"io"
	"math"
	"strings"
)

const (
	HEV1 = "hev1"
	HVC1 = "hvc1"
)

// Enough top-level boxes to pass ftyp, free space and an mdat before the
// moov, and few enough that a file which is not an MP4 stops costing reads.
const maxTopLevelBoxes = 32

// maxBoxes bounds how many box headers one scan reads, so a file built to
// repeat or nest boxes cannot spin it.
const maxBoxes = 4096

// Applies answers whether a name is worth scanning: the tag lives in an ISO
// base media container, so everything else is served without paying a scan.
func Applies(name string) bool {
	n := strings.ToLower(name)
	return strings.HasSuffix(n, ".mp4") || strings.HasSuffix(n, ".m4v") || strings.HasSuffix(n, ".mov")
}

// topLevelBox answers whether a type is one an ISO base media file can open
// with. Anything may be named `.mp4`, and a length read out of arbitrary
// bytes would send the walk anywhere.
func topLevelBox(typ string) bool {
	switch typ {
	case "ftyp", "moov", "mdat", "free", "skip", "wide", "pnot", "styp":
		return true
	}
	return false
}

// scanner walks the box tree by reading box HEADERS where they sit in the
// file, never a box's payload: the scan costs a few bytes per box however
// large the movie header is, so a visitor opening a long recording, or many
// visitors opening it at once, never makes the server hold the moov in
// memory.
type scanner struct {
	read  func(off, n int64) ([]byte, error)
	boxes int
}

// header reads the box at off inside a parent ending at end, or at the top
// level when end is negative. It answers the box's type, where its payload
// starts and where the next box starts. A length that does not fit ends the
// walk: half a box is not a box, and bytes that are not boxes read as
// garbage lengths, which is the same answer.
func (s *scanner) header(off, end int64) (typ string, body, next int64, ok bool) {
	if s.boxes++; s.boxes > maxBoxes {
		return "", 0, 0, false
	}
	if end >= 0 && end-off < 8 {
		return "", 0, 0, false
	}
	head, err := s.read(off, 16)
	if err != nil || len(head) < 8 {
		return "", 0, 0, false
	}
	size := int64(binary.BigEndian.Uint32(head))
	hdr := int64(8)
	switch size {
	case 1:
		if len(head) < 16 {
			return "", 0, 0, false
		}
		size = int64(binary.BigEndian.Uint64(head[8:]))
		hdr = 16
	case 0:
		// To the end of the parent. At the top level the file's end is not
		// known here, and nothing follows such a box, so the walk ends.
		if end < 0 {
			return "", 0, 0, false
		}
		size = end - off
	}
	if size < hdr || size > math.MaxInt64-off || end >= 0 && size > end-off {
		return "", 0, 0, false
	}
	return string(head[4:8]), off + hdr, off + size, true
}

// each calls visit for every box laid end to end in [off, end), with where
// the box starts and where its payload starts and ends.
func (s *scanner) each(off, end int64, visit func(typ string, start, body, next int64)) {
	for off < end {
		typ, body, next, ok := s.header(off, end)
		if !ok {
			return
		}
		visit(typ, off, body, next)
		off = next
	}
}

// hev1Offsets answers where every `hev1` sample-entry type field sits in the
// file, given the moov's payload. Only the sample description is read: the
// four letters appear there as a type, and anywhere else in the file they
// are picture bytes that happen to spell it.
func (s *scanner) hev1Offsets(body, end int64) []int64 {
	var out []int64
	path := []string{"trak", "mdia", "minf", "stbl", "stsd"}
	var descend func(depth int, body, end int64)
	descend = func(depth int, body, end int64) {
		if depth == len(path) {
			// A version byte, three flag bytes and the entry count come
			// before the entries themselves.
			s.each(body+8, end, func(typ string, start, _, _ int64) {
				if typ == HEV1 {
					out = append(out, start+4)
				}
			})
			return
		}
		s.each(body, end, func(typ string, _, body, next int64) {
			if typ == path[depth] {
				descend(depth+1, body, next)
			}
		})
	}
	descend(0, body, end)
	return out
}

// Offsets scans an open file for `hev1` sample entries and answers where they
// are. The reader is left where it was found. Anything that cannot be read as
// an MP4 answers nothing, which serves the file exactly as before.
func Offsets(rs io.ReadSeeker) []int64 {
	here, err := rs.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil
	}
	defer func() { _, _ = rs.Seek(here, io.SeekStart) }()
	s := &scanner{read: func(off, n int64) ([]byte, error) {
		if _, err := rs.Seek(off, io.SeekStart); err != nil {
			return nil, err
		}
		buf := make([]byte, n)
		got, err := io.ReadFull(rs, buf)
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			return buf[:got], nil
		}
		if err != nil {
			return nil, err
		}
		return buf, nil
	}}
	var off int64
	for i := 0; i < maxTopLevelBoxes; i++ {
		typ, body, next, ok := s.header(off, -1)
		if !ok {
			return nil
		}
		if i == 0 && !topLevelBox(typ) {
			return nil
		}
		if typ == "moov" {
			return s.hev1Offsets(body, next)
		}
		off = next
	}
	return nil
}

// Reader serves the file with its `hev1` type fields rewritten. It is a
// ReadSeeker so `http.ServeContent` keeps answering Range exactly as it did:
// the patch happens at the source, in whatever window is actually read.
func Reader(rs io.ReadSeeker, offs []int64) io.ReadSeeker {
	return &retagReader{rs: rs, offs: offs}
}

type retagReader struct {
	rs   io.ReadSeeker
	pos  int64
	offs []int64
}

func (r *retagReader) Read(p []byte) (int, error) {
	n, err := r.rs.Read(p)
	if n > 0 {
		patch(p[:n], r.pos, r.offs)
		r.pos += int64(n)
	}
	return n, err
}

func (r *retagReader) Seek(off int64, whence int) (int64, error) {
	pos, err := r.rs.Seek(off, whence)
	if err == nil {
		r.pos = pos
	}
	return pos, err
}

// patch overwrites any tag the window carries. `start` is the offset in the
// FILE of the window's first byte, so a tag split across two reads is patched
// in both.
func patch(p []byte, start int64, offs []int64) {
	end := start + int64(len(p))
	for _, off := range offs {
		if off+4 <= start || off >= end {
			continue
		}
		for i := int64(0); i < 4; i++ {
			at := off + i - start
			if at >= 0 && at < int64(len(p)) {
				p[at] = HVC1[i]
			}
		}
	}
}
