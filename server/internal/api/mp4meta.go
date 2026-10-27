package api

import (
	"encoding/binary"
	"errors"
	"io"
)

// MP4 header metadata for link previews: display size and duration, read
// straight out of the container's atoms.
//
// This decodes NOTHING. It walks the box tree to `moov/mvhd` (duration) and
// `moov/trak/tkhd` (track dimensions) and reads a few integers, the same
// class of information as the file's name and size, which cards already
// carry. No frame is ever decoded, so no untrusted video data reaches a
// decoder and the server keeps needing nothing but the Go standard library.

// mp4Info is what a card can say about a video beyond its size.
type mp4Info struct {
	Width    int
	Height   int
	Duration int // whole seconds, 0 when unknown
}

// mp4ScanLimit caps how much of the file the walk may traverse. `moov` sits
// at the front of every file we produce (the encoder writes faststart), so a
// small budget is enough; a file that hides `moov` behind gigabytes of `mdat`
// simply reports nothing rather than costing a long read.
const mp4ScanLimit = 8 << 20

// mp4MaxBoxes bounds the number of boxes visited: a malformed or hostile
// file must not be able to spin this walk.
const mp4MaxBoxes = 4096

var errMP4Malformed = errors.New("malformed mp4")

// readMP4Info reads display size and duration from an MP4/QuickTime file's
// bytes. Any error (not an MP4, truncated, weird) yields a zero mp4Info: a
// preview then just omits the fields.
func readMP4Info(f io.ReaderAt) mp4Info {
	var info mp4Info
	visited := 0
	if err := walkMP4(f, 0, mp4ScanLimit, &visited, &info); err != nil && info.Width == 0 {
		return mp4Info{}
	}
	return info
}

// walkMP4 walks the boxes in [off, off+size), descending only into the two
// containers that can hold what we want.
func walkMP4(r io.ReaderAt, off, size int64, visited *int, info *mp4Info) error {
	end := off + size
	for off < end {
		if *visited++; *visited > mp4MaxBoxes {
			return errMP4Malformed
		}
		var header [8]byte
		if _, err := r.ReadAt(header[:], off); err != nil {
			return err
		}
		boxSize := int64(binary.BigEndian.Uint32(header[0:4]))
		name := string(header[4:8])
		body := off + 8
		switch boxSize {
		case 0:
			// "to end of file", only meaningful for the last box; treat the
			// remaining window as its body.
			boxSize = end - off
		case 1:
			// 64-bit size follows the header.
			var ext [8]byte
			if _, err := r.ReadAt(ext[:], body); err != nil {
				return err
			}
			boxSize = int64(binary.BigEndian.Uint64(ext[:]))
			body += 8
		}
		if boxSize < 8 || off+boxSize > end {
			return errMP4Malformed
		}
		switch name {
		case "moov", "trak":
			// Containers on the path to mvhd/tkhd; ignore a failure inside one
			// so a broken sibling can't discard what we already found.
			_ = walkMP4(r, body, off+boxSize-body, visited, info)
		case "mvhd":
			readMVHD(r, body, off+boxSize-body, info)
		case "tkhd":
			readTKHD(r, body, off+boxSize-body, info)
		}
		off += boxSize
	}
	return nil
}

// readMVHD takes the movie duration: version(1)+flags(3), then times, which
// are 32-bit fields in version 0 and 64-bit in version 1.
func readMVHD(r io.ReaderAt, off, size int64, info *mp4Info) {
	if size < 20 {
		return
	}
	buf := make([]byte, min(size, 32))
	if _, err := r.ReadAt(buf, off); err != nil {
		return
	}
	var timescale, duration uint64
	switch buf[0] {
	case 0:
		if len(buf) < 20 {
			return
		}
		timescale = uint64(binary.BigEndian.Uint32(buf[12:16]))
		duration = uint64(binary.BigEndian.Uint32(buf[16:20]))
	case 1:
		if len(buf) < 32 {
			return
		}
		timescale = uint64(binary.BigEndian.Uint32(buf[20:24]))
		duration = binary.BigEndian.Uint64(buf[24:32])
	default:
		return
	}
	if timescale == 0 {
		return
	}
	info.Duration = int(duration / timescale)
}

// readTKHD takes the DISPLAY dimensions of the first track that has any
// (16.16 fixed point at the end of the box). An audio track reports 0×0 and
// is skipped, and a second video track can't overwrite the first.
func readTKHD(r io.ReaderAt, off, size int64, info *mp4Info) {
	if info.Width > 0 || size < 84 {
		return
	}
	buf := make([]byte, min(size, 92))
	if _, err := r.ReadAt(buf, off); err != nil {
		return
	}
	// version 0: 84-byte body, version 1: 96 (the three time fields grow).
	var dimOff int
	switch buf[0] {
	case 0:
		dimOff = 76
	case 1:
		dimOff = 88
	default:
		return
	}
	if len(buf) < dimOff+8 {
		return
	}
	w := binary.BigEndian.Uint32(buf[dimOff:dimOff+4]) >> 16
	h := binary.BigEndian.Uint32(buf[dimOff+4:dimOff+8]) >> 16
	if w == 0 || h == 0 {
		return
	}
	info.Width, info.Height = int(w), int(h)
}
