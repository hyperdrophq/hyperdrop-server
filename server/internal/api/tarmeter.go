package api

import (
	"archive/tar"
	"io"
	"net/http"
	"strings"
)

// batchMaxMetaBytes bounds the tar meta headers (PAX and GNU long-name
// records with their data) one batch request may carry. Go's tar reader
// consumes any number of them inside a single Next(), so entry counts alone
// do not bound the work a stream can cost.
const batchMaxMetaBytes = 16 << 20

// tarMeter reads a batch's decoded tar stream, bounds its total length and
// measures how much of it is meta headers: the bytes read beyond the header
// blocks and padded data of the entries Next() returned.
type tarMeter struct {
	r         io.Reader
	limit     int64
	read      int64
	accounted int64
	prevData  int64
	spent     bool
}

// newTarMeter bounds r at the largest stream a legitimate batch makes: its
// data, its meta headers, and a header block with padding per entry.
func newTarMeter(r io.Reader) *tarMeter {
	return &tarMeter{r: r, limit: batchMaxBytes + batchMaxMetaBytes + batchMaxEntries*1024}
}

func (m *tarMeter) Read(p []byte) (int, error) {
	if left := m.limit - m.read; left <= 0 {
		m.spent = true
		return 0, refuse(http.StatusRequestEntityTooLarge, "", "batch exceeds the per-request byte limit")
	} else if int64(len(p)) > left {
		p = p[:left]
	}
	n, err := m.r.Read(p)
	m.read += int64(n)
	return n, err
}

// entry accounts for the header block hdr came in and the previous entry's
// data rounded up to the 512-byte block, both of which are not meta bytes.
func (m *tarMeter) entry(hdr *tar.Header) {
	m.accounted += 512 + (m.prevData+511)/512*512
	m.prevData = carriedData(hdr)
}

// carriedData is how many data bytes the stream holds after hdr. Only a
// regular entry's data follows its header: the Size of a directory, link or
// device entry is not carried, and a sparse entry's Size is its logical
// length, so it is charged nothing (its stored bytes then count as meta,
// which errs toward refusing).
func carriedData(hdr *tar.Header) int64 {
	if hdr.Typeflag != tar.TypeReg {
		return 0
	}
	for k := range hdr.PAXRecords {
		if strings.HasPrefix(k, "GNU.sparse.") {
			return 0
		}
	}
	return hdr.Size
}

// metaBytes is what has been read beyond the accounted entries.
func (m *tarMeter) metaBytes() int64 { return m.read - m.accounted }

// exhausted reports that the stream hit its total bound.
func (m *tarMeter) exhausted() bool { return m.spent }

// nextRefusal is the refusal for a failed Next(): the byte bound when the
// stream ran into it, otherwise the stream's own failure.
func (m *tarMeter) nextRefusal(err error) error {
	if m.exhausted() {
		return refuse(http.StatusRequestEntityTooLarge, "", "batch exceeds the per-request byte limit")
	}
	return tarRefusal(err)
}

// metaRefusal is the 413 for a stream whose meta headers outgrew their bound.
// It runs after Next() returns, so one Next() can read up to the stream bound
// before the check sees it; the total bound is what stops that read.
func (m *tarMeter) metaRefusal() error {
	if m.metaBytes() > batchMaxMetaBytes {
		return refuse(http.StatusRequestEntityTooLarge, "", "batch headers exceed the per-request limit")
	}
	return nil
}
