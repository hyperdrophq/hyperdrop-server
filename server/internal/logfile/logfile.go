// Package logfile is the server's own log on disk: one line per write,
// rotated by size and bounded to Keep files, so a chatty year cannot fill
// the volume. stderr keeps going to journald or the DSM log; this file is
// what the admin route and Server Management read.
package logfile

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const (
	// Name is the current file; rotated files are Name.1 (newest) … Name.(Keep-1).
	Name = "server.log"
	// MaxSize is where the current file rotates.
	MaxSize = 10 << 20
	// Keep bounds the set: the current file plus Keep-1 rotated ones.
	Keep = 10
)

// Writer appends lines to <dir>/Name and rotates it at MaxSize.
type Writer struct {
	mu   sync.Mutex
	dir  string
	f    *os.File
	size int64
}

// Open creates dir if needed and opens the current file for appending.
func Open(dir string) (*Writer, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	w := &Writer{dir: dir}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *Writer) open() error {
	f, err := os.OpenFile(filepath.Join(w.dir, Name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	w.f, w.size = f, st.Size()
	return nil
}

// Write appends p, rotating first when it would carry the file past MaxSize.
func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.size > 0 && w.size+int64(len(p)) > MaxSize {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	return n, err
}

// rotate shifts every numbered file up one, the current file to .1, and
// lets the oldest fall off.
func (w *Writer) rotate() error {
	w.f.Close()
	base := filepath.Join(w.dir, Name)
	os.Remove(fmt.Sprintf("%s.%d", base, Keep-1))
	for i := Keep - 2; i >= 1; i-- {
		os.Rename(fmt.Sprintf("%s.%d", base, i), fmt.Sprintf("%s.%d", base, i+1))
	}
	if err := os.Rename(base, base+".1"); err != nil && !os.IsNotExist(err) {
		return err
	}
	return w.open()
}

// Close closes the current file.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.f.Close()
}

// Tail answers the last `lines` lines across the rotated set, oldest file
// first, so a reader sees one continuous log. A directory holding no log
// answers nothing.
func Tail(dir string, lines int) ([]byte, error) { return TailBefore(dir, lines, 0) }

// TailBefore is Tail with the newest `skip` lines left out: what a reader
// paging back asks for once it holds the newest ones.
//
// The rotated set can hold Keep × MaxSize bytes, so it is read backwards
// from the end in tailChunk pieces, as far as the lines wanted reach, never
// whole: an admin paging through the log costs what it is shown.
func TailBefore(dir string, lines, skip int) ([]byte, error) {
	set, err := openSet(dir)
	if err != nil {
		return nil, err
	}
	defer set.close()
	// The answer ends at a line end: `end` is just past the newline that
	// closes the newest wanted line.
	end := set.total
	for n := 0; end > 0 && n < skip; {
		end--
		if end > 0 && set.byteAt(end-1) == '\n' {
			n++
		} else if end == 0 {
			n++
		}
	}
	if end == 0 {
		return nil, set.err
	}
	// Walk back `lines` line starts from there.
	start := end - 1 // the newline closing the newest wanted line
	for n := 0; start > 0; start-- {
		if set.byteAt(start-1) == '\n' {
			n++
			if n == lines {
				break
			}
		}
	}
	if set.err != nil {
		return nil, set.err
	}
	out := make([]byte, end-start)
	if err := set.readAt(out, start); err != nil {
		return nil, err
	}
	return out, nil
}

// tailChunk is how much of the log one backward read takes.
const tailChunk = 64 << 10

// logSet is the rotated files read as one log, oldest first, through files
// opened together, so a rotation while it is read moves nothing under it.
type logSet struct {
	files    []*os.File
	offsets  []int64 // where each file starts in the whole
	total    int64
	buf      []byte
	bufStart int64
	err      error
}

func openSet(dir string) (*logSet, error) {
	base := filepath.Join(dir, Name)
	s := &logSet{}
	add := func(path string, required bool) error {
		f, err := os.Open(path)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			if required {
				return err
			}
			return nil
		}
		st, err := f.Stat()
		if err != nil {
			f.Close()
			return err
		}
		s.files = append(s.files, f)
		s.offsets = append(s.offsets, s.total)
		s.total += st.Size()
		return nil
	}
	for i := Keep - 1; i >= 1; i-- {
		if err := add(fmt.Sprintf("%s.%d", base, i), false); err != nil {
			s.close()
			return nil, err
		}
	}
	if err := add(base, true); err != nil {
		s.close()
		return nil, err
	}
	return s, nil
}

func (s *logSet) close() {
	for _, f := range s.files {
		f.Close()
	}
}

// byteAt answers the byte at offset i of the whole log, reading the chunk
// that ends just past it when it is not already held; callers walk
// backwards, so each chunk is read once. A read error is kept in s.err and
// reads as a line end, which stops the walk.
func (s *logSet) byteAt(i int64) byte {
	if s.err != nil {
		return '\n'
	}
	if i < s.bufStart || i >= s.bufStart+int64(len(s.buf)) {
		start := max(0, i+1-tailChunk)
		if cap(s.buf) < tailChunk {
			s.buf = make([]byte, tailChunk)
		}
		s.buf = s.buf[:i+1-start]
		if err := s.readAt(s.buf, start); err != nil {
			s.err = err
			return '\n'
		}
		s.bufStart = start
	}
	return s.buf[i-s.bufStart]
}

// readAt fills p from offset off of the whole log.
func (s *logSet) readAt(p []byte, off int64) error {
	for k := len(s.files) - 1; k >= 0 && len(p) > 0; k-- {
		if off >= s.offsets[k] {
			n, err := s.files[k].ReadAt(p, off-s.offsets[k])
			if n < len(p) && k+1 < len(s.files) {
				// The rest lies in the files after this one.
				if err == nil || err == io.EOF {
					return s.readAt(p[n:], off+int64(n))
				}
			}
			if err == io.EOF && n == len(p) {
				err = nil
			}
			return err
		}
	}
	if len(p) > 0 {
		return io.ErrUnexpectedEOF
	}
	return nil
}

// DefaultTail and MaxTail bound what a reader asks for: the subcommand and
// the admin route share them so both show the same window.
const (
	DefaultTail = 2000
	MaxTail     = 5000
)
