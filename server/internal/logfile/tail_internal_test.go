package logfile

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// tailWhole is TailBefore over the whole set read into memory: the
// definition the backward reader must agree with.
func tailWhole(t *testing.T, dir string, lines, skip int) []byte {
	t.Helper()
	base := filepath.Join(dir, Name)
	var joined []byte
	for i := Keep - 1; i >= 1; i-- {
		if b, err := os.ReadFile(fmt.Sprintf("%s.%d", base, i)); err == nil {
			joined = append(joined, b...)
		}
	}
	b, _ := os.ReadFile(base)
	joined = append(joined, b...)
	end := len(joined)
	for n := 0; end > 0 && n < skip; {
		end--
		if end > 0 && joined[end-1] == '\n' {
			n++
		} else if end == 0 {
			n++
		}
	}
	if end == 0 {
		return nil
	}
	start := end - 1
	for n := 0; start > 0; start-- {
		if joined[start-1] == '\n' {
			n++
			if n == lines {
				break
			}
		}
	}
	return joined[start:end]
}

// The backward reader answers exactly what reading the whole set answers,
// across file and chunk boundaries, lines longer than a chunk and a current
// file without a final newline.
func TestTailReadsBackwardsAsTheWholeSetReads(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	dir := t.TempDir()
	base := filepath.Join(dir, Name)
	for i := Keep - 1; i >= 0; i-- {
		if i == 3 {
			continue // a gap in the numbering
		}
		var b []byte
		for range rng.IntN(400) {
			n := rng.IntN(300)
			if rng.IntN(50) == 0 {
				n = tailChunk + rng.IntN(tailChunk)
			}
			b = append(b, bytes.Repeat([]byte{byte('a' + i)}, n)...)
			b = append(b, '\n')
		}
		path := base
		if i > 0 {
			path = fmt.Sprintf("%s.%d", base, i)
		}
		if i == 0 {
			b = append(b, "no newline at the end"...)
		}
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range [][2]int{{1, 0}, {5, 0}, {2000, 0}, {5000, 0}, {1, 1}, {3, 7}, {100, 900}, {5000, 1500}, {10, 100000}} {
		got, err := TailBefore(dir, c[0], c[1])
		if err != nil {
			t.Fatal(err)
		}
		if want := tailWhole(t, dir, c[0], c[1]); !bytes.Equal(got, want) {
			t.Errorf("TailBefore(%d, %d): %d bytes, want %d", c[0], c[1], len(got), len(want))
		}
	}
}

// A tail costs what it shows: the newest lines of a set holding tens of
// megabytes are read without reading the set.
func TestTailReadsOnlyWhatItShows(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, Name)
	line := append(bytes.Repeat([]byte("x"), 99), '\n')
	file := bytes.Repeat(line, MaxSize/len(line))
	for _, path := range []string{base + ".2", base + ".1", base} {
		if err := os.WriteFile(path, file, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	out, err := Tail(dir, 100)
	runtime.ReadMemStats(&after)
	if err != nil || len(out) != 100*len(line) {
		t.Fatalf("Tail = %d bytes, %v", len(out), err)
	}
	if got := after.TotalAlloc - before.TotalAlloc; got > 1<<20 {
		t.Fatalf("a 100-line tail of %d MiB allocated %d bytes", 3*MaxSize>>20, got)
	}
}
