package sharefs

import (
	"encoding/binary"
	"os"
	"testing"
)

// The ranges of an upload arrive in whatever order and overlap the client
// sends. The list stays sorted, disjoint and without touching neighbours, it
// holds exactly the bytes sent, and what is missing is the rest of the file.
func FuzzAddRange(f *testing.F) {
	f.Add([]byte{0, 0, 0, 5, 0, 5, 0, 5, 0, 20, 0, 1}, uint16(64))
	f.Add([]byte{0, 10, 0, 5, 0, 0, 0, 20, 0, 3, 0, 0}, uint16(30))
	f.Add([]byte{}, uint16(0))
	f.Fuzz(func(t *testing.T, raw []byte, size uint16) {
		total := int64(size)
		sent := make([]bool, total)
		var have []Range
		for ; len(raw) >= 4; raw = raw[4:] {
			start := int64(binary.BigEndian.Uint16(raw))
			r := Range{start, start + int64(binary.BigEndian.Uint16(raw[2:]))}
			if r.End > total {
				continue // the route refuses a range outside the file
			}
			have = addRange(have, r)
			for i := r.Start; i < r.End; i++ {
				sent[i] = true
			}
		}
		var want int64
		for _, s := range sent {
			if s {
				want++
			}
		}
		for i, h := range have {
			if h.Start < 0 || h.Len() <= 0 || h.End > total {
				t.Fatalf("range %d of %v is not inside the file", i, have)
			}
			if i > 0 && have[i-1].End >= h.Start {
				t.Fatalf("ranges %d and %d of %v overlap or touch", i-1, i, have)
			}
			for b := h.Start; b < h.End; b++ {
				if !sent[b] {
					t.Fatalf("%v holds byte %d, which was never sent", have, b)
				}
			}
		}
		if got := receivedBytes(have); got != want {
			t.Fatalf("%v holds %d bytes, %d were sent", have, got, want)
		}
		st := stateOf(rangesState{Total: total, Have: have})
		var missing int64
		for _, m := range st.Missing {
			if m.Len() <= 0 {
				t.Fatalf("an empty missing range in %v", st.Missing)
			}
			for b := m.Start; b < m.End; b++ {
				if sent[b] {
					t.Fatalf("byte %d is reported missing and was sent", b)
				}
			}
			missing += m.Len()
		}
		if missing+want != total || st.Complete != (want == total) {
			t.Fatalf("%d missing, %d held of %d, complete %v", missing, want, total, st.Complete)
		}
		if st.Prefix < 0 || st.Prefix > total || (st.Prefix > 0 && !sent[st.Prefix-1]) {
			t.Fatalf("prefix %d of %v", st.Prefix, have)
		}
	})
}

// A ranges sidecar is read back from disk, where it may be damaged. One that
// reads names a positive total and ranges inside it, so it never counts more
// bytes than the file has, and what it reports missing is the rest.
func FuzzReadRanges(f *testing.F) {
	f.Add([]byte(`{"total":10,"have":[[0,4],[6,10]]}`))
	f.Add([]byte(`{"total":0,"have":[]}`))
	f.Add([]byte(`{"total":5,"have":[[9223372036854775807,-9223372036854775808],[3,1]]}`))
	f.Add([]byte(`{"total":5,"have":[[0]]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(dir+"/p.part"+partRangesExt, data, 0o600); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		st, ok := readRanges(root, "p.part")
		if !ok {
			return
		}
		if st.Total <= 0 {
			t.Fatalf("read a sidecar of total %d", st.Total)
		}
		state := stateOf(st)
		var missing int64
		for _, m := range state.Missing {
			if m.Start < 0 || m.Len() <= 0 || m.End > st.Total {
				t.Fatalf("%s reports %v missing of %d", data, m, st.Total)
			}
			missing += m.Len()
		}
		if state.Received < 0 || state.Received+missing != st.Total || state.Prefix > st.Total {
			t.Fatalf("%s: %d received, %d missing, prefix %d of %d", data, state.Received, missing, state.Prefix, st.Total)
		}
	})
}
