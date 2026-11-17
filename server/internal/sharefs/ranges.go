package sharefs

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Range is one half-open byte range [Start, End) of a ranged upload. On the
// wire it is the pair [start, end].
type Range struct{ Start, End int64 }

// Len is how many bytes the range covers.
func (r Range) Len() int64 { return r.End - r.Start }

// MarshalJSON writes the range as [start, end].
func (r Range) MarshalJSON() ([]byte, error) { return json.Marshal([2]int64{r.Start, r.End}) }

// UnmarshalJSON reads [start, end].
func (r *Range) UnmarshalJSON(b []byte) error {
	var pair [2]int64
	if err := json.Unmarshal(b, &pair); err != nil {
		return err
	}
	r.Start, r.End = pair[0], pair[1]
	return nil
}

// addRange folds r into have, which is sorted, disjoint and never holds two
// touching ranges, and returns the result in the same form.
func addRange(have []Range, r Range) []Range {
	if r.Len() <= 0 {
		return have
	}
	out := make([]Range, 0, len(have)+1)
	i := 0
	for ; i < len(have) && have[i].End < r.Start; i++ {
		out = append(out, have[i])
	}
	for ; i < len(have) && have[i].Start <= r.End; i++ {
		r.Start = min(r.Start, have[i].Start)
		r.End = max(r.End, have[i].End)
	}
	out = append(out, r)
	return append(out, have[i:]...)
}

// missingRanges is [0, total) minus have. Never nil, so an upload with
// nothing missing writes [] on the wire, not null.
func missingRanges(have []Range, total int64) []Range {
	out := []Range{}
	at := int64(0)
	for _, h := range have {
		if h.Start > at {
			out = append(out, Range{at, min(h.Start, total)})
		}
		at = max(at, h.End)
	}
	if at < total {
		out = append(out, Range{at, total})
	}
	return out
}

func receivedBytes(have []Range) (n int64) {
	for _, h := range have {
		n += h.Len()
	}
	return n
}

// contiguousPrefix is how many bytes from 0 are staged with no gap: the
// status route's offset.
func contiguousPrefix(have []Range) int64 {
	if len(have) > 0 && have[0].Start == 0 {
		return have[0].End
	}
	return 0
}

// RangeState is where a ranged upload stands.
type RangeState struct {
	Total    int64
	Received int64
	Prefix   int64
	Missing  []Range
	Complete bool
}

func stateOf(st rangesState) RangeState {
	m := missingRanges(st.Have, st.Total)
	return RangeState{Total: st.Total, Received: receivedBytes(st.Have),
		Prefix: contiguousPrefix(st.Have), Missing: m, Complete: len(m) == 0}
}

// rangesState is the <part>.ranges sidecar of a ranged upload: the total its
// session declared and the ranges whose bytes are synced into the part. A
// range is added only after its bytes are synced, so the sidecar never
// claims a byte the part may not hold. The sidecar is replaced by a synced
// temporary file renamed over it, then the directory is synced, so a power
// cut leaves either the old list or the new one, never a torn file: at worst
// the newest range is lost and the client sends it again.
type rangesState struct {
	Total int64   `json:"total"`
	Have  []Range `json:"have"`
}

// hasRangesSidecar reports whether the part is a ranged one: a ranges
// sidecar exists, readable or not, so a damaged one never lets Commit take
// the sparse part for one Write staged.
func hasRangesSidecar(r *os.Root, part string) bool {
	_, err := r.Stat(part + partRangesExt)
	return err == nil
}

func readRanges(r *os.Root, part string) (rangesState, bool) {
	data, err := r.ReadFile(part + partRangesExt)
	if err != nil {
		return rangesState{}, false
	}
	var st rangesState
	if json.Unmarshal(data, &st) != nil || st.Total <= 0 {
		return rangesState{}, false
	}
	return st, true
}

func writeRanges(r *os.Root, part string, st rangesState) error {
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return replaceFile(r, part+partRangesExt, data, true)
}

// replaceFile replaces rel with data through a temporary file renamed over
// it, so a reader never sees a partial file. durable adds the syncs that
// keep the new content across a power cut: the temporary file before its
// rename and the directory after it. A failed write or rename removes the
// temporary file.
func replaceFile(r *os.Root, rel string, data []byte, durable bool) error {
	tmp := rel + ".tmp"
	fh, err := r.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = fh.Write(data)
	if err == nil && durable {
		err = fh.Sync()
	}
	if closeErr := fh.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = r.Rename(tmp, rel)
	}
	if err != nil {
		r.Remove(tmp)
		return err
	}
	if durable {
		syncDir(r, filepath.Dir(rel))
	}
	return nil
}

// syncDir makes the renames into dir durable: a rename reaches the disk only
// with its directory. A failed sync leaves a whole file either way, so it is
// not an error.
func syncDir(r *os.Root, dir string) {
	if d, err := r.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
}
