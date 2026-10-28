package api

import "testing"

func TestParseLoad1(t *testing.T) {
	if v := parseLoad1([]byte("1.42 0.58 0.59 2/345 6789")); v != 1.42 {
		t.Fatalf("load1 = %v", v)
	}
	if v := parseLoad1([]byte("")); v != 0 {
		t.Fatalf("empty = %v", v)
	}
}

// The parser reads the two fields the verdict needs out of a real
// /proc/meminfo, and answers zeroes for anything it cannot make sense of:
// unknown memory must read as unknown, never as none.
func TestParseMemInfo(t *testing.T) {
	data := []byte("MemTotal:         498048 kB\nMemFree:           71234 kB\nMemAvailable:     102400 kB\nBuffers:            9999 kB\n")
	total, avail := parseMemInfo(data)
	if total != 498048*1024 || avail != 102400*1024 {
		t.Fatalf("total=%d avail=%d", total, avail)
	}
	if total, avail := parseMemInfo([]byte("garbage")); total != 0 || avail != 0 {
		t.Fatal("garbage must parse to zeros")
	}
}
