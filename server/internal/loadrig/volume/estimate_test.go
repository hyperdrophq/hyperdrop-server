package volume

import "testing"

func TestEstimateDiskFollowsTheFileCount(t *testing.T) {
	small, large := EstimateDisk(NewPlan(10_000, 1)), EstimateDisk(NewPlan(100_000, 1))
	files, _ := NewPlan(10_000, 1).Totals()
	if small != files*diskBytesPerFile {
		t.Fatalf("estimate %d, want %d", small, files*diskBytesPerFile)
	}
	if large <= small {
		t.Fatalf("a larger plan estimates %d, not more than %d", large, small)
	}
}

func TestFreeBytesOfADirectoryNotYetMade(t *testing.T) {
	free, ok := FreeBytes(t.TempDir() + "/a/b/c")
	if !ok || free <= 0 {
		t.Fatalf("FreeBytes = %d, %v", free, ok)
	}
}
