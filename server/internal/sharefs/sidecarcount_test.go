package sharefs

import "testing"

// The count is kept in memory, so a fresh process learns it from the disk.
func TestRecountReadsTilesAndPostersFromTheDisk(t *testing.T) {
	f := openTest(t)
	const slug = "6f1c3b0e-2d4a-4b8e-9c3f-0a1b2c3d4e5f"
	tile, poster := jpegBytes(t), jpegBytes(t)
	if err := f.SetThumb(testID, "alice", slug, tile, nil); err != nil {
		t.Fatal(err)
	}
	if err := f.SetPoster(testID, "alice", "", poster); err != nil {
		t.Fatal(err)
	}
	want := int64(len(tile) + len(poster))
	if got := f.SidecarBytes("alice"); got != want {
		t.Fatalf("after the writes: %d, want %d", got, want)
	}
	fresh := reopen(t, f)
	if got := fresh.SidecarBytes("alice"); got != 0 {
		t.Fatalf("a fresh process knows %d before a recount", got)
	}
	fresh.RecountSidecars(testID, "alice")
	if got := fresh.SidecarBytes("alice"); got != want {
		t.Fatalf("after the recount: %d, want %d", got, want)
	}
	fresh.RemoveThumb(testID, slug)
	if err := fresh.RemovePoster(testID); err != nil {
		t.Fatal(err)
	}
	if got := fresh.SidecarBytes("alice"); got != 0 {
		t.Fatalf("after the removals: %d", got)
	}
	fresh.RecountSidecars(testID, "alice")
	if got := fresh.SidecarBytes("alice"); got != 0 {
		t.Fatalf("a recount of nothing: %d", got)
	}
}

// A refusal from the room check leaves the disk and the count alone.
func TestARefusedTileIsNeitherWrittenNorCounted(t *testing.T) {
	f := openTest(t)
	f.SidecarRoom = func(string, string, int64) error { return ErrBadRequest }
	const slug = "6f1c3b0e-2d4a-4b8e-9c3f-0a1b2c3d4e5f"
	if err := f.SetThumb(testID, "alice", slug, jpegBytes(t), nil); err == nil {
		t.Fatal("the refused tile was stored")
	}
	if _, err := f.Thumb(testID, slug); err == nil {
		t.Fatal("the refused tile is on the disk")
	}
	if got := f.SidecarBytes("alice"); got != 0 {
		t.Fatalf("counted %d", got)
	}
}
