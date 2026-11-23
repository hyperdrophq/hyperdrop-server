package housekeep

import (
	"bytes"
	"context"
	"image"
	"image/jpeg"
	"testing"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/sharefs"
)

// The quota's count of tiles and posters lives in memory, so the recount a
// process runs at its start is what brings it back from the disk.
func TestTheRecountLearnsWhatTilesAndPostersOccupy(t *testing.T) {
	x := setup(t)
	id := x.share(t, metadb.CreateOptions{}).ID
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, image.NewRGBA(image.Rect(0, 0, 8, 8)), nil); err != nil {
		t.Fatal(err)
	}
	if err := x.fs.SetPoster(id, "alice", "", buf.Bytes()); err != nil {
		t.Fatal(err)
	}
	fresh, err := sharefs.Open(x.dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := fresh.SidecarBytes("alice"); got != 0 {
		t.Fatalf("a fresh process knows %d", got)
	}
	(&Pass{DB: x.db, FS: fresh}).RecountSidecars(context.Background())
	if got, want := fresh.SidecarBytes("alice"), int64(buf.Len()); got != want {
		t.Fatalf("after the recount: %d, want %d", got, want)
	}
}
