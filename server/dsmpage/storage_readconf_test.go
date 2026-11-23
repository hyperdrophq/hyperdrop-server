package dsmpage

import (
	"net/http"
	"os"
	"syscall"
	"testing"
	"time"
)

// A DSM 7 Storage request reads the conf once. The conf is a named pipe a
// writer fills exactly once: a second open would wait for a writer that
// never comes, and the request would never answer.
func TestStorageOnDSM7ReadsTheConfOnce(t *testing.T) {
	r := newSaveRig(t, freeConf)
	want := r.onVolume1()
	os.Remove(r.deps.ConfPath)
	if err := syscall.Mkfifo(r.deps.ConfPath, 0o600); err != nil {
		t.Fatal(err)
	}
	go func() {
		f, err := os.OpenFile(r.deps.ConfPath, os.O_WRONLY, 0)
		if err != nil {
			return
		}
		f.WriteString(freeConf)
		f.Close()
	}()
	answered := make(chan map[string]any, 1)
	go func() { answered <- decodeMap(t, r.storage(http.MethodGet, "/api/storage")) }()
	select {
	case m := <-answered:
		if m["folder"] != "hyperdrop" || m["path"] != want || m["volume"] != "/volume1" {
			t.Fatalf("%v", m)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the Storage request opened the conf a second time")
	}
}
