//go:build unix

package api

import (
	"os"
	"syscall"
	"testing"
	"time"
)

// A video card reads the clip's header through the file layer's open, so a
// FIFO standing where the stored file was answers at once instead of
// holding the unfurler's request until somebody writes to it.
func TestAVideoCardNeverWaitsOnAFIFO(t *testing.T) {
	h, b := newTestAPIBackend(t)
	id, slugs := shareWithFiles(t, h, "demo",
		map[string]string{"screencast.mp4": mp4Fixture(23, 1920, 1200, 4096)})
	p, err := b.FS.FilePath(id, "screencast.mp4")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(p, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if w, err := os.OpenFile(p, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			w.Close()
		}
	})
	done := make(chan int, 1)
	go func() { done <- doReqUA(t, h, "/view/"+id+"/"+slugs["screencast.mp4"], telegramUA).Code }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the card is still waiting on a FIFO")
	}
}
