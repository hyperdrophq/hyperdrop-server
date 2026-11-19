package api

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestZipDownloadSendsContentLength(t *testing.T) {
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "bundle", map[string]string{
		"a.txt":     "alpha",
		"sub/b.txt": "bravo",
	})
	rec := doReq(t, h, "GET", "/zip/"+id, "", "")
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	cl := rec.Header().Get("Content-Length")
	if cl == "" {
		t.Fatal("no Content-Length on zip download")
	}
	n, err := strconv.Atoi(cl)
	if err != nil || n != rec.Body.Len() {
		t.Fatalf("Content-Length = %q, body is %d bytes", cl, rec.Body.Len())
	}
}

// A request that can't get its turn before its client goes away streams nothing
// (no partial zip bytes, no held place).
func TestZipStreamCapRespectsCancel(t *testing.T) {
	h := newTestAPI(t)
	id, _ := shareWithFiles(t, h, "bundle", map[string]string{"a.txt": "alpha"})

	// Hold every place the load leaves.
	saved := zipSlots
	zipSlots = newZipGate(func(int64) bool { return false })
	t.Cleanup(func() { zipSlots = saved })
	for i := range zipFloor {
		if !zipSlots.acquire(context.Background(), oneShare(fmt.Sprintf("hog-%d", i)), 0) {
			t.Fatal("could not fill the zip places")
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // client already gone
	req := httptest.NewRequest("GET", "/zip/"+id, nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Body.Len() != 0 {
		t.Fatalf("blocked zip wrote %d bytes, want none", rec.Body.Len())
	}
}
