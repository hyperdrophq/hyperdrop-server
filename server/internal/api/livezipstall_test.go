package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/metadb"
)

type endlessZeros struct{}

func (endlessZeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// A visitor who stops reading a live share's zip loses it, as on every other
// file route, or a few of them would hold every place the live share's jobs have
// for as long as their connections stay open.
func TestAStalledLiveZipEndsAndGivesItsPlaceBack(t *testing.T) {
	prevZip, prevFile := zipStallTimeout, fileStallTimeout
	zipStallTimeout, fileStallTimeout = time.Second, time.Second
	t.Cleanup(func() { zipStallTimeout, fileStallTimeout = prevZip, prevFile })
	hh := newHandler(testBackend(t), "2.0.0", testDomain(t), nil, Deployment{})
	srv := httptest.NewServer(hh.routes())
	defer srv.Close()
	do := func(method, path string, body io.Reader) []byte {
		req, _ := http.NewRequest(method, srv.URL+path, body)
		req.Header.Set("Authorization", "Bearer "+testToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		return data
	}
	var share struct{ ID string }
	data := do("POST", "/api/live-share", strings.NewReader(
		`{"name":"l","files":[{"path":"big.bin","size":8589934592,"mime":"image/png","mtime":"2026-01-01T00:00:00Z"}]}`))
	if err := json.Unmarshal(data, &share); err != nil || share.ID == "" {
		t.Fatalf("create = %s", data)
	}
	// The sharer: claims each job and sends zeros for as long as it is read.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			var jobs struct{ Jobs []struct{ Job string } }
			json.Unmarshal(do("GET", "/api/live-share/"+share.ID+"/jobs", nil), &jobs)
			for _, j := range jobs.Jobs {
				go do("POST", "/api/live-share/jobs/"+j.Job, endlessZeros{})
			}
		}
	}()
	time.Sleep(200 * time.Millisecond)
	c, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.(*net.TCPConn).SetReadBuffer(4096)
	fmt.Fprintf(c, "GET /zip/%s HTTP/1.1\r\nHost: x\r\n\r\n", share.ID)
	active := func() int { return hh.dl.activeFor(metadb.DefaultAdminName, []string{share.ID}) }
	deadline := time.Now().Add(3 * time.Second)
	for active() == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if active() == 0 {
		t.Fatal("the zip never started")
	}
	deadline = time.Now().Add(15 * time.Second)
	for active() != 0 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if got := active(); got != 0 {
		t.Fatalf("%d transfers still held by a visitor who stopped reading", got)
	}
}
