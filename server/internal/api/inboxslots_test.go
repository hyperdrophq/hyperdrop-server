package api

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestInboxSlotsBoundEachKeyAndForgetIdleKeys(t *testing.T) {
	s := newInboxSlots()
	var held []func()
	for i := 0; i < inboxUploadsPerAddr; i++ {
		release, ok := s.take(fmt.Sprintf("share%d", i), "addr")
		if !ok {
			t.Fatalf("slot %d refused below the per-address bound", i)
		}
		held = append(held, release)
	}
	if _, ok := s.take("other", "addr"); ok {
		t.Fatal("an address past its bound was given a slot")
	}
	for i := 0; i < inboxUploadsPerShare; i++ {
		release, ok := s.take("share", fmt.Sprintf("addr%d", i))
		if !ok {
			t.Fatalf("slot %d refused below the per-inbox bound", i)
		}
		held = append(held, release)
	}
	if _, ok := s.take("share", "another"); ok {
		t.Fatal("an inbox past its bound was given a slot")
	}
	for i := 0; len(held) < inboxUploadsMax; i++ {
		release, ok := s.take(fmt.Sprintf("s%d", i), fmt.Sprintf("a%d", i))
		if !ok {
			t.Fatalf("slot %d refused below the server-wide bound", len(held))
		}
		held = append(held, release)
	}
	if _, ok := s.take("fresh", "fresh"); ok {
		t.Fatal("a slot past the server-wide bound")
	}
	for _, release := range held {
		release()
		release()
	}
	if s.total != 0 || len(s.byShare) != 0 || len(s.byAddr) != 0 {
		t.Fatalf("released slots left %d, %v, %v", s.total, s.byShare, s.byAddr)
	}
}

// Uploads from one address past its bound are refused while the earlier
// ones are still sending, and admitted again once they finish.
func TestInboxUploadsPastTheAddressBoundAreRefused(t *testing.T) {
	b := testBackend(t)
	h := New(b, "test", testDomain(t), nil)
	id := createInbox(t, h, `{"name":"inbox","receive":true}`)
	entered := make(chan struct{}, inboxUploadsPerAddr)
	release := make(chan struct{})
	done := make(chan int, inboxUploadsPerAddr)
	for i := 0; i < inboxUploadsPerAddr; i++ {
		go func(i int) {
			req := httptest.NewRequest("PUT", fmt.Sprintf("/receive/%s/files/f%d", id, i),
				&inboxHeldBody{Reader: strings.NewReader("x"), entered: entered, release: release})
			req.ContentLength = 1
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			done <- rec.Code
		}(i)
		<-entered
	}
	rec := doReq(t, h, "PUT", "/receive/"+id+"/files/late", "", "x")
	if rec.Code != http.StatusTooManyRequests || errCode(t, rec.Body.String()) != "rate-limited" {
		t.Fatalf("upload past the bound = %d %s", rec.Code, rec.Body)
	}
	close(release)
	for i := 0; i < inboxUploadsPerAddr; i++ {
		if code := <-done; code != 201 {
			t.Fatalf("held upload = %d", code)
		}
	}
	if rec := doReq(t, h, "PUT", "/receive/"+id+"/files/late", "", "x"); rec.Code != 201 {
		t.Fatalf("upload after the others finished = %d %s", rec.Code, rec.Body)
	}
}

// A body that stops sending ends its upload after inboxIdleTimeout instead
// of holding its slot, its claim and its staging for as long as the sender
// keeps the socket open.
func TestAStalledInboxBodyEndsTheUpload(t *testing.T) {
	defer func(d time.Duration) { inboxIdleTimeout = d }(inboxIdleTimeout)
	inboxIdleTimeout = 200 * time.Millisecond
	b := testBackend(t)
	h := New(b, "test", testDomain(t), nil)
	id := createInbox(t, h, `{"name":"inbox","receive":true}`)
	srv := httptest.NewServer(h)
	defer srv.Close()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "PUT /receive/%s/files/slow.bin HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n0123456789", id)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("no answer to a stalled body: %v", err)
	}
	if resp.StatusCode != http.StatusRequestTimeout {
		t.Fatalf("stalled body = %d", resp.StatusCode)
	}
	if left := partsLeft(t, b, id); len(left) != 0 {
		t.Fatalf("staging left behind: %v", left)
	}
	if _, err := b.DB.File(id, "slow.bin"); err == nil {
		t.Fatal("the stalled upload's row survived")
	}
}

// The idle deadline belongs to one upload's body: a kept-alive connection
// that sits quiet past it after a finished upload still takes the next one.
func TestTheIdleDeadlineDoesNotOutliveItsUpload(t *testing.T) {
	defer func(d time.Duration) { inboxIdleTimeout = d }(inboxIdleTimeout)
	inboxIdleTimeout = 200 * time.Millisecond
	b := testBackend(t)
	h := New(b, "test", testDomain(t), nil)
	id := createInbox(t, h, `{"name":"inbox","receive":true}`)
	srv := httptest.NewServer(h)
	defer srv.Close()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	br := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	for i := 0; i < 2; i++ {
		fmt.Fprintf(conn, "PUT /receive/%s/files/f%d HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nok", id, i)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("upload %d on the kept-alive connection: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != 201 {
			t.Fatalf("upload %d = %d", i, resp.StatusCode)
		}
		time.Sleep(3 * inboxIdleTimeout)
	}
}
