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

// A stranger's body has to keep a pace to keep its slot: the calm floor
// while the pool has room, a far higher one once more than half the
// server's slots are taken, so that holding the pool costs bandwidth
// in proportion.
func TestInboxPacingTightensPastHalfThePool(t *testing.T) {
	s := newInboxSlots()
	if got := s.floor(); got != inboxPacing.calm {
		t.Fatalf("empty pool floor = %d, want calm %d", got, inboxPacing.calm)
	}
	var releases []func()
	for i := 0; i < inboxUploadsMax/2; i++ {
		rel, ok := s.take(fmt.Sprintf("share%d", i), fmt.Sprintf("10.0.0.%d", i))
		if !ok {
			t.Fatalf("take %d refused", i)
		}
		releases = append(releases, rel)
	}
	if got := s.floor(); got != inboxPacing.calm {
		t.Fatalf("half-full pool floor = %d, want calm %d", got, inboxPacing.calm)
	}
	rel, ok := s.take("one-more", "10.0.1.1")
	if !ok {
		t.Fatal("take past half refused")
	}
	if got := s.floor(); got != inboxPacing.busy {
		t.Fatalf("pool past half floor = %d, want busy %d", got, inboxPacing.busy)
	}
	rel()
	if got := s.floor(); got != inboxPacing.calm {
		t.Fatalf("floor after release = %d, want calm %d", got, inboxPacing.calm)
	}
	for _, r := range releases {
		r()
	}
}

// trickleInboxUpload sends total bytes of an anonymous upload of name, one byte
// every gap, and answers the status the server gave it.
func trickleInboxUpload(t *testing.T, srv *httptest.Server, id, name string, total int, gap time.Duration) int {
	t.Helper()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "PUT /receive/%s/files/%s HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n", id, name, total)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < total; i++ {
			if _, err := conn.Write([]byte{'x'}); err != nil {
				return
			}
			time.Sleep(gap)
		}
	}()
	conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("no answer to the trickle: %v", err)
	}
	resp.Body.Close()
	<-done
	return resp.StatusCode
}

// A slow sender keeps its slot while the pool is calm, and loses it once the
// pool is past half and its pace is below the busy floor: the server answers
// 408 and keeps neither the staging nor the row.
func TestATricklingInboxBodyYieldsOnlyUnderPressure(t *testing.T) {
	defer func(p inboxPacingLimits) { inboxPacing = p }(inboxPacing)
	// 20 bytes a second is well within the calm floor and far below the
	// busy one; the grace is short so the test does not wait for minutes.
	inboxPacing = inboxPacingLimits{grace: 300 * time.Millisecond, calm: 1, busy: 1 << 20}
	routes, hd := newTestAPIParts(t)
	id := createInbox(t, routes, `{"name":"inbox","receive":true}`)
	srv := httptest.NewServer(routes)
	defer srv.Close()

	if got := trickleInboxUpload(t, srv, id, "calm.bin", 20, 50*time.Millisecond); got != http.StatusCreated {
		t.Fatalf("calm pool: trickle = %d, want 201", got)
	}

	var releases []func()
	for i := 0; i <= inboxUploadsMax/2; i++ {
		rel, ok := hd.inboxSlots.take(fmt.Sprintf("other%d", i), fmt.Sprintf("10.9.%d.1", i))
		if !ok {
			t.Fatalf("filling the pool: take %d refused", i)
		}
		releases = append(releases, rel)
	}
	defer func() {
		for _, r := range releases {
			r()
		}
	}()
	if got := trickleInboxUpload(t, srv, id, "busy.bin", 200, 50*time.Millisecond); got != http.StatusRequestTimeout {
		t.Fatalf("pool past half: trickle = %d, want 408", got)
	}
	if _, err := hd.db.File(id, "busy.bin"); err == nil {
		t.Fatal("the yielded upload's row survived")
	}
}
