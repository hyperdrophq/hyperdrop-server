package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"hyperdrop/server/internal/api"
	"hyperdrop/server/internal/domain"
	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/sharefs"
)

// relayIdle stands in for serverBodyDeadline's minute of silence, so a test
// can pause past it in about a second.
const relayIdle = 300 * time.Millisecond

// liveRelay is the real API behind the server newServer builds, served over
// TLS with HTTP/2 offered and the body limits shortened to relayIdle.
type liveRelay struct {
	mux   http.Handler
	token string
	base  string
	tr    *http.Transport
}

func newLiveRelay(t *testing.T) *liveRelay {
	t.Helper()
	dir := t.TempDir()
	db, err := metadb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store, err := sharefs.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateUser(metadb.DefaultAdminName, "relay-test-password", metadb.RoleAdmin, metadb.Settings{}); err != nil {
		t.Fatal(err)
	}
	token, err := db.MintToken(metadb.DefaultAdminName, "test")
	if err != nil {
		t.Fatal(err)
	}
	dom, err := domain.Load(filepath.Join(dir, "domain"), "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	mux := api.NewServer(api.Backend{DB: db, FS: store}, version, dom, nil, api.Deployment{DataDir: dir})
	t.Cleanup(mux.Drain)

	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newServer("", mux)
	srv.Handler = bodyDeadline{idle: relayIdle, grace: time.Hour}.wrap(mux)
	go srv.Serve(tls.NewListener(tcp, tlsTestConfig(t, "h2", "http/1.1")))
	t.Cleanup(func() { srv.Close() })

	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: true}
	t.Cleanup(tr.CloseIdleConnections)
	return &liveRelay{mux: mux, token: token, base: "https://" + tcp.Addr().String(), tr: tr}
}

// local runs one request through the API in process.
func (lr *liveRelay) local(t *testing.T, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+lr.token)
	rec := httptest.NewRecorder()
	lr.mux.ServeHTTP(rec, req)
	return rec
}

// pausingVisitor is a visitor's response that stops taking bytes for pause
// after the first write, as a paused video or a full media buffer does.
type pausingVisitor struct {
	header http.Header
	pause  time.Duration

	mu     sync.Mutex
	status int
	writes int
	n      int
}

func (v *pausingVisitor) Header() http.Header { return v.header }
func (v *pausingVisitor) WriteHeader(code int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.status == 0 {
		v.status = code
	}
}

func (v *pausingVisitor) Write(p []byte) (int, error) {
	v.mu.Lock()
	if v.status == 0 {
		v.status = http.StatusOK
	}
	v.writes++
	first := v.writes == 1
	v.n += len(p)
	v.mu.Unlock()
	if first {
		time.Sleep(v.pause)
	}
	return len(p), nil
}

func (v *pausingVisitor) received() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.n
}

// startJob creates a one-file live share of size bytes, starts a visitor's
// download of it, and returns the job the sharer's poll hands out with the
// channel the visitor's request ends on.
func (lr *liveRelay) startJob(t *testing.T, size int, visitor *pausingVisitor) (string, <-chan struct{}) {
	t.Helper()
	rec := lr.local(t, "POST", "/api/live-share", `{"name":"relay","files":[`+
		`{"path":"clip.mp4","size":`+strconv.Itoa(size)+`,"mime":"video/mp4","mtime":"2026-08-06T10:00:00Z"}]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create live share: %d %s", rec.Code, rec.Body)
	}
	var sh struct {
		ID    string `json:"id"`
		Files []struct {
			Slug string `json:"slug"`
		} `json:"files"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &sh); err != nil || len(sh.Files) != 1 {
		t.Fatalf("create live share: %s (%v)", rec.Body, err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		lr.mux.ServeHTTP(visitor, httptest.NewRequest("GET", "/download/"+sh.ID+"/"+sh.Files[0].Slug, nil))
	}()
	rec = lr.local(t, "GET", "/api/live-share/"+sh.ID+"/jobs", "")
	var poll struct {
		Jobs []struct {
			Job string `json:"job"`
		} `json:"jobs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &poll); err != nil || len(poll.Jobs) != 1 {
		t.Fatalf("poll: %d %s (%v)", rec.Code, rec.Body, err)
	}
	return poll.Jobs[0].Job, done
}

// send posts body as the sharer's relay of job over the network and returns
// the protocol it went over and the server's status.
func (lr *liveRelay) send(t *testing.T, job string, body io.Reader) (int, int) {
	t.Helper()
	req, err := http.NewRequest("POST", lr.base+"/api/live-share/jobs/"+job, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+lr.token)
	resp, err := lr.tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("relay: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.ProtoMajor, resp.StatusCode
}

func awaitVisitor(t *testing.T, done <-chan struct{}, within time.Duration) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(within):
		t.Fatalf("the visitor's request was still open after %v", within)
	}
}

// A visitor who stops reading for longer than the idle limit (a paused
// video) keeps the relay over HTTP/2: the sharer's body is waited on only
// while the server is inside a Read, and nothing is left armed on the
// stream between reads.
func TestALiveRelaySurvivesAPausedVisitorOverHTTP2(t *testing.T) {
	lr := newLiveRelay(t)
	// More than the stream's flow-control window, so the sharer still has
	// bytes to send when the visitor resumes.
	const size = 24 << 20
	visitor := &pausingVisitor{header: http.Header{}, pause: 4 * relayIdle}
	job, done := lr.startJob(t, size, visitor)

	proto, status := lr.send(t, job, bytes.NewReader(bytes.Repeat([]byte("x"), size)))
	if proto != 2 {
		t.Fatalf("the relay went over HTTP/%d, want 2", proto)
	}
	if status != http.StatusOK {
		t.Fatalf("relay status %d, want 200", status)
	}
	awaitVisitor(t, done, 10*time.Second)
	if got := visitor.received(); got != size {
		t.Fatalf("the visitor received %d bytes, want %d", got, size)
	}
}

// A sharer that sends part of the file and then goes silent loses the relay
// after the idle limit, and the visitor's request ends with it.
func TestAStalledLiveRelayEndsOverHTTP2(t *testing.T) {
	lr := newLiveRelay(t)
	const size = 1 << 20
	visitor := &pausingVisitor{header: http.Header{}}
	job, done := lr.startJob(t, size, visitor)

	pr, pw := io.Pipe()
	defer pw.Close()
	go pw.Write(bytes.Repeat([]byte("x"), 4096))
	type answer struct{ proto, status int }
	answered := make(chan answer, 1)
	go func() {
		proto, status := lr.send(t, job, pr)
		answered <- answer{proto, status}
	}()
	select {
	case a := <-answered:
		if a.proto != 2 {
			t.Fatalf("the relay went over HTTP/%d, want 2", a.proto)
		}
		if a.status != http.StatusBadRequest {
			t.Fatalf("relay status %d, want 400", a.status)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a silent sharer still held its relay after 10 s")
	}
	awaitVisitor(t, done, 5*time.Second)
	if got := visitor.received(); got >= size {
		t.Fatalf("the visitor received %d bytes of a relay that stalled", got)
	}
}
