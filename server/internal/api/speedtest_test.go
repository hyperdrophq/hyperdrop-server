package api

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func speedTestReq(t *testing.T, h http.Handler, token string, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/speedtest", body)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// zeros is an endless body, for a probe that has to be bigger than the cap
// without allocating it.
type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// The probe measures the wire and nothing else: the body is counted and
// discarded, no share appears, and the answer says how much arrived.
func TestSpeedTestCountsAndDiscardsTheBody(t *testing.T) {
	h := newTestAPI(t)
	before := doReq(t, h, "GET", "/api/shares", testToken, "").Body.String()
	payload := make([]byte, 3<<20)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	rec := speedTestReq(t, h, testToken, bytes.NewReader(payload))
	if rec.Code != 200 {
		t.Fatalf("speedtest = %d: %s", rec.Code, rec.Body)
	}
	var out struct {
		Bytes   int64   `json:"bytes"`
		Seconds float64 `json:"seconds"`
	}
	unmarshal(t, rec, &out)
	if out.Bytes != int64(len(payload)) {
		t.Fatalf("bytes = %d, want %d", out.Bytes, len(payload))
	}
	if out.Seconds < 0 {
		t.Fatalf("seconds = %v", out.Seconds)
	}
	if after := doReq(t, h, "GET", "/api/shares", testToken, "").Body.String(); after != before {
		t.Fatalf("the probe changed the share list:\n%s\n%s", before, after)
	}
}

// Guests upload too, so the probe is for any signed-in account, and for
// nobody else.
func TestSpeedTestIsForAnySignedInAccount(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	if rec := speedTestReq(t, h, "", strings.NewReader("x")); rec.Code != 401 {
		t.Fatalf("anonymous speedtest = %d, want 401", rec.Code)
	}
	tok := seedUser(t, um, "alice")
	if rec := speedTestReq(t, h, tok, strings.NewReader("xxxx")); rec.Code != 200 {
		t.Fatalf("user speedtest = %d: %s", rec.Code, rec.Body)
	}
}

func TestSpeedTestRefusesABodyOverTheCap(t *testing.T) {
	h := newTestAPI(t)
	rec := speedTestReq(t, h, testToken, io.LimitReader(zeros{}, speedTestMaxBytes+1))
	if rec.Code != 413 {
		t.Fatalf("over-cap speedtest = %d: %s", rec.Code, rec.Body)
	}
	var e struct {
		Code string `json:"code"`
	}
	unmarshal(t, rec, &e)
	if e.Code != "body-too-large" {
		t.Fatalf("code = %q, want body-too-large", e.Code)
	}
}

// Two probes at once would measure each other, so the second is refused
// with a code the client can word, and the first finishes undisturbed.
func TestSpeedTestRunsOneAtATime(t *testing.T) {
	h := newTestAPI(t)
	pr, pw := io.Pipe()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- speedTestReq(t, h, testToken, pr) }()
	// A pipe write returns only once the handler has consumed it, so after
	// this the first probe is inside the handler and holds the slot.
	if _, err := pw.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	rec := speedTestReq(t, h, testToken, strings.NewReader("second"))
	if rec.Code != 429 {
		t.Fatalf("concurrent speedtest = %d: %s", rec.Code, rec.Body)
	}
	var e struct {
		Code string `json:"code"`
	}
	unmarshal(t, rec, &e)
	if e.Code != "speedtest-busy" {
		t.Fatalf("code = %q, want speedtest-busy", e.Code)
	}
	pw.Close()
	if first := <-done; first.Code != 200 {
		t.Fatalf("first speedtest = %d: %s", first.Code, first.Body)
	}
}

// One probe holds the server's one slot for at most its time limit: a body
// that stops arriving is answered at the limit with what arrived, and the
// next probe gets the slot.
func TestASpeedTestThatStallsGivesTheSlotBack(t *testing.T) {
	hd := newHandler(testBackend(t), "2.0.0", testDomain(t), nil, Deployment{})
	hd.speedTestTimeout = 200 * time.Millisecond
	srv := httptest.NewServer(hd.routes())
	defer srv.Close()
	pr, pw := io.Pipe()
	defer pw.Close()
	go pw.Write([]byte("x")) // one byte, then nothing
	req, _ := http.NewRequest("POST", srv.URL+"/api/speedtest", pr)
	req.Header.Set("Authorization", "Bearer "+testToken)
	start := time.Now()
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || time.Since(start) > 10*time.Second {
		t.Fatalf("stalled probe = %d %s after %v, want 200 within the limit", res.StatusCode, body, time.Since(start))
	}
	var got struct {
		Bytes int64 `json:"bytes"`
	}
	if err := json.Unmarshal(body, &got); err != nil || got.Bytes != 1 {
		t.Fatalf("stalled probe answered %s (%v), want the one byte that arrived", body, err)
	}
	if rec := speedTestReq(t, hd.routes(), testToken, strings.NewReader("abc")); rec.Code != 200 {
		t.Fatalf("the next probe = %d %s, want the slot back", rec.Code, rec.Body)
	}
}

// pacedBody streams an endless body a block at a time, pausing between
// blocks, like a client asked for a probe longer than the server's limit.
type pacedBody struct{ sent int64 }

func (b *pacedBody) Read(p []byte) (int, error) {
	time.Sleep(10 * time.Millisecond)
	n := min(len(p), 4096)
	clear(p[:n])
	b.sent += int64(n)
	return n, nil
}

// A probe still sending when the limit arrives is a measurement cut short,
// not an error: over HTTP/1.1 and HTTP/2 the client gets 200 with the bytes
// counted, although its body never ended.
func TestASpeedTestLongerThanTheLimitIsMeasured(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "HTTP/1.1", true: "HTTP/2"}[h2], func(t *testing.T) {
			hd := newHandler(testBackend(t), "2.0.0", testDomain(t), nil, Deployment{})
			hd.speedTestTimeout = 300 * time.Millisecond
			srv := httptest.NewUnstartedServer(hd.routes())
			srv.EnableHTTP2 = h2
			srv.StartTLS()
			defer srv.Close()
			req, _ := http.NewRequest("POST", srv.URL+"/api/speedtest", &pacedBody{})
			req.Header.Set("Authorization", "Bearer "+testToken)
			start := time.Now()
			res, err := srv.Client().Do(req)
			if err != nil {
				t.Fatalf("probe: %v", err)
			}
			body, _ := io.ReadAll(res.Body)
			res.Body.Close()
			if (res.ProtoMajor == 2) != h2 {
				t.Fatalf("the probe went over %s", res.Proto)
			}
			if res.StatusCode != 200 || time.Since(start) > 10*time.Second {
				t.Fatalf("probe = %d %s after %v, want 200 at the limit", res.StatusCode, body, time.Since(start))
			}
			var got struct {
				Bytes   int64   `json:"bytes"`
				Seconds float64 `json:"seconds"`
			}
			if err := json.Unmarshal(body, &got); err != nil || got.Bytes <= 0 || got.Seconds < 0.3 {
				t.Fatalf("probe answered %s (%v), want the bytes counted over the limit", body, err)
			}
		})
	}
}
