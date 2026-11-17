package dsmpage

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeWebAPI stands in for DSM's web server on loopback: it records the one
// request the check makes and answers what the test says.
type fakeWebAPI struct {
	srv    *httptest.Server
	status int
	body   string
	gotReq atomic.Pointer[http.Request]
	hits   atomic.Int32
}

func newFakeWebAPI(t *testing.T, tlsOn bool) *fakeWebAPI {
	t.Helper()
	f := &fakeWebAPI{status: http.StatusOK, body: `{"data":{"username":"tester","email":""},"success":true}`}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		r2 := r.Clone(context.Background())
		f.gotReq.Store(r2)
		w.WriteHeader(f.status)
		w.Write([]byte(f.body))
	})
	if tlsOn {
		f.srv = httptest.NewTLSServer(h)
	} else {
		f.srv = httptest.NewServer(h)
	}
	t.Cleanup(f.srv.Close)
	return f
}

// env is the CGI environment of a request DSM served on the fake's port.
func (f *fakeWebAPI) env(extra ...string) []string {
	u, _ := url.Parse(f.srv.URL)
	scheme := "REQUEST_SCHEME=" + u.Scheme
	return append([]string{scheme, "SERVER_PORT=" + u.Port(), "HTTP_COOKIE=stay_login=0; id=session; smid=x",
		"HTTP_X_SYNO_TOKEN=tok", "HTTP_HOST=nas.example:5000", "REMOTE_ADDR=192.0.2.7", "HTTP_PROXY=http://127.0.0.1:1"}, extra...)
}

func TestWebAPIAuthenticateNamesTheSessionsUser(t *testing.T) {
	f := newFakeWebAPI(t, false)
	user, err := webAPIAuthenticate(context.Background(), f.env())
	if err != nil || user != "tester" {
		t.Fatalf("got %q, %v; want tester", user, err)
	}
	r := f.gotReq.Load()
	if r == nil {
		t.Fatal("DSM was not asked")
	}
	if r.Method != http.MethodGet || r.URL.Path != "/webapi/entry.cgi" {
		t.Errorf("%s %s", r.Method, r.URL.Path)
	}
	q := r.URL.Query()
	if q.Get("api") != "SYNO.Core.NormalUser" || q.Get("version") != "1" || q.Get("method") != "get" {
		t.Errorf("query %v", q)
	}
	if got := r.Header.Get("Cookie"); got != "stay_login=0; id=session; smid=x" {
		t.Errorf("Cookie %q: want the request's own, verbatim", got)
	}
	if got := r.Header.Get("X-Syno-Token"); got != "tok" {
		t.Errorf("X-SYNO-TOKEN %q", got)
	}
	if got := r.Header.Get("X-Forwarded-For"); got != "192.0.2.7" {
		t.Errorf("X-Forwarded-For %q: want the request's own REMOTE_ADDR", got)
	}
	for _, h := range []string{"X-Real-IP", "Referer", "Origin", "Host"} {
		if r.Header.Get(h) != "" {
			t.Errorf("the check sent %s", h)
		}
	}
	if r.Host != "nas.example:5000" {
		t.Errorf("Host %q: want the request's own HTTP_HOST, so DSM's web server picks the block that served the browser", r.Host)
	}
}

// Without an HTTP_HOST the call names loopback itself.
func TestWebAPIAuthenticateNamesLoopbackWithoutAHostHeader(t *testing.T) {
	f := newFakeWebAPI(t, false)
	u, _ := url.Parse(f.srv.URL)
	env := []string{"REQUEST_SCHEME=http", "SERVER_PORT=" + u.Port(), "HTTP_COOKIE=id=session", "REMOTE_ADDR=192.0.2.7"}
	if user, err := webAPIAuthenticate(context.Background(), env); err != nil || user != "tester" {
		t.Fatalf("got %q, %v", user, err)
	}
	if r := f.gotReq.Load(); r == nil || r.Host != "127.0.0.1:"+u.Port() {
		t.Errorf("Host %v", r)
	}
}

// A header value with a line break never reaches DSM: the request is refused
// before anything is dialled.
func TestWebAPIAuthenticateRefusesHeaderValuesWithLineBreaks(t *testing.T) {
	f := newFakeWebAPI(t, false)
	u, _ := url.Parse(f.srv.URL)
	base := []string{"REQUEST_SCHEME=http", "SERVER_PORT=" + u.Port(), "REMOTE_ADDR=192.0.2.7"}
	for _, c := range []struct {
		name string
		env  []string
	}{
		{"cookie with CRLF", append(slices.Clone(base), "HTTP_COOKIE=id=s\r\nX-Forwarded-For: 10.0.0.1")},
		{"cookie with LF", append(slices.Clone(base), "HTTP_COOKIE=id=s\nX-Forwarded-For: 10.0.0.1")},
		{"token with CRLF", append(slices.Clone(base), "HTTP_COOKIE=id=s", "HTTP_X_SYNO_TOKEN=t\r\nX-Forwarded-For: 10.0.0.1")},
		{"host with CRLF", append(slices.Clone(base), "HTTP_COOKIE=id=s", "HTTP_HOST=nas\r\nX-Forwarded-For: 10.0.0.1")},
		{"host with a space", append(slices.Clone(base), "HTTP_COOKIE=id=s", "HTTP_HOST=nas example")},
	} {
		t.Run(c.name, func(t *testing.T) {
			before := f.hits.Load()
			user, err := webAPIAuthenticate(context.Background(), c.env)
			if err == nil || user != "" {
				t.Errorf("got %q, %v; want a refusal", user, err)
			}
			if f.hits.Load() != before {
				t.Error("DSM was dialled")
			}
		})
	}
}

// An answer exactly at the body limit is read; one byte more is refused.
func TestWebAPIAuthenticateBodyLimitBoundary(t *testing.T) {
	f := newFakeWebAPI(t, false)
	head := `{"success":true,"data":{"username":"tester","pad":"`
	tail := `"}}`
	f.body = head + strings.Repeat("x", webAPIBodyLimit-len(head)-len(tail)) + tail
	if len(f.body) != webAPIBodyLimit {
		t.Fatalf("body is %d bytes", len(f.body))
	}
	if user, err := webAPIAuthenticate(context.Background(), f.env()); err != nil || user != "tester" {
		t.Errorf("at the limit: got %q, %v", user, err)
	}
	f.body = head + strings.Repeat("x", webAPIBodyLimit-len(head)-len(tail)+1) + tail
	if user, err := webAPIAuthenticate(context.Background(), f.env()); err == nil || user != "" {
		t.Errorf("one over the limit: got %q, %v", user, err)
	}
}

func TestWebAPIAuthenticateOverHTTPSOnLoopback(t *testing.T) {
	f := newFakeWebAPI(t, true)
	user, err := webAPIAuthenticate(context.Background(), f.env())
	if err != nil || user != "tester" {
		t.Fatalf("got %q, %v; want tester through DSM's own certificate", user, err)
	}
}

func TestWebAPIAuthenticateAnswersNobodyForWhatDSMRefuses(t *testing.T) {
	for _, c := range []struct {
		name   string
		status int
		body   string
	}{
		{"session not found (119)", 200, `{"error":{"code":119},"success":false}`},
		{"success false with a name", 200, `{"data":{"username":"tester"},"success":false}`},
		{"no username", 200, `{"data":{"email":""},"success":true}`},
		{"empty username", 200, `{"data":{"username":""},"success":true}`},
		{"not JSON", 200, `<html>page not found</html>`},
		{"empty body", 200, ``},
		{"a 500", 500, `{"data":{"username":"tester"},"success":true}`},
		{"a 403", 403, `{"data":{"username":"tester"},"success":true}`},
		{"a huge body", 200, `{"data":{"username":"tester","pad":"` + strings.Repeat("x", webAPIBodyLimit) + `"},"success":true}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeWebAPI(t, false)
			f.status, f.body = c.status, c.body
			user, err := webAPIAuthenticate(context.Background(), f.env())
			if err == nil || user != "" {
				t.Errorf("got %q, %v; want no user and an error", user, err)
			}
		})
	}
}

func TestWebAPIAuthenticateNeverFollowsARedirect(t *testing.T) {
	target := newFakeWebAPI(t, false)
	hop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.srv.URL+r.URL.RequestURI(), http.StatusFound)
	}))
	t.Cleanup(hop.Close)
	u, _ := url.Parse(hop.URL)
	env := []string{"REQUEST_SCHEME=http", "SERVER_PORT=" + u.Port(), "HTTP_COOKIE=id=session", "HTTP_X_SYNO_TOKEN=tok", "REMOTE_ADDR=192.0.2.7"}
	user, err := webAPIAuthenticate(context.Background(), env)
	if err == nil || user != "" {
		t.Errorf("got %q, %v; want a refusal", user, err)
	}
	if target.hits.Load() != 0 {
		t.Error("the redirect was followed")
	}
}

func TestWebAPIAuthenticateRefusesWithoutDiallingWhenTheRequestIsNotOneToForward(t *testing.T) {
	f := newFakeWebAPI(t, false)
	u, _ := url.Parse(f.srv.URL)
	port := "SERVER_PORT=" + u.Port()
	for _, c := range []struct {
		name string
		env  []string
	}{
		{"no cookie", []string{"REQUEST_SCHEME=http", port, "HTTP_X_SYNO_TOKEN=tok", "REMOTE_ADDR=192.0.2.7"}},
		{"empty cookie", []string{"REQUEST_SCHEME=http", port, "HTTP_COOKIE=", "HTTP_X_SYNO_TOKEN=tok", "REMOTE_ADDR=192.0.2.7"}},
		{"no port", []string{"REQUEST_SCHEME=http", "HTTP_COOKIE=id=s", "REMOTE_ADDR=192.0.2.7"}},
		{"port 0", []string{"REQUEST_SCHEME=http", "SERVER_PORT=0", "HTTP_COOKIE=id=s", "REMOTE_ADDR=192.0.2.7"}},
		{"port 70000", []string{"REQUEST_SCHEME=http", "SERVER_PORT=70000", "HTTP_COOKIE=id=s", "REMOTE_ADDR=192.0.2.7"}},
		{"port with a host", []string{"REQUEST_SCHEME=http", "SERVER_PORT=example.com:" + u.Port(), "HTTP_COOKIE=id=s", "REMOTE_ADDR=192.0.2.7"}},
		{"no scheme", []string{port, "HTTP_COOKIE=id=s", "REMOTE_ADDR=192.0.2.7"}},
		{"ftp", []string{"REQUEST_SCHEME=ftp", port, "HTTP_COOKIE=id=s", "REMOTE_ADDR=192.0.2.7"}},
		{"HTTPS=off with no scheme", []string{"HTTPS=off", port, "HTTP_COOKIE=id=s", "REMOTE_ADDR=192.0.2.7"}},
		{"no client address", []string{"REQUEST_SCHEME=http", port, "HTTP_COOKIE=id=s"}},
		{"a client address that is not an IP", []string{"REQUEST_SCHEME=http", port, "HTTP_COOKIE=id=s", "REMOTE_ADDR=10.0.2.2, evil"}},
		{"a client address with a port", []string{"REQUEST_SCHEME=http", port, "HTTP_COOKIE=id=s", "REMOTE_ADDR=10.0.2.2:1234"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			before := f.hits.Load()
			user, err := webAPIAuthenticate(context.Background(), c.env)
			if err == nil || user != "" {
				t.Errorf("got %q, %v; want a refusal", user, err)
			}
			if f.hits.Load() != before {
				t.Error("DSM was dialled")
			}
		})
	}
}

// HTTPS=on alone (no REQUEST_SCHEME) means https, as nginx sets both.
func TestWebAPIAuthenticateReadsHTTPSOn(t *testing.T) {
	f := newFakeWebAPI(t, true)
	u, _ := url.Parse(f.srv.URL)
	env := []string{"HTTPS=on", "SERVER_PORT=" + u.Port(), "HTTP_COOKIE=id=session", "REMOTE_ADDR=2001:db8::7"}
	if user, err := webAPIAuthenticate(context.Background(), env); err != nil || user != "tester" {
		t.Errorf("got %q, %v", user, err)
	}
}

func TestSessionTargetIn(t *testing.T) {
	for _, c := range []struct {
		env          []string
		scheme, port string
		ok           bool
	}{
		{[]string{"REQUEST_SCHEME=http", "SERVER_PORT=5000"}, "http", "5000", true},
		{[]string{"REQUEST_SCHEME=https", "SERVER_PORT=5001"}, "https", "5001", true},
		{[]string{"HTTPS=on", "SERVER_PORT=5001"}, "https", "5001", true},
		{[]string{"REQUEST_SCHEME=http", "HTTPS=on", "SERVER_PORT=5001"}, "https", "5001", true},
		{[]string{"SERVER_PORT=5000"}, "", "", false},
		{[]string{"REQUEST_SCHEME=http", "SERVER_PORT=65536"}, "", "", false},
		{[]string{"REQUEST_SCHEME=http", "SERVER_PORT=-1"}, "", "", false},
		{[]string{"REQUEST_SCHEME=http", "SERVER_PORT=05000"}, "", "", false},
		{[]string{"REQUEST_SCHEME=http", "SERVER_PORT="}, "", "", false},
		{[]string{"REQUEST_SCHEME=HTTP", "SERVER_PORT=5000"}, "", "", false},
	} {
		scheme, port, ok := sessionTargetIn(c.env)
		if scheme != c.scheme || port != c.port || ok != c.ok {
			t.Errorf("%v: got %q %q %v, want %q %q %v", c.env, scheme, port, ok, c.scheme, c.port, c.ok)
		}
	}
}

// The dialer reaches 127.0.0.1 on the request's port whatever address the
// transport hands it.
func TestLoopbackDialIgnoresTheAddressItIsGiven(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Close()
		}
	}()
	conn, err := loopbackDial(port)(context.Background(), "tcp", "203.0.113.9:80")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got := conn.RemoteAddr().String(); got != "127.0.0.1:"+port {
		t.Errorf("dialled %s", got)
	}
}

func TestWebAPIAuthenticateStopsAtTheDeadline(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	}))
	t.Cleanup(slow.Close)
	u, _ := url.Parse(slow.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	user, err := webAPIAuthenticate(ctx, []string{"REQUEST_SCHEME=http", "SERVER_PORT=" + u.Port(), "HTTP_COOKIE=id=s", "REMOTE_ADDR=192.0.2.7"})
	if err == nil || user != "" {
		t.Errorf("got %q, %v", user, err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("returned after %v", d)
	}
}

func TestWebAPIAuthenticateRefusesAPortNothingListensOn(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	start := time.Now()
	user, err := webAPIAuthenticate(ctx, []string{"REQUEST_SCHEME=http", "SERVER_PORT=" + port, "HTTP_COOKIE=id=s", "REMOTE_ADDR=192.0.2.7"})
	if err == nil || user != "" || time.Since(start) > 2*time.Second {
		t.Errorf("got %q, %v after %v", user, err, time.Since(start))
	}
}

// The client is built for one loopback call: no proxy from the
// environment, no kept connection, and the TLS of DSM's own certificate.
func TestLoopbackClientShape(t *testing.T) {
	c := loopbackClient("5001")
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport %T", c.Transport)
	}
	if tr.Proxy != nil {
		t.Error("the transport consults a proxy")
	}
	if !tr.DisableKeepAlives {
		t.Error("the transport keeps connections")
	}
	if tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify || tr.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Errorf("TLS config %+v", tr.TLSClientConfig)
	}
	if c.CheckRedirect == nil {
		t.Error("redirects are followed")
	}
}
