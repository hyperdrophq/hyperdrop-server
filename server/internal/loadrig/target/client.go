package target

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptrace"
	"strings"
	"time"

	"hyperdrop/server/internal/loadrig/report"
)

// The limits on how long a request may take. They are variables so tests can
// shorten them.
var (
	// requestTimeout bounds one request of Do, including its body.
	requestTimeout = 5 * time.Minute
	// streamHeaderWait bounds how long Stream waits for an answer's headers:
	// past the 5 minutes the server's zip line keeps a client that is not a
	// browser waiting for its turn.
	streamHeaderWait = 10 * time.Minute
	// streamIdleGap bounds how long Stream waits for the next bytes of a
	// body: past the 60 s the server lets one chunk of a zip wait on its
	// client.
	streamIdleGap = 2 * time.Minute
)

const (
	// bodyKeepLimit is how much of an answer's body is kept in memory for
	// the check; a longer body is drained and counted, and the check sees
	// the kept part with ContentLength set to the true length. It holds a
	// whole listing page at the page cap of 2000 rows, each carrying up to
	// 100 file entries within the page's 50,000-entry budget.
	bodyKeepLimit = 64 << 20
	// idleConnsPerHost is how many keep-alive connections one client holds.
	idleConnsPerHost = 256
)

// Client drives a Target from one source address and records every answer.
type Client struct {
	t    Target
	rec  *report.Recorder
	tr   *http.Transport
	http *http.Client
	// stream is http without the whole-request timeout, for Stream.
	stream *http.Client
}

// NewClient makes a client whose connections leave from source (the default
// address when nil), with keep-alives, no redirect following and no cookies.
func NewClient(t Target, rec *report.Recorder, source net.IP) *Client {
	d := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	if source != nil {
		d.LocalAddr = &net.TCPAddr{IP: source}
	}
	tr := &http.Transport{
		DialContext:         d.DialContext,
		MaxIdleConnsPerHost: idleConnsPerHost,
		IdleConnTimeout:     90 * time.Second,
	}
	return &Client{t: t, rec: rec, tr: tr, http: newHTTP(tr, nil, requestTimeout), stream: newHTTP(tr, nil, 0)}
}

// newHTTP is a client over tr that follows no redirect; a zero timeout is
// none.
func newHTTP(tr *http.Transport, jar http.CookieJar, timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		Jar:       jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// WithJar returns a copy that shares the connections and keeps its own
// cookies, for a scenario that plays a visitor.
func (c *Client) WithJar() *Client {
	jar, _ := cookiejar.New(nil)
	cp := *c
	cp.http = newHTTP(c.tr, jar, requestTimeout)
	cp.stream = newHTTP(c.tr, jar, 0)
	return &cp
}

// Close drops the client's idle connections.
func (c *Client) Close() { c.tr.CloseIdleConnections() }

// Do sends one request and records exactly one observation under op: the
// time from just before the request to the end of reading the body, the
// status and the code answerCode gives it. A transport error is recorded
// with Fail. A non-nil check runs after the body has been read, with a
// readable body; its error is returned and recorded with Wrong, or, for an
// answer Observe already counted wrong (an error status the scenario did
// not expect), kept as that answer's reason without counting it twice.
func (c *Client) Do(ctx context.Context, op, method, path, token string, body io.Reader, check func(*http.Response) error) error {
	return c.DoHeader(ctx, op, method, path, token, nil, body, check)
}

// DoHeader is Do with header's fields added to the request, for a route
// that reads its own headers, such as an upload's Upload-Range.
func (c *Client) DoHeader(ctx context.Context, op, method, path, token string, header http.Header, body io.Reader, check func(*http.Response) error) error {
	req, err := http.NewRequestWithContext(ctx, method, c.t.BaseURL()+path, body)
	if err != nil {
		c.rec.Fail(op, err)
		return err
	}
	for k, v := range header {
		req.Header[http.CanonicalHeaderKey(k)] = v
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	start := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		c.rec.Fail(op, err)
		return err
	}
	defer resp.Body.Close()
	kept, total, err := drain(resp.Body)
	took := time.Since(start)
	if err != nil {
		c.rec.Fail(op, err)
		return err
	}
	counted := c.rec.Observe(op, took, resp.StatusCode, AnswerCode(resp, kept))
	if check == nil {
		return nil
	}
	resp.Body = io.NopCloser(bytes.NewReader(kept))
	resp.ContentLength = total
	checkErr := check(resp)
	switch {
	case checkErr == nil:
	case counted:
		c.rec.Reason(op, checkErr.Error())
	default:
		c.rec.Wrong(op, checkErr.Error())
	}
	return checkErr
}

// Stream sends one request and hands a 2xx answer to sink with its body unread,
// along with the time from just before the request to the answer's first byte.
// Whatever sink leaves unread is drained, so a body of any size is measured
// without being kept. It records one observation under op whose latency ends
// when the body has been read to its end. Any other answer is read and
// recorded as Do records it, and sink is not called. A transport error,
// sending or reading the body, is recorded with Fail and returned; sink's own
// error is recorded with Wrong and returned.
//
// No limit applies to the whole request, since a large body is slow without
// being wrong: the headers must come within streamHeaderWait and each read of
// the body within streamIdleGap of the last, and past either the request ends
// as a timeout.
func (c *Client) Stream(ctx context.Context, op, method, path, token string, sink func(r *http.Response, first time.Duration) error) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	waiting := time.AfterFunc(streamHeaderWait, func() { cancel(waitError{"no answer", streamHeaderWait}) })
	defer waiting.Stop()
	// failed is err, or the wait that ended the request when one did.
	failed := func(err error) error {
		if cause := context.Cause(ctx); errors.As(cause, new(waitError)) {
			err = cause
		}
		c.rec.Fail(op, err)
		return err
	}

	var firstByte time.Time
	trace := &httptrace.ClientTrace{GotFirstResponseByte: func() { firstByte = time.Now() }}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), method, c.t.BaseURL()+path, nil)
	if err != nil {
		c.rec.Fail(op, err)
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	start := time.Now()
	resp, err := c.stream.Do(req)
	if err != nil {
		return failed(err)
	}
	defer resp.Body.Close()
	waiting.Stop()
	idle := time.AfterFunc(streamIdleGap, func() { cancel(waitError{"no bytes", streamIdleGap}) })
	defer idle.Stop()
	body := &watchedBody{r: resp.Body, read: func() { idle.Reset(streamIdleGap) }}
	resp.Body = body
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		kept, _, err := drain(body)
		took := time.Since(start)
		if err != nil {
			return failed(err)
		}
		c.rec.Observe(op, took, resp.StatusCode, AnswerCode(resp, kept))
		return nil
	}
	first := time.Since(start)
	if !firstByte.IsZero() {
		first = firstByte.Sub(start)
	}
	sinkErr := sink(resp, first)
	io.Copy(io.Discard, body)
	took := time.Since(start)
	if body.err != nil {
		return failed(body.err)
	}
	c.rec.Observe(op, took, resp.StatusCode, "")
	if sinkErr != nil {
		c.rec.Wrong(op, sinkErr.Error())
	}
	return sinkErr
}

// waitError ends a Stream that waited past one of its limits; it reads as a
// timeout.
type waitError struct {
	what  string
	limit time.Duration
}

func (e waitError) Error() string   { return fmt.Sprintf("%s within %s", e.what, e.limit) }
func (e waitError) Timeout() bool   { return true }
func (e waitError) Temporary() bool { return false }

// watchedBody keeps the first error reading a body met other than its end,
// and calls read after every read that returned bytes.
type watchedBody struct {
	r    io.ReadCloser
	read func()
	err  error
}

func (b *watchedBody) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	if n > 0 {
		b.read()
	}
	if err != nil && err != io.EOF && b.err == nil {
		b.err = err
	}
	return n, err
}

func (b *watchedBody) Close() error { return b.r.Close() }

// drain reads a body to its end, keeping its first bodyKeepLimit bytes, and
// answers them with the body's whole length.
func drain(body io.Reader) (kept []byte, total int64, err error) {
	kept, err = io.ReadAll(io.LimitReader(body, bodyKeepLimit))
	total = int64(len(kept))
	if err == nil {
		var rest int64
		rest, err = io.Copy(io.Discard, body)
		total += rest
	}
	return kept, total, err
}

// AnswerCode is the code an answer is recorded with: for an error answer, the
// "code" of its JSON body, or "busy" for the load guard's busy page, a 503
// HTML page with Retry-After that names nothing of what was asked for.
func AnswerCode(resp *http.Response, kept []byte) string {
	if resp.StatusCode < 400 {
		return ""
	}
	if code := errorCode(kept); code != "" {
		return code
	}
	if resp.StatusCode == http.StatusServiceUnavailable && resp.Header.Get("Retry-After") != "" &&
		strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		return "busy"
	}
	return ""
}

// errorCode is the "code" field of a JSON error body, empty otherwise.
func errorCode(b []byte) string {
	var e struct {
		Code string `json:"code"`
	}
	if json.Unmarshal(b, &e) != nil {
		return ""
	}
	return e.Code
}
