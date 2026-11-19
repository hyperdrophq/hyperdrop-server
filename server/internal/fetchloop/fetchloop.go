// Package fetchloop is what the server's two release readers share: the
// self-update check (selfupdate) and the web bundle fetch (webapp). Loop is
// their schedule, a run after a first wait, then after each next wait or at
// once when nudged; Get is their capped download.
package fetchloop

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Loop runs run after first, then again after each wait next answers (asked
// after the run before), until ctx ends. A value on nudge runs it at once
// with nudged true. The caller's nudge channel is buffered, so a nudge sent
// while run is going waits there and starts the next run as soon as this one
// returns. Loop returns when ctx ends while it waits; a run in progress is
// the caller's to end through the same ctx.
func Loop(ctx context.Context, first time.Duration, next func() time.Duration, nudge <-chan struct{}, run func(nudged bool)) {
	wait := first
	for {
		nudged := false
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-nudge:
			t.Stop()
			nudged = true
		case <-t.C:
		}
		run(nudged)
		wait = next()
	}
}

// ErrTooLarge is Get refusing a body longer than its limit; nothing is
// returned with it.
var ErrTooLarge = errors.New("the body is over its limit")

// tooLarge is ErrTooLarge naming the URL and the limit.
type tooLarge struct {
	url   string
	limit int64
}

func (e *tooLarge) Error() string { return fmt.Sprintf("%s is over %d bytes", e.url, e.limit) }

func (e *tooLarge) Is(target error) bool { return target == ErrTooLarge }

// Get fetches url through hc with userAgent, refusing an answer other than
// 200 ("<url> answered <status>") and a body over limit bytes (ErrTooLarge,
// "<url> is over <limit> bytes").
func Get(ctx context.Context, hc *http.Client, url, userAgent string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %s", url, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, &tooLarge{url: url, limit: limit}
	}
	return body, nil
}
