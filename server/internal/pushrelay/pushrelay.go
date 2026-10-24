// Package pushrelay posts sealed notifications to the HyperDrop push relay
// (the names service's POST /v1/push/send). The relay is configured once per
// server (HYPERDROP_PUSH_RELAY); nothing a client sends chooses where this
// client dials.
package pushrelay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Timeout bounds one send, so a relay that hangs delays the next
// notification instead of holding the pusher forever.
const Timeout = 10 * time.Second

// Message is one send. CollapseID, when set, makes a newer notification
// replace an older one with the same id on the phone.
type Message struct {
	Handle, Ciphertext, CollapseID string
}

// Sender is what the pusher sends through; tests replace it.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// ErrGone is the relay's 410 handle-gone: the relay no longer holds that
// handle (Apple said the device is gone, or it went unused too long), so
// its registration is dropped. It is the only answer that drops one.
var ErrGone = errors.New("pushrelay: the relay says this handle is gone")

// Error is any other answer than 200 or 410 (a refusal, a redirect, a
// relay that is off or full): the registration stays. Code is the relay's
// "code", empty when the answer carried none. It never holds the handle.
type Error struct {
	Status int
	Code   string
}

func (e *Error) Error() string {
	return fmt.Sprintf("pushrelay: relay answered %d %s", e.Status, e.Code)
}

// Client posts to one relay.
type Client struct {
	BaseURL, UserAgent string
	HTTP               *http.Client
}

// New answers a client for the relay at baseURL.
func New(baseURL, userAgent string) *Client {
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), UserAgent: userAgent, HTTP: &http.Client{
		Timeout: Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

type sendBody struct {
	Handle     string `json:"handle"`
	Ciphertext string `json:"ciphertext"`
	CollapseID string `json:"collapseId,omitempty"`
}

// Send posts one message. A transport error is returned without the
// request's body, which holds the handle.
func (c *Client) Send(ctx context.Context, m Message) error {
	body, err := json.Marshal(sendBody(m))
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/v1/push/send", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		// A *url.Error leads with the method and URL; the cause is what matters.
		if u := errors.Unwrap(err); u != nil {
			err = u
		}
		return fmt.Errorf("pushrelay: %w", err)
	}
	defer resp.Body.Close()
	var answer struct {
		Code string `json:"code"`
	}
	json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&answer)
	switch {
	case resp.StatusCode == http.StatusOK:
		return nil
	case resp.StatusCode == http.StatusGone:
		return ErrGone
	default:
		return &Error{Status: resp.StatusCode, Code: answer.Code}
	}
}
