package pushrelay

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func relay(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return New(srv.URL, "hyperdrop-server/test")
}

func TestASendPostsExactlyTheRelaysBody(t *testing.T) {
	var got map[string]any
	c := relay(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/push/send" || r.Header.Get("Content-Type") != "application/json" ||
			r.Header.Get("User-Agent") != "hyperdrop-server/test" {
			t.Errorf("request %s %s %v", r.Method, r.URL.Path, r.Header)
		}
		json.NewDecoder(r.Body).Decode(&got)
		w.Write([]byte(`{"sent":true}`))
	})
	err := c.Send(context.Background(), Message{Handle: strings.Repeat("a", 32), Ciphertext: "QUJD", CollapseID: "in-x"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got["handle"] != strings.Repeat("a", 32) || got["ciphertext"] != "QUJD" || got["collapseId"] != "in-x" {
		t.Fatalf("body %v", got)
	}
}

func TestNoCollapseIDIsLeftOut(t *testing.T) {
	var raw string
	c := relay(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		raw = string(b)
	})
	c.Send(context.Background(), Message{Handle: "h", Ciphertext: "QUJD"})
	if strings.Contains(raw, "collapseId") {
		t.Fatalf("an empty collapseId was sent: %s", raw)
	}
}

func TestGoneIsTheOneAnswerThatDropsAHandle(t *testing.T) {
	c := relay(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(410)
		w.Write([]byte(`{"code":"handle-gone","error":"this push handle is gone; register again"}`))
	})
	if err := c.Send(context.Background(), Message{Handle: "h", Ciphertext: "QUJD"}); !errors.Is(err, ErrGone) {
		t.Fatalf("410: %v", err)
	}
	for _, status := range []int{429, 502, 503, 413, 400} {
		c := relay(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			w.Write([]byte(`{"code":"x","error":"y"}`))
		})
		err := c.Send(context.Background(), Message{Handle: strings.Repeat("b", 32), Ciphertext: "QUJD"})
		var re *Error
		if errors.Is(err, ErrGone) || !errors.As(err, &re) || re.Status != status || re.Code != "x" {
			t.Fatalf("%d: %v", status, err)
		}
		if strings.Contains(err.Error(), strings.Repeat("b", 32)) {
			t.Fatalf("%d: the error names the handle: %v", status, err)
		}
	}
}

func TestTheClientGivesUpAfterItsTimeout(t *testing.T) {
	release := make(chan struct{})
	c := relay(t, func(w http.ResponseWriter, r *http.Request) { <-release })
	defer close(release)
	c.HTTP.Timeout = 100 * time.Millisecond
	start := time.Now()
	if err := c.Send(context.Background(), Message{Handle: "h", Ciphertext: "QUJD"}); err == nil {
		t.Fatal("a relay that never answers was a success")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("the send waited past its timeout")
	}
}

func TestARedirectIsNotFollowed(t *testing.T) {
	var followed bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed = true }))
	t.Cleanup(srv.Close)
	c := relay(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL, http.StatusTemporaryRedirect)
	})
	if err := c.Send(context.Background(), Message{Handle: "h", Ciphertext: "QUJD"}); err == nil || followed {
		t.Fatalf("redirect: err %v, followed %v", err, followed)
	}
}

// Every refusal the relay answers besides 410 (names/push.go) leaves the
// registration in place: none of them is ErrGone.
func TestEveryOtherRelayRefusalKeepsTheHandle(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		code   string
	}{
		{400, `{"error":"invalid JSON body"}`, ""},
		{400, `{"code":"invalid","error":"handle: expected 32 lowercase hexadecimal characters"}`, "invalid"},
		{404, `404 page not found`, ""},
		{409, `{"code":"environment-unavailable","error":"x"}`, "environment-unavailable"},
		{413, `{"code":"too-large","error":"x"}`, "too-large"},
		{429, `{"code":"rate-limited","error":"x"}`, "rate-limited"},
		{502, `{"code":"apns-refused","error":"x"}`, "apns-refused"},
		{502, `{"code":"apns-unavailable","error":"x"}`, "apns-unavailable"},
		{503, `{"code":"push-off","error":"x"}`, "push-off"},
		{503, `{"code":"push-full","error":"x"}`, "push-full"},
		{307, ``, ""},
	} {
		c := relay(t, func(w http.ResponseWriter, r *http.Request) {
			if tc.status == 429 {
				w.Header().Set("Retry-After", "3")
			}
			w.WriteHeader(tc.status)
			w.Write([]byte(tc.body))
		})
		err := c.Send(context.Background(), Message{Handle: strings.Repeat("c", 32), Ciphertext: "QUJD"})
		var re *Error
		if errors.Is(err, ErrGone) || !errors.As(err, &re) || re.Status != tc.status || re.Code != tc.code {
			t.Fatalf("%d %s: %v", tc.status, tc.body, err)
		}
	}
}

func TestACancelledContextStopsTheSend(t *testing.T) {
	release := make(chan struct{})
	c := relay(t, func(w http.ResponseWriter, r *http.Request) { <-release })
	defer close(release)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	start := time.Now()
	err := c.Send(ctx, Message{Handle: "h", Ciphertext: "QUJD"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled send: %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("the send outlived its context")
	}
}

func TestATransportErrorNamesNeitherHandleNorCiphertext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()
	handle, ct := strings.Repeat("d", 32), strings.Repeat("Q", 64)
	err := New(url, "hyperdrop-server/test").Send(context.Background(), Message{Handle: handle, Ciphertext: ct})
	if err == nil || errors.Is(err, ErrGone) {
		t.Fatalf("closed relay: %v", err)
	}
	if strings.Contains(err.Error(), handle) || strings.Contains(err.Error(), ct) {
		t.Fatalf("the error names the message: %v", err)
	}
}

func TestATrailingSlashOnTheRelayIsDropped(t *testing.T) {
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { path = r.URL.Path }))
	t.Cleanup(srv.Close)
	if err := New(srv.URL+"/", "ua").Send(context.Background(), Message{Handle: "h", Ciphertext: "QUJD"}); err != nil {
		t.Fatal(err)
	}
	if path != "/v1/push/send" {
		t.Fatalf("posted to %q", path)
	}
}
