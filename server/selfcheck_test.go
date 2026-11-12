package main

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

// The self-check turns "starts but never serves" into a nonzero exit, which
// is what lets the updater's rollback see a broken new binary. It must pass
// once the health route answers, even when the first probes fail.
func TestWaitServingSucceedsOnceHealthAnswers(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			http.Error(w, "warming up", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	if !waitServing(5*time.Second, 10*time.Millisecond, srv.URL) {
		t.Fatal("a serving health route must pass the self-check")
	}
}

func TestWaitServingFailsWhenNothingAnswers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "wedged", http.StatusInternalServerError)
	}))
	defer srv.Close()
	if waitServing(300*time.Millisecond, 50*time.Millisecond, srv.URL) {
		t.Fatal("a route that never answers 200 must fail the self-check")
	}
}

// The self-check dials the address the listener is bound to, so a server
// bound to one address does not fail its own check and crash-loop; a
// wildcard IPv6 listener is dialled at both loopbacks.
func TestTheSelfCheckDialsTheBoundAddress(t *testing.T) {
	for addr, want := range map[string][]string{
		":80":              {"http://127.0.0.1:80/api/health"},
		"0.0.0.0:5080":     {"http://127.0.0.1:5080/api/health"},
		"[::]:80":          {"http://127.0.0.1:80/api/health", "http://[::1]:80/api/health"},
		"203.0.113.5:80":   {"http://203.0.113.5:80/api/health"},
		"[::1]:8080":       {"http://[::1]:8080/api/health"},
		"localhost:8081":   {"http://localhost:8081/api/health"},
		"[2001:db8::5]:80": {"http://[2001:db8::5]:80/api/health"},
	} {
		if got, ok := selfCheckURLs(addr); !ok || !slices.Equal(got, want) {
			t.Errorf("selfCheckURLs(%q) = %q, %v; want %q", addr, got, ok, want)
		}
	}
	for _, addr := range []string{"", "80", "host:"} {
		if got, ok := selfCheckURLs(addr); ok {
			t.Errorf("selfCheckURLs(%q) = %q, want no check", addr, got)
		}
	}
}

// The check passes when any one of its URLs answers: a box with no ::1 has
// its [::] listener answer at 127.0.0.1.
func TestWaitServingPassesOnAnyURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	if !waitServing(2*time.Second, 10*time.Millisecond, dead.URL, srv.URL) {
		t.Fatal("a check whose second URL answers failed")
	}
}
