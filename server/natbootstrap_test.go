package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNASBootstrapRetriesUntilTrustedPublicIPCanBeManaged(t *testing.T) {
	observations, registrations := 0, 0
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	bootstrapIPCertificate(ctx, time.Millisecond, time.Millisecond, func(context.Context) (string, error) {
		observations++
		switch observations {
		case 1:
			return "", errors.New("offline")
		case 2:
			return "192.168.1.2", nil
		default:
			return "8.8.4.4", nil
		}
	}, func(subject string) error {
		if subject != "8.8.4.4" {
			t.Fatalf("untrusted bootstrap subject %q", subject)
		}
		registrations++
		if registrations == 1 {
			return errors.New("temporary certificate registration failure")
		}
		cancel()
		return nil
	}, func(string) {})
	if observations != 4 || registrations != 2 {
		t.Fatalf("observers=%d registrations=%d", observations, registrations)
	}
}

func TestNASBootstrapRefreshesChangedIPAndDeduplicatesRegistration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	observed := 0
	registered := []string{}
	bootstrapIPCertificate(ctx, time.Millisecond, time.Millisecond, func(context.Context) (string, error) {
		observed++
		switch observed {
		case 1, 2:
			return "8.8.4.4", nil
		case 3:
			return "192.168.1.8", nil
		case 4:
			return "", errors.New("temporary observation failure")
		default:
			return "8.8.8.8", nil
		}
	}, func(ip string) error {
		registered = append(registered, ip)
		if len(registered) == 2 {
			cancel()
		}
		return nil
	}, func(string) {})
	if observed != 5 || len(registered) != 2 || registered[0] != "8.8.4.4" || registered[1] != "8.8.8.8" {
		t.Fatalf("observations=%d registrations=%v", observed, registered)
	}
}

// A new public IP's certificate is managed first; the previous IP's is
// dropped only once that succeeded, so the box is never left without one.
func TestNASBootstrapDropsThePreviousIPOnceTheNewOneIsManaged(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	observed := 0
	var events []string
	bootstrapIPCertificate(ctx, time.Millisecond, time.Millisecond, func(context.Context) (string, error) {
		observed++
		switch observed {
		case 1:
			return "8.8.4.4", nil
		default:
			return "8.8.8.8", nil
		}
	}, func(ip string) error {
		events = append(events, "manage "+ip)
		if ip == "8.8.8.8" && observed == 2 {
			return errors.New("temporary certificate registration failure")
		}
		return nil
	}, func(ip string) {
		events = append(events, "drop "+ip)
		cancel()
	})
	want := []string{"manage 8.8.4.4", "manage 8.8.8.8", "manage 8.8.8.8", "drop 8.8.4.4"}
	if len(events) != len(want) {
		t.Fatalf("events %v, want %v", events, want)
	}
	for i := range want {
		if events[i] != want[i] {
			t.Fatalf("events %v, want %v", events, want)
		}
	}
}
