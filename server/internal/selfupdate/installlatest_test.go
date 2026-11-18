package selfupdate

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestInstallLatestRefusesUnsupported(t *testing.T) {
	r := newRig(t, "1.1.0")
	r.channel = "synology"
	r.publish("1.1.1", "2026-11-02", releaseKey)
	v, err := r.checker().InstallLatest(context.Background())
	if !errors.Is(err, ErrUnsupported) || v != "" || !strings.Contains(err.Error(), "Package Center") {
		t.Fatalf("%q %v", v, err)
	}
	for _, h := range r.site.lockedHits() {
		t.Fatalf("an unsupported box fetched %s", h)
	}
	if len(r.staged) != 0 {
		t.Fatal("staged")
	}
}

func TestInstallLatestInstallsNewest(t *testing.T) {
	r := newRig(t, "1.1.0")
	r.publish("1.1.0", "2026-11-01", releaseKey)
	raw := r.publish("1.1.1", "2026-11-02", releaseKey)
	// The automatic-update switch does not gate an administrator's update.
	if err := Switch(r.store, false); err != nil {
		t.Fatal(err)
	}
	c := r.checker()
	v, err := c.InstallLatest(context.Background())
	if err != nil || v != "1.1.1" {
		t.Fatalf("%q %v", v, err)
	}
	if len(r.staged) != 1 || !bytes.Equal(r.staged[0], raw) {
		t.Fatalf("staged %d", len(r.staged))
	}
	if _, err := c.InstallLatest(context.Background()); !errors.Is(err, ErrPending) {
		t.Fatalf("second install while staged: %v", err)
	}

	cur := newRig(t, "1.1.1")
	cur.publish("1.1.1", "2026-11-02", releaseKey)
	if v, err := cur.checker().InstallLatest(context.Background()); v != "" || err != nil || len(cur.staged) != 0 {
		t.Fatalf("already current: %q %v", v, err)
	}
}

func TestConcurrentInstallLatestStagesOnce(t *testing.T) {
	r := newRig(t, "1.1.0")
	r.publish("1.1.1", "2026-11-02", releaseKey)
	c := r.checker()
	errs := make([]error, 2)
	vs := make([]string, 2)
	var wg sync.WaitGroup
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			vs[i], errs[i] = c.InstallLatest(context.Background())
		}()
	}
	wg.Wait()
	if len(r.staged) != 1 {
		t.Fatalf("staged %d", len(r.staged))
	}
	ok, pending := 0, 0
	for i, err := range errs {
		switch {
		case err == nil && vs[i] == "1.1.1":
			ok++
		case errors.Is(err, ErrPending):
			pending++
		}
	}
	if ok != 1 || pending != 1 {
		t.Fatalf("%v %v", vs, errs)
	}
}

func TestInstallLatestConcurrentWithCheckStagesOnce(t *testing.T) {
	r := newRig(t, "1.1.0")
	r.publish("1.1.1", "2026-11-02", releaseKey)
	c := r.checker()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); c.Check(context.Background()) }()
	go func() { defer wg.Done(); c.InstallLatest(context.Background()) }()
	wg.Wait()
	if len(r.staged) != 1 {
		t.Fatalf("staged %d", len(r.staged))
	}
}
