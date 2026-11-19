package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"hyperdrop/server/internal/webapp"
)

// webFetchHandler is a handler running version, serving a store opened for
// contract that holds a bundle of the bundle contract, "" for none.
func webFetchHandler(t *testing.T, version, contract, bundle string, fetcher *webapp.Fetcher) *handler {
	t.Helper()
	st, err := webapp.Open(t.TempDir(), []string{webTestPub()}, contract)
	if err != nil {
		t.Fatal(err)
	}
	if bundle != "" {
		installWebBundle(t, st, bundle, "<html></html>")
	}
	return newHandler(testBackend(t), version, testDomain(t), nil, Deployment{Web: st, WebFetcher: fetcher})
}

// countingManifestSite answers every request with an empty web manifest and
// counts them.
func countingManifestSite(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte(`{"releases":[]}`))
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/", &hits
}

func waitHits(hits *atomic.Int32, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for hits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	return hits.Load() > 0
}

func TestWebFetchFollowsTheAutoUpdateSwitch(t *testing.T) {
	const running = "2.0.0"
	tests := []struct {
		name       string
		auto       bool
		trigger    webapp.Trigger
		fetchedFor string // "" is absent; "other" is a version other than running
		bundle     string // the installed bundle's contract, "" for none
		version    string
		want       bool
	}{
		{"on, daily", true, webapp.TriggerDaily, running, "2.0.0", running, true},
		{"off, daily", false, webapp.TriggerDaily, running, "2.0.0", running, false},
		{"off, boot", false, webapp.TriggerBoot, running, "2.0.0", running, false},
		{"off, boot, another version fetched for", false, webapp.TriggerBoot, "other", "2.0.0", running, true},
		{"off, daily, never recorded", false, webapp.TriggerDaily, "", "2.0.0", running, true},
		{"off, boot, no bundle", false, webapp.TriggerBoot, running, "", running, true},
		{"off, boot, another minor's bundle", false, webapp.TriggerBoot, "2.2.0", "2.0.0", "2.2.0", true},
		{"off, asked", false, webapp.TriggerAsked, running, "2.0.0", running, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := webFetchHandler(t, tc.version, "2.0.0", tc.bundle, nil)
			if err := h.updates.SetAuto(tc.auto); err != nil {
				t.Fatal(err)
			}
			switch tc.fetchedFor {
			case "":
			case "other":
				webNoErr(t, h.db.SetSetting(webFetchedForKey, "1.3.1"))
			default:
				webNoErr(t, h.db.SetSetting(webFetchedForKey, tc.fetchedFor))
			}
			if got := (webFetchPolicy{h}).Allow(tc.trigger); got != tc.want {
				t.Fatalf("Allow = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTheWebFetchRecordsTheVersionItFetchedFor(t *testing.T) {
	h := webFetchHandler(t, "2.0.0", "2.0.0", "2.0.0", nil)
	if v, ok, _ := h.db.Setting(webFetchedForKey); ok {
		t.Fatalf("recorded %q before any fetch", v)
	}
	(webFetchPolicy{h}).Fetched()
	if v, ok, err := h.db.Setting(webFetchedForKey); err != nil || !ok || v != "2.0.0" {
		t.Fatalf("recorded %q, %v, %v", v, ok, err)
	}
	if h.webFetchOwed() {
		t.Fatal("a recorded fetch is still owed")
	}
}

func TestAnOwedFetchRetriesUntilItSucceeds(t *testing.T) {
	h := webFetchHandler(t, "2.0.0", "2.0.0", "2.0.0", nil)
	webNoErr(t, h.updates.SetAuto(false))
	p := webFetchPolicy{h}
	if !p.Allow(webapp.TriggerDaily) {
		t.Fatal("an unrecorded fetch is not owed")
	}
	// A run that failed calls no Fetched, so the debt stands.
	if !p.Allow(webapp.TriggerDaily) {
		t.Fatal("a failed fetch stopped being owed")
	}
	p.Fetched()
	if p.Allow(webapp.TriggerDaily) {
		t.Fatal("a fetch stayed owed after it succeeded")
	}
}

func TestNudgeWebFetchIsNilSafe(t *testing.T) {
	h := webFetchHandler(t, "2.0.0", "2.0.0", "2.0.0", nil)
	h.nudgeWebFetch()
}

func TestTurningAutomaticUpdatesOnAsksTheWebFetch(t *testing.T) {
	base, hits := countingManifestSite(t)
	st, err := webapp.Open(t.TempDir(), []string{webTestPub()}, "2.0.0")
	if err != nil {
		t.Fatal(err)
	}
	f := webapp.NewFetcher(st, base, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.Start(ctx)
	hd, _ := settingsHandler(t, Deployment{Releases: "https://releases.test/", Official: true, Web: st, WebFetcher: f}, true)
	h := hd.routes()
	webNoErr(t, hd.updates.SetAuto(false))
	webNoErr(t, hd.db.SetSetting(webFetchedForKey, "2.0.0"))
	installWebBundleAt(t, st)
	if rec := doReq(t, h, "PATCH", "/api/server/settings", testToken, `{"autoUpdate":false}`); rec.Code != 200 {
		t.Fatalf("off: %d %s", rec.Code, rec.Body)
	}
	time.Sleep(100 * time.Millisecond)
	if hits.Load() != 0 {
		t.Fatal("turning automatic updates off fetched")
	}
	if rec := doReq(t, h, "PATCH", "/api/server/settings", testToken, `{"autoUpdate":true}`); rec.Code != 200 {
		t.Fatalf("on: %d %s", rec.Code, rec.Body)
	}
	if !waitHits(hits, 2*time.Second) {
		t.Fatal("turning automatic updates on did not ask the web fetch")
	}
}

// installWebBundleAt installs a bundle speaking st's contract, so the fetch
// is not owed for want of one.
func installWebBundleAt(t *testing.T, st *webapp.Store) {
	t.Helper()
	installWebBundle(t, st, "2.0.0", "<html></html>")
}

func TestRereadNudgesTheWebFetchOnlyWhenAutomaticUpdatesAreOn(t *testing.T) {
	base, hits := countingManifestSite(t)
	st, err := webapp.Open(t.TempDir(), []string{webTestPub()}, "2.0.0")
	if err != nil {
		t.Fatal(err)
	}
	installWebBundleAt(t, st)
	f := webapp.NewFetcher(st, base, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.Start(ctx)
	hd := newHandler(testBackend(t), "2.0.0", testDomain(t), nil, Deployment{Web: st, WebFetcher: f})
	webNoErr(t, hd.db.SetSetting(webFetchedForKey, "2.0.0"))
	s := &Server{h: hd}

	webNoErr(t, hd.updates.SetAuto(false))
	s.RereadSelfUpdate()
	time.Sleep(150 * time.Millisecond)
	if hits.Load() != 0 {
		t.Fatal("a reread with automatic updates off fetched")
	}
	webNoErr(t, hd.updates.SetAuto(true))
	s.RereadSelfUpdate()
	if !waitHits(hits, 2*time.Second) {
		t.Fatal("a reread with automatic updates on did not ask the web fetch")
	}
}

func TestUpdateLatestAlreadyCurrentAsksTheWebFetch(t *testing.T) {
	base, hits := countingManifestSite(t)
	st, err := webapp.Open(t.TempDir(), []string{webTestPub()}, "9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	installWebBundle(t, st, "9.9.9", "<html></html>")
	f := webapp.NewFetcher(st, base, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.Start(ctx)
	hd := latestHandler(t, "9.9.9", Deployment{Official: true, Web: st, WebFetcher: f})
	webNoErr(t, hd.db.SetSetting(webFetchedForKey, "9.9.9"))
	h := hd.routes()
	secret, _ := enableTOTP(t, h, testToken, testAdminPassword)
	rec := postLatest(t, h, `{"currentPassword":"`+testAdminPassword+`","totp":"`+nextCode(t, secret)+`"}`)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if !waitHits(hits, 2*time.Second) {
		t.Fatal("an already-current answer did not ask the web fetch")
	}
}
