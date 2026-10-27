package webapp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"hyperdrop/core/webbundle"
)

// releaseSite is a web release directory: a manifest and the files it names.
type releaseSite struct {
	srv       *httptest.Server
	files     map[string][]byte
	downloads atomic.Int32
}

func newReleaseSite(t *testing.T, releases []webbundle.Release, files map[string][]byte) *releaseSite {
	t.Helper()
	m, err := json.Marshal(webbundle.Manifest{Releases: releases})
	if err != nil {
		t.Fatal(err)
	}
	site := &releaseSite{files: files}
	site.files["releases.json"] = m
	site.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, ok := site.files[r.URL.Path[len("/downloads/web/"):]]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if r.URL.Path != "/downloads/web/releases.json" {
			site.downloads.Add(1)
		}
		w.Write(data)
	}))
	t.Cleanup(site.srv.Close)
	return site
}

func (s *releaseSite) base() string { return s.srv.URL + "/downloads/web/" }

func release(t *testing.T, s signer, version string, build int, contract string, files map[string]string) (webbundle.Release, []byte, []byte) {
	t.Helper()
	archive := buildArchive(t, files)
	sum := sha256.Sum256(archive)
	name := "hyperdrop-web-" + version + ".tar.gz"
	return webbundle.Release{
		Version: version, Build: build, Date: "2026-10-25", Contract: contract,
		SHA256: hex.EncodeToString(sum[:]), Size: int64(len(archive)), URL: name, Sig: name + ".sig",
	}, archive, s.sign(t, version, build, contract, archive)
}

// pickSite offers a release of a newer minor, the one to pick (in a
// subdirectory, so its URLs resolve against the base) and an older one.
func pickSite(t *testing.T, s signer) *releaseSite {
	t.Helper()
	newer, newerA, newerS := release(t, s, "2.0.0", 1, "1.3.0", map[string]string{"index.html": "too new"})
	want, wantA, wantS := release(t, s, "1.0.1", 2, "1.2.0", map[string]string{"index.html": "picked"})
	want.URL, want.Sig = "sub/"+want.URL, "sub/"+want.Sig
	old, oldA, oldS := release(t, s, "1.0.0", 1, "1.2.0", map[string]string{"index.html": "old"})
	return newReleaseSite(t, []webbundle.Release{newer, want, old}, map[string][]byte{
		newer.URL: newerA, newer.Sig: newerS,
		want.URL: wantA, want.Sig: wantS,
		old.URL: oldA, old.Sig: oldS,
	})
}

func TestFetcherInstallsPick(t *testing.T) {
	s := newSigner(t)
	site := pickSite(t, s)
	st := openStore(t, t.TempDir(), s)
	f := NewFetcher(st, site.base(), nil)
	before := time.Now()
	if err := f.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	inst, ok := st.Current()
	if !ok || inst.Version != "1.0.1" || inst.Build != 2 {
		t.Fatalf("installed %+v %v", inst, ok)
	}
	got := f.Status()
	if got.Latest != "1.0.1" || got.Failed != "" || got.CheckedAt.Before(before) {
		t.Fatalf("status %+v", got)
	}
}

func TestFetcherSkipsCurrent(t *testing.T) {
	s := newSigner(t)
	want, archive, sig := release(t, s, "1.0.1", 2, "1.2.0", map[string]string{"index.html": "picked"})
	site := newReleaseSite(t, []webbundle.Release{want}, map[string][]byte{want.URL: archive, want.Sig: sig})
	st := openStore(t, t.TempDir(), s)
	f := NewFetcher(st, site.base(), nil)
	if err := f.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := site.downloads.Load(); n != 2 {
		t.Fatalf("first run downloaded %d files, want the archive and its signature", n)
	}
	if err := f.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := site.downloads.Load(); n != 2 {
		t.Fatalf("a run with the pick already current downloaded again (%d)", n)
	}
}

func TestFetcherRecordsFailure(t *testing.T) {
	s := newSigner(t)
	other := newSigner(t)
	want, archive, _ := release(t, s, "1.0.1", 2, "1.2.0", map[string]string{"index.html": "picked"})
	bad := other.sign(t, "1.0.1", 2, "1.2.0", archive)
	site := newReleaseSite(t, []webbundle.Release{want}, map[string][]byte{want.URL: archive, want.Sig: bad})
	st := openStore(t, t.TempDir(), s)
	f := NewFetcher(st, site.base(), nil)
	if err := f.Run(context.Background()); err == nil {
		t.Fatal("a bundle signed by an untrusted key installed")
	}
	if _, ok := st.Current(); ok {
		t.Fatal("an untrusted bundle became current")
	}
	if got := f.Status(); got.Failed == "" || got.Latest != "1.0.1" {
		t.Fatalf("status %+v", got)
	}

	// A good signature clears the failure.
	site.files[want.Sig] = s.sign(t, "1.0.1", 2, "1.2.0", archive)
	if err := f.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := f.Status(); got.Failed != "" {
		t.Fatalf("a successful run kept the failure %q", got.Failed)
	}

	// An unreadable manifest is a failure too.
	gone := NewFetcher(st, site.srv.URL+"/nowhere/", nil)
	if err := gone.Run(context.Background()); err == nil || gone.Status().Failed == "" {
		t.Fatalf("a missing manifest: %v %+v", err, gone.Status())
	}
}

func TestFetcherRefusesAnotherOrigin(t *testing.T) {
	s := newSigner(t)
	want, archive, sig := release(t, s, "1.0.1", 2, "1.2.0", map[string]string{"index.html": "picked"})
	elsewhere := newReleaseSite(t, nil, map[string][]byte{want.URL: archive, want.Sig: sig})
	want.URL = elsewhere.base() + want.URL
	site := newReleaseSite(t, []webbundle.Release{want}, map[string][]byte{})
	f := NewFetcher(openStore(t, t.TempDir(), s), site.base(), nil)
	if err := f.Run(context.Background()); err == nil {
		t.Fatal("downloaded a bundle from another origin")
	}
	if elsewhere.downloads.Load() != 0 {
		t.Fatal("dialled the other origin")
	}
}

func TestFetcherStartAndNudge(t *testing.T) {
	s := newSigner(t)
	want, archive, sig := release(t, s, "1.0.1", 2, "1.2.0", map[string]string{"index.html": "picked"})
	site := newReleaseSite(t, []webbundle.Release{want}, map[string][]byte{want.URL: archive, want.Sig: sig})
	st := openStore(t, t.TempDir(), s)
	f := NewFetcher(st, site.base(), nil)
	f.firstDelay, f.every, f.spread = time.Hour, time.Hour, time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.Start(ctx)
	f.Nudge()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := st.Current(); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a nudge did not run the fetch")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// The loop's own timer runs it too.
	st2 := openStore(t, t.TempDir(), s)
	g := NewFetcher(st2, site.base(), nil)
	g.firstDelay, g.every, g.spread = 10*time.Millisecond, time.Hour, time.Millisecond
	g.Start(ctx)
	deadline = time.Now().Add(5 * time.Second)
	for {
		if _, ok := st2.Current(); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the first scheduled run did not happen")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestResolveBase(t *testing.T) {
	for _, c := range []struct {
		name      string
		web       string
		webSet    bool
		server    string
		serverSet bool
		want      string
		wantErr   bool
	}{
		{name: "both unset", want: "https://gethyperdrop.com/downloads/web/"},
		{name: "web empty", webSet: true, server: "https://x/downloads/server/", serverSet: true, want: ""},
		{name: "web wins", web: "https://w.example/rel", webSet: true, server: "https://x/downloads/server/", serverSet: true, want: "https://w.example/rel/"},
		{name: "server empty", server: "", serverSet: true, want: ""},
		{name: "beside the server", server: "https://x/downloads/server/", serverSet: true, want: "https://x/downloads/web/"},
		{name: "beside the server, no slash", server: "https://x/downloads/server", serverSet: true, want: "https://x/downloads/web/"},
		{name: "loopback http", web: "http://127.0.0.1:9/web/", webSet: true, want: "http://127.0.0.1:9/web/"},
		{name: "web plain http", web: "http://example.com/web/", webSet: true, wantErr: true},
		{name: "server plain http", server: "http://example.com/server/", serverSet: true, wantErr: true},
		{name: "web credentials", web: "https://u:p@example.com/", webSet: true, wantErr: true},
	} {
		got, err := ResolveBase(c.web, c.webSet, c.server, c.serverSet)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("%s: got %q, %v", c.name, got, err)
		}
	}
}

// The fetcher never replaces a current install that still serves the server
// with an older version or build; an admin's install (the Store's) may.
func TestFetcherRefusesADowngrade(t *testing.T) {
	s := newSigner(t)
	old, oldA, oldS := release(t, s, "1.0.1", 2, testContract, map[string]string{"index.html": "older"})
	site := newReleaseSite(t, []webbundle.Release{old}, map[string][]byte{old.URL: oldA, old.Sig: oldS})
	for _, cur := range []struct {
		version string
		build   int
	}{{"1.0.2", 1}, {"1.0.1", 3}} {
		dir := t.TempDir()
		st := openStore(t, dir, s)
		install(t, st, s, cur.version, cur.build, map[string]string{"index.html": "current"})
		f := NewFetcher(st, site.base(), nil)
		if err := f.Run(context.Background()); err != nil {
			t.Fatal(err)
		}
		if inst, _ := st.Current(); inst.Version != cur.version || inst.Build != cur.build {
			t.Fatalf("the fetcher moved %s build %d to %s build %d", cur.version, cur.build, inst.Version, inst.Build)
		}
		if n := site.downloads.Load(); n != 0 {
			t.Fatalf("the fetcher downloaded the older bundle (%d files)", n)
		}
		if got := f.Status().Latest; got != cur.version {
			t.Fatalf("latest %q, want the current %q, which outranks the pick", got, cur.version)
		}
		// The admin's install of the older bundle goes through.
		if err := st.Install(oldA, oldS, old.Version, old.Build, old.Contract); err != nil {
			t.Fatalf("installing the older bundle by hand: %v", err)
		}
		if inst, _ := st.Current(); inst.Version != "1.0.1" || inst.Build != 2 {
			t.Fatalf("after the admin's install: %+v", inst)
		}
	}
}

// A current install that no longer serves the server (it went back a minor)
// is replaced by the newest bundle that does, though that one is older.
func TestFetcherMovesToAnOlderBundleThatServes(t *testing.T) {
	s := newSigner(t)
	dir := t.TempDir()
	newerServer, err := Open(dir, []string{s.pub}, "1.3.0")
	if err != nil {
		t.Fatal(err)
	}
	archive := buildArchive(t, map[string]string{"index.html": "for 1.3"})
	if err := newerServer.Install(archive, s.sign(t, "1.1.0", 1, "1.3.0", archive), "1.1.0", 1, "1.3.0"); err != nil {
		t.Fatal(err)
	}
	old, oldA, oldS := release(t, s, "1.0.1", 2, testContract, map[string]string{"index.html": "for 1.2"})
	site := newReleaseSite(t, []webbundle.Release{old}, map[string][]byte{old.URL: oldA, old.Sig: oldS})
	st := openStore(t, dir, s)
	if err := NewFetcher(st, site.base(), nil).Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if inst, _ := st.Current(); inst.Version != "1.0.1" || inst.Build != 2 || inst.Contract != testContract {
		t.Fatalf("installed %+v, want 1.0.1 build 2", inst)
	}
}
