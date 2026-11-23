package target

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"hyperdrop/server/internal/loadrig/report"
	"hyperdrop/server/internal/loadrig/volume"
)

var (
	buildOnce  sync.Once
	binaryPath string
	buildErr   error
	volOnce    sync.Once
	volDir     string
	volMan     volume.Manifest
	volErr     error
	scratch    string
)

func TestMain(m *testing.M) {
	var err error
	scratch, err = os.MkdirTemp("", "loadrig-target-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(scratch)
	os.Exit(code)
}

func serverBinary(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("starts a server")
	}
	buildOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		binaryPath, buildErr = BuildServer(ctx, "../../..", scratch)
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return binaryPath
}

// tinyVolume is one small generated volume the tests share.
func tinyVolume(t *testing.T) (string, volume.Manifest) {
	t.Helper()
	volOnce.Do(func() {
		volDir = scratch + "/volume"
		if volErr = os.Mkdir(volDir, 0o755); volErr != nil {
			return
		}
		volMan, volErr = volume.Generate(context.Background(), volume.Options{Dir: volDir, Plan: volume.NewPlan(300, 1)})
	})
	if volErr != nil {
		t.Fatal(volErr)
	}
	return volDir, volMan
}

func startTarget(t *testing.T) (Target, volume.Manifest) {
	t.Helper()
	bin := serverBinary(t)
	dir, man := tinyVolume(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	tg, err := StartLocal(ctx, bin, dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tg.Close() })
	return tg, man
}

func TestStartLocalIsHealthyAndReportsItself(t *testing.T) {
	tg, _ := startTarget(t)
	v, err := health(context.Background(), tg.BaseURL())
	if err != nil {
		t.Fatal(err)
	}
	info := tg.Info()
	if !info.Local || info.BaseURL != tg.BaseURL() || info.Version != v || v == "" {
		t.Fatalf("info = %+v, health version %q", info, v)
	}
	if !tg.Alive() {
		t.Fatal("not alive")
	}
	dir, _ := tinyVolume(t)
	b, err := os.ReadFile(pidPath(dir))
	if first, _, _ := strings.Cut(string(b), "\n"); err != nil || first != strconv.Itoa(tg.(*local).cmd.Process.Pid) {
		t.Fatalf("pid file %q, %v while the server runs", b, err)
	}
	tg.Close()
	if _, err := os.Stat(pidPath(dir)); !os.IsNotExist(err) {
		t.Fatalf("the pid file outlived Close: %v", err)
	}
}

func TestMemoryAndLog(t *testing.T) {
	tg, _ := startTarget(t)
	cur, peak, ok := tg.Memory()
	if !ok || cur <= 0 || peak < cur {
		t.Fatalf("Memory() = %d, %d, %v", cur, peak, ok)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	line, err := tg.WaitLog(ctx, "housekeeping first pass: ")
	if err != nil {
		t.Fatal(err)
	}
	lines, ok := tg.Log()
	if !ok || len(lines) == 0 {
		t.Fatalf("Log() = %d lines, %v", len(lines), ok)
	}
	found := false
	for _, l := range lines {
		found = found || strings.HasSuffix(l, line)
	}
	if !found {
		t.Fatalf("WaitLog line %q is not in Log()", line)
	}
}

func TestRestartWaitsForTheNewProcessLog(t *testing.T) {
	tg, _ := startTarget(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if _, err := tg.WaitLog(ctx, "housekeeping first pass: "); err != nil {
		t.Fatal(err)
	}
	before, _ := tg.Log()
	took, err := tg.Restart(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if took <= 0 || !tg.Alive() {
		t.Fatalf("took %v, alive %v", took, tg.Alive())
	}
	if _, err := tg.WaitLog(ctx, "housekeeping first pass: "); err != nil {
		t.Fatal(err)
	}
	after, _ := tg.Log()
	if len(after) <= len(before) {
		t.Fatalf("log did not grow across the restart: %d then %d", len(before), len(after))
	}
}

func TestKilledChildIsNotAliveAndDoFails(t *testing.T) {
	tg, _ := startTarget(t)
	l := tg.(*local)
	l.cmd.Process.Kill()
	<-l.done
	if tg.Alive() {
		t.Fatal("alive after kill")
	}
	if info := tg.Info(); info.Version == "" {
		t.Fatalf("Info() after the kill lost the version: %+v", info)
	}
	if cur, _, ok := tg.Memory(); !ok || cur <= 0 {
		t.Fatalf("Memory() after the kill = %d, %v", cur, ok)
	}
	rec := report.NewRecorder()
	c := NewClient(tg, rec, nil)
	defer c.Close()
	if err := c.Do(context.Background(), "health", "GET", "/api/health", "", nil, nil); err == nil {
		t.Fatal("Do succeeded against a dead server")
	}
	sc := rec.Scenario("dead", time.Second)
	if len(sc.Ops) != 1 || sc.Ops[0].Wrong == 0 {
		t.Fatalf("recorder = %+v", sc.Ops)
	}
}

func TestRestartKilledEndsTheProcessBySignalAndStartsAgain(t *testing.T) {
	tg, _ := startTarget(t)
	l := tg.(*local)
	old := l.cmd
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	took, err := tg.RestartKilled(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if old.ProcessState == nil || old.ProcessState.ExitCode() != -1 {
		t.Fatalf("the first process ended with %v, want a signal", old.ProcessState)
	}
	if l.cmd == old || l.cmd.Process.Pid == old.Process.Pid {
		t.Fatal("no new process started")
	}
	if took <= 0 || !tg.Alive() {
		t.Fatalf("took %v, alive %v", took, tg.Alive())
	}
	if _, err := tg.WaitLog(ctx, "housekeeping first pass: "); err != nil {
		t.Fatal(err)
	}
}

func TestRemoteHasNoMemoryOrLog(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "9.9.9"})
	}))
	defer srv.Close()
	r := Remote(srv.URL + "/")
	if _, _, ok := r.Memory(); ok {
		t.Fatal("remote Memory ok")
	}
	if _, ok := r.Log(); ok {
		t.Fatal("remote Log ok")
	}
	if _, err := r.Restart(context.Background()); err == nil {
		t.Fatal("remote Restart succeeded")
	}
	if _, err := r.RestartKilled(context.Background()); err == nil || !strings.Contains(err.Error(), "did not start") {
		t.Fatalf("remote RestartKilled = %v, want an error naming a server the rig did not start", err)
	}
	if info := r.Info(); info.Version != "9.9.9" || info.Local || info.BaseURL != srv.URL {
		t.Fatalf("info = %+v", info)
	}
	if !r.Alive() {
		t.Fatal("remote not alive")
	}
}

func TestClientListsAnAccountsShares(t *testing.T) {
	tg, man := startTarget(t)
	acc := man.Accounts[0]
	rec := report.NewRecorder()
	c := NewClient(tg, rec, nil)
	defer c.Close()
	var got struct {
		Shares []json.RawMessage `json:"shares"`
	}
	err := c.Do(context.Background(), "list", "GET", "/api/shares", acc.Token, nil, func(r *http.Response) error {
		if r.StatusCode != 200 {
			return fmt.Errorf("status %d", r.StatusCode)
		}
		return json.NewDecoder(r.Body).Decode(&got)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Shares) == 0 {
		t.Fatalf("account %s lists no shares (owns %d)", acc.Name, acc.Shares)
	}
}

func TestClientRecordsErrorCodesAndWrongAnswers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/denied":
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "no", "code": "nope"})
		case "/boom":
			w.WriteHeader(http.StatusInternalServerError)
		case "/big":
			fmt.Fprint(w, strings.Repeat("y", bodyKeepLimit+10))
		case "/moved":
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		case "/cookie":
			if _, err := r.Cookie("k"); err != nil {
				http.SetCookie(w, &http.Cookie{Name: "k", Value: "v"})
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			fmt.Fprint(w, strings.Repeat("x", 1000))
		}
	}))
	defer srv.Close()
	rec := report.NewRecorder()
	c := NewClient(Remote(srv.URL), rec, nil)
	defer c.Close()
	ctx := context.Background()
	c.Do(ctx, "denied", "GET", "/denied", "tok", nil, nil)
	c.Do(ctx, "moved", "GET", "/moved", "", nil, nil)
	err := c.Do(ctx, "wrong", "GET", "/ok", "", nil, func(*http.Response) error { return fmt.Errorf("bad body") })
	if err == nil {
		t.Fatal("check error not returned")
	}
	c.Do(ctx, "boom", "GET", "/boom", "", nil, func(*http.Response) error { return fmt.Errorf("rejected") })
	c.Do(ctx, "denied checked", "GET", "/denied", "tok", nil, func(*http.Response) error { return fmt.Errorf("refused") })
	var seen int64
	var kept int
	c.Do(ctx, "big", "GET", "/big", "", nil, func(r *http.Response) error {
		b, _ := io.ReadAll(r.Body)
		seen, kept = r.ContentLength, len(b)
		return nil
	})
	if seen != bodyKeepLimit+10 || kept != bodyKeepLimit {
		t.Fatalf("big body: length %d, kept %d", seen, kept)
	}
	if bodyKeepLimit != 64<<20 {
		t.Fatalf("bodyKeepLimit = %d, want 64 MiB: a full listing page at the page cap must reach the check", bodyKeepLimit)
	}
	jar := c.WithJar()
	jar.Do(ctx, "cookie", "GET", "/cookie", "", nil, nil)
	jar.Do(ctx, "cookie", "GET", "/cookie", "", nil, nil)
	c.Do(ctx, "nojar", "GET", "/cookie", "", nil, nil)
	c.Do(ctx, "nojar", "GET", "/cookie", "", nil, nil)

	sc := rec.Scenario("s", time.Second)
	byName := map[string]report.Op{}
	for _, o := range sc.Ops {
		byName[o.Name] = o
	}
	if a := byName["denied"].ByAnswer; a["403 nope"] != 1 {
		t.Fatalf("denied answers = %v", byName["denied"].ByAnswer)
	}
	if b := byName["boom"]; b.Wrong != 1 || b.Count != 1 {
		t.Fatalf("boom = %+v", b)
	}
	if d := byName["denied checked"]; d.Wrong != 1 || d.Count != 1 || len(d.WrongReasons) != 1 || d.WrongReasons[0] != "refused" {
		t.Fatalf("an unexpected 4xx the check also rejects = %+v, want one wrong with the check's reason", d)
	}
	if a := byName["moved"].ByAnswer; a["302"] != 1 {
		t.Fatalf("moved answers = %v", byName["moved"].ByAnswer)
	}
	if w := byName["wrong"]; w.Wrong != 1 || w.Count != 1 {
		t.Fatalf("wrong op = %+v", w)
	}
	if a := byName["cookie"].ByAnswer; a["204"] != 1 {
		t.Fatalf("jar did not carry its cookie: %v", a)
	}
	if a := byName["nojar"].ByAnswer; a["204"] != 0 {
		t.Fatalf("the plain client kept a cookie: %v", a)
	}
}

func TestDoHeaderSendsItsHeadersAndBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if r.Header.Get("Upload-Range") != "0-5" || r.Header.Get("Authorization") != "Bearer tok" || string(b) != "hello" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	rec := report.NewRecorder()
	c := NewClient(Remote(srv.URL), rec, nil)
	defer c.Close()
	h := http.Header{"Upload-Range": {"0-5"}}
	if err := c.DoHeader(context.Background(), "put", "PUT", "/f", "tok", h, strings.NewReader("hello"), func(r *http.Response) error {
		if r.StatusCode != http.StatusCreated {
			return fmt.Errorf("answered %d", r.StatusCode)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if o := rec.Scenario("s", time.Second).Ops[0]; o.ByAnswer["201"] != 1 || o.Wrong != 0 {
		t.Fatalf("put = %+v", o)
	}
}

func TestSourceAddrsAndAliasHint(t *testing.T) {
	addrs := SourceAddrs()
	if len(addrs) == 0 || addrs[0].String() != "127.0.0.1" {
		t.Fatalf("addrs = %v", addrs)
	}
	if AliasHint(3) == "" {
		t.Fatal("empty hint")
	}
}

func TestStreamHandsOverTheBodyAndTimesItsFirstByte(t *testing.T) {
	const size = 3 << 20
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/big":
			w.Header().Set("Content-Length", strconv.Itoa(size))
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			time.Sleep(50 * time.Millisecond)
			w.Write([]byte(strings.Repeat("z", size)))
		case "/short":
			w.Header().Set("Content-Length", "1000")
			w.Write([]byte(strings.Repeat("s", 10)))
			panic(http.ErrAbortHandler)
		case "/busy":
			w.Header().Set("Retry-After", "30")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, "<!doctype html><title>This server is busy</title>")
		case "/gone":
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	rec := report.NewRecorder()
	c := NewClient(Remote(srv.URL), rec, nil)
	defer c.Close()
	ctx := context.Background()

	var first time.Duration
	var read, length int64
	err := c.Stream(ctx, "big", "GET", "/big", "", func(r *http.Response, f time.Duration) error {
		first, length = f, r.ContentLength
		n, err := io.CopyN(io.Discard, r.Body, size/2)
		read = n
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if first <= 0 || first >= 50*time.Millisecond || read != size/2 || length != size {
		t.Fatalf("first %v, read %d, length %d", first, read, length)
	}
	called := false
	sink := func(*http.Response, time.Duration) error { called = true; return nil }
	if err := c.Stream(ctx, "short", "GET", "/short", "", func(r *http.Response, _ time.Duration) error {
		_, err := io.Copy(io.Discard, r.Body)
		return err
	}); err == nil {
		t.Fatal("a body cut short streamed without error")
	}
	c.Stream(ctx, "busy", "GET", "/busy", "", sink)
	c.Stream(ctx, "gone", "GET", "/gone", "", sink)
	if called {
		t.Fatal("sink called for an answer that is not a success")
	}
	if err := c.Stream(ctx, "rejected", "GET", "/big", "", func(*http.Response, time.Duration) error { return fmt.Errorf("bad zip") }); err == nil {
		t.Fatal("sink error not returned")
	}
	c.Do(ctx, "busy page", "GET", "/busy", "", nil, nil)

	sc := rec.Scenario("s", time.Second)
	byName := map[string]report.Op{}
	for _, o := range sc.Ops {
		byName[o.Name] = o
	}
	if b := byName["big"]; b.Count != 1 || b.Wrong != 0 || b.ByAnswer["200"] != 1 || b.Max < 50*time.Millisecond {
		t.Fatalf("big = %+v", b)
	}
	if s := byName["short"]; s.Count != 1 || s.Wrong != 1 {
		t.Fatalf("short = %+v", s)
	}
	for _, name := range []string{"busy", "busy page"} {
		if b := byName[name]; b.Count != 1 || b.Wrong != 0 || b.ByAnswer["503 busy"] != 1 {
			t.Fatalf("%s = %+v", name, b)
		}
	}
	if g := byName["gone"]; g.Count != 1 || g.Wrong != 1 || g.ByAnswer["404"] != 1 {
		t.Fatalf("gone = %+v", g)
	}
	if r := byName["rejected"]; r.Count != 1 || r.Wrong != 1 || r.WrongReasons[0] != "bad zip" {
		t.Fatalf("rejected = %+v", r)
	}
}

func TestStreamWaitsOnProgressNotOnTheWholeRequest(t *testing.T) {
	savedRequest, savedHeader, savedIdle := requestTimeout, streamHeaderWait, streamIdleGap
	requestTimeout, streamHeaderWait, streamIdleGap = 200*time.Millisecond, 300*time.Millisecond, 300*time.Millisecond
	t.Cleanup(func() { requestTimeout, streamHeaderWait, streamIdleGap = savedRequest, savedHeader, savedIdle })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/queued":
			// Headers late, but within the header wait.
			time.Sleep(150 * time.Millisecond)
			fallthrough
		case "/trickle":
			// A body taking well past the whole-request timeout, never idle long.
			w.Header().Set("Content-Length", "20")
			for range 20 {
				w.Write([]byte("t"))
				w.(http.Flusher).Flush()
				time.Sleep(50 * time.Millisecond)
			}
		case "/no-headers":
			time.Sleep(time.Second)
		case "/stalls":
			w.Header().Set("Content-Length", "20")
			w.Write([]byte("0123456789"))
			w.(http.Flusher).Flush()
			time.Sleep(time.Second)
		}
	}))
	defer srv.Close()
	rec := report.NewRecorder()
	c := NewClient(Remote(srv.URL), rec, nil)
	defer c.Close()
	ctx := context.Background()
	readAll := func(r *http.Response, _ time.Duration) error {
		_, err := io.Copy(io.Discard, r.Body)
		return err
	}
	for _, path := range []string{"/trickle", "/queued"} {
		if err := c.Stream(ctx, path, "GET", path, "", readAll); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
	for _, path := range []string{"/no-headers", "/stalls"} {
		began := time.Now()
		if err := c.Stream(ctx, path, "GET", path, "", readAll); err == nil {
			t.Fatalf("%s streamed without error", path)
		}
		if took := time.Since(began); took > 800*time.Millisecond {
			t.Fatalf("%s gave up after %v", path, took)
		}
	}
	sc := rec.Scenario("s", time.Second)
	byName := map[string]report.Op{}
	for _, o := range sc.Ops {
		byName[o.Name] = o
	}
	for _, name := range []string{"/trickle", "/queued"} {
		if o := byName[name]; o.Count != 1 || o.Wrong != 0 || o.Max < 4*requestTimeout {
			t.Fatalf("%s = %+v", name, o)
		}
	}
	for _, name := range []string{"/no-headers", "/stalls"} {
		if o := byName[name]; o.Count != 1 || o.ByAnswer["failed: timeout"] != 1 {
			t.Fatalf("%s = %+v", name, o)
		}
	}
}

func TestTheServerEnvironmentHoldsOnlyTheRigsHyperDropVariables(t *testing.T) {
	env := serverEnv([]string{"PATH=/bin", "HOME=/h", "HYPERDROP_DOMAIN=example.com", "HYPERDROP_DATA=/elsewhere",
		"HYPERDROP_AUTO_UPDATE=1", "NOT_HYPERDROP_X=1"}, "/vol", "127.0.0.1:9")
	got := map[string][]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		got[k] = append(got[k], v)
	}
	for k, want := range map[string]string{"PATH": "/bin", "HOME": "/h", "NOT_HYPERDROP_X": "1",
		"HYPERDROP_DATA": "/vol", "HYPERDROP_HTTP_ADDR": "127.0.0.1:9", "HYPERDROP_ALLOW_PRIVATE": "1",
		"HYPERDROP_PUSH_RELAY": "", "HYPERDROP_SERVER_RELEASES": ""} {
		if len(got[k]) != 1 || got[k][0] != want {
			t.Errorf("%s = %q, want once %q", k, got[k], want)
		}
	}
	for _, k := range []string{"HYPERDROP_DOMAIN", "HYPERDROP_AUTO_UPDATE"} {
		if _, ok := got[k]; ok {
			t.Errorf("%s from the rig's environment reached the server", k)
		}
	}
}

func TestTheCommitIsTheOneTheBinaryCarries(t *testing.T) {
	for _, c := range []struct {
		settings []debug.BuildSetting
		want     string
	}{
		{[]debug.BuildSetting{{Key: "vcs.revision", Value: "abc123"}, {Key: "vcs.modified", Value: "false"}}, "abc123"},
		{[]debug.BuildSetting{{Key: "vcs.modified", Value: "true"}, {Key: "vcs.revision", Value: "abc123"}}, "abc123+dirty"},
		{[]debug.BuildSetting{{Key: "vcs.modified", Value: "true"}}, ""},
		{nil, ""},
	} {
		if got := vcsCommit(c.settings); got != c.want {
			t.Errorf("vcsCommit(%v) = %q, want %q", c.settings, got, c.want)
		}
	}
	notGo := filepath.Join(t.TempDir(), "server")
	if err := os.WriteFile(notGo, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := binaryCommit(notGo); got != "" {
		t.Fatalf("a binary carrying no build information has commit %q", got)
	}
}

func TestTheRigsBuildCarriesItsCommit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not on PATH, so the build cannot be known to stamp a commit")
	}
	if out, err := exec.Command("git", "-C", "../../..", "rev-parse", "--is-inside-work-tree").Output(); err != nil || strings.TrimSpace(string(out)) != "true" {
		t.Skip("the server module is not inside a git work tree, so go build stamps no commit")
	}
	bin := serverBinary(t)
	if got := binaryCommit(bin); got == "" {
		t.Fatal("the rig's build of the server carries no commit")
	}
}
