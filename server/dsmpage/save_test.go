package dsmpage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fakeClock moves only when Sleep is called.
type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time        { return c.now }
func (c *fakeClock) Sleep(d time.Duration) { c.now = c.now.Add(d) }

// startOutcome is what one Start does: the script's own refusal, the reason
// the start leaves in the status file, and whether the server then keeps
// running and answers its health check.
type startOutcome struct {
	err       error
	lastError string
	runs      bool
	healthy   bool
}

// fakeService stands in for start-stop-status and the server it starts.
type fakeService struct {
	t      *testing.T
	clk    *fakeClock
	r      *stateRig
	starts []startOutcome
	onStop func()
	stops  []error // what each Stop answers, nil once used up

	calls   []string
	confs   []string // the conf each Start found
	running bool
	healthy bool
	checks  int
}

func (f *fakeService) Stop() error {
	f.calls = append(f.calls, "stop")
	if f.onStop != nil {
		f.onStop()
	}
	var err error
	if len(f.stops) > 0 {
		err, f.stops = f.stops[0], f.stops[1:]
	}
	if err == nil {
		f.running, f.healthy = false, false
	}
	return err
}

func (f *fakeService) Start() error {
	f.calls = append(f.calls, "start")
	b, _ := os.ReadFile(f.r.deps.ConfPath)
	f.confs = append(f.confs, string(b))
	o := startOutcome{runs: true, healthy: true}
	if len(f.starts) > 0 {
		o, f.starts = f.starts[0], f.starts[1:]
	}
	if o.lastError != "" {
		f.r.status(fmt.Sprintf(`{"lastError":%q,"at":%d}`, o.lastError, f.clk.Now().Unix()))
	} else if o.runs {
		f.r.status(`{"version":"1.2.3"}`)
	}
	f.running, f.healthy = o.runs, o.healthy
	return o.err
}

func (f *fakeService) Running() bool { return f.running }

func (f *fakeService) Healthy(ctx context.Context) bool {
	f.checks++
	if _, ok := ctx.Deadline(); !ok {
		f.t.Error("the health check runs without a deadline")
	}
	return f.healthy
}

type saveRig struct {
	*stateRig
	svc     *fakeService
	clk     *fakeClock
	workers []string // the job file each started worker was given
	lock    *os.File // the lock the last started worker was handed
}

func newSaveRig(t *testing.T, conf string) *saveRig {
	t.Helper()
	r := &saveRig{stateRig: newStateRig(t, conf)}
	r.clk = &fakeClock{now: time.Unix(1_800_000_000, 0)}
	r.svc = &fakeService{t: t, clk: r.clk, r: r.stateRig, running: true, healthy: true}
	r.deps.VarDir = filepath.Join(r.root, "var")
	r.deps.StartWorker = func(job string, lock *os.File) error {
		r.workers = append(r.workers, job)
		// The worker keeps the lock past the CGI: hold the same open file
		// description, as a child that inherited it does.
		fd, err := syscall.Dup(int(lock.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		r.lock = os.NewFile(uintptr(fd), "lock")
		t.Cleanup(func() { r.lock.Close() })
		return nil
	}
	return r
}

func (r *saveRig) page() *page { return newPage(r.deps) }

func (r *saveRig) save(req SettingsRequest) LastChange {
	r.t.Helper()
	return r.page().Save(req, r.svc, r.clk)
}

func (r *saveRig) read(rel string) string {
	r.t.Helper()
	b, err := os.ReadFile(filepath.Join(r.root, rel))
	if err != nil {
		r.t.Fatal(err)
	}
	return string(b)
}

func (r *saveRig) exists(rel string) bool {
	_, err := os.Lstat(filepath.Join(r.root, rel))
	return err == nil
}

func (r *saveRig) lastChange() LastChange {
	r.t.Helper()
	var c LastChange
	if err := json.Unmarshal([]byte(r.read("var/last-change.json")), &c); err != nil {
		r.t.Fatal(err)
	}
	return c
}

func (r *saveRig) post(body string) *httptest.ResponseRecorder {
	r.t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(body))
	req.Header.Set("X-SYNO-TOKEN", "tok")
	w := httptest.NewRecorder()
	New(r.deps).ServeHTTP(w, req)
	return w
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode()
}

var newPorts = SettingsRequest{Kind: "free", Address: "alice", HTTPPort: 8080, HTTPSPort: 8443, Proxy: "192.0.2.10, 10.0.0.0/8"}

const newPortsConf = "HYPERDROP_DOMAIN=\nHYPERDROP_DDNS_NAME=alice\nHYPERDROP_HTTP_ADDR=:8080\n" +
	"HYPERDROP_HTTPS_ADDR=:8443\nHYPERDROP_TRUSTED_PROXIES=\"192.0.2.10, 10.0.0.0/8\"\nHYPERDROP_SHARED_FOLDER=\"hyperdrop\"\n"

func TestSaveKeepsTheNewSettingsWhenHyperDropComesUpHealthy(t *testing.T) {
	r := newSaveRig(t, freeConf)
	res := r.save(newPorts)
	if res.State != "done" || res.Text() != "Saved." {
		t.Fatalf("result %+v", res)
	}
	if got := r.read("var/hyperdrop.conf"); got != newPortsConf {
		t.Fatalf("conf =\n%s\nwant\n%s", got, newPortsConf)
	}
	if got := r.read("var/hyperdrop.conf.prev"); got != freeConf {
		t.Fatalf(".prev = %q", got)
	}
	for _, f := range []string{"var/hyperdrop.conf", "var/hyperdrop.conf.prev", "var/last-change.json"} {
		if m := mode(t, filepath.Join(r.root, f)); !m.IsRegular() || m.Perm() != 0o600 {
			t.Errorf("%s mode %v", f, m)
		}
	}
	if !slices.Equal(r.svc.calls, []string{"stop", "start"}) {
		t.Fatalf("calls %v", r.svc.calls)
	}
	if r.svc.confs[0] != newPortsConf {
		t.Fatalf("started on %q", r.svc.confs[0])
	}
	if r.exists("var/address-request") {
		t.Fatal("an unchanged address wrote a request")
	}
	if c := r.lastChange(); c.State != "done" || c.At != r.clk.Now().Unix() {
		t.Fatalf("last change %+v", c)
	}
}

func TestSaveUndoesAChangeHyperDropCannotStartOn(t *testing.T) {
	r := newSaveRig(t, freeConf)
	r.svc.starts = []startOutcome{{lastError: "Port 8443 is already in use by another app."}, {runs: true, healthy: true}}
	res := r.save(newPorts)
	if res.State != "undone" || res.Reason != "Port 8443 is already in use by another app." ||
		res.Text() != "Last change undone: Port 8443 is already in use by another app." {
		t.Fatalf("result %+v", res)
	}
	if got := r.read("var/hyperdrop.conf"); got != freeConf {
		t.Fatalf("conf not restored:\n%s", got)
	}
	if !slices.Equal(r.svc.calls, []string{"stop", "start", "stop", "start"}) {
		t.Fatalf("calls %v", r.svc.calls)
	}
	if r.svc.confs[0] != newPortsConf || r.svc.confs[1] != freeConf {
		t.Fatalf("started on %q then %q", r.svc.confs[0], r.svc.confs[1])
	}
	// The failed server exits at once: no 60-second wait for it.
	if waited := r.clk.Now().Sub(time.Unix(1_800_000_000, 0)); waited > 10*time.Second {
		t.Fatalf("waited %v for a server that had exited", waited)
	}
	if c := r.lastChange(); c != res {
		t.Fatalf("recorded %+v, answered %+v", c, res)
	}
}

func TestSaveUndoesAChangeThatNeverTurnsHealthy(t *testing.T) {
	r := newSaveRig(t, freeConf)
	r.svc.starts = []startOutcome{{runs: true, healthy: false}, {runs: true, healthy: true}}
	start := r.clk.Now()
	res := r.save(newPorts)
	if res.State != "undone" || res.Text() != "Last change undone: HyperDrop did not start in 60 seconds." {
		t.Fatalf("result %+v", res)
	}
	waited := r.clk.Now().Sub(start)
	if waited < 60*time.Second || waited > 66*time.Second {
		t.Fatalf("waited %v, want about 60 s", waited)
	}
	if r.svc.checks < 25 || r.svc.checks > 33 {
		t.Fatalf("%d health checks, want one every 2 s", r.svc.checks)
	}
	if got := r.read("var/hyperdrop.conf"); got != freeConf {
		t.Fatalf("conf not restored:\n%s", got)
	}
	if !slices.Equal(r.svc.calls, []string{"stop", "start", "stop", "start"}) {
		t.Fatalf("calls %v", r.svc.calls)
	}
}

func TestSaveStartRefusedWithoutAReason(t *testing.T) {
	r := newSaveRig(t, freeConf)
	r.svc.starts = []startOutcome{{err: errors.New("exit status 1")}, {runs: true, healthy: true}}
	res := r.save(newPorts)
	if res.State != "undone" || res.Reason != "HyperDrop stopped as soon as it started. Open the log to see why." {
		t.Fatalf("result %+v", res)
	}
}

// The start script fails a start whose server exited at once, after the
// server recorded why: the change is undone with the server's reason.
func TestSaveStartRefusedWithTheServersReason(t *testing.T) {
	r := newSaveRig(t, freeConf)
	r.svc.starts = []startOutcome{{err: errors.New("exit status 1"), lastError: "Port 8443 is already in use by another app."}, {runs: true, healthy: true}}
	res := r.save(newPorts)
	if res.State != "undone" || res.Reason != "Port 8443 is already in use by another app." {
		t.Fatalf("result %+v", res)
	}
	if !slices.Equal(r.svc.calls, []string{"stop", "start", "stop", "start"}) {
		t.Fatalf("calls %v", r.svc.calls)
	}
}

// A reason in the status file from before this start is not this start's.
func TestSaveIgnoresAnOlderLastError(t *testing.T) {
	r := newSaveRig(t, freeConf)
	r.status(fmt.Sprintf(`{"lastError":"Old trouble.","at":%d}`, r.clk.Now().Unix()-3600))
	r.svc.starts = []startOutcome{{runs: false}, {runs: true, healthy: true}}
	res := r.save(newPorts)
	if res.State != "undone" || res.Reason != "HyperDrop stopped as soon as it started. Open the log to see why." {
		t.Fatalf("result %+v", res)
	}
}

func TestSaveFailsWhenTheOldSettingsCannotStartEither(t *testing.T) {
	r := newSaveRig(t, freeConf)
	r.svc.starts = []startOutcome{
		{lastError: "Port 8443 is already in use by another app."},
		{lastError: "The HyperDrop folder is locked or missing. Unlock it in Control Panel, Shared Folder.", err: errors.New("exit status 1")},
	}
	res := r.save(newPorts)
	if res.State != "failed" || res.Text() != "Change failed: The HyperDrop folder is locked or missing. Unlock it in Control Panel, Shared Folder." {
		t.Fatalf("result %+v", res)
	}
	if got := r.read("var/hyperdrop.conf"); got != freeConf {
		t.Fatalf("conf not restored:\n%s", got)
	}
	if c := r.lastChange(); c.State != "failed" {
		t.Fatalf("recorded %+v", c)
	}
}

func TestSaveRecordsApplyingWhileItRuns(t *testing.T) {
	r := newSaveRig(t, freeConf)
	seen := LastChange{}
	r.svc.onStop = func() { seen = r.lastChange() }
	r.save(newPorts)
	if seen.State != "applying" || seen.At != 1_800_000_000 {
		t.Fatalf("while stopping, the record said %+v", seen)
	}
}

func TestSaveRefusesAnInvalidPortBeforeAnythingStops(t *testing.T) {
	r := newSaveRig(t, freeConf)
	for _, req := range []SettingsRequest{
		{Kind: "free", Address: "alice", HTTPPort: 0, HTTPSPort: 5443},
		{Kind: "free", Address: "alice", HTTPPort: 5080, HTTPSPort: 65536},
		{Kind: "free", Address: "alice", HTTPPort: -1, HTTPSPort: 5443},
	} {
		res := r.save(req)
		if res.State != "failed" || res.Reason != "A port is a number from 1 to 65535." {
			t.Errorf("%+v: %+v", req, res)
		}
	}
	if len(r.svc.calls) != 0 {
		t.Fatalf("calls %v", r.svc.calls)
	}
	if got := r.read("var/hyperdrop.conf"); got != freeConf {
		t.Fatalf("conf changed:\n%s", got)
	}
	if r.exists("var/hyperdrop.conf.prev") {
		t.Fatal("a refused change kept a copy")
	}
}

func TestSaveRefusesAnotherFreeNameBeforeAnythingStops(t *testing.T) {
	r := newSaveRig(t, freeConf)
	res := r.save(SettingsRequest{Kind: "free", Address: "bobby", HTTPPort: 5080, HTTPSPort: 5443})
	if res.State != "failed" || res.Reason != "Change your free name in the HyperDrop app." {
		t.Fatalf("result %+v", res)
	}
	if len(r.svc.calls) != 0 || r.exists("var/address-request") {
		t.Fatalf("calls %v", r.svc.calls)
	}
	w := r.post(`{"kind":"free","address":"bobby","httpPort":5080,"httpsPort":5443,"proxy":""}`)
	if w.Code != http.StatusBadRequest || errorText(t, w) != "Change your free name in the HyperDrop app." {
		t.Fatalf("POST: %d %s", w.Code, w.Body)
	}
	if len(r.workers) != 0 {
		t.Fatal("a worker started")
	}
}

func TestSaveWritesAnAddressChangeAsARequest(t *testing.T) {
	r := newSaveRig(t, freeConf)
	res := r.save(SettingsRequest{Kind: "domain", Address: "Share.Example.com", HTTPPort: 5080, HTTPSPort: 5443})
	if res.State != "done" {
		t.Fatalf("result %+v", res)
	}
	if got := r.read("var/address-request"); got != "domain share.example.com\n" {
		t.Fatalf("request %q", got)
	}
	if m := mode(t, filepath.Join(r.root, "var/address-request")); m.Perm() != 0o600 || !m.IsRegular() {
		t.Fatalf("request mode %v", m)
	}
	conf := r.read("var/hyperdrop.conf")
	if !strings.Contains(conf, "HYPERDROP_DDNS_NAME=alice\n") || !strings.Contains(conf, "HYPERDROP_DOMAIN=\n") {
		t.Fatalf("the conf's address lines changed:\n%s", conf)
	}

	// From an own domain, a free name is a request too.
	r = newSaveRig(t, strings.Replace(strings.Replace(freeConf, "HYPERDROP_DDNS_NAME=alice", "HYPERDROP_DDNS_NAME=", 1),
		"HYPERDROP_DOMAIN=", "HYPERDROP_DOMAIN=share.example.com", 1))
	if res := r.save(SettingsRequest{Kind: "free", Address: "bobby", HTTPPort: 5080, HTTPSPort: 5443}); res.State != "done" {
		t.Fatalf("result %+v", res)
	}
	if got := r.read("var/address-request"); got != "free bobby\n" {
		t.Fatalf("request %q", got)
	}
}

func TestSaveUndoRestoresTheAddressRequest(t *testing.T) {
	r := newSaveRig(t, freeConf)
	r.svc.starts = []startOutcome{{lastError: "Port 8443 is already in use by another app."}, {runs: true, healthy: true}}
	req := newPorts
	req.Kind, req.Address = "domain", "share.example.com"
	if res := r.save(req); res.State != "undone" {
		t.Fatalf("result %+v", res)
	}
	if r.exists("var/address-request") {
		t.Fatal("the undone change's address request stayed")
	}

	r = newSaveRig(t, freeConf)
	r.write("var/address-request", "domain old.example.com\n")
	r.svc.starts = []startOutcome{{lastError: "Port 8443 is already in use by another app."}, {runs: true, healthy: true}}
	if res := r.save(req); res.State != "undone" {
		t.Fatalf("result %+v", res)
	}
	if got := r.read("var/address-request"); got != "domain old.example.com\n" {
		t.Fatalf("request %q, want the one waiting before", got)
	}
}

// Saving the address the conf already holds drops a request still waiting,
// as the upgrade wizard does.
func TestSaveWithTheCurrentAddressDropsAStaleRequest(t *testing.T) {
	r := newSaveRig(t, freeConf)
	r.write("var/address-request", "domain old.example.com\n")
	if res := r.save(SettingsRequest{Kind: "free", Address: "alice", HTTPPort: 5080, HTTPSPort: 5443}); res.State != "done" {
		t.Fatalf("result %+v", res)
	}
	if r.exists("var/address-request") {
		t.Fatal("the stale request stayed")
	}
}

// The conf is read again after the stop: the server rewrites its address
// lines while it runs.
func TestSaveMergesIntoTheConfAsItIsAfterTheStop(t *testing.T) {
	r := newSaveRig(t, freeConf)
	r.svc.onStop = func() { r.write("var/hyperdrop.conf", freeConf+"HYPERDROP_DATA_ID=0123\n") }
	if res := r.save(newPorts); res.State != "done" {
		t.Fatalf("result %+v", res)
	}
	if got := r.read("var/hyperdrop.conf"); got != newPortsConf+"HYPERDROP_DATA_ID=0123\n" {
		t.Fatalf("conf =\n%s", got)
	}
}

func TestSettingsPostStartsTheWorkerAndAnswers202(t *testing.T) {
	r := newSaveRig(t, freeConf)
	w := r.post(`{"kind":"free","address":"alice","httpPort":8080,"httpsPort":8443,"proxy":"192.0.2.10, 10.0.0.0/8"}`)
	if w.Code != http.StatusAccepted || strings.TrimSpace(w.Body.String()) != `{"state":"applying"}` {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	job := filepath.Join(r.root, "var", ".dsmpage-job.json")
	if !slices.Equal(r.workers, []string{job}) {
		t.Fatalf("workers %v", r.workers)
	}
	if m := mode(t, job); m.Perm() != 0o600 || !m.IsRegular() {
		t.Fatalf("job mode %v", m)
	}
	var req SettingsRequest
	if err := json.Unmarshal([]byte(r.read("var/.dsmpage-job.json")), &req); err != nil || req != newPorts {
		t.Fatalf("job %+v, %v", req, err)
	}
	if c := r.lastChange(); c.State != "applying" {
		t.Fatalf("last change %+v", c)
	}
	if got := r.read("var/hyperdrop.conf"); got != freeConf {
		t.Fatal("the CGI changed the conf itself")
	}
	if s := r.get(); s.LastChange == nil || s.LastChange.State != "applying" || s.LastChange.Text != "Applying your change…" {
		t.Fatalf("state reports %+v", s.LastChange)
	}

	// The worker holds the lock, so a second change waits for it.
	w = r.post(`{"kind":"free","address":"alice","httpPort":8081,"httpsPort":8443,"proxy":""}`)
	if w.Code != http.StatusConflict || errorText(t, w) != "Another change is being applied. Wait for it to finish." {
		t.Fatalf("second POST: %d %s", w.Code, w.Body)
	}
	if len(r.workers) != 1 {
		t.Fatalf("workers %v", r.workers)
	}

	// The worker runs the job and removes it.
	if res := r.page().apply(job, r.svc, r.clk); res.State != "done" {
		t.Fatalf("worker %+v", res)
	}
	if r.exists("var/.dsmpage-job.json") {
		t.Fatal("the job stayed")
	}
	if got := r.read("var/hyperdrop.conf"); got != newPortsConf {
		t.Fatalf("conf =\n%s", got)
	}
	r.lock.Close()
	if w := r.post(`{"kind":"free","address":"alice","httpPort":8081,"httpsPort":8443,"proxy":""}`); w.Code != http.StatusAccepted {
		t.Fatalf("after the worker: %d %s", w.Code, w.Body)
	}
}

func TestSettingsPostWhileAChangeIsApplyingAnswers409(t *testing.T) {
	r := newSaveRig(t, freeConf)
	f, err := os.OpenFile(filepath.Join(r.root, "var", ".dsmpage.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	w := r.post(`{"kind":"free","address":"alice","httpPort":8080,"httpsPort":8443,"proxy":""}`)
	if w.Code != http.StatusConflict || errorText(t, w) != "Another change is being applied. Wait for it to finish." {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if len(r.workers) != 0 || r.exists("var/.dsmpage-job.json") || r.exists("var/last-change.json") {
		t.Fatal("a refused change left a job or a record")
	}
}

func TestSettingsRefusals(t *testing.T) {
	ok := map[string]any{"kind": "free", "address": "alice", "httpPort": 5080, "httpsPort": 5443, "proxy": ""}
	with := func(k string, v any) string {
		m := map[string]any{}
		for kk, vv := range ok {
			m[kk] = vv
		}
		m[k] = v
		b, _ := json.Marshal(m)
		return string(b)
	}
	const (
		port   = "A port is a number from 1 to 65535."
		free   = "5-32 lowercase letters, digits and single hyphens, for example alice."
		domain = "A domain name, for example share.example.com."
		proxy  = "Proxy address must be IP addresses separated by commas, for example 192.168.1.10 or 127.0.0.1."
		bad    = "The request is not valid."
	)
	for _, tc := range []struct{ body, want string }{
		{with("httpPort", 0), port},
		{with("httpsPort", 70000), port},
		{with("httpsPort", 5080), "The HTTPS and HTTP ports must be different."},
		{with("kind", "other"), "Choose a free HyperDrop address or your own domain."},
		{with("address", "Alice"), free},
		{with("address", "ali"), free},
		{with("address", "al--ice"), free},
		{with("address", "-alice"), free},
		{with("address", "alice.example.com"), free},
		{with("address", strings.Repeat("a", 33)), free},
		{`{"kind":"domain","address":"localhost","httpPort":5080,"httpsPort":5443,"proxy":""}`, domain},
		{`{"kind":"domain","address":"a..example.com","httpPort":5080,"httpsPort":5443,"proxy":""}`, domain},
		{`{"kind":"domain","address":"example.com.","httpPort":5080,"httpsPort":5443,"proxy":""}`, domain},
		{`{"kind":"domain","address":"bob.hyperdrop.link","httpPort":5080,"httpsPort":5443,"proxy":""}`, domain},
		{`{"kind":"domain","address":"a_b.example.com","httpPort":5080,"httpsPort":5443,"proxy":""}`, domain},
		{`{"kind":"domain","address":"$(id).example.com","httpPort":5080,"httpsPort":5443,"proxy":""}`, domain},
		{`{"kind":"domain","address":"","httpPort":5080,"httpsPort":5443,"proxy":""}`, domain},
		{with("proxy", "0.0.0.0/0"), proxy},
		{with("proxy", " , "), proxy},
		{with("proxy", "192.0.2.1\"; id; \""), proxy},
		{with("proxy", "bogus"), proxy},
		{with("httpPort", "5080"), bad},
		{`{"kind":"free","address":"alice","httpPort":5080,"httpsPort":5443,"proxy":"","extra":1}`, bad},
		{`{"kind":"free","address":"alice","httpPort":5080,"httpsPort":5443,"proxy":""} {}`, bad},
		{`{"kind":"free","address":"alice","httpPort":5080,"httpsPort":5443,"proxy":"` + strings.Repeat(" ", 70<<10) + `"}`, bad},
		{``, bad},
	} {
		r := newSaveRig(t, freeConf)
		w := r.post(tc.body)
		if w.Code != http.StatusBadRequest || errorText(t, w) != tc.want {
			t.Errorf("%.80s: %d %s, want 400 %q", tc.body, w.Code, w.Body, tc.want)
		}
		if len(r.workers) != 0 || r.exists("var/.dsmpage-job.json") || r.exists("var/last-change.json") {
			t.Errorf("%.80s: a refused change left a worker, a job or a record", tc.body)
		}
	}
}

func TestStateReportsTheLastChange(t *testing.T) {
	r := newSaveRig(t, freeConf)
	if s := r.get(); s.LastChange != nil {
		t.Fatalf("no change yet, reported %+v", s.LastChange)
	}
	for _, tc := range []struct{ file, state, text string }{
		{`{"state":"done","reason":"","at":5}`, "done", "Saved."},
		{`{"state":"undone","reason":"Port 8443 is already in use by another app.","at":5}`, "undone", "Last change undone: Port 8443 is already in use by another app."},
		{`{"state":"failed","reason":"HyperDrop could not be stopped, so nothing was changed.","at":5}`, "failed", "Change failed: HyperDrop could not be stopped, so nothing was changed."},
		// No worker holds the lock: the change was cut short.
		{`{"state":"applying","reason":"","at":5}`, "failed", "Change failed: The change was interrupted. Check the settings and save again."},
	} {
		r.write("var/last-change.json", tc.file)
		s := r.get()
		if s.LastChange == nil || s.LastChange.State != tc.state || s.LastChange.Text != tc.text || s.LastChange.At != 5 {
			t.Errorf("%s: reported %+v", tc.file, s.LastChange)
		}
	}
}

// The DSM page writes the conf the upgrade wizard reads back: sourced the
// way start-stop-status sources it, every value it saved passes the
// package's own validate_answers and reads back as saved.
func TestTheSavedConfPassesThePackagesValidation(t *testing.T) {
	common, err := filepath.Abs("../../platforms/synology/scripts/common")
	if err != nil {
		t.Fatal(err)
	}
	for _, req := range []SettingsRequest{
		newPorts,
		{Kind: "free", Address: "alice", HTTPPort: 1, HTTPSPort: 65535, Proxy: ""},
		{Kind: "free", Address: "alice", HTTPPort: 5080, HTTPSPort: 5443, Proxy: " 2001:db8::/32 , ::ffff:192.0.2.1,127.0.0.1 "},
		{Kind: "domain", Address: "Share.Example.com", HTTPPort: 5080, HTTPSPort: 5443, Proxy: "::1"},
	} {
		r := newSaveRig(t, freeConf)
		if res := r.save(req); res.State != "done" {
			t.Fatalf("%+v: %+v", req, res)
		}
		script := `. "$1"
. "$2"
wizard_http_port=${HYPERDROP_HTTP_ADDR#:}
wizard_https_port=${HYPERDROP_HTTPS_ADDR#:}
wizard_trusted_proxies=$HYPERDROP_TRUSTED_PROXIES
wizard_shared_folder=$HYPERDROP_SHARED_FOLDER
wizard_address=$HYPERDROP_DDNS_NAME
wizard_kind_free=true
validate_answers || exit 1
printf '%s|%s|%s' "$wizard_http_port" "$wizard_https_port" "$wizard_trusted_proxies"`
		cmd := exec.Command("sh", "-c", script, "sh", common, r.deps.ConfPath)
		cmd.Env = append(os.Environ(), "SYNOPKG_PKGVAR="+r.deps.VarDir)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%+v: validate_answers refused the conf: %v: %s\n%s", req, err, out, r.read("var/hyperdrop.conf"))
		}
		want := fmt.Sprintf("%d|%d|%s", req.HTTPPort, req.HTTPSPort, strings.TrimSpace(req.Proxy))
		if string(out) != want {
			t.Errorf("read back %q, want %q", out, want)
		}
	}
}

// Every proxy value the page accepts, the package's validate_answers accepts
// too, so the upgrade wizard never refuses what the page saved; and the
// values both refuse are refused here.
func TestProxyValidationAgreesWithThePackage(t *testing.T) {
	common, err := filepath.Abs("../../platforms/synology/scripts/common")
	if err != nil {
		t.Fatal(err)
	}
	shellAccepts := func(v string) bool {
		cmd := exec.Command("sh", "-c", `. "$1"; wizard_trusted_proxies=$2; validate_answers`, "sh", common, v)
		cmd.Env = append(os.Environ(), "SYNOPKG_PKGVAR="+t.TempDir())
		return cmd.Run() == nil
	}
	for _, v := range []string{
		"192.0.2.10", "10.0.0.0/8, 127.0.0.1", "::1", "2001:db8::/32", "::ffff:192.0.2.1", "fd00::1/64,10.1.2.3",
		"0.0.0.0/0", "::/0", "10.0.0.0/08", "1.2.3.4/", "01.2.3.4", " , ", "a.b.c.d", "fe80::1%en0", "1.2.3.4/33",
		"1.2.3.4;id", "1.2.3.4\n5.6.7.8", "256.1.1.1", ":", "1.2.3.4 5.6.7.8", "::ffff:0:0/96", "1.2.3.4/0",
	} {
		page := proxyRefusal(v) == ""
		shell := shellAccepts(v)
		if page && !shell {
			t.Errorf("%q: the page accepts what the package refuses", v)
		}
		if shell && !page {
			t.Logf("%q: refused by the page only", v)
		}
	}
}

func TestHoldLockTakesTheInheritedLockAndClosesItOnExec(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".dsmpage.lock")
	parent, busy, err := takeLock(path)
	if err != nil || busy {
		t.Fatal(err, busy)
	}
	fd, err := syscall.Dup(int(parent.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	parent.Close()
	held, err := holdLock(path, uintptr(fd))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if held.Fd() != uintptr(fd) {
		t.Fatalf("took a new lock (fd %d) instead of the inherited fd %d", held.Fd(), fd)
	}
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
	if errno != 0 || flags&syscall.FD_CLOEXEC == 0 {
		t.Fatalf("the inherited lock would pass to the server: flags %d, %v", flags, errno)
	}
	if _, busy, _ := takeLock(path); !busy {
		t.Fatal("the lock is free while the worker holds it")
	}

	// Without an inherited lock the worker takes its own.
	other := filepath.Join(dir, "other.lock")
	own, err := holdLock(other, uintptr(fd))
	if err != nil || own.Fd() == uintptr(fd) {
		t.Fatalf("own lock %v, %v", own, err)
	}
	defer own.Close()
	if _, busy, _ := takeLock(other); !busy {
		t.Fatal("the worker's own lock is free")
	}
}

// The real worker start: the program runs detached in its own session with
// the lock as fd 3, so the lock outlives the CGI that took it.
func TestStartWorkerDetachesAndPassesTheLock(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	bin := writeScript(t, `OUT='`+out+`'
printf '%s %s' "$1" "$2" > "$OUT.args"
echo $$ > "$OUT.tmp" && mv "$OUT.tmp" "$OUT.pid"
exec sleep 30
`)
	lockPath := filepath.Join(dir, ".dsmpage.lock")
	lock, busy, err := takeLock(lockPath)
	if err != nil || busy {
		t.Fatal(err, busy)
	}
	if err := startWorker(bin, filepath.Join(dir, "job.json"), lock); err != nil {
		t.Fatal(err)
	}
	lock.Close()
	var pid int
	for i := 0; i < 100 && pid == 0; i++ {
		if b, err := os.ReadFile(out + ".pid"); err == nil {
			pid, _ = strconv.Atoi(strings.TrimSpace(string(b)))
		} else {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if pid == 0 {
		t.Fatal("the worker never ran")
	}
	defer syscall.Kill(pid, syscall.SIGKILL)
	if b, _ := os.ReadFile(out + ".args"); string(b) != "dsmpage-apply "+filepath.Join(dir, "job.json") {
		t.Fatalf("args %q", b)
	}
	// A process started with setsid leads its own session and process
	// group, and Getpgid answers on every system the tests run on.
	if pgid, err := syscall.Getpgid(pid); err != nil || pgid != pid {
		t.Fatalf("process group %d, %v: the worker is not in its own session", pgid, err)
	}
	if _, busy, _ := takeLock(lockPath); !busy {
		t.Fatal("the lock did not pass to the worker")
	}
}

// The server that does not come up is never restored over: when it cannot
// be stopped, the change fails and the new conf stays in place.
func TestSaveFailsWhenTheFailedServerCannotBeStopped(t *testing.T) {
	r := newSaveRig(t, freeConf)
	r.svc.starts = []startOutcome{{runs: true, healthy: false}}
	r.svc.stops = []error{nil, errors.New("exit status 1")}
	res := r.save(newPorts)
	if res.State != "failed" || res.Reason != "HyperDrop could not be stopped to put the previous settings back." {
		t.Fatalf("result %+v", res)
	}
	if !slices.Equal(r.svc.calls, []string{"stop", "start", "stop"}) {
		t.Fatalf("calls %v", r.svc.calls)
	}
	if got := r.read("var/hyperdrop.conf"); got != newPortsConf {
		t.Fatalf("conf =\n%s", got)
	}
}

// A lock the state poll holds for a moment does not refuse a Save.
func TestSettingsPostWaitsBrieflyForTheLock(t *testing.T) {
	r := newSaveRig(t, freeConf)
	f, busy, err := takeLock(filepath.Join(r.root, "var", ".dsmpage.lock"))
	if err != nil || busy {
		t.Fatal(err, busy)
	}
	go func() {
		time.Sleep(30 * time.Millisecond)
		f.Close()
	}()
	if w := r.post(`{"kind":"free","address":"alice","httpPort":8080,"httpsPort":8443,"proxy":""}`); w.Code != http.StatusAccepted {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// A worker that cannot take the lock leaves no job behind.
func TestTheWorkerRemovesItsJobWhenTheLockIsTaken(t *testing.T) {
	r := newSaveRig(t, freeConf)
	f, _, err := takeLock(filepath.Join(r.root, "var", ".dsmpage.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	job := filepath.Join(r.root, "var", ".dsmpage-job.json")
	r.write("var/.dsmpage-job.json", `{"kind":"free","address":"alice","httpPort":8080,"httpsPort":8443,"proxy":""}`)
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	if code := r.page().work(job, null.Fd(), r.svc, r.clk); code == 0 {
		t.Fatal("the worker ran without the lock")
	}
	if r.exists("var/.dsmpage-job.json") || len(r.svc.calls) != 0 {
		t.Fatalf("job left behind or service called: %v", r.svc.calls)
	}
}

// A waiting address change is reported, so the page saves it again rather
// than cancelling it.
func TestStateReportsAPendingAddressAndSaveKeepsIt(t *testing.T) {
	r := newSaveRig(t, freeConf)
	if s := r.get(); s.PendingAddress != nil {
		t.Fatalf("no request, reported %+v", s.PendingAddress)
	}
	r.write("var/address-request", "domain share.example.com\n")
	s := r.get()
	if s.PendingAddress == nil || *s.PendingAddress != (Address{"domain", "share.example.com"}) {
		t.Fatalf("pending %+v", s.PendingAddress)
	}
	if s.Address != (Address{"free", "alice"}) {
		t.Fatalf("address %+v", s.Address)
	}
	r.write("var/address-request", "free bobby\n")
	if s := r.get(); s.PendingAddress == nil || *s.PendingAddress != (Address{"free", "bobby"}) {
		t.Fatalf("pending %+v", s.PendingAddress)
	}
	for _, bad := range []string{"domain localhost\n", "free Bob\n", "domain bob.hyperdrop.link\n", "free bobby\nfree carol\n",
		"domain " + strings.Repeat("a", 600) + ".example.com\n", "nonsense"} {
		r.write("var/address-request", bad)
		if s := r.get(); s.PendingAddress != nil {
			t.Errorf("%.40q: reported %+v", bad, s.PendingAddress)
		}
	}
	os.Remove(filepath.Join(r.root, "var", "address-request"))
	if err := os.WriteFile(filepath.Join(r.root, "elsewhere"), []byte("domain share.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(r.root, "elsewhere"), filepath.Join(r.root, "var", "address-request")); err != nil {
		t.Fatal(err)
	}
	if s := r.get(); s.PendingAddress != nil {
		t.Fatalf("a linked request was read: %+v", s.PendingAddress)
	}
	os.Remove(filepath.Join(r.root, "var", "address-request"))

	// A request for the conf's own address is stale, not waiting.
	r.write("var/address-request", "free alice\n")
	if s := r.get(); s.PendingAddress != nil {
		t.Fatalf("a request for the current address reported %+v", s.PendingAddress)
	}

	// A ports-only Save sends the pending address and keeps the request.
	r.write("var/address-request", "domain share.example.com\n")
	if res := r.save(SettingsRequest{Kind: "domain", Address: "share.example.com", HTTPPort: 8080, HTTPSPort: 8443}); res.State != "done" {
		t.Fatalf("result %+v", res)
	}
	if got := r.read("var/address-request"); got != "domain share.example.com\n" {
		t.Fatalf("request %q", got)
	}
}

// running counts the server, never the DSM page's CGI or its Save worker,
// which run the same binary.
func TestRunningSkipsTheDSMPageProcesses(t *testing.T) {
	r := newStateRig(t, freeConf)
	proc := func(pid, cmdline string) {
		dir := filepath.Join(r.root, "proc", pid)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(rigBin, filepath.Join(dir, "exe")); err != nil {
			t.Fatal(err)
		}
		r.write(filepath.Join("proc", pid, "cmdline"), cmdline)
	}
	proc("100", rigBin+"\x00dsmpage\x00")
	proc("101", rigBin+"\x00dsmpage-apply\x00/var/packages/hyperdrop/var/.dsmpage-job.json\x00")
	if r.get().Running {
		t.Fatal("the page's own processes count as the server")
	}
	// The server always starts with no argument; an operator subcommand of
	// the same binary is not the server.
	proc("104", rigBin+"\x00admins\x00--standing\x00")
	proc("105", rigBin+"\x00resetadmin\x00")
	if r.get().Running {
		t.Fatal("an operator subcommand counts as the server")
	}
	// A process that exits between the two reads leaves an empty cmdline.
	proc("103", "")
	if r.get().Running {
		t.Fatal("a process with no command line counts as the server")
	}
	os.Remove(filepath.Join(r.root, "proc", "103", "cmdline"))
	if r.get().Running {
		t.Fatal("a process whose command line cannot be read counts as the server")
	}
	proc("102", rigBin+"\x00")
	if !r.get().Running {
		t.Fatal("the server is not seen")
	}
}

// Healthy needs HyperDrop's own health answer: a 200 from anything else on
// the port is not HyperDrop coming up.
func TestHealthyRecognisesHyperDrop(t *testing.T) {
	for _, tc := range []struct {
		code int
		body string
		want bool
	}{
		{200, `{"status":"ok","serverID":"0123abcd","version":"1.0.1"}`, true},
		{200, `<html>DSM</html>`, false},
		{200, `{"status":"ok"}`, false},
		{200, `{"serverID":""}`, false},
		{503, `{"serverID":"0123abcd"}`, false},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.code)
			w.Write([]byte(tc.body))
		}))
		port := srv.URL[strings.LastIndex(srv.URL, ":")+1:]
		r := newStateRig(t, "HYPERDROP_HTTP_ADDR=:"+port+"\n")
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		got := newScriptService(newPage(r.deps)).Healthy(ctx)
		cancel()
		srv.Close()
		if got != tc.want {
			t.Errorf("%d %s: healthy %v, want %v", tc.code, tc.body, got, tc.want)
		}
	}
}
