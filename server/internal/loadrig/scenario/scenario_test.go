package scenario

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"hyperdrop/server/internal/housekeep"
	"hyperdrop/server/internal/loadrig/report"
	"hyperdrop/server/internal/loadrig/target"
	"hyperdrop/server/internal/loadrig/volume"
	"hyperdrop/server/internal/metadb"
)

// testShares is the size of the test volumes: the smallest plan that holds
// every kind the scenarios read (shares at the file cap, expired shares,
// single-file shares of the largest account). The three cap shares, 60,000
// files, are most of what generating one costs.
const testShares = 300

// testScale shrinks repetitions and holds so a scenario runs in seconds.
const testScale = 0.1

var (
	scratch string

	buildOnce  sync.Once
	binaryPath string
	buildErr   error

	volumes sync.Map // name -> *testVolume
)

type testVolume struct {
	once sync.Once
	dir  string
	man  volume.Manifest
	err  error
}

func TestMain(m *testing.M) {
	var err error
	scratch, err = os.MkdirTemp("", "loadrig-scenario-")
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
		binaryPath, buildErr = target.BuildServer(ctx, "../../..", scratch)
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return binaryPath
}

// generated is the volume called name, generated once per test binary. A
// test that changes a volume beyond what a first boot does uses a name of
// its own.
func generated(t *testing.T, name string) (string, volume.Manifest) {
	t.Helper()
	v, _ := volumes.LoadOrStore(name, &testVolume{})
	tv := v.(*testVolume)
	tv.once.Do(func() {
		tv.dir = filepath.Join(scratch, name)
		if tv.err = os.Mkdir(tv.dir, 0o755); tv.err != nil {
			return
		}
		tv.man, tv.err = volume.Generate(context.Background(), volume.Options{Dir: tv.dir, Plan: volume.NewPlan(testShares, 1)})
	})
	if tv.err != nil {
		t.Fatal(tv.err)
	}
	return tv.dir, tv.man
}

// start runs a server on the named volume for the length of the test.
func start(t *testing.T, name string) (target.Target, Env) {
	t.Helper()
	bin := serverBinary(t)
	dir, man := generated(t, name)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	tg, err := target.StartLocal(ctx, bin, dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tg.Close() })
	return tg, Env{Target: tg, Volume: man, Plan: man.Plan, Scale: testScale}
}

func settle(t *testing.T, tg target.Target) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := tg.WaitLog(ctx, firstPassPrefix); err != nil {
		t.Fatal(err)
	}
}

func run(t *testing.T, s Scenario, e Env) report.Scenario {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return RunOne(ctx, s, e)
}

func byName(t *testing.T, name string) Scenario {
	t.Helper()
	for _, s := range All() {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no scenario %q", name)
	return Scenario{}
}

func opNamed(sc report.Scenario, name string) (report.Op, bool) {
	for _, o := range sc.Ops {
		if o.Name == name {
			return o, true
		}
	}
	return report.Op{}, false
}

func valueNamed(sc report.Scenario, name string) (report.Value, bool) {
	for _, v := range sc.Values {
		if v.Name == name {
			return v, true
		}
	}
	return report.Value{}, false
}

func completed(t *testing.T, sc report.Scenario) {
	t.Helper()
	if sc.Failed != "" || sc.Skipped != "" {
		t.Fatalf("%s: failed %q, skipped %q", sc.Name, sc.Failed, sc.Skipped)
	}
}

func TestAllRunsHousekeepingFirstAndOverloadLast(t *testing.T) {
	var names []string
	for _, s := range All() {
		if s.Run == nil || s.About == "" {
			t.Fatalf("%q has no Run or no About", s.Name)
		}
		names = append(names, s.Name)
	}
	if got := strings.Join(names, ","); got != "housekeeping,startup,startup-killed,reads,visitors,zips,upload,catchup,accounts,overload" {
		t.Fatalf("All() = %s", got)
	}
}

// TestTheLimitsCopiedMatchTheServer holds each limit the scenarios copy from
// package api, which does not export them, to the server's source.
func TestTheLimitsCopiedMatchTheServer(t *testing.T) {
	for _, c := range []struct {
		file, pattern string
		want          string
	}{
		{"loadguard.go", `(?m)^\s*guardPerAddress\s*=\s*(\d+)\s*$`, strconv.Itoa(perAddressRequests)},
		{"loadguard.go", `(?m)^\s*guardConnsPerAddress\s*=\s*(\d+)\s*$`, strconv.Itoa(perAddressConns)},
		{"zip.go", `(?m)^const zipsPerAddress = (\d+)$`, strconv.Itoa(zipsPerAddress)},
		{"visits.go", `(?m)^const visitFlushInterval = (\d+) \* time\.Second$`, strconv.Itoa(int(visitFlushInterval / time.Second))},
		{"watch.go", `(?m)^\s*watchMaxPerOwner\s*=\s*(\d+)\s*$`, strconv.Itoa(watchMaxPerOwner)},
		{"watch.go", `(?m)^\s*watchMaxTotal\s*=\s*(\d+)\s*$`, strconv.Itoa(watchMaxTotal)},
		{"createlimit.go", `(?m)^\s*createBurst\s*=\s*(\d+)\s*$`, strconv.Itoa(createBurst)},
		{"createlimit.go", `(?m)^\s*createPerHour\s*=\s*(\d+)\s*$`, strconv.Itoa(createPerHour)},
	} {
		src, err := os.ReadFile(filepath.Join("..", "..", "api", c.file))
		if err != nil {
			t.Fatal(err)
		}
		m := regexp.MustCompile(c.pattern).FindSubmatch(src)
		if m == nil {
			t.Fatalf("%s no longer matches %s: copy the limit again", c.file, c.pattern)
		}
		if string(m[1]) != c.want {
			t.Fatalf("%s says %s, the scenarios copy %s", c.file, m[1], c.want)
		}
	}
}

// zipOf is a stored zip of n small files.
func zipOf(t *testing.T, n int) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for i := range n {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: fmt.Sprintf("set/file_%05d.txt", i), Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(w, "file %d\n", i)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func zipAnswer(body []byte, length int64) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, ContentLength: length, Body: io.NopCloser(bytes.NewReader(body))}
}

func TestReadZipCountsTheEntriesFromItsTail(t *testing.T) {
	z := zipOf(t, 500)
	got, err := readZip(zipAnswer(z, int64(len(z))), 500, 64<<10)
	if err != nil || got.entries != 500 || got.size != int64(len(z)) {
		t.Fatalf("readZip = %+v, %v", got, err)
	}
	if _, err := readZip(zipAnswer(z, int64(len(z))), 499, 64<<10); err == nil {
		t.Fatal("a zip of 500 entries passed for a share of 499 files")
	}
	if got, err := readZip(zipAnswer(z, int64(len(z))), 500, 1<<10); err != nil || got.entries != -1 {
		t.Fatalf("a directory longer than the tail: %+v, %v", got, err)
	}
	if _, err := readZip(zipAnswer(z, int64(len(z))+10), 500, 64<<10); err == nil {
		t.Fatal("a zip short of its Content-Length passed")
	}
	if _, err := readZip(zipAnswer(z[:len(z)/2], -1), 500, 64<<10); err == nil {
		t.Fatal("half a zip passed")
	}
}

func TestTailKeepsTheLastBytesWritten(t *testing.T) {
	var all []byte
	tl := newTail(10)
	for i, chunk := range []string{"abc", "defghij", "k", "lmnopqrstuvwxyz", "0123"} {
		tl.Write([]byte(chunk))
		all = append(all, chunk...)
		want := all[max(0, len(all)-10):]
		if got := tl.bytes(); !bytes.Equal(got, want) {
			t.Fatalf("after write %d: %q, want %q", i, got, want)
		}
	}
	r := tl.readerAt(int64(len(all)))
	p := make([]byte, 4)
	if n, err := r.ReadAt(p, int64(len(all))-6); n != 4 || err != nil || string(p) != "yz01" {
		t.Fatalf("ReadAt = %d, %v, %q", n, err, p)
	}
	if _, err := r.ReadAt(p, 0); !errors.Is(err, errBeforeTail) {
		t.Fatalf("ReadAt before the tail = %v", err)
	}
}

func TestTheLinesReadAreTheOnesTheServerLogs(t *testing.T) {
	first := housekeep.Result{First: true, Took: 1500 * time.Millisecond,
		Steps: []housekeep.Step{{Name: "expiry", Took: 800 * time.Millisecond}, {Name: "integrity", Took: 25 * time.Millisecond}}}
	line := first.Timing()
	if !strings.HasPrefix(line, firstPassPrefix) {
		t.Fatalf("first pass line %q lacks %q", line, firstPassPrefix)
	}
	p, err := parsePass(line)
	if err != nil {
		t.Fatal(err)
	}
	if p.total != 1500*time.Millisecond || len(p.steps) != 2 ||
		p.steps[0] != (passStep{"expiry", 800 * time.Millisecond}) || p.steps[1] != (passStep{"integrity", 25 * time.Millisecond}) {
		t.Fatalf("parsePass(%q) = %+v", line, p)
	}
	quick := housekeep.Result{First: true, Took: 4 * time.Millisecond}
	if p, err := parsePass(quick.Timing()); err != nil || p.total != 4*time.Millisecond || len(p.steps) != 0 {
		t.Fatalf("parsePass(%q) = %+v, %v", quick.Timing(), p, err)
	}
	lines := housekeep.Result{Expired: 1234}.Lines()
	if len(lines) != 1 {
		t.Fatalf("Lines() = %q", lines)
	}
	if n, ok, err := parseRemoved(lines[0]); err != nil || !ok || n != 1234 {
		t.Fatalf("parseRemoved(%q) = %d, %v, %v", lines[0], n, ok, err)
	}
}

func TestLocalScenariosSkipAServerNamedByURL(t *testing.T) {
	e := Env{Target: target.Remote("http://127.0.0.1:1"), Scale: testScale}
	for _, name := range []string{"startup", "startup-killed", "housekeeping"} {
		sc := RunOne(context.Background(), byName(t, name), e)
		if sc.Skipped == "" || sc.Failed != "" || len(sc.Ops) != 0 {
			t.Fatalf("%s against a remote server: %+v", name, sc)
		}
	}
}

// largestOwner is the plan's largest account and how many shares the
// default listing shows it once the first pass has run: inboxes are listed
// apart and expired shares are gone.
func largestOwner(p volume.Plan) (owner string, listed int) {
	owner, _ = p.Largest()
	for i := 0; i < p.Shares; i++ {
		if s := p.Share(i); s.Owner == owner && s.Kind != volume.Inbox && s.Kind != volume.Expired {
			listed++
		}
	}
	return owner, listed
}

func TestReadsRecordsEveryReadAndWalksEveryPage(t *testing.T) {
	tg, e := start(t, "shared")
	settle(t, tg)
	sc := run(t, byName(t, "reads"), e)
	completed(t, sc)
	for _, name := range []string{opListPage, opListSearch, opWalkPage, opWalk, opUsage, opCapShare, opPublicListing, opListPageParallel, opUsageParallel} {
		o, ok := opNamed(sc, name)
		if !ok || o.Count == 0 {
			t.Fatalf("op %q missing: %+v", name, sc.Ops)
		}
		if o.Wrong != 0 {
			t.Fatalf("op %q: %d wrong %q, answers %v", name, o.Wrong, o.WrongReasons, o.ByAnswer)
		}
	}
	_, listed := largestOwner(e.Plan)
	wantPages := (listed + metadb.MaxListLimit - 1) / metadb.MaxListLimit
	if v, ok := valueNamed(sc, valWalkPages); !ok || int(v.V) != wantPages {
		t.Fatalf("walk pages = %+v, want %d", v, wantPages)
	}
	if v, ok := valueNamed(sc, valWalkShares); !ok || int(v.V) != listed {
		t.Fatalf("walk shares = %+v, want %d", v, listed)
	}
}

func TestHousekeepingMeasuresTheSweepOfTheExpiredShares(t *testing.T) {
	tg, e := start(t, "housekeeping")
	sc := run(t, byName(t, "housekeeping"), e)
	completed(t, sc)

	var expired []volume.ShareSpec
	for i := 0; i < e.Plan.Shares; i++ {
		if s := e.Plan.Share(i); s.Kind == volume.Expired {
			expired = append(expired, s)
		}
	}
	if v, ok := valueNamed(sc, valRemoved); !ok || int(v.V) != len(expired) || len(expired) == 0 {
		t.Fatalf("removed = %+v, want %d", v, len(expired))
	}
	for _, o := range sc.Ops {
		if o.Wrong != 0 {
			t.Fatalf("op %q: %d wrong %q", o.Name, o.Wrong, o.WrongReasons)
		}
	}
	if _, ok := valueNamed(sc, valFirstPass); !ok {
		t.Fatalf("no %q value: %+v", valFirstPass, sc.Values)
	}
	for _, name := range []string{opListAfter, opDownloadAfter, opExpiredGone} {
		if o, ok := opNamed(sc, name); !ok || o.Count == 0 || o.Wrong != 0 {
			t.Fatalf("op %q: %+v (all: %+v)", name, o, sc.Ops)
		}
	}

	tokens := map[string]string{}
	for _, a := range e.Volume.Accounts {
		tokens[a.Name] = a.Token
	}
	for _, s := range expired {
		for _, probe := range []struct{ path, token string }{{"/api/shares/" + s.ID, tokens[s.Owner]}, {"/share/" + s.ID, ""}} {
			req, _ := http.NewRequest(http.MethodGet, tg.BaseURL()+probe.path, nil)
			if probe.token != "" {
				req.Header.Set("Authorization", "Bearer "+probe.token)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("expired share %s: %s answered %d", s.ID, probe.path, resp.StatusCode)
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if _, err := tg.Restart(ctx); err != nil {
		t.Fatal(err)
	}
	again := run(t, byName(t, "housekeeping"), e)
	if again.Skipped != "already swept" {
		t.Fatalf("a run on the swept volume: %+v", again)
	}
}

// passingTarget is a server whose first pass is logged once release is
// closed.
type passingTarget struct {
	target.Target
	release chan struct{}
}

func (p passingTarget) WaitLog(ctx context.Context, prefix string) (string, error) {
	select {
	case <-p.release:
		return firstPassPrefix + "2s (expiry 1.5s)", nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (p passingTarget) Alive() bool { return true }

func TestDuringRequestsUntilThePassIsLogged(t *testing.T) {
	release := make(chan struct{})
	e := Env{Target: passingTarget{release: release}}
	rec := report.NewRecorder()
	var lists, downloads atomic.Int64
	list := func(op string) error {
		rec.Observe(op, time.Millisecond, http.StatusOK, "")
		if lists.Add(1) == 3 {
			close(release)
		}
		return nil
	}
	download := func(op string) error {
		rec.Observe(op, time.Millisecond, http.StatusOK, "")
		downloads.Add(1)
		return nil
	}
	line, err := during(context.Background(), e, rec, list, download)
	if err != nil || !strings.HasPrefix(line, firstPassPrefix) {
		t.Fatalf("during = %q, %v", line, err)
	}
	if lists.Load() < 3 || downloads.Load() != lists.Load() {
		t.Fatalf("%d list and %d download requests", lists.Load(), downloads.Load())
	}
	sc := rec.Scenario("housekeeping", time.Second)
	if v, ok := valueNamed(sc, valDuring); !ok || int(v.V) != int(lists.Load()+downloads.Load()) {
		t.Fatalf("%s = %+v", valDuring, v)
	}
}

func TestStartupReportsBootFirstPassAndMemory(t *testing.T) {
	_, e := start(t, "shared")
	sc := run(t, byName(t, "startup"), e)
	completed(t, sc)
	for _, name := range []string{valHealthyAfter, valFirstPassAfter, valPeakToFirstPass, memoryAfterName(e.hold(memoryHold))} {
		v, ok := valueNamed(sc, name)
		if !ok || v.NotAvailable != "" || v.V <= 0 {
			t.Fatalf("value %q = %+v (all: %+v)", name, v, sc.Values)
		}
	}
	for _, b := range bootLines {
		if v, ok := valueNamed(sc, b.value); !ok || v.NotAvailable != "" {
			t.Fatalf("value %q = %+v (all: %+v)", b.value, v, sc.Values)
		}
	}
}

func TestStartupKilledReportsHealthyAndTheBootPhases(t *testing.T) {
	tg, e := start(t, "shared")
	settle(t, tg)
	sc := run(t, byName(t, "startup-killed"), e)
	completed(t, sc)
	for _, name := range []string{valHealthyAfter, valFirstPassAfter} {
		if v, ok := valueNamed(sc, name); !ok || v.NotAvailable != "" || v.V <= 0 {
			t.Fatalf("%s = %+v", name, v)
		}
	}
	if _, ok := logged(tg, firstPassPrefix); !ok {
		t.Fatal("startup-killed returned before the first housekeeping pass was logged")
	}
	for _, b := range bootLines {
		if v, ok := valueNamed(sc, b.value); !ok || v.NotAvailable != "" {
			t.Fatalf("%q = %+v (all: %+v)", b.value, v, sc.Values)
		}
	}
}

// bootLogTarget is a server whose log holds the lines it is given; only
// WaitLog answers.
type bootLogTarget struct {
	target.Target
	lines []string
}

func (b bootLogTarget) WaitLog(ctx context.Context, prefix string) (string, error) {
	for _, l := range b.lines {
		if strings.HasPrefix(l, prefix) {
			return l, nil
		}
	}
	return "", errors.New("not logged")
}

func TestBootLinesRecordAsSecondsAndAMissingOneIsNotAvailable(t *testing.T) {
	tg := bootLogTarget{lines: []string{
		"boot: database check: 612.4s (31.3 GB, ok)",
		"boot: schema: 1m16.2s (additive 12ms, names 2.1s, fold keys 1m14s, second factors 3ms)",
		"boot: store: 410ms (folds case: false)",
		"boot: share ids: 3.2s (1000000 shares)",
		"boot pass progress: 100000 of 1000000 entries after 9.6s",
		"boot pass: 1m35.2s (1000000 entries, 1000000 share directories, 0 without a row)",
		"boot: volume ready: 812.3s",
	}}
	rec := report.NewRecorder()
	recordBoot(tg, rec)
	sc := rec.Scenario("startup", time.Second)
	for name, want := range map[string]float64{
		"boot database check": 612.4, "boot schema": 76.2, "boot store": 0.41, "boot share ids": 3.2,
		"boot pass": 95.2, "boot volume ready": 812.3,
	} {
		v, ok := valueNamed(sc, name)
		if !ok || v.NotAvailable != "" || math.Abs(v.V-want) > 1e-6 || v.Unit != "s" {
			t.Errorf("%q = %+v, want %v s", name, v, want)
		}
	}
	if v, ok := valueNamed(sc, "boot publishes"); !ok || v.NotAvailable == "" {
		t.Errorf("a line the server did not log = %+v, want not available", v)
	}
}

func TestTheIntegrityScanRecordsAsSecondsOnlyWhenLogged(t *testing.T) {
	rec := report.NewRecorder()
	recordIntegrity(bootLogTarget{lines: []string{
		"housekeeping first pass: 2.1s (expiry 1.5s)",
		"integrity scan: 4m30.25s (5800000 files, 0 missing)",
	}}, rec)
	sc := rec.Scenario("startup", time.Second)
	if v, ok := valueNamed(sc, valIntegrity); !ok || v.NotAvailable != "" || math.Abs(v.V-270.25) > 1e-6 || v.Unit != "s" {
		t.Fatalf("%q = %+v, want 270.25 s", valIntegrity, v)
	}

	rec = report.NewRecorder()
	recordIntegrity(bootLogTarget{lines: []string{"housekeeping first pass: 2.1s (expiry 1.5s)"}}, rec)
	if v, ok := valueNamed(rec.Scenario("startup", time.Second), valIntegrity); ok {
		t.Fatalf("a process that logged no scan records %+v", v)
	}
}

// dyingTarget stops the server it wraps once the rig has asked for its
// address after more than calls requests.
type dyingTarget struct {
	target.Target
	calls atomic.Int64
	after int64
	once  sync.Once
}

func (d *dyingTarget) BaseURL() string {
	if d.calls.Add(1) > d.after {
		d.once.Do(func() { go d.Target.Close() })
	}
	return d.Target.BaseURL()
}

func TestATargetThatDiesMidScenarioFailsAndKeepsItsOps(t *testing.T) {
	tg, e := start(t, "shared")
	settle(t, tg)
	e.Target = &dyingTarget{Target: tg, after: 8}
	sc := run(t, byName(t, "reads"), e)
	if sc.Failed == "" || sc.Skipped != "" {
		t.Fatalf("reads on a dying server: %+v", sc)
	}
	if len(sc.Ops) == 0 {
		t.Fatal("no ops kept")
	}
	if !strings.Contains(sc.Failed, logTailMarker) {
		t.Fatalf("failure carries no log lines: %q", sc.Failed)
	}
}

// loadScale is the scale of the visitors, zips and overload tests.
const loadScale = 0.05

func noWrongOp(t *testing.T, sc report.Scenario, name string) report.Op {
	t.Helper()
	o, ok := opNamed(sc, name)
	if !ok || o.Count == 0 {
		t.Fatalf("op %q missing: %+v", name, sc.Ops)
	}
	if o.Wrong != 0 {
		t.Fatalf("op %q: %d wrong %q, answers %v", name, o.Wrong, o.WrongReasons, o.ByAnswer)
	}
	return o
}

func TestVisitorsOpenPagesViewsAndDownloadsAndAreCounted(t *testing.T) {
	tg, e := start(t, "shared")
	settle(t, tg)
	e.Scale = loadScale
	sc := run(t, byName(t, "visitors"), e)
	completed(t, sc)
	for _, n := range visitorSteps {
		page, view, download := visitorOps(n)
		for _, name := range []string{page, view, download} {
			noWrongOp(t, sc, name)
		}
		if _, ok := valueNamed(sc, refusedName(n)); !ok {
			t.Fatalf("no %q value: %+v", refusedName(n), sc.Values)
		}
	}
	if v, ok := valueNamed(sc, valSampleVisitors); !ok || v.V <= 0 {
		t.Fatalf("%s = %+v", valSampleVisitors, v)
	}
	if v, ok := valueNamed(sc, valPerAddress); !ok || v.V != perAddressRequests {
		t.Fatalf("%s = %+v", valPerAddress, v)
	}
}

func TestZipsReadEveryZipWhole(t *testing.T) {
	tg, e := start(t, "shared")
	settle(t, tg)
	e.Scale = loadScale
	sc := run(t, byName(t, "zips"), e)
	completed(t, sc)
	for _, n := range zipSteps {
		if o := noWrongOp(t, sc, zipOp(n)); o.Count != n {
			t.Fatalf("%s: %d zips", zipOp(n), o.Count)
		}
		for _, name := range []string{zipFirstByte(n), zipRate(n)} {
			if v, ok := valueNamed(sc, name); !ok || v.V <= 0 {
				t.Fatalf("%s = %+v", name, v)
			}
		}
	}
	if v, ok := valueNamed(sc, valZipEntries); !ok || int(v.V) != e.Plan.FileCap {
		t.Fatalf("%s = %+v, want %d", valZipEntries, v, e.Plan.FileCap)
	}
}

func TestOverloadIsRefusedKeepsHealthAndRecovers(t *testing.T) {
	tg, e := start(t, "shared")
	settle(t, tg)
	e.Scale = loadScale
	sc := run(t, byName(t, "overload"), e)
	completed(t, sc)
	noWrongOp(t, sc, opHealthFlood)
	noWrongOp(t, sc, opListBefore)
	if v, ok := valueNamed(sc, valFloodRefusals); !ok || v.V <= 0 {
		t.Fatalf("%s = %+v (all: %+v)", valFloodRefusals, v, sc.Values)
	}
	recovered, _ := valueNamed(sc, valRecovered)
	after, ok := valueNamed(sc, valRecovery)
	switch {
	case !ok:
		t.Fatalf("no %s value", valRecovery)
	case recovered.Text == "yes" && (after.NotAvailable != "" || after.V < 0),
		recovered.Text == "no" && after.NotAvailable == "",
		recovered.Text != "yes" && recovered.Text != "no":
		t.Fatalf("%s = %+v, %s = %+v", valRecovered, recovered, valRecovery, after)
	}
	for _, o := range sc.Ops {
		if o.Wrong != 0 {
			t.Fatalf("op %q: %d wrong %q", o.Name, o.Wrong, o.WrongReasons)
		}
	}
}

func TestOverloadSkipsAServerNamedByURLWithoutARequest(t *testing.T) {
	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Write([]byte(`{"status":"ok","version":"9.9.9"}`))
	}))
	defer srv.Close()
	man := volume.Manifest{Plan: volume.NewPlan(testShares, 1), Accounts: []volume.Account{{Name: "u000000", Token: "t", Shares: 1}}}
	e := Env{Target: target.Remote(srv.URL), Volume: man, Plan: man.Plan, Scale: testScale}
	sc := RunOne(context.Background(), byName(t, "overload"), e)
	if sc.Skipped == "" || sc.Failed != "" || len(sc.Ops) != 0 {
		t.Fatalf("overload against a server named by URL: %+v", sc)
	}
	if n := requests.Load(); n != 0 {
		t.Fatalf("overload sent %d requests to a server named by URL", n)
	}
}

func TestEveryVisitorMovesAcrossShares(t *testing.T) {
	const shares = 8
	for _, workers := range []int{1, shares, 2 * shares, 3} {
		seen := map[int]bool{}
		for k := range shares {
			seen[visitorShare(0, k, shares)] = true
		}
		if len(seen) != shares {
			t.Fatalf("with %d workers, a worker visits %d of %d shares", workers, len(seen), shares)
		}
		at := map[int]bool{}
		for w := range min(workers, shares) {
			at[visitorShare(w, 0, shares)] = true
		}
		if len(at) != min(workers, shares) {
			t.Fatalf("with %d workers, the first round opens %d shares", workers, len(at))
		}
	}
}

func TestFloodCountsOnlyTheGuardsClosesAsAnswers(t *testing.T) {
	flood := report.NewRecorder()
	tally := &floodTally{}
	for _, err := range []error{
		&url.Error{Op: "Get", URL: "http://x/", Err: io.EOF},
		&url.Error{Op: "Get", URL: "http://x/", Err: syscall.ECONNRESET},
		&url.Error{Op: "Get", URL: "http://x/", Err: syscall.ECONNREFUSED},
		context.DeadlineExceeded,
	} {
		flood.Fail(floodListOp, err)
		tally.failed(err)
	}
	flood.Observe(floodListOp, time.Millisecond, http.StatusServiceUnavailable, "busy")
	rec := report.NewRecorder()
	floodAnswers(rec, flood.Scenario("flood", time.Second), map[string]*floodTally{floodListOp: tally})
	sc := rec.Scenario("overload", time.Second)
	o, ok := opNamed(sc, floodListOp)
	if !ok || o.Wrong != 1 {
		t.Fatalf("a refused connection and a timeout are wrong, the guard's closes are not: %+v", o)
	}
	if why := o.WrongReasons[0]; !strings.Contains(why, "connection refused") || !strings.Contains(why, "deadline exceeded") {
		t.Fatalf("the reason does not name the answers: %q", why)
	}
	if v, ok := valueNamed(sc, valFloodClosed); !ok || v.V != 2 {
		t.Fatalf("%s = %+v", valFloodClosed, v)
	}
	if v, ok := valueNamed(sc, valFloodRefusals); !ok || v.V != 1 {
		t.Fatalf("%s = %+v", valFloodRefusals, v)
	}
}

func noWrongAnywhere(t *testing.T, sc report.Scenario) {
	t.Helper()
	for _, o := range sc.Ops {
		if o.Wrong != 0 {
			t.Fatalf("op %q: %d wrong %q, answers %v", o.Name, o.Wrong, o.WrongReasons, o.ByAnswer)
		}
	}
}

func TestAccountsSignInTheSampleAndListEveryAccount(t *testing.T) {
	tg, e := start(t, "shared")
	settle(t, tg)
	sc := run(t, byName(t, "accounts"), e)
	completed(t, sc)
	noWrongAnywhere(t, sc)
	sample := e.times(signInSample)
	if sample != 20 {
		t.Fatalf("the test scale samples %d accounts, want the 20 created through the server", sample)
	}
	if o := noWrongOp(t, sc, opSignIn); o.Count != sample || o.ByAnswer["200"] != sample {
		t.Fatalf("%s = %+v", opSignIn, o)
	}
	if o := noWrongOp(t, sc, opSignOut); o.ByAnswer["204"] != sample {
		t.Fatalf("%s = %+v", opSignOut, o)
	}
	for _, name := range []string{opAccountList, opAccountUsage} {
		if o := noWrongOp(t, sc, name); o.Count != len(e.Volume.Accounts) || o.ByAnswer["200"] != o.Count {
			t.Fatalf("%s = %+v, want one answer for each of %d accounts", name, o, len(e.Volume.Accounts))
		}
	}
	if v, ok := valueNamed(sc, valSignInRefused); !ok || v.V != 0 {
		t.Fatalf("%s = %+v", valSignInRefused, v)
	}
}

func TestCatchupWalksEveryShareAndCapsTheWatchers(t *testing.T) {
	tg, e := start(t, "shared")
	settle(t, tg)
	sc := run(t, byName(t, "catchup"), e)
	completed(t, sc)
	noWrongAnywhere(t, sc)
	if o := noWrongOp(t, sc, opFeedZero); o.ByAnswer["200"] != 1 {
		t.Fatalf("%s = %+v", opFeedZero, o)
	}
	if v, ok := valueNamed(sc, valFeedReset); !ok || v.Text != "yes" {
		t.Fatalf("%s = %+v: the volume's journal is pruned, so the feed from zero resets", valFeedReset, v)
	}
	total, ok := valueNamed(sc, valCatchupTotal)
	walked, ok2 := valueNamed(sc, valCatchupShares)
	if !ok || !ok2 || total.V <= 0 || walked.V != total.V {
		t.Fatalf("the walk found %+v distinct shares of a listing of %+v", walked, total)
	}
	for _, name := range []string{opCatchupWalk, opCatchupWatch, opWatchWrite} {
		noWrongOp(t, sc, name)
	}
	// noWrongOp holds each step to the caps: Wrong counts a step whose
	// too-many-watchers refusals pass the excess over the cap, or fall short of
	// it by more than the watchers that took no slot or came late.
	for _, n := range []int{watchMaxPerOwner, watchMaxPerOwner + watchOver} {
		noWrongOp(t, sc, watchStepOp(n))
		refused, ok := valueNamed(sc, watchRefusedName(watchStepOp(n)))
		short, ok2 := valueNamed(sc, watchNoSlotName(watchStepOp(n)))
		want := float64(n - watchMaxPerOwner)
		if !ok || !ok2 || refused.V > want || refused.V+short.V < want {
			t.Fatalf("%d watchers of one account: %+v refused, %+v took no slot, want %v refused", n, refused, short, want)
		}
	}
	if _, ok := opNamed(sc, watchAnsweredOp(watchMaxPerOwner)); !ok {
		t.Fatalf("no %q op: %+v", watchAnsweredOp(watchMaxPerOwner), sc.Ops)
	}
	if v, ok := valueNamed(sc, valAcrossWatchers); !ok || v.V <= float64(watchMaxPerOwner) {
		t.Fatalf("%s = %+v", valAcrossWatchers, v)
	}
}

// TestUploadFillsSharesAndCreatesAcrossAccounts runs on a volume of its own:
// it leaves the shares it creates in the volume.
func TestUploadFillsSharesAndCreatesAcrossAccounts(t *testing.T) {
	tg, e := start(t, "upload")
	settle(t, tg)
	e.Scale = 0.01
	sc := run(t, byName(t, "upload"), e)
	completed(t, sc)
	noWrongAnywhere(t, sc)
	for _, op := range []string{uploadWindowOp(1), pendingWindowOp(1)} {
		if o := noWrongOp(t, sc, op); o.Count != uploadLeast || o.ByAnswer["201"] != uploadLeast {
			t.Fatalf("%s = %+v, want %d files", op, o, uploadLeast)
		}
	}
	if o := noWrongOp(t, sc, batchWindowOp(1)); o.Count != 1 || o.ByAnswer["200"] != 1 {
		t.Fatalf("%s = %+v, want one batch", batchWindowOp(1), o)
	}
	for _, name := range []string{valFilesUploaded, valShareFiles, valBatchFilesUploaded, valBatchShareFiles,
		valManifestFiles, valPendingUploaded, valManifestShareFiles} {
		if v, ok := valueNamed(sc, name); !ok || int(v.V) != uploadLeast {
			t.Fatalf("%s = %+v, want %d", name, v, uploadLeast)
		}
	}
	if v, ok := valueNamed(sc, valPastCap); !ok || v.NotAvailable == "" {
		t.Fatalf("%s = %+v: a fill short of the cap sends nothing past it", valPastCap, v)
	}
	for _, op := range []string{opCreateShare, opCreateBatchShare, opCreateWithManifest, opCreateOne} {
		noWrongOp(t, sc, op)
	}
	if v, ok := valueNamed(sc, valSharesCreated); !ok || v.V < 4 {
		t.Fatalf("%s = %+v", valSharesCreated, v)
	}
	if _, ok := valueNamed(sc, valCreateRate); !ok {
		t.Fatalf("no %q value: %+v", valCreateRate, sc.Values)
	}
}

// TestClosedByGuardKnowsEachWayACloseAtAcceptReads holds closedByGuard to
// each error net/http's transport reports for a connection the server closed
// as it was accepted, and to nothing else.
func TestClosedByGuardKnowsEachWayACloseAtAcceptReads(t *testing.T) {
	get := func(err error) error { return &url.Error{Op: "Get", URL: "http://127.0.0.1:1/api/shares", Err: err} }
	for _, c := range []struct {
		name string
		err  error
		want bool
	}{
		{"the end of the stream", get(io.EOF), true},
		{"a reset", get(&net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", syscall.ECONNRESET)}), true},
		{"a reset found peeking", get(fmt.Errorf("readLoopPeekFailLocked: %w", syscall.ECONNRESET)), true},
		{"a write to a closed peer", get(&net.OpError{Op: "write", Net: "tcp", Err: os.NewSyscallError("write", syscall.EPIPE)}), true},
		{"the transport's close under the write", get(&net.OpError{Op: "write", Net: "tcp", Err: net.ErrClosed}), true},
		{"the close before the request was read", get(errors.New("http: server closed idle connection")), true},
		{"a refused connection", get(&net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}), false},
		{"a timeout", get(context.DeadlineExceeded), false},
		{"anything else", get(errors.New("malformed HTTP response")), false},
	} {
		if got := closedByGuard(c.err); got != c.want {
			t.Errorf("%s (%v): closedByGuard = %v, want %v", c.name, c.err, got, c.want)
		}
	}
}

// TestEveryFailureOfACloseAtAcceptIsClosedByGuard closes every connection as
// it is accepted, as the load guard does past an address's limit, and sends
// requests at it from many fresh connections at once: whatever the transport
// reports for each must read as the guard's close.
func TestEveryFailureOfACloseAtAcceptIsClosedByGuard(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	var mu sync.Mutex
	kinds := map[string]int{}
	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tr := &http.Transport{}
			defer tr.CloseIdleConnections()
			c := &http.Client{Transport: tr, Timeout: 10 * time.Second}
			for range 20 {
				resp, err := c.Get("http://" + l.Addr().String() + "/api/shares")
				if err == nil {
					resp.Body.Close()
					t.Error("a connection closed at accept answered")
					return
				}
				if !closedByGuard(err) {
					mu.Lock()
					kinds[err.Error()]++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	if len(kinds) > 0 {
		t.Fatalf("failures of a close at accept closedByGuard does not know: %v", kinds)
	}
}

// TestRecoveryThatNeverComesIsAValueNotWrong holds a server that never
// answers the listing within the wait to "recovered: no", with the time not
// available, and nothing counted wrong; and one that answers to "yes".
func TestRecoveryThatNeverComesIsAValueNotWrong(t *testing.T) {
	for _, ok := range []bool{false, true} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !ok {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.Write([]byte(`{"shares":[]}`))
		}))
		rec := report.NewRecorder()
		c := target.NewClient(target.Remote(srv.URL), report.NewRecorder(), nil)
		err := recovery(context.Background(), rec, c, "t", time.Minute, time.Now(), 50*time.Millisecond)
		c.Close()
		srv.Close()
		if err != nil {
			t.Fatal(err)
		}
		sc := rec.Scenario("overload", time.Second)
		recovered, _ := valueNamed(sc, valRecovered)
		after, _ := valueNamed(sc, valRecovery)
		want := map[bool]string{false: "no", true: "yes"}[ok]
		if recovered.Text != want || (after.NotAvailable == "") == !ok {
			t.Fatalf("answering %v: %s = %+v, %s = %+v", ok, valRecovered, recovered, valRecovery, after)
		}
		if len(sc.Ops) != 0 {
			t.Fatalf("answering %v: recovery recorded ops %+v", ok, sc.Ops)
		}
	}
}

func TestTheVolumeSizesAreTheDatabaseItsLogAndTheManifest(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, metadb.FileName), make([]byte, 3<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := report.NewRecorder()
	RecordVolumeSizes(rec, dir, volume.Manifest{DiskBytes: 5 << 20, Inodes: 42}, "at start", true)
	if err := os.WriteFile(filepath.Join(dir, metadb.FileName+"-wal"), make([]byte, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	RecordVolumeSizes(rec, dir, volume.Manifest{}, "at end", false)
	sc := rec.Scenario(VolumeName, time.Second)
	for name, want := range map[string]float64{
		valDatabase + " at start": 3, valDatabaseLog + " at start": 0, valGeneratedDisk: 5, valGeneratedNode: 42,
		valDatabase + " at end": 3, valDatabaseLog + " at end": 1,
	} {
		if v, ok := valueNamed(sc, name); !ok || v.NotAvailable != "" || v.V != want {
			t.Errorf("%s = %+v, want %v", name, v, want)
		}
	}
	if len(sc.Values) != 6 {
		t.Errorf("values %+v, want the six", sc.Values)
	}

	missing := report.NewRecorder()
	RecordVolumeSizes(missing, t.TempDir(), volume.Manifest{}, "at start", true)
	for _, v := range missing.Scenario(VolumeName, time.Second).Values {
		if v.NotAvailable == "" {
			t.Errorf("%s = %+v, want not available with a reason", v.Name, v)
		}
	}
}

// scanLogTarget logs the lines of its map, each from the time it is mapped
// to; a prefix with no line is never logged, and the wait for it answers an
// error once exit is closed.
type scanLogTarget struct {
	target.Target
	lines map[string]scanLine
	exit  chan struct{}
}

type scanLine struct {
	line  string
	until time.Time
}

func (s scanLogTarget) WaitLog(ctx context.Context, prefix string) (string, error) {
	l, ok := s.lines[prefix]
	if ok && !time.Now().Before(l.until) {
		return l.line, nil
	}
	var late <-chan time.Time
	if ok {
		late = time.After(time.Until(l.until))
	}
	select {
	case <-late:
		return l.line, nil
	case <-s.exit:
		return "", errors.New("the server exited")
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func TestWaitIntegrityReturnsOnlyAfterTheScanLine(t *testing.T) {
	const line = "integrity scan: 4m30s (5800000 files, 0 missing)"
	rec := report.NewRecorder()
	begin := time.Now()
	tg := scanLogTarget{lines: map[string]scanLine{integrityPrefix: {line, begin.Add(150 * time.Millisecond)}}}
	if err := waitIntegrity(context.Background(), tg, rec, passTiming{steps: []passStep{{"expiry", time.Second}}}); err != nil {
		t.Fatal(err)
	}
	if time.Since(begin) < 150*time.Millisecond {
		t.Fatal("returned before the scan line")
	}
	if v, ok := valueNamed(rec.Scenario("housekeeping", time.Second), valIntegrity); !ok || v.NotAvailable != "" || v.V != 270 {
		t.Fatalf("%q = %+v, want 270 s", valIntegrity, v)
	}
}

func TestWaitIntegrityDoesNotWaitWhenThePassRanTheScan(t *testing.T) {
	rec := report.NewRecorder()
	begin := time.Now()
	tg := scanLogTarget{}
	pass := passTiming{steps: []passStep{{"expiry", time.Second}, {"integrity", 3 * time.Second}}}
	if err := waitIntegrity(context.Background(), tg, rec, pass); err != nil {
		t.Fatal(err)
	}
	if time.Since(begin) > time.Second {
		t.Fatal("waited for a scan line the pass already covers")
	}
	if v, ok := valueNamed(rec.Scenario("housekeeping", time.Second), valIntegrity); ok {
		t.Fatalf("recorded %+v with no scan line", v)
	}
}

func TestWaitIntegrityReturnsAtOnceOnTheNotDueLine(t *testing.T) {
	rec := report.NewRecorder()
	const line = "integrity scan not due: last finished 2026-11-14T01:02:03Z (5800000 files, 0 missing)"
	tg := scanLogTarget{lines: map[string]scanLine{integrityNotDuePrefix: {line, time.Time{}}}}
	begin := time.Now()
	if err := waitIntegrity(context.Background(), tg, rec, passTiming{}); err != nil {
		t.Fatal(err)
	}
	if time.Since(begin) > time.Second {
		t.Fatal("waited past the not-due line")
	}
	v, ok := valueNamed(rec.Scenario("housekeeping", time.Second), valIntegrity)
	if !ok || !strings.HasPrefix(v.NotAvailable, "no scan due (last finished 2026-11-14T01:02:03Z") {
		t.Fatalf("%q = %+v", valIntegrity, v)
	}
}

func TestWaitIntegrityRecordsNotAvailableWithTheErrorWhenTheServerExits(t *testing.T) {
	rec := report.NewRecorder()
	exit := make(chan struct{})
	close(exit)
	if err := waitIntegrity(context.Background(), scanLogTarget{exit: exit}, rec, passTiming{}); err != nil {
		t.Fatal(err)
	}
	v, ok := valueNamed(rec.Scenario("housekeeping", time.Second), valIntegrity)
	if !ok || !strings.Contains(v.NotAvailable, "the server exited") {
		t.Fatalf("%q = %+v, want not available naming the error", valIntegrity, v)
	}
}

func TestWaitIntegrityReturnsTheErrorOfAStoppedContext(t *testing.T) {
	rec := report.NewRecorder()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := waitIntegrity(ctx, scanLogTarget{}, rec, passTiming{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if v, ok := valueNamed(rec.Scenario("housekeeping", time.Second), valIntegrity); ok {
		t.Fatalf("recorded %+v", v)
	}
}
