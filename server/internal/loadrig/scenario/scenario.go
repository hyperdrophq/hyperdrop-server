// Package scenario is what the load rig does to a server: named scenarios
// that drive a target on a generated volume and record what it answered.
// A scenario fails only when it could not run or the server answered
// wrongly; how fast the server answered is printed, never judged.
package scenario

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"hyperdrop/server/internal/loadrig/report"
	"hyperdrop/server/internal/loadrig/target"
	"hyperdrop/server/internal/loadrig/volume"
)

// Env is what a scenario runs against. Volume is the generated volume's
// manifest, whose accounts carry the tokens the load signs in with; it is
// empty for a server named by URL without one. Sources are the local
// addresses connections leave from (the default address when empty).
// Scale shrinks repetition counts and hold times for a quick run, never the
// volume; zero means 1.
type Env struct {
	Target  target.Target
	Volume  volume.Manifest
	Plan    volume.Plan
	Sources []net.IP
	Scale   float64
}

// Scenario is one named measurement. NeedsLocal marks a scenario that
// restarts the server, reads its log or memory, or floods it, so it runs
// only on a server the rig started. Run returns an error when the scenario could not
// run; Skip makes that error a skip with its reason.
type Scenario struct {
	Name, About string
	NeedsLocal  bool
	Run         func(ctx context.Context, e Env, rec *report.Recorder) error
}

// All is every scenario in the order a full run takes them: housekeeping
// first, because it consumes the volume's expired shares; startup next,
// booting the swept volume, and startup-killed after it; then the reads on a settled server, the
// visitors and the zips, which read the volume as generated. Upload, catchup
// and accounts follow them, since upload leaves the shares it creates in the
// volume. Overload is last, because it leaves the server's guards and
// limiters hot for whatever runs after it.
func All() []Scenario {
	return []Scenario{
		housekeepingScenario, startupScenario, startupKilledScenario, readsScenario,
		visitorsScenario, zipsScenario,
		uploadScenario, catchupScenario, accountsScenario,
		overloadScenario,
	}
}

// The server's limits the scenarios run up to. Package api does not export
// them; TestTheLimitsCopiedMatchTheServer holds each copy to the server's
// source.
const (
	// perAddressRequests is the load guard's guardPerAddress: how many
	// requests one address may have running at once.
	perAddressRequests = 128
	// perAddressConns is the load guard's guardConnsPerAddress: how many
	// connections one address may hold, past which a new one is closed as
	// it is accepted.
	perAddressConns = 256
	// zipsPerAddress is api's zipsPerAddress: how many zips run from one
	// address at once, the rest waiting behind them.
	zipsPerAddress = 3
	// visitFlushInterval is api's visitFlushInterval: how often the server
	// writes the visits it has counted.
	visitFlushInterval = 15 * time.Second
	// watchMaxPerOwner is api's watchMaxPerOwner: how many watches one
	// account may hold at once, past which one is refused too-many-watchers.
	watchMaxPerOwner = 16
	// watchMaxTotal is api's watchMaxTotal: how many watches the server holds
	// at once over every account, refused the same way past it.
	watchMaxTotal = 256
	// createBurst and createPerHour are api's create limit: the shares one
	// account may create at once, and how many more an hour refills.
	createBurst   = 100
	createPerHour = 600
)

// Values more than one scenario reports.
const (
	valSources    = "source addresses"
	valPerAddress = "load guard requests per address"
)

// logTail is how many of the server's last log lines a failure carries,
// after logTailMarker.
const (
	logTail       = 20
	logTailMarker = "last log lines:"
)

type skipped struct{ reason string }

func (s skipped) Error() string { return "skipped: " + s.reason }

// Skip is the error a scenario's Run returns when it does not apply to this
// server or volume; RunOne reports it as skipped with reason.
func Skip(reason string) error { return skipped{reason} }

// errStopped is what a scenario returns when the server stopped answering.
var errStopped = errors.New("the server stopped answering")

// RunOne runs s against e and returns what it recorded in every case:
// skipped with the reason, failed with the error and the server's last log
// lines, or completed. A server that no longer answers when the scenario
// ends is a failure, whatever Run returned.
func RunOne(ctx context.Context, s Scenario, e Env) (out report.Scenario) {
	// Log answers whether the rig started the server without sending it a
	// request.
	if _, local := e.Target.Log(); s.NeedsLocal && !local {
		return report.Scenario{Name: s.Name, Skipped: "needs a server the rig started: it restarts the server, reads its log or memory, or floods it"}
	}
	rec := report.NewRecorder()
	began := time.Now()
	err := runGuarded(ctx, s, e, rec)
	out = rec.Scenario(s.Name, time.Since(began))
	var skip skipped
	switch {
	case errors.As(err, &skip):
		out.Skipped = skip.reason
	case err != nil:
		out.Failed = failure(err, e.Target)
	case !answering(e.Target):
		out.Failed = failure(errStopped, e.Target)
	}
	return out
}

func runGuarded(ctx context.Context, s Scenario, e Env, rec *report.Recorder) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic: %v\n%s", p, debug.Stack())
		}
	}()
	return s.Run(ctx, e, rec)
}

// healthTimeout bounds the health request answering sends.
const healthTimeout = 10 * time.Second

var healthClient = &http.Client{Transport: &http.Transport{}, Timeout: healthTimeout}

// answering reports whether the server's process is alive and answers
// /api/health with 200. A stopping server's process outlives its listener,
// so a live process alone does not say it still answers.
func answering(t target.Target) bool {
	if !t.Alive() {
		return false
	}
	resp, err := healthClient.Get(t.BaseURL() + "/api/health")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func failure(err error, t target.Target) string {
	msg := err.Error()
	if !answering(t) && !errors.Is(err, errStopped) {
		msg += "; " + errStopped.Error()
	}
	if lines, ok := t.Log(); ok && len(lines) > 0 {
		msg += "\n" + logTailMarker + "\n" + strings.Join(lines[max(0, len(lines)-logTail):], "\n")
	}
	return msg
}

// times is n scaled, at least 1.
func (e Env) times(n int) int {
	s := e.Scale
	if s <= 0 {
		s = 1
	}
	return max(1, int(math.Round(float64(n)*s)))
}

// hold is d scaled.
func (e Env) hold(d time.Duration) time.Duration {
	s := e.Scale
	if s <= 0 {
		s = 1
	}
	return time.Duration(float64(d) * s).Round(time.Millisecond)
}

// client is a recording client whose connections leave from the k-th source
// address, round robin.
func (e Env) client(rec *report.Recorder, k int) *target.Client {
	var src net.IP
	if len(e.Sources) > 0 {
		src = e.Sources[k%len(e.Sources)]
	}
	return target.NewClient(e.Target, rec, src)
}

// probe is a client whose requests are the scenario's own bookkeeping
// (finding a slug, checking a precondition) and stay out of the report.
func (e Env) probe() *target.Client { return e.client(report.NewRecorder(), 0) }

// token is the bearer token of account name from the volume's manifest.
func (e Env) token(name string) (string, error) {
	for _, a := range e.Volume.Accounts {
		if a.Name == name && a.Token != "" {
			return a.Token, nil
		}
	}
	return "", Skip("the volume's manifest has no token for " + name)
}

// largest is the account of the manifest owning the most shares.
func (e Env) largest() (volume.Account, error) {
	var best volume.Account
	for _, a := range e.Volume.Accounts {
		if a.Token != "" && a.Shares > best.Shares {
			best = a
		}
	}
	if best.Name == "" {
		return best, Skip("the volume's manifest carries no account tokens")
	}
	return best, nil
}

// find is the first share of the plan that ok accepts.
func (e Env) find(ok func(volume.ShareSpec) bool) (volume.ShareSpec, bool) {
	for i := 0; i < e.Plan.Shares; i++ {
		if s := e.Plan.Share(i); ok(s) {
			return s, true
		}
	}
	return volume.ShareSpec{}, false
}

// rounds says whether a loop runs its i-th round, counting from 0.
type rounds func(i int) bool

// count is n rounds.
func count(n int) rounds { return func(i int) bool { return i < n } }

// until is as many rounds as begin before t; a round that has begun runs to
// its end.
func until(t time.Time) rounds { return func(int) bool { return time.Now().Before(t) } }

// repeat calls fn for as many rounds as r gives, one after another. It stops
// at the context's end, and when a request fails on a server that no longer
// answers.
func repeat(ctx context.Context, e Env, r rounds, fn func() error) error {
	for i := 0; r(i); i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := fn(); err != nil && !answering(e.Target) {
			return errStopped
		}
	}
	return nil
}

// parallel runs workers goroutines, each with its own client leaving from
// the w-th source address round robin, each calling fn with its index for as
// many rounds as r gives, and waits for all of them.
func parallel(ctx context.Context, e Env, rec *report.Recorder, workers int, r rounds, fn func(w int, c *target.Client) error) error {
	var wg sync.WaitGroup
	errs := make([]error, workers)
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := e.client(rec, w)
			defer c.Close()
			errs[w] = repeat(ctx, e, r, func() error { return fn(w, c) })
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}

// addresses is how many source addresses the scenario's connections leave
// from: the default one when none is named.
func (e Env) addresses() int { return max(1, len(e.Sources)) }

// refusals is how many of an op's answers were refusals by the server's
// limits: a 429 with any code, or a 503 busy.
func refusals(o report.Op) int {
	n := 0
	for k, v := range o.ByAnswer {
		if k == "429" || strings.HasPrefix(k, "429 ") || k == "503 busy" {
			n += v
		}
	}
	return n
}

// refusedByLimit reports an answer the server's limits gave instead of
// serving the request: a 429 with any code, or a 503 (the load guard's busy
// answer, which the recorder holds to its code).
func refusedByLimit(r *http.Response) bool {
	return r.StatusCode == http.StatusTooManyRequests || r.StatusCode == http.StatusServiceUnavailable
}

// wantStatus is a check that the answer had status code.
func wantStatus(code int) func(*http.Response) error {
	return func(r *http.Response) error {
		if r.StatusCode != code {
			return fmt.Errorf("answered %d, want %d", r.StatusCode, code)
		}
		return nil
	}
}

// decodeOK is a check that the answer is 200 with a JSON body decoding into v.
func decodeOK(r *http.Response, v any) error {
	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("answered %d", r.StatusCode)
	}
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return fmt.Errorf("body: %w", err)
	}
	return nil
}

// shareRead is the part of GET /api/shares/{id} the scenarios read.
type shareRead struct {
	ID        string `json:"id"`
	FileCount int    `json:"fileCount"`
	Visitors  int    `json:"visitors"`
	PinnedAt  string `json:"pinnedAt"`
	Files     []struct {
		Path string `json:"path"`
		Size int64  `json:"size"`
		Slug string `json:"slug"`
	} `json:"files"`
}

// readShare is the owner's read of one share through c.
func readShare(ctx context.Context, c *target.Client, op, id, token string) (shareRead, error) {
	var s shareRead
	err := c.Do(ctx, op, http.MethodGet, "/api/shares/"+id, token, nil, func(r *http.Response) error {
		if err := decodeOK(r, &s); err != nil {
			return err
		}
		if s.ID != id {
			return fmt.Errorf("asked for %s, answered %s", id, s.ID)
		}
		return nil
	})
	return s, err
}

// Log lines the scenarios read, as the server's housekeeping writes them
// (housekeep.Result.Timing and Result.Lines).
const (
	firstPassPrefix = "housekeeping first pass: "
	removedPrefix   = "expiry sweep: "
	removedVerb     = "removed expired shares: "
	// integrityPrefix starts the line a finished integrity scan logs
	// (housekeep.IntegrityResult.Line): "<prefix><took> (<files> files,
	// <missing> missing)". No other line the server logs starts with it.
	integrityPrefix = "integrity scan: "
	// integrityNotDuePrefix starts the line a process logs at its first
	// check when no scan is owed (housekeep.Pass.NotDueLine).
	integrityNotDuePrefix = "integrity scan not due: "

	valIntegrity = "integrity scan"
)

// recordIntegrity records how long the current server process's integrity
// scan took, in seconds, when it has logged one by now; a process that has
// not (no scan was due, or it is still under way) records nothing.
func recordIntegrity(t target.Target, rec *report.Recorder) {
	line, ok := logged(t, integrityPrefix)
	if !ok {
		return
	}
	took, _, _ := strings.Cut(strings.TrimPrefix(line, integrityPrefix), " ")
	d, err := time.ParseDuration(took)
	if err != nil {
		rec.NotAvailable(valIntegrity, fmt.Sprintf("the server logged %q", line))
		return
	}
	rec.Value(valIntegrity, d.Seconds(), "s")
}

type passStep struct {
	name string
	took time.Duration
}

type passTiming struct {
	total time.Duration
	steps []passStep
}

// parsePass reads a pass's timing line: "<prefix><total> (<step> <took>, …)",
// the parenthesis absent when no step took 10 ms.
func parsePass(line string) (passTiming, error) {
	var p passTiming
	_, rest, ok := strings.Cut(line, "pass: ")
	if !ok {
		return p, fmt.Errorf("not a pass timing line: %q", line)
	}
	total, steps, _ := strings.Cut(rest, " (")
	var err error
	if p.total, err = time.ParseDuration(total); err != nil {
		return p, fmt.Errorf("pass total in %q: %w", line, err)
	}
	steps = strings.TrimSuffix(steps, ")")
	if steps == "" {
		return p, nil
	}
	for _, s := range strings.Split(steps, ", ") {
		name, took, ok := strings.Cut(s, " ")
		d, err := time.ParseDuration(took)
		if !ok || err != nil {
			return p, fmt.Errorf("step %q in %q", s, line)
		}
		p.steps = append(p.steps, passStep{name, d})
	}
	return p, nil
}

// record writes a pass's total and each step it names as values under
// label.
func (p passTiming) record(rec *report.Recorder, label string) {
	rec.Value(label, p.total.Seconds(), "s")
	for _, s := range p.steps {
		rec.Value(label+" "+s.name, s.took.Seconds(), "s")
	}
}

// parseRemoved reads the expiry sweep's line: how many shares it removed,
// ok false for a line that is not the expiry sweep's, and an error for the
// sweep's own failure.
func parseRemoved(line string) (n int, ok bool, err error) {
	rest, isSweep := strings.CutPrefix(line, removedPrefix)
	if !isSweep {
		return 0, false, nil
	}
	count, isCount := strings.CutPrefix(rest, removedVerb)
	if !isCount {
		return 0, true, fmt.Errorf("the expiry sweep logged %q", line)
	}
	n, err = strconv.Atoi(count)
	if err != nil {
		return 0, true, fmt.Errorf("the expiry sweep logged %q", line)
	}
	return n, true, nil
}

// logged is the first line of the current server process starting with
// prefix, without waiting for one.
func logged(t target.Target, prefix string) (string, bool) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	line, err := t.WaitLog(ctx, prefix)
	return line, err == nil
}

// mib is a byte count in MiB.
func mib(b int64) float64 { return float64(b) / (1 << 20) }
