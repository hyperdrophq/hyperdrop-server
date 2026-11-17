// Command hyperdrop-loadrig generates a large volume of shares, runs load
// scenarios against a server on it and prints the numbers. It never judges
// them.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"hyperdrop/server/internal/loadrig/report"
	"hyperdrop/server/internal/loadrig/scenario"
	"hyperdrop/server/internal/loadrig/target"
	"hyperdrop/server/internal/loadrig/volume"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

const usage = `usage:
  hyperdrop-loadrig generate --dir <dir> --shares <n> [--seed 1] [--workers N]
  hyperdrop-loadrig project  --small <dir> --large <dir> --shares <n>
  hyperdrop-loadrig run      --dir <volume> [--server <binary>] [--url <base>] [--only a,b] [--scale 1] [--out <dir>]
  hyperdrop-loadrig compare  <before.json> <after.json>
  hyperdrop-loadrig sources  [--add 8]
`

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "generate":
		err = generate(args[1:], stdout, stderr)
	case "project":
		err = project(args[1:], stdout, stderr)
	case "run":
		err = runScenarios(args[1:], stdout, stderr)
	case "compare":
		err = compare(args[1:], stdout, stderr)
	case "sources":
		err = sources(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n%s", args[0], usage)
		return 2
	}
	switch {
	case err == nil:
		return 0
	case errors.Is(err, flag.ErrHelp):
		return 0
	case errors.Is(err, errUsage):
		return 2
	}
	fmt.Fprintln(stderr, "hyperdrop-loadrig:", err)
	return 1
}

// errUsage marks an error whose message the flag set has already printed.
var errUsage = errors.New("usage")

func newFlags(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return errUsage
	}
	return nil
}

func generate(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("generate", stderr)
	dir := fs.String("dir", "", "directory to generate the volume into")
	shares := fs.Int("shares", 0, "number of shares (10000, 100000 or 1000000)")
	seed := fs.Int64("seed", 1, "seed of the plan")
	workers := fs.Int("workers", runtime.NumCPU(), "goroutines laying files on disk")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *dir == "" || *shares <= 0 {
		return errors.New("generate needs --dir and --shares")
	}
	plan := volume.NewPlan(*shares, *seed)
	files, byKind := plan.Totals()
	estimate := volume.EstimateDisk(plan)
	fmt.Fprintf(stdout, "Plan: %d shares, %d files, %d accounts\n", plan.Shares, files, plan.Accounts)
	fmt.Fprintf(stdout, "By kind: %s\n", kindList(byKind))
	fmt.Fprintf(stdout, "Estimated disk use: %s\n", gib(estimate))
	if free, ok := volume.FreeBytes(*dir); ok {
		fmt.Fprintf(stdout, "Free space: %s\n", gib(free))
		if free < 2*estimate {
			return fmt.Errorf("free space %s on the file system of %s is under twice the estimated %s", gib(free), *dir, gib(estimate))
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	prog := newProgress(stdout)
	man, err := volume.Generate(ctx, volume.Options{Dir: *dir, Plan: plan, Workers: *workers, Progress: prog.report})
	prog.finish()
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Generated %d shares, %d files in %s\n", man.Shares, man.Files, man.Took.Round(time.Second))
	fmt.Fprintf(stdout, "Disk used: %s, %d inodes\n", gib(man.DiskBytes), man.Inodes)
	return nil
}

func kindList(byKind map[volume.Kind]int) string {
	var parts []string
	for k := volume.Plain; k <= volume.Inbox; k++ {
		if n, ok := byKind[k]; ok {
			parts = append(parts, fmt.Sprintf("%s %d", k, n))
		}
	}
	return strings.Join(parts, ", ")
}

func gib(n int64) string { return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30)) }

// progress prints how far a generation has come: one updating line on a
// terminal, at most once a second, and an occasional line otherwise.
type progress struct {
	w        io.Writer
	terminal bool
	every    time.Duration
	last     time.Time
	wrote    bool
}

func newProgress(w io.Writer) *progress {
	p := &progress{w: w, every: 10 * time.Second}
	if f, ok := w.(*os.File); ok {
		if st, err := f.Stat(); err == nil && st.Mode()&os.ModeCharDevice != 0 {
			p.terminal, p.every = true, time.Second
		}
	}
	return p
}

func (p *progress) report(done, total int) {
	if done != total && time.Since(p.last) < p.every {
		return
	}
	p.last = time.Now()
	p.wrote = true
	if p.terminal {
		fmt.Fprintf(p.w, "\r%d of %d shares", done, total)
		return
	}
	fmt.Fprintf(p.w, "%d of %d shares\n", done, total)
}

func (p *progress) finish() {
	if p.terminal && p.wrote {
		fmt.Fprintln(p.w)
	}
}

func project(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("project", stderr)
	small := fs.String("small", "", "a generated volume")
	large := fs.String("large", "", "a larger generated volume of the same seed")
	shares := fs.Int("shares", 0, "size of the volume to project")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *small == "" || *large == "" || *shares <= 0 {
		return errors.New("project needs --small, --large and --shares")
	}
	a, err := volume.ReadManifest(*small)
	if err != nil {
		return fmt.Errorf("%s: %w", *small, err)
	}
	b, err := volume.ReadManifest(*large)
	if err != nil {
		return fmt.Errorf("%s: %w", *large, err)
	}
	p := volume.Project(a, b, *shares)
	fmt.Fprintf(stdout, "Projected for %d shares: %d files, %s disk, %d inodes, %s to generate\n",
		p.Shares, p.Files, gib(p.DiskBytes), p.Inodes, p.Took.Round(time.Second))
	return nil
}

func compare(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("compare", stderr)
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("compare needs <before.json> <after.json>")
	}
	before, err := report.Load(fs.Arg(0))
	if err != nil {
		return err
	}
	after, err := report.Load(fs.Arg(1))
	if err != nil {
		return err
	}
	report.Compare(before, after, stdout)
	return nil
}

func sources(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("sources", stderr)
	add := fs.Int("add", 0, "print the commands that make this many loopback addresses available")
	if err := parse(fs, args); err != nil {
		return err
	}
	addrs := target.SourceAddrs()
	fmt.Fprintf(stdout, "%d usable loopback source addresses:\n", len(addrs))
	for _, a := range addrs {
		fmt.Fprintln(stdout, a)
	}
	if *add > 0 {
		fmt.Fprintf(stdout, "\nTo make %d available (run these yourself; the rig never does):\n%s\n", *add, target.AliasHint(*add))
	}
	return nil
}

func runScenarios(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("run", stderr)
	dir := fs.String("dir", "", "the generated volume")
	serverBin := fs.String("server", "", "server binary to run on the volume (default: build this module's server)")
	url := fs.String("url", "", "base URL of a server someone else started on the volume")
	only := fs.String("only", "", "comma-separated scenario names")
	scale := fs.Float64("scale", 1, "shrinks repetition counts and hold times, never the volume")
	out := fs.String("out", "", "directory for the saved result (default: <volume>/loadrig-results)")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *dir == "" {
		return errors.New("run needs --dir")
	}
	if *scale <= 0 {
		return errors.New("--scale must be above zero")
	}
	if *url != "" && *serverBin != "" {
		return errors.New("--url and --server are exclusive")
	}
	chosen, err := choose(*only)
	if err != nil {
		return err
	}
	man, err := volume.ReadManifest(*dir)
	if err != nil {
		return fmt.Errorf("%s: %w", *dir, err)
	}
	resultsDir := *out
	if resultsDir == "" {
		resultsDir = filepath.Join(*dir, "loadrig-results")
	}

	// A hangup cancels the run as Ctrl-C does, so a closed terminal still
	// saves what the run measured and stops the server the rig started.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()

	var tgt target.Target
	if *url != "" {
		tgt = target.Remote(*url)
	} else {
		binary := *serverBin
		if binary == "" {
			built, cleanup, err := buildHere(ctx, stdout)
			if err != nil {
				return err
			}
			defer cleanup()
			binary = built
		}
		tgt, err = waitBooting(stdout, bootNoticeEvery, func() (target.Target, error) {
			return target.StartLocal(ctx, binary, *dir)
		})
		if err != nil {
			return fmt.Errorf("start the server: %w", err)
		}
	}
	defer tgt.Close()

	_, byKind := man.Plan.Totals()
	kinds := map[string]int{}
	for k, n := range byKind {
		kinds[k.String()] = n
	}
	files := man.Files
	if files == 0 {
		files, _ = man.Plan.Totals()
	}
	res := report.Run{
		At:      time.Now().UTC(),
		Machine: report.ThisMachine(*dir),
		Server:  tgt.Info(),
		Volume: report.VolumeInfo{
			Shares: int64(man.Plan.Shares), Files: files, Accounts: len(man.Accounts),
			Seed: man.Plan.Seed, ByKind: kinds, Dir: *dir,
		},
		Scale: *scale,
	}
	if strings.TrimSpace(*only) != "" {
		for _, s := range chosen {
			res.Only = append(res.Only, s.Name)
		}
	}
	// The volume's sizes on disk come first, read again when the run ends.
	sizes := report.NewRecorder()
	scenario.RecordVolumeSizes(sizes, *dir, man, "at start", true)
	res.Scenarios = []report.Scenario{sizes.Scenario(scenario.VolumeName, 0)}
	res.Write(stdout)
	// The run is saved before the first scenario and again after each one,
	// so an interruption at any point keeps every scenario that finished.
	path, err := report.Save(res, resultsDir)
	if err != nil {
		return fmt.Errorf("save the result: %w", err)
	}

	env := scenario.Env{Target: tgt, Volume: man, Plan: man.Plan, Sources: target.SourceAddrs(), Scale: *scale}
	failed := false
	for _, s := range chosen {
		if ctx.Err() != nil {
			break
		}
		sc := scenario.RunOne(ctx, s, env)
		res.Scenarios = append(res.Scenarios, sc)
		if sc.Failed != "" {
			failed = true
		}
		report.WriteScenario(stdout, sc)
		if err := report.SaveAs(res, path); err != nil {
			return fmt.Errorf("save the result: %w", err)
		}
	}
	scenario.RecordVolumeSizes(sizes, *dir, man, "at end", false)
	res.Scenarios[0] = sizes.Scenario(scenario.VolumeName, 0)
	report.WriteScenario(stdout, res.Scenarios[0])
	if err := report.SaveAs(res, path); err != nil {
		return fmt.Errorf("save the result: %w", err)
	}
	fmt.Fprintf(stdout, "\nSaved %s\n", path)
	switch {
	case ctx.Err() != nil:
		return errors.New("interrupted")
	case failed:
		return errors.New("a scenario failed")
	}
	return nil
}

// bootNoticeEvery is how often waitBooting says it is still waiting.
const bootNoticeEvery = 30 * time.Second

// waitBooting runs start, which returns once the server is healthy, has
// exited or the run is cancelled, and prints a line every interval until it
// returns, so a boot that reads a large database is not taken for a hang.
func waitBooting(w io.Writer, every time.Duration, start func() (target.Target, error)) (target.Target, error) {
	began := time.Now()
	done := make(chan struct{})
	printed := make(chan struct{})
	go func() {
		defer close(printed)
		tick := time.NewTicker(every)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-tick.C:
				fmt.Fprintf(w, "waiting for the server to boot: %s\n", time.Since(began).Round(time.Second))
			}
		}
	}()
	tgt, err := start()
	close(done)
	<-printed
	return tgt, err
}

// choose is the scenarios --only names, in the order a full run takes them,
// or all of them when it is empty.
func choose(only string) ([]scenario.Scenario, error) {
	all := scenario.All()
	if strings.TrimSpace(only) == "" {
		return all, nil
	}
	valid := make([]string, len(all))
	byName := map[string]bool{}
	for i, s := range all {
		valid[i] = s.Name
	}
	for _, n := range strings.Split(only, ",") {
		n = strings.TrimSpace(n)
		if !contains(valid, n) {
			sort.Strings(valid)
			return nil, fmt.Errorf("unknown scenario %q; the scenarios are %s", n, strings.Join(valid, ", "))
		}
		byName[n] = true
	}
	var out []scenario.Scenario
	for _, s := range all {
		if byName[s.Name] {
			out = append(out, s)
		}
	}
	return out, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// buildHere builds the server from the module found by walking up from the
// working directory, into a directory the returned function removes.
func buildHere(ctx context.Context, stdout io.Writer) (binary string, cleanup func(), err error) {
	moduleDir, err := findModule()
	if err != nil {
		return "", nil, err
	}
	tmp, err := os.MkdirTemp("", "hyperdrop-loadrig-")
	if err != nil {
		return "", nil, err
	}
	fmt.Fprintf(stdout, "Building the server from %s\n", moduleDir)
	binary, err = target.BuildServer(ctx, moduleDir, tmp)
	if err != nil {
		os.RemoveAll(tmp)
		return "", nil, err
	}
	return binary, func() { os.RemoveAll(tmp) }, nil
}

// findModule walks up from the working directory to the go.mod of module
// hyperdrop/server.
func findModule() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if f, err := os.Open(filepath.Join(dir, "go.mod")); err == nil {
			sc := bufio.NewScanner(f)
			module := ""
			for sc.Scan() {
				if rest, ok := strings.CutPrefix(strings.TrimSpace(sc.Text()), "module "); ok {
					module = strings.TrimSpace(rest)
					break
				}
			}
			f.Close()
			if module == "hyperdrop/server" {
				return dir, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("no go.mod of module hyperdrop/server above the working directory: run from inside the server module or pass --server <binary> or --url")
		}
		dir = parent
	}
}
