package scenario

import (
	"context"
	"fmt"
	"strings"
	"time"

	"hyperdrop/server/internal/loadrig/report"
	"hyperdrop/server/internal/loadrig/target"
)

const (
	valHealthyAfter    = "healthy after"
	valFirstPassAfter  = "first pass logged after"
	valFirstPass       = "first pass"
	valPeakToFirstPass = "peak memory to first pass"

	// memoryHold is how long after the first pass the settled memory is read.
	memoryHold = 30 * time.Second
)

// memoryAfterName names the memory read hold after the first pass.
func memoryAfterName(hold time.Duration) string {
	return fmt.Sprintf("memory %s after first pass", hold)
}

// bootLineWait bounds how long recordBoot waits for the boot's last line.
const bootLineWait = 5 * time.Second

// bootLines are the lines a boot logs for its phases, each with the value the
// scenarios record it as: the line's prefix, then the phase's duration.
var bootLines = []struct{ prefix, value string }{
	{"boot: database check: ", "boot database check"},
	{"boot: schema: ", "boot schema"},
	{"boot: store: ", "boot store"},
	{"boot: share ids: ", "boot share ids"},
	{"boot pass: ", "boot pass"},
	{"boot: publishes: ", "boot publishes"},
	{"boot: volume ready: ", "boot volume ready"},
}

// recordBoot records the duration each boot line of the current server
// process states, in seconds. The lines are logged before the server answers
// healthy, so it waits at most bootLineWait for the last of them (a line may
// still be in the log pipe) and no longer for any other: a line the process
// did not log (a server built before it existed) is recorded as not
// available.
func recordBoot(t target.Target, rec *report.Recorder) {
	ctx, cancel := context.WithTimeout(context.Background(), bootLineWait)
	t.WaitLog(ctx, bootLines[len(bootLines)-1].prefix)
	cancel()
	for _, b := range bootLines {
		line, ok := logged(t, b.prefix)
		if !ok {
			rec.NotAvailable(b.value, "the server did not log a line starting "+fmt.Sprintf("%q", b.prefix))
			continue
		}
		took, _, _ := strings.Cut(strings.TrimPrefix(line, b.prefix), " ")
		d, err := time.ParseDuration(took)
		if err != nil {
			rec.NotAvailable(b.value, fmt.Sprintf("the server logged %q", line))
			continue
		}
		rec.Value(b.value, d.Seconds(), "s")
	}
}

var startupKilledScenario = Scenario{
	Name: "startup-killed",
	About: "A restart after SIGKILL, which leaves no clean-shutdown record: how long until the server answers healthy " +
		"and what each boot phase took, then until its first housekeeping pass is logged, so the scenarios after it " +
		"measure a settled server.",
	NeedsLocal: true,
	Run:        startupKilled,
}

func startupKilled(ctx context.Context, e Env, rec *report.Recorder) error {
	healthy, err := e.Target.RestartKilled(ctx)
	if err != nil {
		return fmt.Errorf("restart after a kill: %w", err)
	}
	answered := time.Now()
	rec.Value(valHealthyAfter, healthy.Seconds(), "s")
	recordBoot(e.Target, rec)
	if _, err := e.Target.WaitLog(ctx, firstPassPrefix); err != nil {
		return fmt.Errorf("waiting for the first pass: %w", err)
	}
	rec.Value(valFirstPassAfter, (healthy + time.Since(answered)).Seconds(), "s")
	return nil
}

var startupScenario = Scenario{
	Name: "startup",
	About: "A restart on the volume: how long until the server answers healthy and what each boot phase took, " +
		"until its first housekeeping pass is logged and what each of that pass's steps took, its peak memory up to then, " +
		"its memory 30 s later, and the integrity scan's time when the process has logged one by then.",
	NeedsLocal: true,
	Run:        startup,
}

func startup(ctx context.Context, e Env, rec *report.Recorder) error {
	healthy, err := e.Target.Restart(ctx)
	if err != nil {
		return fmt.Errorf("restart: %w", err)
	}
	answered := time.Now()
	rec.Value(valHealthyAfter, healthy.Seconds(), "s")
	recordBoot(e.Target, rec)

	line, err := e.Target.WaitLog(ctx, firstPassPrefix)
	if err != nil {
		return fmt.Errorf("waiting for the first pass: %w", err)
	}
	rec.Value(valFirstPassAfter, (healthy + time.Since(answered)).Seconds(), "s")
	if _, peak, ok := e.Target.Memory(); ok {
		rec.Value(valPeakToFirstPass, mib(peak), "MiB")
	} else {
		rec.NotAvailable(valPeakToFirstPass, "the server's memory is not readable")
	}
	pass, err := parsePass(line)
	if err != nil {
		return err
	}
	pass.record(rec, valFirstPass)

	hold := e.hold(memoryHold)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(hold):
	}
	name := memoryAfterName(hold)
	if !answering(e.Target) {
		return errStopped
	}
	if cur, _, ok := e.Target.Memory(); ok {
		rec.Value(name, mib(cur), "MiB")
	} else {
		rec.NotAvailable(name, "the server's memory is not readable")
	}
	recordIntegrity(e.Target, rec)
	return nil
}
