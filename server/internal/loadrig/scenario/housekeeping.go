package scenario

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"hyperdrop/server/internal/loadrig/report"
	"hyperdrop/server/internal/loadrig/target"
	"hyperdrop/server/internal/loadrig/volume"
)

const (
	opListDuring     = "list page during pass"
	opDownloadDuring = "download during pass"
	opListAfter      = "list page after pass"
	opDownloadAfter  = "download after pass"
	opExpiredGone    = "expired share after pass"

	valRemoved = "expired shares removed"
	valPlanned = "expired shares in plan"
	valDuring  = "requests during pass"

	// expiredChecked is how many of the plan's expired shares are read back
	// after the pass.
	expiredChecked = 20
)

var housekeepingScenario = Scenario{
	Name: "housekeeping",
	About: "The first housekeeping pass on a volume whose expired shares are due: what each step took, how many " +
		"shares it removed, and the listing page and a public download in a loop while it runs, beside the same " +
		"two after it, then waits for the integrity scan, which runs beside the pass, and records its time, or that none was " +
		"due (a server that runs the scan inside the pass is not waited for).",
	NeedsLocal: true,
	Run:        housekeeping,
}

func housekeeping(ctx context.Context, e Env, rec *report.Recorder) error {
	acct, err := e.largest()
	if err != nil {
		return err
	}
	var sample []volume.ShareSpec
	planned := 0
	for i := 0; i < e.Plan.Shares; i++ {
		if s := e.Plan.Share(i); s.Kind == volume.Expired {
			planned++
			if len(sample) < expiredChecked {
				sample = append(sample, s)
			}
		}
	}
	if planned == 0 {
		return Skip("the plan holds no expired shares")
	}
	sampleToken, err := e.token(sample[0].Owner)
	if err != nil {
		return err
	}
	dl, ok := e.find(func(s volume.ShareSpec) bool {
		return s.Kind == volume.Plain && s.Files == 1 && s.Owner == acct.Name
	})
	if !ok {
		return Skip(acct.Name + " owns no share of one file to download")
	}

	probe := e.probe()
	defer probe.Close()
	share, err := readShare(ctx, probe, "probe", dl.ID, acct.Token)
	if err != nil {
		return fmt.Errorf("reading share %s: %w", dl.ID, err)
	}
	if len(share.Files) != 1 {
		return fmt.Errorf("share %s of one file answered %d files", dl.ID, len(share.Files))
	}
	file := share.Files[0]
	downloadPath := "/download/" + dl.ID + "/" + file.Slug
	present := func() (bool, error) {
		status := 0
		err := probe.Do(ctx, "probe", http.MethodGet, "/api/shares/"+sample[0].ID, sampleToken, nil, func(r *http.Response) error {
			status = r.StatusCode
			return nil
		})
		if err != nil {
			return false, err
		}
		switch status {
		case http.StatusOK:
			return true, nil
		case http.StatusNotFound:
			return false, nil
		}
		return false, fmt.Errorf("reading expired share %s answered %d", sample[0].ID, status)
	}

	// The pass measured is the current process's first one. When that pass
	// has ended without removing anything, a share still present calls for
	// a new process and its first pass; none present means the volume was
	// swept before.
	line, passed := logged(e.Target, firstPassPrefix)
	if passed {
		n, err := removedNow(e.Target)
		if err != nil {
			return err
		}
		if n == 0 {
			if there, err := present(); err != nil {
				return err
			} else if !there {
				return Skip("already swept")
			}
			if _, err := e.Target.Restart(ctx); err != nil {
				return fmt.Errorf("restart: %w", err)
			}
			passed = false
		}
	}

	c := e.client(rec, 0)
	defer c.Close()
	list := func(op string) error {
		return c.Do(ctx, op, http.MethodGet, "/api/shares", acct.Token, nil, wantStatus(http.StatusOK))
	}
	download := func(op string) error {
		return c.Do(ctx, op, http.MethodGet, downloadPath, "", nil, func(r *http.Response) error {
			if r.StatusCode != http.StatusOK {
				return fmt.Errorf("answered %d", r.StatusCode)
			}
			if r.ContentLength != file.Size {
				return fmt.Errorf("a file of %d bytes answered %d", file.Size, r.ContentLength)
			}
			return nil
		})
	}

	if !passed {
		if line, err = during(ctx, e, rec, list, download); err != nil {
			return err
		}
	} else {
		rec.NotAvailable(valDuring, "the first pass ended before the scenario began")
	}

	pass, err := parsePass(line)
	if err != nil {
		return err
	}
	pass.record(rec, valFirstPass)
	removed, err := removedNow(e.Target)
	if err != nil {
		return err
	}
	rec.Value(valRemoved, float64(removed), "shares")
	rec.Value(valPlanned, float64(planned), "shares")
	if removed == 0 {
		if there, err := present(); err != nil {
			return err
		} else if !there {
			return Skip("already swept")
		}
	}
	if removed != planned {
		rec.Wrong(valRemoved, fmt.Sprintf("the first pass removed %d expired shares of the %d the plan holds", removed, planned))
	}

	n := e.times(readsSerial)
	if err := repeat(ctx, e, count(n), func() error { return list(opListAfter) }); err != nil {
		return err
	}
	if err := repeat(ctx, e, count(n), func() error { return download(opDownloadAfter) }); err != nil {
		return err
	}
	rec.Expect(opExpiredGone, http.StatusNotFound, "not-found")
	for _, s := range sample {
		token, err := e.token(s.Owner)
		if err != nil {
			rec.Wrong(opExpiredGone, "expired share "+s.ID+": "+err.Error())
			continue
		}
		if err := c.Do(ctx, opExpiredGone, http.MethodGet, "/api/shares/"+s.ID, token, nil, wantStatus(http.StatusNotFound)); err != nil && !answering(e.Target) {
			return errStopped
		}
	}
	return waitIntegrity(ctx, e.Target, rec, pass)
}

// waitIntegrity waits for the current process to say what its integrity scan
// is doing: the finished-scan line, whose time it records, or the line a
// process logs when no scan is due, which it records as not available with
// that line's reason. A pass whose timing line names an integrity step ran
// the scan inside the pass, so nothing is waited for. A server that exits
// without either line is recorded as not available with the error; only a
// stopped context ends the wait with an error.
func waitIntegrity(ctx context.Context, t target.Target, rec *report.Recorder, pass passTiming) error {
	for _, s := range pass.steps {
		if s.name == "integrity" {
			recordIntegrity(t, rec)
			return nil
		}
	}
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type answer struct {
		line string
		err  error
	}
	finished, notDue := make(chan answer, 1), make(chan answer, 1)
	wait := func(prefix string, out chan<- answer) {
		line, err := t.WaitLog(wctx, prefix)
		out <- answer{line, err}
	}
	go wait(integrityPrefix, finished)
	go wait(integrityNotDuePrefix, notDue)
	var errs []error
	for len(errs) < 2 {
		select {
		case a := <-finished:
			if a.err == nil {
				recordIntegrity(t, rec)
				return nil
			}
			errs = append(errs, a.err)
		case a := <-notDue:
			if a.err == nil {
				rec.NotAvailable(valIntegrity, "no scan due ("+strings.TrimPrefix(a.line, integrityNotDuePrefix)+")")
				return nil
			}
			errs = append(errs, a.err)
		}
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("waiting for the integrity scan: %w", err)
	}
	rec.NotAvailable(valIntegrity, "the server logged no integrity scan line: "+errs[0].Error())
	return nil
}

// during requests the listing page and the download, in turn, until the
// current process logs its first pass, and answers that line.
func during(ctx context.Context, e Env, rec *report.Recorder, list, download func(op string) error) (string, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type logLine struct {
		line string
		err  error
	}
	done := make(chan logLine, 1)
	go func() {
		line, err := e.Target.WaitLog(ctx, firstPassPrefix)
		done <- logLine{line, err}
	}()
	rounds := 0
	for {
		select {
		case l := <-done:
			if l.err != nil {
				return "", fmt.Errorf("waiting for the first pass: %w", l.err)
			}
			if rounds == 0 {
				rec.NotAvailable(valDuring, "the first pass ended before the first request")
			} else {
				rec.Value(valDuring, float64(rounds*2), "requests")
			}
			return l.line, nil
		default:
		}
		errList, errDownload := list(opListDuring), download(opDownloadDuring)
		if (errList != nil || errDownload != nil) && !answering(e.Target) {
			return "", errStopped
		}
		rounds++
	}
}

// removedNow is how many expired shares the current server process's
// expiry sweep has logged removing, zero before it logs any.
func removedNow(t target.Target) (int, error) {
	line, ok := logged(t, removedPrefix)
	if !ok {
		return 0, nil
	}
	n, _, err := parseRemoved(line)
	return n, err
}
