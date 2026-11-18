package scenario

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"hyperdrop/server/internal/loadrig/report"
	"hyperdrop/server/internal/loadrig/target"
	"hyperdrop/server/internal/loadrig/volume"
)

const (
	opListBefore    = "list page before flood"
	opHealthFlood   = "health during flood"
	floodListOp     = "flood list page"
	floodDownloadOp = "flood download"

	valConnsPerAddress  = "load guard connections per address"
	valFloodOpen        = "flood requests open"
	valFloodPerAddress  = "flood requests open per address"
	valFloodRefusals    = "flood refusals (429 or 503 busy)"
	valFloodClosed      = "flood connections the load guard closed"
	valListMedianBefore = "list page median before flood"
	valMemoryBefore     = "memory before flood"
	valPeakDuring       = "peak memory during flood"
	valRecovered        = "recovered"
	valRecovery         = "recovered after"
	valRecoveryRequests = "list requests until recovered"

	// floodTimesLimit is how many times the per-address limit of open
	// requests the flood holds from each address.
	floodTimesLimit = 4
	// floodMostOpen bounds the flood's requests over every address, and so
	// the goroutines and connections the rig opens.
	floodMostOpen = 2048
	// floodHold is how long the flood runs.
	floodHold = 30 * time.Second
	// floodPause is how long a flood request that was refused or failed
	// waits before the next: a refusal closes its connection, and the pause
	// bounds how fast the flood opens new ones.
	floodPause = 10 * time.Millisecond
	// healthEvery is the pace of the health probe during the flood.
	healthEvery = 200 * time.Millisecond
	// baselineLists is how many listing requests set the pre-flood median.
	baselineLists = 20
	// recoveryStreak is how many listing requests in a row must succeed, each
	// under recoverySlower times the pre-flood median, for the server to
	// count as recovered.
	recoveryStreak = 20
	recoverySlower = 2
	// recoveryWait is how long the server gets to recover, scaled, and never
	// less than recoveryLeast.
	recoveryWait  = 2 * time.Minute
	recoveryLeast = 20 * time.Second
)

var overloadScenario = Scenario{
	Name: "overload",
	About: "A flood from every source address of 4 times the per-address limit of open requests (128), at most 2048 " +
		"in all, half on the largest account's listing page and half on a public file download, for 30 s, while " +
		"one client asks /api/health every 200 ms. Reported: the flood's answers by code (a connection closed or " +
		"reset as it was accepted is the load guard closing one past the 256 an address may hold), the health " +
		"probe (any failure is wrong), peak memory, and whether and how long after the flood 20 listing requests " +
		"in a row succeed under twice their pre-flood median, waiting up to 2 minutes (scaled, at least 20 s): a " +
		"server that has not by then is reported as not recovered, never as wrong. Only on a server the rig " +
		"started: on a server named by URL the flood would be an outage.",
	NeedsLocal: true,
	Run:        overload,
}

func overload(ctx context.Context, e Env, rec *report.Recorder) error {
	acct, err := e.largest()
	if err != nil {
		return err
	}
	dl, ok := e.find(func(s volume.ShareSpec) bool {
		return s.Kind == volume.Plain && s.Files == 1 && visitable(s, time.Now())
	})
	if !ok {
		return Skip("the plan holds no share of one file to download")
	}
	dlToken, err := e.token(dl.Owner)
	if err != nil {
		return err
	}
	probe := e.probe()
	defer probe.Close()
	share, err := readShare(ctx, probe, "probe", dl.ID, dlToken)
	if err != nil {
		return fmt.Errorf("reading share %s: %w", dl.ID, err)
	}
	if len(share.Files) != 1 {
		return fmt.Errorf("share %s of one file answered %d files", dl.ID, len(share.Files))
	}
	downloadPath := "/download/" + dl.ID + "/" + share.Files[0].Slug

	c := e.client(rec, 0)
	defer c.Close()
	var took []time.Duration
	if err := repeat(ctx, e, count(baselineLists), func() error {
		began := time.Now()
		err := c.Do(ctx, opListBefore, http.MethodGet, "/api/shares", acct.Token, nil, wantStatus(http.StatusOK))
		if err == nil {
			took = append(took, time.Since(began))
		}
		return err
	}); err != nil {
		return err
	}
	if len(took) == 0 {
		return fmt.Errorf("no listing request succeeded before the flood")
	}
	slices.Sort(took)
	median := took[len(took)/2]
	rec.Value(valListMedianBefore, median.Seconds()*1000, "ms")
	if cur, _, ok := e.Target.Memory(); ok {
		rec.Value(valMemoryBefore, mib(cur), "MiB")
	} else {
		rec.NotAvailable(valMemoryBefore, "the server's memory is not readable")
	}

	stopHealth := make(chan struct{})
	healthy := make(chan struct{})
	var peak int64
	var peakOK bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		hc := e.client(rec, 0)
		defer hc.Close()
		tick := time.NewTicker(healthEvery)
		defer tick.Stop()
		for first := true; ; first = false {
			hc.Do(ctx, opHealthFlood, http.MethodGet, "/api/health", "", nil, wantStatus(http.StatusOK))
			if cur, _, ok := e.Target.Memory(); ok {
				peak, peakOK = max(peak, cur), true
			}
			if first {
				close(healthy)
			}
			select {
			case <-stopHealth:
				return
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}()
	<-healthy

	perAddress := min(floodTimesLimit*perAddressRequests, floodMostOpen/e.addresses())
	rec.Value(valFloodOpen, float64(perAddress*e.addresses()), "requests")
	rec.Value(valFloodPerAddress, float64(perAddress), "requests")
	rec.Value(valSources, float64(e.addresses()), "addresses")
	rec.Value(valPerAddress, perAddressRequests, "requests")
	rec.Value(valConnsPerAddress, perAddressConns, "connections")
	floodRec := report.NewRecorder()
	tallies := map[string]*floodTally{floodListOp: {}, floodDownloadOp: {}}
	began := time.Now()
	err = parallel(ctx, e, floodRec, perAddress*e.addresses(), until(began.Add(e.hold(floodHold))), func(w int, fc *target.Client) error {
		op, path, token := floodListOp, "/api/shares", acct.Token
		if w%2 == 1 {
			op, path, token = floodDownloadOp, downloadPath, ""
		}
		served := false
		err := fc.Do(ctx, op, http.MethodGet, path, token, nil, func(r *http.Response) error {
			served = r.StatusCode == http.StatusOK
			if !served {
				tallies[op].answered(r)
			}
			return nil
		})
		if err != nil {
			tallies[op].failed(err)
		}
		if !served {
			select {
			case <-ctx.Done():
			case <-time.After(floodPause):
			}
		}
		return nil
	})
	stopped := time.Now()
	close(stopHealth)
	wg.Wait()
	if err != nil {
		return err
	}
	floodAnswers(rec, floodRec.Scenario("flood", stopped.Sub(began)), tallies)
	if peakOK {
		rec.Value(valPeakDuring, mib(peak), "MiB")
	} else {
		rec.NotAvailable(valPeakDuring, "the server's memory is not readable")
	}
	return recovery(ctx, rec, probe, acct.Token, median, stopped, max(e.hold(recoveryWait), recoveryLeast))
}

// floodTally is what one flood op's answers held beyond the recorder's
// count: how many connections the load guard closed, and a description of
// each kind of answer that was neither served, refused by a limit, nor such
// a close.
type floodTally struct {
	mu     sync.Mutex
	closed int
	other  map[string]int
}

// maxFloodOthers is how many kinds of unclassified answer a tally describes.
const maxFloodOthers = 5

// failed notes a request that got no answer.
func (t *floodTally) failed(err error) {
	if closedByGuard(err) {
		t.mu.Lock()
		t.closed++
		t.mu.Unlock()
		return
	}
	t.note("failed: " + err.Error())
}

// answered notes an answer other than 200, by the rule the recorder counts
// it wrong by: a 429 and a 503 busy are refusals, a redirect is served.
func (t *floodTally) answered(r *http.Response) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 200))
	code := target.AnswerCode(r, body)
	switch {
	case r.StatusCode >= 200 && r.StatusCode < 400,
		r.StatusCode == http.StatusTooManyRequests,
		r.StatusCode == http.StatusServiceUnavailable && code == "busy":
		return
	}
	t.note(fmt.Sprintf("answered %d %q: %q", r.StatusCode, code, body))
}

func (t *floodTally) note(what string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.other == nil {
		t.other = map[string]int{}
	}
	if _, seen := t.other[what]; seen || len(t.other) < maxFloodOthers {
		t.other[what]++
	}
}

// describe lists the unclassified answers noted, most frequent first.
func (t *floodTally) describe() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	kinds := make([]string, 0, len(t.other))
	for k := range t.other {
		kinds = append(kinds, k)
	}
	sort.Slice(kinds, func(i, j int) bool { return t.other[kinds[i]] > t.other[kinds[j]] })
	for i, k := range kinds {
		kinds[i] = fmt.Sprintf("%d × %s", t.other[k], k)
	}
	return strings.Join(kinds, "; ")
}

// floodAnswers writes the flood's answers into rec: each op's rate, its
// answers by code and the median of those served. A connection the load
// guard closed (closedByGuard), which it does to one past its address's
// limit as it is accepted, is an answer. Every other answer neither served
// nor refused by a limit is wrong, including a connection refused or a
// timeout, and the reason names what each was.
func floodAnswers(rec *report.Recorder, sc report.Scenario, tallies map[string]*floodTally) {
	refused, closes := 0, 0
	for _, o := range sc.Ops {
		t := tallies[o.Name]
		if t == nil {
			t = &floodTally{}
		}
		refused += refusals(o)
		closes += t.closed
		rec.Value(o.Name+" rate", o.PerSecond, "/s")
		keys := make([]string, 0, len(o.ByAnswer))
		for k := range o.ByAnswer {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			rec.Value(o.Name+" "+k, float64(o.ByAnswer[k]), "answers")
		}
		if o.ByAnswer["200"] > 0 {
			rec.Value(o.Name+" served median", o.P50.Seconds()*1000, "ms")
		}
		if wrong := o.Wrong - t.closed; wrong > 0 {
			rec.Wrong(o.Name, fmt.Sprintf("%d answers neither served, refused by a limit, nor a connection the load guard closed: %s", wrong, t.describe()))
		}
	}
	rec.Value(valFloodRefusals, float64(refused), "answers")
	rec.Value(valFloodClosed, float64(closes), "connections")
}

// closedByGuard reports a request failed the way one does whose connection
// the server closed as it was accepted, which net/http's transport reports
// in one of several ways depending on what it was doing at that moment:
//   - reading the answer: the end of the stream, or a reset;
//   - before the request was registered on the connection: its unexported
//     errServerClosedIdle, which it retries only on a reused connection, so
//     on a fresh one it reaches the caller (matched by its text);
//   - writing the request: a broken pipe, or the connection its read side
//     already closed on seeing the end of the stream (net.ErrClosed).
//
// Within the flood the rig never closes a connection that is in use, so a
// closed connection under a write is always one the server ended.
func closedByGuard(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), serverClosedIdle)
}

// serverClosedIdle is the text of net/http's errServerClosedIdle.
const serverClosedIdle = "http: server closed idle connection"

// recovery measures how long after stopped the listing page has answered
// recoveryStreak times in a row under recoverySlower times median, to the end
// of the last of them. A server that has not within wait of stopped is
// recorded as not recovered, with the time as not available and why: how
// fast a server recovers is a number, never a wrong answer.
func recovery(ctx context.Context, rec *report.Recorder, c *target.Client, token string, median time.Duration, stopped time.Time, wait time.Duration) error {
	deadline := stopped.Add(wait)
	streak, requests := 0, 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		began := time.Now()
		status := 0
		err := c.Do(ctx, "probe", http.MethodGet, "/api/shares", token, nil, func(r *http.Response) error {
			status = r.StatusCode
			return nil
		})
		requests++
		if err == nil && status == http.StatusOK && time.Since(began) < recoverySlower*median {
			if streak++; streak == recoveryStreak {
				rec.Text(valRecovered, "yes")
				rec.Value(valRecovery, time.Since(stopped).Seconds(), "s")
				rec.Value(valRecoveryRequests, float64(requests), "requests")
				return nil
			}
			continue
		}
		streak = 0
		if time.Now().After(deadline) {
			why := fmt.Sprintf("%d listing requests in a row never succeeded under %s within %s of the flood's end",
				recoveryStreak, recoverySlower*median, wait)
			rec.Text(valRecovered, "no")
			rec.NotAvailable(valRecovery, why)
			rec.NotAvailable(valRecoveryRequests, why)
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(floodPause):
		}
	}
}
