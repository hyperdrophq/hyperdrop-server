// Package report records what a load scenario observed and prints, saves and compares it.
// It states numbers and never judges them.
package report

import (
	"errors"
	"math"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Op is one named operation's result within a scenario.
type Op struct {
	Name         string         `json:"name"`
	Count        int            `json:"count"`
	Wrong        int            `json:"wrong"`
	WrongReasons []string       `json:"wrongReasons,omitempty"`
	ByAnswer     map[string]int `json:"byAnswer"`
	PerSecond    float64        `json:"perSecond"`
	P50          time.Duration  `json:"p50"`
	P95          time.Duration  `json:"p95"`
	P99          time.Duration  `json:"p99"`
	Max          time.Duration  `json:"max"`
}

// Value is one measured number, a word for an outcome that is not a number
// (Text), or a statement that none is available and why.
type Value struct {
	Name         string  `json:"name"`
	V            float64 `json:"v"`
	Unit         string  `json:"unit"`
	Text         string  `json:"text,omitempty"`
	NotAvailable string  `json:"notAvailable,omitempty"`
}

// Scenario is everything one scenario produced. Skipped and Failed carry a reason.
type Scenario struct {
	Name    string  `json:"name"`
	Ops     []Op    `json:"ops,omitempty"`
	Values  []Value `json:"values,omitempty"`
	Skipped string  `json:"skipped,omitempty"`
	Failed  string  `json:"failed,omitempty"`
}

const maxWrongReasons = 5

// The histogram has logarithmic buckets of ratio histGrowth from 1 ns up, so a
// percentile is accurate to one bucket (5 percent) and memory is fixed.
const (
	histGrowth  = 1.05
	histBuckets = 600
)

var histLogGrowth = math.Log(histGrowth)

type histogram struct {
	counts [histBuckets]int64
	n      int64
	max    time.Duration
}

func bucketOf(d time.Duration) int {
	if d <= 1 {
		return 0
	}
	b := int(math.Log(float64(d)) / histLogGrowth)
	if b >= histBuckets {
		b = histBuckets - 1
	}
	return b
}

func (h *histogram) add(d time.Duration) {
	if d < 0 {
		d = 0
	}
	h.counts[bucketOf(d)]++
	h.n++
	if d > h.max {
		h.max = d
	}
}

// quantile returns the upper bound of the bucket holding the q-th observation,
// never above the largest observation.
func (h *histogram) quantile(q float64) time.Duration {
	if h.n == 0 {
		return 0
	}
	rank := int64(math.Ceil(q * float64(h.n)))
	if rank < 1 {
		rank = 1
	}
	var seen int64
	for i, c := range h.counts {
		seen += c
		if seen >= rank {
			up := time.Duration(math.Pow(histGrowth, float64(i+1)))
			if up > h.max {
				up = h.max
			}
			return up
		}
	}
	return h.max
}

type opState struct {
	count, wrong int
	reasons      []string
	byAnswer     map[string]int
	expected     map[string]bool
	hist         histogram
	first, last  time.Time
}

// Recorder collects observations from many goroutines.
type Recorder struct {
	mu     sync.Mutex
	order  []string
	ops    map[string]*opState
	values []Value
}

// NewRecorder returns an empty Recorder.
func NewRecorder() *Recorder {
	return &Recorder{ops: map[string]*opState{}}
}

func (r *Recorder) op(name string) *opState {
	s := r.ops[name]
	if s == nil {
		s = &opState{byAnswer: map[string]int{}, expected: map[string]bool{}}
		r.ops[name] = s
		r.order = append(r.order, name)
	}
	return s
}

func answerKey(status int, code string) string {
	if code == "" || (status >= 200 && status < 400) {
		return strconv.Itoa(status)
	}
	return strconv.Itoa(status) + " " + code
}

// Observe records one answer: how long it took, its status and, for an error,
// its code. It reports whether it counted the answer wrong.
func (r *Recorder) Observe(op string, took time.Duration, status int, code string) (wrong bool) {
	now := time.Now()
	key := answerKey(status, code)
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.op(op)
	s.count++
	s.byAnswer[key]++
	if s.first.IsZero() {
		s.first = now
	}
	s.last = now
	switch {
	case status >= 200 && status < 400, s.expected[key]:
		s.hist.add(took)
	case status == 429, status == 503 && code == "busy":
		// Refusals by the server's own limits are an answer, not an error.
	default:
		s.wrong++
		return true
	}
	return false
}

// Expect declares an answer the scenario provokes on purpose, so it is not Wrong
// and its latency counts in the percentiles.
func (r *Recorder) Expect(op string, status int, code string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.op(op).expected[answerKey(status, code)] = true
}

// Fail records a transport error, which counts as Wrong.
func (r *Recorder) Fail(op string, err error) {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.op(op)
	s.count++
	s.wrong++
	s.byAnswer["failed: "+errorClass(err)]++
	if s.first.IsZero() {
		s.first = now
	}
	s.last = now
}

func errorClass(err error) string {
	var ne net.Error
	switch {
	case err == nil:
		return "unknown"
	case errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	case isRefused(err):
		return "connection refused"
	case isReset(err):
		return "connection reset"
	}
	return "error"
}

// Wrong records a body the scenario rejected on an otherwise accepted answer.
// Up to five distinct reasons are kept per op.
func (r *Recorder) Wrong(op, why string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.op(op)
	s.wrong++
	s.reason(why)
}

// Reason keeps why an answer already counted wrong was wrong, without
// counting it again.
func (r *Recorder) Reason(op, why string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.op(op).reason(why)
}

func (s *opState) reason(why string) {
	for _, w := range s.reasons {
		if w == why {
			return
		}
	}
	if len(s.reasons) < maxWrongReasons {
		s.reasons = append(s.reasons, why)
	}
}

// Value records one measured number.
func (r *Recorder) Value(name string, v float64, unit string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.values = append(r.values, Value{Name: name, V: v, Unit: unit})
}

// Text records an outcome that is a word rather than a number, such as
// whether something happened.
func (r *Recorder) Text(name, text string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.values = append(r.values, Value{Name: name, Text: text})
}

// NotAvailable records that a number could not be measured, and why.
func (r *Recorder) NotAvailable(name, why string) {
	if why == "" {
		why = "not measured"
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.values = append(r.values, Value{Name: name, NotAvailable: why})
}

// Scenario summarises what was recorded. An op's rate is its count over the time
// between its first and last observation, or over wall when that span is zero.
func (r *Recorder) Scenario(name string, wall time.Duration) Scenario {
	r.mu.Lock()
	defer r.mu.Unlock()
	sc := Scenario{Name: name, Values: append([]Value(nil), r.values...)}
	for _, n := range r.order {
		s := r.ops[n]
		span := s.last.Sub(s.first)
		if span <= 0 {
			span = wall
		}
		o := Op{
			Name:         n,
			Count:        s.count,
			Wrong:        s.wrong,
			WrongReasons: append([]string(nil), s.reasons...),
			ByAnswer:     map[string]int{},
			P50:          s.hist.quantile(0.50),
			P95:          s.hist.quantile(0.95),
			P99:          s.hist.quantile(0.99),
			Max:          s.hist.max,
		}
		for k, v := range s.byAnswer {
			o.ByAnswer[k] = v
		}
		if span > 0 {
			o.PerSecond = float64(s.count) / span.Seconds()
		}
		sc.Ops = append(sc.Ops, o)
	}
	return sc
}

func sortedKeys(m map[string]int) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
