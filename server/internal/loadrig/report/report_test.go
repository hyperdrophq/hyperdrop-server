package report

import (
	"bytes"
	"errors"
	"math"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPercentilesWithinOneBucket(t *testing.T) {
	r := NewRecorder()
	for i := 1; i <= 1000; i++ {
		r.Observe("get", time.Duration(i)*time.Millisecond, 200, "")
	}
	op := r.Scenario("s", time.Second).Ops[0]
	for _, c := range []struct {
		got  time.Duration
		want time.Duration
	}{{op.P50, 500 * time.Millisecond}, {op.P95, 950 * time.Millisecond}, {op.P99, 990 * time.Millisecond}} {
		if math.Abs(float64(c.got-c.want))/float64(c.want) > histGrowth-1 {
			t.Errorf("got %v want %v within one bucket", c.got, c.want)
		}
	}
	if op.Max != time.Second {
		t.Errorf("max %v", op.Max)
	}
}

func TestRefusalIsItsOwnAnswerAndNotWrong(t *testing.T) {
	r := NewRecorder()
	r.Observe("watch", 10*time.Millisecond, 200, "")
	r.Observe("watch", time.Hour, 429, "too-many-watchers")
	r.Observe("watch", time.Hour, 503, "busy")
	op := r.Scenario("s", time.Second).Ops[0]
	if op.ByAnswer["429 too-many-watchers"] != 1 || op.ByAnswer["503 busy"] != 1 || op.ByAnswer["200"] != 1 {
		t.Fatalf("answers %v", op.ByAnswer)
	}
	if op.Wrong != 0 || op.P50 > 20*time.Millisecond || op.Max != 10*time.Millisecond {
		t.Fatalf("wrong %d p50 %v max %v", op.Wrong, op.P50, op.Max)
	}
}

func TestWrongAnswers(t *testing.T) {
	r := NewRecorder()
	r.Observe("a", time.Millisecond, 500, "")
	r.Observe("a", time.Millisecond, 400, "too-many-files")
	r.Fail("a", errors.New("boom"))
	for i := 0; i < 9; i++ {
		r.Wrong("a", "reason "+string(rune('a'+i)))
	}
	r.Wrong("a", "reason a")
	op := r.Scenario("s", time.Second).Ops[0]
	if op.Wrong != 3+10 || len(op.WrongReasons) != 5 {
		t.Fatalf("wrong %d reasons %v", op.Wrong, op.WrongReasons)
	}
	if op.ByAnswer["failed: error"] != 1 {
		t.Fatalf("answers %v", op.ByAnswer)
	}
}

func TestExpectedAnswerIsNotWrong(t *testing.T) {
	r := NewRecorder()
	r.Expect("create", 400, "too-many-files")
	r.Observe("create", 5*time.Millisecond, 400, "too-many-files")
	op := r.Scenario("s", time.Second).Ops[0]
	if op.Wrong != 0 || op.ByAnswer["400 too-many-files"] != 1 || op.P50 == 0 {
		t.Fatalf("%+v", op)
	}
}

func TestConcurrentUse(t *testing.T) {
	r := NewRecorder()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				r.Observe("x", time.Millisecond, 200, "")
			}
		}()
	}
	wg.Wait()
	if c := r.Scenario("s", time.Second).Ops[0].Count; c != 4000 {
		t.Fatalf("count %d", c)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	r := NewRecorder()
	r.Observe("get", time.Millisecond, 200, "")
	r.Value("rss", 12.5, "MiB")
	run := Run{At: time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC), Machine: Machine{OS: "x", Cores: 4},
		Volume:    VolumeInfo{Shares: 3, ByKind: map[string]int{"file": 3}},
		Scenarios: []Scenario{r.Scenario("s", time.Second)}}
	path, err := Save(run, t.TempDir()+"/sub")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	var a, b bytes.Buffer
	run.Write(&a)
	got.Write(&b)
	if a.String() != b.String() || !got.At.Equal(run.At) || got.Volume.ByKind["file"] != 3 {
		t.Fatalf("round trip differs:\n%s\n%s", a.String(), b.String())
	}
}

func TestNotAvailablePrintsReasonNotZero(t *testing.T) {
	r := NewRecorder()
	r.NotAvailable("server memory", "server is remote")
	var buf bytes.Buffer
	Run{Scenarios: []Scenario{r.Scenario("mem", time.Second), {Name: "gone", Skipped: "no docker"}}}.Write(&buf)
	out := buf.String()
	if !strings.Contains(out, "server is remote") || strings.Contains(out, "server memory  0") || !strings.Contains(out, "skipped: no docker") {
		t.Fatalf("%s", out)
	}
}

func TestCompare(t *testing.T) {
	mk := func(p95 time.Duration, extra bool) Run {
		r := NewRecorder()
		r.Observe("get", p95, 200, "")
		if extra {
			r.Value("only after", 1, "x")
		}
		return Run{Scenarios: []Scenario{r.Scenario("s", time.Second)}}
	}
	var buf bytes.Buffer
	Compare(mk(100*time.Millisecond, false), mk(125*time.Millisecond, true), &buf)
	out := buf.String()
	if !strings.Contains(out, "+25.0%") {
		t.Fatalf("no change:\n%s", out)
	}
	var line string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "only after") {
			line = l
		}
	}
	if !strings.Contains(line, " -  ") || !strings.Contains(line, "1.00 x") {
		t.Fatalf("one-sided row %q", line)
	}
}

func TestSig3(t *testing.T) {
	for in, want := range map[time.Duration]string{1234567: "1.23ms", 999 * time.Microsecond: "999us", 12345 * time.Millisecond: "12.3s",
		999600: "1.00ms", 999_600_000: "1.00s", 999: "999ns", 1000: "1.00us", 99_960: "100us"} {
		if got := fmtDur(in); got != want {
			t.Errorf("%v: %s want %s", in, got, want)
		}
	}
	for in, want := range map[float64]string{999.6: "1000", 0.9996: "1.00", 1.234: "1.23", 0.01234: "0.0123", 123456: "123000", 99.96: "100"} {
		if got := sig3(in); got != want {
			t.Errorf("sig3(%v) = %s want %s", in, got, want)
		}
	}
}

func TestCountsPrintExactlyAndMeasuresToThreeFigures(t *testing.T) {
	for _, c := range []struct {
		v    Value
		want string
	}{
		{Value{V: 2, Unit: "pages"}, "2 pages"},
		{Value{V: 300412, Unit: "shares"}, "300412 shares"},
		{Value{V: 1234567, Unit: "requests"}, "1234567 requests"},
		{Value{V: 2.5, Unit: "watches"}, "2.50 watches"},
		{Value{V: 300412, Unit: "s"}, "300000 s"},
		{Value{V: 1234.5, Unit: "MiB/s"}, "1230 MiB/s"},
		{Value{V: 12.345, Unit: "MiB"}, "12.3 MiB"},
		{Value{V: 1234, Unit: "x"}, "1230 x"},
	} {
		if got := fmtValue(c.v); got != c.want {
			t.Errorf("%+v printed %q, want %q", c.v, got, c.want)
		}
	}
}

// line is the line of out whose first column is key.
func line(out, key string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, key+"  ") {
			return l
		}
	}
	return ""
}

func TestCompareShowsEveryScenarioAndEveryAnswer(t *testing.T) {
	before := NewRecorder()
	before.Observe("get", time.Millisecond, 200, "")
	before.Observe("get", time.Millisecond, 429, "")
	before.Value("seen", 1, "x")
	before.Value("seen", 2, "x")
	after := NewRecorder()
	after.Observe("get", time.Millisecond, 200, "")
	after.Observe("get", time.Millisecond, 503, "busy")
	after.Value("seen", 3, "x")
	after.Value("seen", 4, "x")
	b := Run{Scale: 1, Scenarios: []Scenario{
		before.Scenario("s", time.Second),
		{Name: "gone", Skipped: "no volume"},
		{Name: "both", Failed: "boom\nlast log lines:\nx"},
	}}
	a := Run{Scenarios: []Scenario{
		after.Scenario("s", time.Second),
		{Name: "both"},
		{Name: "new"},
	}}
	var buf bytes.Buffer
	Compare(b, a, &buf)
	out := buf.String()
	for key, want := range map[string][]string{
		"s / get answer 200":      {" 1 ", " 1 "},
		"s / get answer 429":      {" 1 ", " - "},
		"s / get answer 503 busy": {" - ", " 1 "},
		"s / seen":                {"1.00 x", "3.00 x", "+200.0%"},
		"s / seen #2":             {"2.00 x", "4.00 x", "+100.0%"},
		"gone":                    {"skipped: no volume", "not run"},
		"both":                    {"failed: boom", "completed"},
		"new":                     {"not run", "completed"},
	} {
		l := line(out, key)
		for _, w := range want {
			if !strings.Contains(l, w) {
				t.Errorf("row %q = %q, want %q in it", key, l, w)
			}
		}
	}
	if l := line(out, "s"); l != "" {
		t.Errorf("a scenario completed in both runs has a state row: %q", l)
	}
	if strings.Contains(out, "last log lines") {
		t.Errorf("a failure's state carries more than its first line:\n%s", out)
	}
	if !strings.Contains(out, "Settings: scale 1, scenarios all") || !strings.Contains(out, "Settings: scale unknown") {
		t.Errorf("the headers lack the settings:\n%s", out)
	}
	if !strings.Contains(out, "note: the runs differ in scale") {
		t.Errorf("no note on the scale:\n%s", out)
	}
}

func TestCompareNotesWhatDiffersAndNothingElse(t *testing.T) {
	base := Run{Machine: Machine{OS: "linux", Cores: 4}, Server: ServerInfo{Version: "1.0.0", Commit: "a"},
		Volume: VolumeInfo{Shares: 10, Files: 20, Seed: 1}, Scale: 1, Only: []string{"reads"}}
	other := base
	other.Server.Commit = "b"
	other.Only = nil
	var same bytes.Buffer
	Compare(base, other, &same)
	if strings.Contains(same.String(), "note:") {
		t.Fatalf("runs differing only in commit and scenarios carry a note:\n%s", same.String())
	}
	if !strings.Contains(same.String(), "scenarios reads") {
		t.Fatalf("the header does not name the scenarios asked for:\n%s", same.String())
	}
	other.Machine.Cores = 8
	other.Server.Version = "1.0.1"
	other.Volume.Seed = 2
	other.Scale = 0.5
	var diff bytes.Buffer
	Compare(base, other, &diff)
	for _, what := range []string{"machine", "server version", "volume", "scale"} {
		if !strings.Contains(diff.String(), "note: the runs differ in "+what+"\n") {
			t.Errorf("no note on the %s:\n%s", what, diff.String())
		}
	}
}

func TestWriteScenarioPrintsWhatWritePrintsForIt(t *testing.T) {
	r := NewRecorder()
	r.Observe("get", time.Millisecond, 200, "")
	sc := r.Scenario("s", time.Second)
	var head, whole, one bytes.Buffer
	Run{}.Write(&head)
	Run{Scenarios: []Scenario{sc}}.Write(&whole)
	WriteScenario(&one, sc)
	if head.String()+one.String() != whole.String() {
		t.Fatalf("header then WriteScenario:\n%s%s\nWrite:\n%s", head.String(), one.String(), whole.String())
	}
}

func TestATextValuePrintsItsWordAndComparesWithoutAChange(t *testing.T) {
	mk := func(word string) Run {
		r := NewRecorder()
		r.Text("recovered", word)
		return Run{Scenarios: []Scenario{r.Scenario("s", time.Second)}}
	}
	var one bytes.Buffer
	mk("no").Write(&one)
	if !strings.Contains(one.String(), "recovered  no") {
		t.Fatalf("the text value is not printed as its word:\n%s", one.String())
	}
	var cmp bytes.Buffer
	Compare(mk("yes"), mk("no"), &cmp)
	if l := line(cmp.String(), "s / recovered"); !strings.Contains(l, "yes") || !strings.Contains(l, "no") || !strings.HasSuffix(strings.TrimSpace(l), "-") {
		t.Fatalf("row %q", l)
	}
}

func TestSaveAsReplacesTheRunWholeAndLeavesNothingElse(t *testing.T) {
	dir := t.TempDir()
	run := Run{At: time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)}
	path, err := Save(run, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"one", "two"} {
		run.Scenarios = append(run.Scenarios, Scenario{Name: name})
		if err := SaveAs(run, path); err != nil {
			t.Fatal(err)
		}
		got, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Scenarios) != len(run.Scenarios) {
			t.Fatalf("saved %d scenarios, read back %d", len(run.Scenarios), len(got.Scenarios))
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("the results directory holds %v, want the run alone", entries)
	}
}
