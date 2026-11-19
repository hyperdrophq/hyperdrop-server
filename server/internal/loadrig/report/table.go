package report

import (
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

// Write prints the run's header and then its scenarios as plain tables, one
// per scenario.
func (r Run) Write(w io.Writer) {
	r.writeHeader(w)
	for _, sc := range r.Scenarios {
		WriteScenario(w, sc)
	}
}

// WriteScenario prints one scenario's table after a blank line, as Write
// prints each.
func WriteScenario(w io.Writer, sc Scenario) {
	fmt.Fprintln(w)
	sc.write(w)
}

// writeHeader prints when the run was, the machine, the server, the volume
// and the run's settings.
func (r Run) writeHeader(w io.Writer) {
	fmt.Fprintf(w, "Run at %s\n", r.At.UTC().Format(time.RFC3339))
	m := r.Machine
	fmt.Fprintf(w, "Machine: %s/%s, %d cores", m.OS, m.Arch, m.Cores)
	if m.CPU != "" {
		fmt.Fprintf(w, ", %s", m.CPU)
	}
	if m.MemoryBytes > 0 {
		fmt.Fprintf(w, ", %.1f GiB memory", float64(m.MemoryBytes)/(1<<30))
	}
	if m.FileSystem != "" {
		fmt.Fprintf(w, ", file system %s", m.FileSystem)
	}
	fmt.Fprintln(w)
	s := r.Server
	commit := s.Commit
	if commit == "" {
		commit = "unknown"
	}
	fmt.Fprintf(w, "Server: version %s, commit %s, %s, local %t\n", orDash(s.Version), commit, orDash(s.BaseURL), s.Local)
	v := r.Volume
	fmt.Fprintf(w, "Volume: %d shares, %d files, %d accounts, seed %d", v.Shares, v.Files, v.Accounts, v.Seed)
	for _, k := range sortedKeys(v.ByKind) {
		fmt.Fprintf(w, ", %s %d", k, v.ByKind[k])
	}
	fmt.Fprintln(w)
	scale := "unknown"
	if r.Scale > 0 {
		scale = strconv.FormatFloat(r.Scale, 'g', -1, 64)
	}
	only := "all"
	if len(r.Only) > 0 {
		only = strings.Join(r.Only, ", ")
	}
	fmt.Fprintf(w, "Settings: scale %s, scenarios %s\n", scale, only)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func (sc Scenario) write(w io.Writer) {
	fmt.Fprintf(w, "== %s ==\n", sc.Name)
	if sc.Skipped != "" {
		fmt.Fprintf(w, "skipped: %s\n", sc.Skipped)
		return
	}
	if sc.Failed != "" {
		fmt.Fprintf(w, "failed: %s\n", sc.Failed)
		return
	}
	if len(sc.Ops) > 0 {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "op\tcount\twrong\tper s\tp50\tp95\tp99\tmax\tanswers")
		for _, o := range sc.Ops {
			var as []string
			for _, k := range sortedKeys(o.ByAnswer) {
				as = append(as, fmt.Sprintf("%s x%d", k, o.ByAnswer[k]))
			}
			fmt.Fprintf(tw, "%s\t%d\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n", o.Name, o.Count, o.Wrong,
				sig3(o.PerSecond), fmtDur(o.P50), fmtDur(o.P95), fmtDur(o.P99), fmtDur(o.Max), strings.Join(as, ", "))
		}
		tw.Flush()
		for _, o := range sc.Ops {
			for _, why := range o.WrongReasons {
				fmt.Fprintf(w, "wrong %s: %s\n", o.Name, why)
			}
		}
	}
	if len(sc.Values) > 0 {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for _, v := range sc.Values {
			fmt.Fprintf(tw, "%s\t%s\n", v.Name, fmtValue(v))
		}
		tw.Flush()
	}
}

func fmtValue(v Value) string {
	if v.NotAvailable != "" {
		return "not available: " + v.NotAvailable
	}
	if v.Text != "" {
		return v.Text
	}
	n := sig3(v.V)
	if counts(v.Unit) && v.V == math.Trunc(v.V) && math.Abs(v.V) < 1<<53 {
		n = strconv.FormatFloat(v.V, 'f', 0, 64)
	}
	if v.Unit == "" {
		return n
	}
	return n + " " + v.Unit
}

// counts reports whether unit counts things (pages, shares, requests),
// whose whole values print exactly. A time, a size, a ratio, a percentage
// or a rate (any unit with a "/") is a measure, printed to three
// significant figures.
func counts(unit string) bool {
	switch unit {
	case "", "s", "ms", "us", "MiB", "GiB", "x", "%":
		return false
	}
	return !strings.Contains(unit, "/")
}

// round3 rounds f to three significant figures.
func round3(f float64) float64 {
	mag := int(math.Floor(math.Log10(math.Abs(f))))
	if mag >= 2 {
		p := math.Pow(10, float64(mag-2))
		return math.Round(f/p) * p
	}
	p := math.Pow(10, float64(2-mag))
	return math.Round(f*p) / p
}

// sig3 formats a number to three significant figures without exponents.
// It rounds before it chooses the decimals, so 999.6 prints as 1000.
func sig3(f float64) string {
	if f == 0 || math.IsNaN(f) || math.IsInf(f, 0) {
		return fmt.Sprintf("%g", f)
	}
	f = round3(f)
	dec := 2 - int(math.Floor(math.Log10(math.Abs(f))))
	if dec < 0 {
		return fmt.Sprintf("%.0f", f)
	}
	return fmt.Sprintf("%.*f", dec, f)
}

// fmtDur formats a duration to three significant figures in its natural
// unit, chosen after rounding, so 999.6us prints as 1.00ms.
func fmtDur(d time.Duration) string {
	if d < time.Microsecond {
		return fmt.Sprintf("%dns", int64(d))
	}
	r := round3(float64(d))
	switch {
	case r < 1e6:
		return sig3(r/1e3) + "us"
	case r < 1e9:
		return sig3(r/1e6) + "ms"
	}
	return sig3(r/1e9) + "s"
}
