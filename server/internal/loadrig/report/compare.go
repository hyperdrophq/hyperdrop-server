package report

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
)

type number struct {
	text string
	v    float64
	ok   bool
}

// row is one line of a comparison: a number, or a scenario's state, whose
// side missing from a run prints as "not run" rather than "-".
type row struct {
	key   string
	state bool
	nums  map[int]number
}

type comparison struct {
	rows  []*row
	index map[string]*row
}

func (c *comparison) add(side int, key string, state bool, n number) {
	r := c.index[key]
	if r == nil {
		r = &row{key: key, state: state, nums: map[int]number{}}
		c.index[key] = r
		c.rows = append(c.rows, r)
	}
	r.nums[side] = n
}

// Compare prints both runs' headers, a note for each way the runs differ
// that bears on their numbers, and then every number of both runs side by
// side with the change in percent. A number present in one run only shows
// "-" for the other. A scenario that is in one run only, or was skipped or
// failed in either, gets a line of its own with each side's state, and only
// a completed scenario's numbers are compared. It states no verdict and
// refuses nothing.
func Compare(before, after Run, w io.Writer) {
	fmt.Fprintln(w, "Before:")
	before.writeHeader(w)
	fmt.Fprintln(w, "After:")
	after.writeHeader(w)
	for _, d := range differences(before, after) {
		fmt.Fprintf(w, "note: the runs differ in %s\n", d)
	}
	fmt.Fprintln(w)

	c := &comparison{index: map[string]*row{}}
	for side, run := range []Run{before, after} {
		for _, sc := range run.Scenarios {
			c.add(side, sc.Name, true, number{text: state(sc)})
			if sc.Skipped != "" || sc.Failed != "" {
				continue
			}
			for _, o := range sc.Ops {
				p := sc.Name + " / " + o.Name + " "
				c.add(side, p+"count", false, number{fmt.Sprint(o.Count), float64(o.Count), true})
				c.add(side, p+"wrong", false, number{fmt.Sprint(o.Wrong), float64(o.Wrong), true})
				c.add(side, p+"per s", false, number{sig3(o.PerSecond), o.PerSecond, true})
				for _, d := range []struct {
					n string
					v time.Duration
				}{{"p50", o.P50}, {"p95", o.P95}, {"p99", o.P99}, {"max", o.Max}} {
					c.add(side, p+d.n, false, number{fmtDur(d.v), float64(d.v), true})
				}
				for _, k := range sortedKeys(o.ByAnswer) {
					n := o.ByAnswer[k]
					c.add(side, p+"answer "+k, false, number{fmt.Sprint(n), float64(n), true})
				}
			}
			seen := map[string]int{}
			for _, v := range sc.Values {
				key := sc.Name + " / " + v.Name
				if seen[key]++; seen[key] > 1 {
					key += fmt.Sprintf(" #%d", seen[key])
				}
				if v.NotAvailable != "" || v.Text != "" {
					c.add(side, key, false, number{text: fmtValue(v)})
					continue
				}
				c.add(side, key, false, number{fmtValue(v), v.V, true})
			}
		}
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "number\tbefore (%s)\tafter (%s)\tchange\n", before.At.UTC().Format(time.RFC3339), after.At.UTC().Format(time.RFC3339))
	for _, r := range c.rows {
		b, hasB := r.nums[0]
		a, hasA := r.nums[1]
		if r.state && hasB && hasA && b.text == completed && a.text == completed {
			continue
		}
		missing := "-"
		if r.state {
			missing = "not run"
		}
		bt, at, ch := missing, missing, "-"
		if hasB {
			bt = b.text
		}
		if hasA {
			at = a.text
		}
		if hasB && hasA && b.ok && a.ok && b.v != 0 {
			ch = fmt.Sprintf("%+.1f%%", (a.v-b.v)/b.v*100)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.key, bt, at, ch)
	}
	tw.Flush()
}

const completed = "completed"

// state is how a scenario ended: completed, skipped with its reason, or
// failed with the first line of its reason.
func state(sc Scenario) string {
	switch {
	case sc.Skipped != "":
		return "skipped: " + sc.Skipped
	case sc.Failed != "":
		first, _, _ := strings.Cut(sc.Failed, "\n")
		return "failed: " + first
	}
	return completed
}

// differences names what differs between two runs that bears on their
// numbers: the machine, the server's version, the volume and the scale.
func differences(before, after Run) []string {
	var out []string
	if before.Machine != after.Machine {
		out = append(out, "machine")
	}
	if before.Server.Version != after.Server.Version {
		out = append(out, "server version")
	}
	bv, av := before.Volume, after.Volume
	if bv.Shares != av.Shares || bv.Files != av.Files || bv.Accounts != av.Accounts || bv.Seed != av.Seed {
		out = append(out, "volume")
	}
	if before.Scale != after.Scale {
		out = append(out, "scale")
	}
	return out
}
