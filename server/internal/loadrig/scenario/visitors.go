package scenario

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"hyperdrop/server/internal/loadrig/report"
	"hyperdrop/server/internal/loadrig/target"
	"hyperdrop/server/internal/loadrig/volume"
)

const (
	valVisitorShares  = "shares visited"
	valSampleVisitors = "visitors of a visited share"

	// visitorShares is how many shares the visitors are spread over.
	visitorShares = 64
	// visitorHold is how long each step runs.
	visitorHold = 20 * time.Second
	// visitCountWait is how long past the flush interval the visit count is
	// waited for.
	visitCountWait = 5 * time.Second
)

// visitorSteps are the concurrency steps below the per-address limit; a
// step of perAddressRequests per address follows when there is more than
// one address.
var visitorSteps = []int{16, 64, perAddressRequests}

func visitorOps(n int) (page, view, download string) {
	return fmt.Sprintf("page @%d", n), fmt.Sprintf("view @%d", n), fmt.Sprintf("download @%d", n)
}

func refusedName(n int) string { return fmt.Sprintf("refused @%d", n) }

var visitorsScenario = Scenario{
	Name: "visitors",
	About: "Anonymous visitors, each with its own cookies, spread over the source addresses and over 64 shares " +
		"(plain, gallery, folders and text, none protected or expired): each opens a share's page, follows it to " +
		"a file's view and downloads that file, in steps of 16, 64 and 128 visitors (and 128 per address when " +
		"there are several), each held 20 s. The load guard's limit of 128 running requests per address bounds " +
		"the largest step, and the report names it with the number of source addresses. Then one visited " +
		"share's visit count, once the server has written its visits.",
	Run: visitors,
}

// visitedShare is one share the visitors open, with the files its owner's
// read named.
type visitedShare struct {
	id      string
	files   map[string]int64 // slug -> size
	slugs   []string
	visited atomic.Bool
}

func visitors(ctx context.Context, e Env, rec *report.Recorder) error {
	specs := visitorSample(e.Plan, visitorShares)
	if len(specs) == 0 {
		return Skip("the plan holds no share a visitor can open")
	}
	probe := e.probe()
	defer probe.Close()
	shares := make([]*visitedShare, len(specs))
	tokens := make([]string, len(specs))
	for i, s := range specs {
		token, err := e.token(s.Owner)
		if err != nil {
			return err
		}
		r, err := readShare(ctx, probe, "probe", s.ID, token)
		if err != nil {
			return fmt.Errorf("reading share %s: %w", s.ID, err)
		}
		if len(r.Files) == 0 {
			return fmt.Errorf("share %s of %d files answered none", s.ID, s.Files)
		}
		v := &visitedShare{id: s.ID, files: map[string]int64{}}
		for _, f := range r.Files {
			v.files[f.Slug] = f.Size
			v.slugs = append(v.slugs, f.Slug)
		}
		shares[i], tokens[i] = v, token
	}
	rec.Value(valVisitorShares, float64(len(shares)), "shares")
	rec.Value(valSources, float64(e.addresses()), "addresses")
	rec.Value(valPerAddress, perAddressRequests, "requests")

	steps := append([]int(nil), visitorSteps...)
	if e.addresses() > 1 {
		steps = append(steps, perAddressRequests*e.addresses())
	}
	for _, n := range steps {
		if err := visitorStep(ctx, e, rec, shares, n); err != nil {
			return err
		}
	}
	sc := rec.Scenario("", 0)
	for _, n := range steps {
		page, view, download := visitorOps(n)
		refused, answers := 0, 0
		for _, o := range sc.Ops {
			if o.Name == page || o.Name == view || o.Name == download {
				refused += refusals(o)
				answers += o.Count
			}
		}
		if answers > 0 {
			rec.Value(refusedName(n), 100*float64(refused)/float64(answers), "%")
		}
	}

	for i, s := range shares {
		if s.visited.Load() {
			return visitCount(ctx, probe, rec, s.id, tokens[i])
		}
	}
	rec.Wrong(valSampleVisitors, "no visitor's page was answered, so no share was visited")
	return nil
}

// visitorStep runs n visitors for the hold.
func visitorStep(ctx context.Context, e Env, rec *report.Recorder, shares []*visitedShare, n int) error {
	pageOp, viewOp, downloadOp := visitorOps(n)
	jars := make([]*target.Client, n)
	visits := make([]int, n)
	return parallel(ctx, e, rec, n, until(time.Now().Add(e.hold(visitorHold))), func(w int, c *target.Client) error {
		if jars[w] == nil {
			jars[w] = c.WithJar()
		}
		k := visits[w]
		visits[w]++
		return visit(ctx, jars[w], shares[visitorShare(w, k, len(shares))], pageOp, viewOp, downloadOp)
	})
}

// visitorShare is which of shares visitor w opens on its k-th visit: each
// visitor moves on to the next share every visit, from a start of its own,
// so it reaches every share whatever the number of visitors.
func visitorShare(w, k, shares int) int { return (w + k) % shares }

// visit opens s's page, follows it to a file's view (the file the page
// redirects to, or one of the listing's), and downloads that file. A
// refusal by the server's limits ends the visit there.
func visit(ctx context.Context, c *target.Client, s *visitedShare, pageOp, viewOp, downloadOp string) error {
	var slug string
	refused := false
	err := c.Do(ctx, pageOp, http.MethodGet, "/share/"+s.id, "", nil, func(r *http.Response) error {
		switch r.StatusCode {
		case http.StatusTooManyRequests, http.StatusServiceUnavailable:
			refused = true
			return nil
		case http.StatusOK:
			if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
				return fmt.Errorf("answered %s", ct)
			}
			slug = s.slugs[len(s.slugs)/2]
		case http.StatusFound:
			var err error
			if slug, err = s.viewSlug(r.Header.Get("Location")); err != nil {
				return err
			}
		default:
			return fmt.Errorf("answered %d", r.StatusCode)
		}
		s.visited.Store(true)
		return nil
	})
	if err != nil || refused {
		return err
	}
	size := s.files[slug]
	if err := c.Do(ctx, viewOp, http.MethodGet, "/view/"+s.id+"/"+slug, "", nil, payload(size, &refused)); err != nil || refused {
		return err
	}
	return c.Do(ctx, downloadOp, http.MethodGet, "/download/"+s.id+"/"+slug, "", nil, payload(size, &refused))
}

// viewSlug is the slug of the file a page's redirect names, which must be
// one of the share's own.
func (s *visitedShare) viewSlug(location string) (string, error) {
	u, err := url.Parse(location)
	if err != nil {
		return "", fmt.Errorf("redirected to %q: %w", location, err)
	}
	slug, ok := strings.CutPrefix(u.Path, "/view/"+s.id+"/")
	if _, known := s.files[slug]; !ok || !known {
		return "", fmt.Errorf("redirected to %q, not a file of share %s", location, s.id)
	}
	return slug, nil
}

// payload is a check that a file answer carries the whole file, setting
// refused for a refusal by the server's limits.
func payload(size int64, refused *bool) func(*http.Response) error {
	return func(r *http.Response) error {
		switch r.StatusCode {
		case http.StatusTooManyRequests, http.StatusServiceUnavailable:
			*refused = true
			return nil
		case http.StatusOK:
		default:
			return fmt.Errorf("answered %d", r.StatusCode)
		}
		if r.ContentLength != size {
			return fmt.Errorf("a file of %d bytes answered %d", size, r.ContentLength)
		}
		return nil
	}
}

// visitCount reads share id's visit count through its owner until it is not
// zero, waiting past the server's visit flush; zero then is wrong.
func visitCount(ctx context.Context, c *target.Client, rec *report.Recorder, id, token string) error {
	deadline := time.Now().Add(visitFlushInterval + visitCountWait)
	for {
		s, err := readShare(ctx, c, "probe", id, token)
		if err != nil {
			return fmt.Errorf("reading share %s: %w", id, err)
		}
		if s.Visitors > 0 {
			rec.Value(valSampleVisitors, float64(s.Visitors), "visitors")
			return nil
		}
		if time.Now().After(deadline) {
			rec.Wrong(valSampleVisitors, fmt.Sprintf("share %s counts no visitor %s after the visits", id, visitFlushInterval+visitCountWait))
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// visitorSample is up to n shares a visitor can open, spread over the plan:
// plain, gallery, folders and text shares, none protected, expired or an
// inbox.
func visitorSample(p volume.Plan, n int) []volume.ShareSpec {
	var out []volume.ShareSpec
	next := 0
	for k := range n {
		i := max(next, k*p.Shares/n)
		for ; i < p.Shares; i++ {
			if s := p.Share(i); visitable(s, time.Now()) {
				out = append(out, s)
				break
			}
		}
		next = i + 1
	}
	return out
}

func visitable(s volume.ShareSpec, now time.Time) bool {
	switch s.Kind {
	case volume.Plain, volume.Gallery, volume.Folders, volume.Text:
		return s.ExpiresAt.IsZero() || s.ExpiresAt.After(now)
	}
	return false
}
