package scenario

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"hyperdrop/server/internal/loadrig/report"
	"hyperdrop/server/internal/loadrig/target"
	"hyperdrop/server/internal/loadrig/volume"
	"hyperdrop/server/internal/metadb"
)

const (
	opListPage         = "list page"
	opListSearch       = "list search"
	opWalkPage         = "walk page"
	opWalk             = "walk"
	opUsage            = "usage (/api/me)"
	opCapShare         = "share at file cap"
	opPublicListing    = "public listing page"
	opListPageParallel = "list page x16"
	opUsageParallel    = "usage (/api/me) x16"

	valWalkPages  = "walk pages"
	valWalkShares = "walk shares"

	// readsSerial is how many times each read runs one after another.
	readsSerial = 50
	// walksSerial is how many full walks run one after another: one walk of
	// the largest account at 1,000,000 shares is about 150 pages of several
	// MB each.
	walksSerial = 3
	// readsWorkers is how many clients read at once in the parallel part,
	// each as many times as a serial read.
	readsWorkers = 16
	// searchTerm is a word of every tenth planned share name.
	searchTerm = "invoice"
)

var readsScenario = Scenario{
	Name: "reads",
	About: "The largest account's reads on the full volume: its default listing page, a name search, " +
		"a full cursor walk at the page cap, its usage, one share at the file cap and that share's public page, " +
		"each one after another (the walk 3 times, the rest 50 times), then the listing page and usage from 16 clients at once. " +
		"A walk's time is the whole walk, its pages' requests and the rig decoding each page to read the next cursor.",
	Run: reads,
}

func reads(ctx context.Context, e Env, rec *report.Recorder) error {
	acct, err := e.largest()
	if err != nil {
		return err
	}
	c := e.client(rec, 0)
	defer c.Close()
	n := e.times(readsSerial)

	listPage := func(c *target.Client, op string) error { return firstPage(ctx, c, op, acct.Token) }
	usage := func(c *target.Client, op string) error { return me(ctx, c, op, acct.Token, acct.Name) }
	search := func() error {
		return c.Do(ctx, opListSearch, http.MethodGet, "/api/shares?q="+searchTerm, acct.Token, nil, func(r *http.Response) error {
			p, err := readListPage(r)
			if err != nil {
				return err
			}
			for _, name := range p.names {
				if !strings.Contains(strings.ToLower(name), searchTerm) {
					return fmt.Errorf("search for %q answered %q", searchTerm, name)
				}
			}
			return p.within(metadb.DefaultListLimit)
		})
	}

	if err := repeat(ctx, e, count(n), func() error { return listPage(c, opListPage) }); err != nil {
		return err
	}
	if err := repeat(ctx, e, count(n), search); err != nil {
		return err
	}
	first := true
	if err := repeat(ctx, e, count(e.times(walksSerial)), func() error {
		w, err := walk(ctx, c, rec, acct.Token, readsWalk)
		if err == nil && first {
			first = false
			rec.Value(valWalkPages, float64(w.pages), "pages")
			if w.cut {
				rec.NotAvailable(valWalkShares, "a page longer than the client keeps was cut before its rows were counted")
			} else {
				rec.Value(valWalkShares, float64(w.rows), "shares")
			}
		}
		return err
	}); err != nil {
		return err
	}
	if err := repeat(ctx, e, count(n), func() error { return usage(c, opUsage) }); err != nil {
		return err
	}

	capShare, ok := e.find(func(s volume.ShareSpec) bool { return s.Files == e.Plan.FileCap && s.Owner == acct.Name })
	if !ok {
		rec.NotAvailable(opCapShare, acct.Name+" owns no share at the file cap")
	} else {
		if err := repeat(ctx, e, count(n), func() error {
			s, err := readShare(ctx, c, opCapShare, capShare.ID, acct.Token)
			if err == nil && (s.FileCount != e.Plan.FileCap || len(s.Files) != e.Plan.FileCap) {
				rec.Wrong(opCapShare, fmt.Sprintf("a share of %d files answered fileCount %d with %d entries", e.Plan.FileCap, s.FileCount, len(s.Files)))
			}
			return err
		}); err != nil {
			return err
		}
		if err := repeat(ctx, e, count(n), func() error {
			return c.Do(ctx, opPublicListing, http.MethodGet, "/share/"+capShare.ID, "", nil, func(r *http.Response) error {
				if r.StatusCode != http.StatusOK {
					return fmt.Errorf("answered %d", r.StatusCode)
				}
				if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
					return fmt.Errorf("answered %s", ct)
				}
				return nil
			})
		}); err != nil {
			return err
		}
	}

	if err := parallel(ctx, e, rec, readsWorkers, count(n), func(_ int, c *target.Client) error { return listPage(c, opListPageParallel) }); err != nil {
		return err
	}
	return parallel(ctx, e, rec, readsWorkers, count(n), func(_ int, c *target.Client) error { return usage(c, opUsageParallel) })
}

// firstPage is the account's default listing page through c, checked
// against the default limit.
func firstPage(ctx context.Context, c *target.Client, op, token string) error {
	return c.Do(ctx, op, http.MethodGet, "/api/shares", token, nil, func(r *http.Response) error {
		p, err := readListPage(r)
		if err != nil {
			return err
		}
		return p.within(metadb.DefaultListLimit)
	})
}

// me is account name's GET /api/me through c, which must answer for name.
func me(ctx context.Context, c *target.Client, op, token, name string) error {
	return c.Do(ctx, op, http.MethodGet, "/api/me", token, nil, func(r *http.Response) error {
		var got struct {
			Username string `json:"username"`
		}
		if err := decodeOK(r, &got); err != nil {
			return err
		}
		if got.Username != name {
			return fmt.Errorf("signed in as %s, answered for %q", name, got.Username)
		}
		return nil
	})
}

type walked struct {
	pages, rows int
	// distinct is how many share ids the walk answered, each counted once.
	distinct int
	// total is the listing's own count from its first page, -1 when no page
	// carried one.
	total int
	// cut is set when a page was longer than the client keeps, so its rows
	// were not all counted.
	cut bool
}

// walkOps names what a walk records: each page, and the whole walk.
type walkOps struct{ page, whole string }

var readsWalk = walkOps{page: opWalkPage, whole: opWalk}

// walk pages through the account's whole listing by cursor at the page cap,
// recording each page under ops.page and the whole walk under ops.whole. A
// share answered twice, or a walk whose rows differ from the listing's
// total, is wrong.
func walk(ctx context.Context, c *target.Client, rec *report.Recorder, token string, ops walkOps) (walked, error) {
	w := walked{total: -1}
	seen := map[string]bool{}
	after := ""
	began := time.Now()
	for {
		path := "/api/shares?limit=" + strconv.Itoa(metadb.MaxListLimit)
		if after != "" {
			path += "&after=" + url.QueryEscape(after)
		}
		var p listPage
		err := c.Do(ctx, ops.page, http.MethodGet, path, token, nil, func(r *http.Response) error {
			var err error
			if p, err = readListPage(r); err != nil {
				return err
			}
			return p.within(metadb.MaxListLimit)
		})
		if err != nil {
			return w, err
		}
		w.pages++
		w.cut = w.cut || p.cut
		if w.total < 0 && p.hasTotal {
			w.total = p.total
		}
		for _, id := range p.ids {
			if seen[id] {
				rec.Wrong(ops.whole, "share "+id+" answered on two pages")
			}
			seen[id] = true
		}
		w.rows += len(p.ids)
		if p.next == "" {
			break
		}
		after = p.next
	}
	w.distinct = len(seen)
	rec.Observe(ops.whole, time.Since(began), http.StatusOK, "")
	if !w.cut && w.total >= 0 && w.rows != w.total {
		rec.Wrong(ops.whole, fmt.Sprintf("the walk answered %d shares of a listing of %d", w.rows, w.total))
	}
	return w, nil
}

// listPage is what the scenarios read of one GET /api/shares answer.
type listPage struct {
	next     string
	total    int
	hasTotal bool
	ids      []string
	names    []string
	// cut is set when the answer was longer than the client keeps; the page
	// holds what was read before the cut.
	cut bool
}

// within checks a whole page against the limit it was asked for.
func (p listPage) within(limit int) error {
	if p.cut {
		return nil
	}
	if !p.hasTotal {
		return fmt.Errorf("no total")
	}
	if len(p.ids) > limit {
		return fmt.Errorf("%d rows for a limit of %d", len(p.ids), limit)
	}
	if p.total > 0 && len(p.ids) == 0 {
		return fmt.Errorf("no rows of %d", p.total)
	}
	return nil
}

// readListPage decodes a listing answer field by field, so an answer cut at
// the client's keep limit still yields what precedes the cut. The server
// writes the answer from a map, whose keys encoding/json sorts: nextCursor
// comes before shares, so a cut page still names the page after it.
func readListPage(r *http.Response) (listPage, error) {
	var p listPage
	if r.StatusCode != http.StatusOK {
		return p, fmt.Errorf("answered %d", r.StatusCode)
	}
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return p, err
	}
	p.cut = int64(len(b)) < r.ContentLength
	if err := p.decode(json.NewDecoder(bytes.NewReader(b))); err != nil && !p.cut {
		return p, fmt.Errorf("body: %w", err)
	}
	return p, nil
}

func (p *listPage) decode(dec *json.Decoder) error {
	if err := expectDelim(dec, '{'); err != nil {
		return err
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		switch tok {
		case "nextCursor":
			err = dec.Decode(&p.next)
		case "total":
			err = dec.Decode(&p.total)
			p.hasTotal = err == nil
		case "shares":
			err = p.decodeRows(dec)
		default:
			var skip json.RawMessage
			err = dec.Decode(&skip)
		}
		if err != nil {
			return err
		}
	}
	return expectDelim(dec, '}')
}

func (p *listPage) decodeRows(dec *json.Decoder) error {
	if err := expectDelim(dec, '['); err != nil {
		return err
	}
	for dec.More() {
		var row struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if err := dec.Decode(&row); err != nil {
			return err
		}
		p.ids = append(p.ids, row.ID)
		p.names = append(p.names, row.Name)
	}
	return expectDelim(dec, ']')
}

func expectDelim(dec *json.Decoder, want json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok != want {
		return fmt.Errorf("found %v where %v belongs", tok, want)
	}
	return nil
}
