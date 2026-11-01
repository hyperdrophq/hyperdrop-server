package webapp

import (
	"context"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net/http"
	"net/url"
	"sync"
	"time"

	"hyperdrop/core/webbundle"
	"hyperdrop/server/internal/selfupdate"
)

// DefaultBase is where the website publishes the web release manifest and
// bundles.
const DefaultBase = "https://gethyperdrop.com/downloads/web/"

const (
	maxManifest = 1 << 20
	maxArchive  = 64 << 20
	maxSig      = 4 << 10
)

// ResolveBase answers where the web manifest is read from, "" turning
// fetching off: HYPERDROP_WEB_RELEASES (web) when set, even to ""; else, when
// HYPERDROP_SERVER_RELEASES (server) is set, the web directory beside it
// ("../web/" against it), "" when it is ""; else DefaultBase. Each is
// validated as selfupdate.ParseBase validates the server's.
func ResolveBase(web string, webSet bool, server string, serverSet bool) (string, error) {
	switch {
	case webSet:
		b, err := selfupdate.ParseBase(web)
		if err != nil {
			return "", fmt.Errorf("HYPERDROP_WEB_RELEASES: %w", err)
		}
		return b, nil
	case serverSet:
		b, err := selfupdate.ParseBase(server)
		if err != nil {
			return "", fmt.Errorf("HYPERDROP_SERVER_RELEASES: %w", err)
		}
		if b == "" {
			return "", nil
		}
		u, err := url.Parse(b)
		if err != nil {
			return "", fmt.Errorf("HYPERDROP_SERVER_RELEASES: %w", err)
		}
		return selfupdate.ParseBase(u.ResolveReference(&url.URL{Path: "../web/"}).String())
	}
	return selfupdate.ParseBase(DefaultBase)
}

// FetchStatus is what the last fetch found: the version of the release it
// picked, or of the current install when that outranks the pick (keeps); ""
// when the manifest offers none for this server, or was never read; when the
// manifest was last read, and why the last run failed ("" when it did not).
type FetchStatus struct {
	Latest    string
	CheckedAt time.Time
	Failed    string
}

// Fetcher reads the web manifest and installs the bundle webbundle.Pick
// chooses for this server.
type Fetcher struct {
	st   *Store
	base string
	http *http.Client

	run    sync.Mutex // one run at a time
	mu     sync.Mutex
	status FetchStatus
	policy Policy
	nudge  chan struct{}

	// The schedule: the first run firstDelay after Start, then every `every`
	// plus up to `spread`, so servers do not all ask at once.
	firstDelay, every, spread time.Duration
}

// NewFetcher fetches into st from base (ResolveBase's answer; "" never
// fetches). client is copied, its redirects held to base's origin; nil uses a
// client with a five-minute timeout.
func NewFetcher(st *Store, base string, client *http.Client) *Fetcher {
	hc := http.Client{Timeout: 5 * time.Minute}
	if client != nil {
		hc = *client
	}
	hc.CheckRedirect = selfupdate.SameOrigin(base)
	return &Fetcher{
		st: st, base: base, http: &hc, nudge: make(chan struct{}, 1),
		firstDelay: 30 * time.Second, every: 24 * time.Hour, spread: time.Hour,
	}
}

// Trigger is why the Start loop is about to fetch.
type Trigger int

const (
	// TriggerBoot is the first run after Start.
	TriggerBoot Trigger = iota + 1
	// TriggerDaily is each later scheduled run.
	TriggerDaily
	// TriggerAsked is a Nudge: an administrator's act asked for a fetch.
	TriggerAsked
)

// Policy decides whether the Start loop fetches for a trigger.
type Policy interface {
	// Allow reports whether a run for t goes ahead.
	Allow(t Trigger) bool
	// Fetched is called after a run that returned no error.
	Fetched()
}

// SetPolicy sets the policy the Start loop consults before each run; nil
// fetches on every trigger. Run itself is unconditional.
func (f *Fetcher) SetPolicy(p Policy) {
	f.mu.Lock()
	f.policy = p
	f.mu.Unlock()
}

func (f *Fetcher) currentPolicy() Policy {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.policy
}

// Start runs the fetch on its schedule until ctx ends, and whenever Nudge
// asks, each run subject to the policy. A Fetcher with no base never starts.
func (f *Fetcher) Start(ctx context.Context) {
	if f.base == "" {
		return
	}
	go func() {
		wait := f.firstDelay
		trigger := TriggerBoot
		for {
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-f.nudge:
				t.Stop()
				trigger = TriggerAsked
			case <-t.C:
			}
			p := f.currentPolicy()
			if p == nil || p.Allow(trigger) {
				if err := f.Run(ctx); err != nil {
					if ctx.Err() == nil {
						log.Printf("web client: %v", err)
					}
				} else if p != nil {
					p.Fetched()
				}
			}
			trigger = TriggerDaily
			wait = f.every
			if f.spread > 0 {
				wait += time.Duration(rand.Int64N(int64(f.spread))) // #nosec G404 -- a schedule spread, not a secret
			}
		}
	}()
}

// Nudge runs a fetch now, as TriggerAsked.
func (f *Fetcher) Nudge() {
	select {
	case f.nudge <- struct{}{}:
	default:
	}
}

// Status is what the last run found.
func (f *Fetcher) Status() FetchStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status
}

// Run reads the manifest, picks this server's bundle and installs it unless
// that version and build is already current. A failure is returned and kept
// in Status until a run succeeds.
func (f *Fetcher) Run(ctx context.Context) error {
	if f.base == "" {
		return nil
	}
	f.run.Lock()
	defer f.run.Unlock()

	body, err := f.get(ctx, f.base+"releases.json", maxManifest)
	if err == nil {
		var m webbundle.Manifest
		if m, err = webbundle.ParseManifest(body); err == nil {
			r, ok := webbundle.Pick(m, f.st.contract)
			f.mu.Lock()
			f.status.CheckedAt, f.status.Latest = time.Now(), ""
			if ok {
				f.status.Latest = r.Version
				if cur, keep := f.keeps(r); keep {
					f.status.Latest = cur.Version
				}
			}
			f.mu.Unlock()
			if ok {
				err = f.install(ctx, r)
			}
		}
	}
	if err != nil {
		err = fmt.Errorf("fetching the web version from %s: %w", f.base, err)
	}
	f.mu.Lock()
	f.status.Failed = ""
	if err != nil {
		f.status.Failed = err.Error()
	}
	f.mu.Unlock()
	return err
}

// keeps answers the current install when the fetcher leaves it in place of
// r: r is that install, or older than it while it still serves this server
// (webbundle.Serves). The fetcher moves to an older bundle only when the
// current one no longer serves the server's contract, as after the server
// went back a minor. An admin's PUT /api/server/web installs through the
// Store and may install an older bundle.
func (f *Fetcher) keeps(r webbundle.Release) (Installed, bool) {
	cur, ok := f.st.installed()
	if !ok {
		return Installed{}, false
	}
	same := cur.Version == r.Version && cur.Build == r.Build
	newer := webbundle.Serves(cur.Contract, f.st.contract) && webbundle.Newer(cur.Version, cur.Build, r.Version, r.Build)
	return cur, same || newer
}

func (f *Fetcher) install(ctx context.Context, r webbundle.Release) error {
	if _, keep := f.keeps(r); keep {
		return nil
	}
	if r.Size <= 0 || r.Size > maxArchive {
		return fmt.Errorf("the web version %s is %d bytes, outside the %d byte limit", r.Version, r.Size, maxArchive)
	}
	archiveURL, err := f.resolve(r.URL)
	if err != nil {
		return err
	}
	sigURL, err := f.resolve(r.Sig)
	if err != nil {
		return err
	}
	archive, err := f.get(ctx, archiveURL, maxArchive)
	if err != nil {
		return err
	}
	sig, err := f.get(ctx, sigURL, maxSig)
	if err != nil {
		return err
	}
	if err := f.st.Install(archive, sig, r.Version, r.Build, r.Contract); err != nil {
		return fmt.Errorf("installing the web version %s build %d: %w", r.Version, r.Build, err)
	}
	log.Printf("web client: installed the web version %s build %d", r.Version, r.Build)
	return nil
}

// resolve reads a manifest URL relative to the base, refusing one on another
// origin: the manifest is unsigned, so it names nothing the server dials
// beyond where the manifest itself came from.
func (f *Fetcher) resolve(ref string) (string, error) {
	base, err := url.Parse(f.base)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(ref)
	if err != nil || ref == "" {
		return "", fmt.Errorf("the manifest names %q, which is not a URL", ref)
	}
	abs := base.ResolveReference(u)
	if abs.Scheme != base.Scheme || abs.Host != base.Host || abs.User != nil {
		return "", fmt.Errorf("the manifest names %s, outside %s", abs.Redacted(), f.base)
	}
	return abs.String(), nil
}

// get fetches u, refusing a body over limit bytes.
func (f *Fetcher) get(ctx context.Context, u string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "hyperdrop-server/"+f.st.contract)
	resp, err := f.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %s", u, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%s is over %d bytes", u, limit)
	}
	return body, nil
}
