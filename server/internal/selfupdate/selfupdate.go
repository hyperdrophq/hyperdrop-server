// Package selfupdate keeps a Linux box on the newest signed release on its
// own. Once a day it reads the website's server manifest; when a newer
// release exists, automatic updates are on and the running binary is an
// official build (Config.Official), it downloads the binary for
// this host's arch, checks the manifest's length and SHA-256, the
// decompression bound and the release signature, and stages it through the
// same function the update route uses, where the root installer's
// verify-update (the binary already installed) decides again. It also
// derives what an admin is told: whether an update is available, whether
// the box updates itself, and the reminders due (core/updatenotice).
//
// Its state is five server settings (metadb meta, "setting:" keys): the
// switch, the attempt in flight (written BEFORE staging), the first failed
// download of a newer release, the last failure and the last successful
// self-update.
package selfupdate

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"hyperdrop/core/releasemanifest"
	"hyperdrop/core/updatenotice"
	"hyperdrop/server/internal/updatesig"
)

// DefaultBase is where the website publishes the server manifest and the
// binaries (HYPERDROP_SERVER_RELEASES overrides it).
const DefaultBase = releasemanifest.DefaultBase

const (
	// CheckEvery is the daily check; each one is moved by up to an hour so
	// boxes do not all ask at once.
	CheckEvery = 24 * time.Hour
	// SettleAfter is how long the root installer gets to swap, restart and
	// health-check a staged release (it waits up to 90 s, then as long
	// again for a rollback) before the attempt counts as failed.
	SettleAfter = 10 * time.Minute
	// StallAfter turns a newer release that cannot be downloaded into a
	// failure: the website being briefly away is not one.
	StallAfter = 48 * time.Hour
	// DoneShown is how long a successful self-update stays in Activity.
	DoneShown = 14 * 24 * time.Hour

	maxManifest = 1 << 20
	maxBinary   = 64 << 20 // gzipped; a real release is around 8 MB
)

// maxRaw bounds what a download may decompress to.
var maxRaw int64 = 256 << 20

const (
	keyAuto     = "selfupdate.auto"     // "off" when turned off or a new volume started off; absent = on
	keyAttempt  = "selfupdate.attempt"  // Attempt, while a staged release waits for the installer
	keyFailed   = "selfupdate.failed"   // Failure
	keyDone     = "selfupdate.done"     // Done
	keyRetrying = "selfupdate.retrying" // attempt: the first failed download of a newer release
)

// Store keeps the settings (*metadb.DB).
type Store interface {
	Setting(key string) (string, bool, error)
	SetSetting(key, value string) error
	DeleteSetting(key string) error
}

// Config is what a Checker needs.
type Config struct {
	Base     string // the manifest's directory, ending in "/"; "" never checks
	HTTP     *http.Client
	Version  string // running
	Arch     string // runtime.GOARCH
	Channel  string // "synology": Package Center owns the binary
	CanStage func() bool
	Store    Store
	Stage    func(raw, sig []byte) error
	Keys     []string
	Now      func() time.Time

	// Official is true in a binary HyperDrop's build scripts made. Any
	// other build reads the manifest and reports what it finds, as a box
	// that cannot install on its own does, and never installs a release
	// itself: replacing a fork with the official build is its admin's
	// choice (Update Server), never the daily check's.
	Official bool
}

type attempt struct {
	From    string    `json:"from"`
	Version string    `json:"version"`
	At      time.Time `json:"at"`
}

// Failure is the newest release that did not install itself, and why.
type Failure struct {
	Version string    `json:"version"`
	Reason  string    `json:"reason"`
	At      time.Time `json:"at"`
}

// Done is a self-update that came up.
type Done struct {
	From string    `json:"from"`
	To   string    `json:"to"`
	At   time.Time `json:"at"`
}

// Facts is what an admin reads (GET /api/server/settings).
type Facts struct {
	AutoUpdate      bool
	SelfUpdate      string // updatenotice.On, Off, NAS, Failed, Manual
	Latest          string // "" until the manifest was read
	UpdateAvailable bool
	CheckedAt       time.Time
	Failed          *Failure
	LastAutoUpdate  *Done
	Notices         []updatenotice.Notice
}

// Checker is the daily check and the state behind it.
type Checker struct {
	cfg       Config
	mu        sync.Mutex
	manifest  *releasemanifest.Manifest
	checkedAt time.Time
	nudge     chan struct{}
	cancel    context.CancelFunc
	done      chan struct{}
}

// New builds a Checker; Start runs it.
func New(cfg Config) *Checker {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	hc := http.Client{Timeout: 5 * time.Minute}
	if cfg.HTTP != nil {
		hc = *cfg.HTTP
	}
	hc.CheckRedirect = sameOrigin(cfg.Base)
	cfg.HTTP = &hc
	if cfg.CanStage == nil {
		cfg.CanStage = func() bool { return false }
	}
	return &Checker{cfg: cfg, nudge: make(chan struct{}, 1)}
}

// ParseBase reads HYPERDROP_SERVER_RELEASES: "" turns checking off;
// otherwise an absolute https URL (plain http only to a loopback host, the
// e2e scenario's manifest on the box itself), answered ending in "/".
func ParseBase(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("%q is not an absolute URL without credentials or a query", raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		host := u.Hostname()
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return "", fmt.Errorf("%q: plain http is accepted only to a loopback host", raw)
		}
	default:
		return "", fmt.Errorf("%q is not an https URL", raw)
	}
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	return u.String(), nil
}

// sameOrigin refuses a redirect that leaves the base's scheme and host: the
// manifest is unsigned, so a hop to plain http or to another host could
// invent a release, its date and the reminders that follow from them.
func sameOrigin(base string) func(*http.Request, []*http.Request) error {
	b, err := url.Parse(base)
	return func(req *http.Request, via []*http.Request) error {
		if err != nil || req.URL.Scheme != b.Scheme || req.URL.Host != b.Host {
			return fmt.Errorf("refusing a redirect to %s: it leaves %s", req.URL.Redacted(), base)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
}

// permanent is an install failure waiting will not fix: the published
// bytes or signature do not hold, the release lacks this arch, or staging
// refused. Anything else is retried on the next check.
type permanent struct{ error }

func (p permanent) Unwrap() error { return p.error }

// Start settles what the last run left and, when checking is on, runs the
// daily check: the first a few minutes after boot, then every day, and
// every minute while a staged release waits for the installer.
func (c *Checker) Start() {
	c.Settle()
	if c.cfg.Base == "" {
		return
	}
	if !c.cfg.Official && c.cfg.Channel != "synology" && c.cfg.CanStage() {
		log.Printf("self-update: not an official HyperDrop build, so newer releases are reported and never installed on their own")
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel, c.done = cancel, make(chan struct{})
	go func() {
		defer close(c.done)
		wait := 2*time.Minute + jitter(30*time.Minute)
		for {
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-c.nudge:
				t.Stop()
			case <-t.C:
			}
			if c.pending() {
				c.Settle()
			} else if err := c.Check(ctx); err != nil && ctx.Err() == nil {
				log.Printf("self-update: %v", err)
			}
			wait = CheckEvery + jitter(time.Hour)
			if c.pending() {
				wait = time.Minute
			}
		}
	}()
}

// Stop ends the loop and waits for a check in flight.
func (c *Checker) Stop() {
	if c.cancel == nil {
		return
	}
	c.cancel()
	<-c.done
}

// Nudge runs a check now (an admin turned automatic updates on).
func (c *Checker) Nudge() {
	select {
	case c.nudge <- struct{}{}:
	default:
	}
}

// jitter spreads the fleet's checks; it needs no unpredictability.
func jitter(limit time.Duration) time.Duration {
	return time.Duration(rand.Int64N(int64(limit))) // #nosec G404 -- a schedule spread, not a secret
}

// SetAuto turns automatic updates on or off. Turning them on forgets a
// failure, so the next check (started now) tries the newest release again.
func (c *Checker) SetAuto(on bool) error {
	if err := Switch(c.cfg.Store, on); err != nil {
		return err
	}
	if on {
		c.Nudge()
	}
	return nil
}

// Switch turns automatic updates on or off in s, as SetAuto does, for a
// process that runs no Checker: the operator's auto-update command, beside
// a running server that learns of it through Reread.
func Switch(s Store, on bool) error {
	if !on {
		return s.SetSetting(keyAuto, "off")
	}
	for _, key := range []string{keyAuto, keyFailed, keyRetrying} {
		if err := s.DeleteSetting(key); err != nil {
			return err
		}
	}
	return nil
}

// AutoIn reports whether automatic updates are on in s.
func AutoIn(s Store) (bool, error) {
	v, ok, err := s.Setting(keyAuto)
	if err != nil {
		return false, err
	}
	return !ok || v != "off", nil
}

// Reread checks now when automatic updates are on, for a switch another
// process turned in the store (the operator's command, then SIGUSR1).
func (c *Checker) Reread() {
	if c.auto() {
		c.Nudge()
	}
}

// ParseChoice reads HYPERDROP_AUTO_UPDATE, whether a new volume starts with
// automatic updates on: "1", "on" or "true" turns them on; unset, "", "0",
// "off" or "false" leaves them off. Anything else is an error.
func ParseChoice(raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "on", "true":
		return true, nil
	case "", "0", "off", "false":
		return false, nil
	}
	return false, fmt.Errorf("%q is not on or off (1, on, true; 0, off, false)", raw)
}

// StartWith records a new volume's choice. Off is stored; on is the switch's
// absence, which is also how every volume made before the choice existed
// reads, so such a volume keeps updating itself. On clears an off an earlier,
// unfinished first boot stored.
func StartWith(s Store, on bool) error {
	if on {
		return s.DeleteSetting(keyAuto)
	}
	return s.SetSetting(keyAuto, "off")
}

// Settle resolves what the last staging left: a running version at or
// above the attempt is a self-update done; an attempt the installer has not
// brought up within SettleAfter is a failure (refused or rolled back). A
// failure of a version this box has since reached is forgotten.
func (c *Checker) Settle() {
	now := c.cfg.Now()
	var a attempt
	if c.load(keyAttempt, &a) {
		switch {
		// The attempt is forgotten only once its outcome is recorded, so a
		// store that refuses the record leaves the attempt for the next
		// Settle to record.
		case !releasemanifest.Less(c.cfg.Version, a.Version):
			if c.save(keyDone, Done{From: a.From, To: c.cfg.Version, At: now}) == nil {
				c.forget(keyAttempt)
			}
		case now.Sub(a.At) >= SettleAfter:
			if c.save(keyFailed, Failure{Version: a.Version, At: now,
				Reason: "the installer did not bring it up, so the box kept " + c.cfg.Version}) == nil {
				c.forget(keyAttempt)
			}
		}
	}
	var f Failure
	if c.load(keyFailed, &f) && !releasemanifest.Less(c.cfg.Version, f.Version) {
		c.forget(keyFailed)
	}
}

// Check reads the manifest and, when the box updates itself, installs the
// newest release (a build that is not official only reads it). An error is a
// check that did not complete (logged); a failed install is also recorded
// and reported through Facts.
func (c *Checker) Check(ctx context.Context) error {
	c.Settle()
	if c.cfg.Base == "" {
		return nil
	}
	body, err := c.get(ctx, c.cfg.Base+"releases.json", maxManifest)
	if err != nil {
		return fmt.Errorf("reading the server releases at %s: %w", c.cfg.Base, err)
	}
	m, err := releasemanifest.Parse(body)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.manifest, c.checkedAt = &m, c.cfg.Now()
	c.mu.Unlock()
	return c.maybeInstall(ctx, m)
}

func (c *Checker) maybeInstall(ctx context.Context, m releasemanifest.Manifest) error {
	r, ok := m.Newest()
	if !ok || !releasemanifest.Less(c.cfg.Version, r.Version) {
		c.forget(keyRetrying)
		return nil
	}
	if c.state(r.Version) != updatenotice.On || c.pending() {
		return nil
	}
	err := c.install(ctx, r)
	if err == nil {
		return nil
	}
	var p permanent
	if !errors.As(err, &p) {
		var first attempt
		if !c.load(keyRetrying, &first) || first.Version != r.Version {
			// save logs a refused record; the retry clock then starts on the
			// next check that records it.
			_ = c.save(keyRetrying, attempt{From: c.cfg.Version, Version: r.Version, At: c.cfg.Now()})
			return err
		}
		if c.cfg.Now().Sub(first.At) < StallAfter {
			return err
		}
		err = fmt.Errorf("it could not be downloaded for two days (%v)", err)
	}
	c.forget(keyRetrying)
	// save logs a refused record, and the error is returned either way.
	_ = c.save(keyFailed, Failure{Version: r.Version, Reason: err.Error(), At: c.cfg.Now()})
	return err
}

func (c *Checker) install(ctx context.Context, r releasemanifest.Release) error {
	f, ok := r.Linux[c.cfg.Arch]
	if !ok || f.Length <= 0 {
		return permanent{fmt.Errorf("HyperDrop Server %s has no %s build", r.Version, c.cfg.Arch)}
	}
	if f.Length > maxBinary {
		return permanent{fmt.Errorf("HyperDrop Server %s for %s is %d bytes, over the %d byte limit", r.Version, c.cfg.Arch, f.Length, maxBinary)}
	}
	name := releasemanifest.BinaryName(r.Version, c.cfg.Arch)
	gz, err := c.get(ctx, c.cfg.Base+name, f.Length+1)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", name, err)
	}
	if err := releasemanifest.CheckDigest(name, gz, f); err != nil {
		return permanent{err}
	}
	sig, err := c.get(ctx, c.cfg.Base+name+".sig", updatesig.MaxSize)
	if err != nil {
		return fmt.Errorf("downloading the signature of %s: %w", name, err)
	}
	raw, err := gunzip(gz)
	if err != nil {
		return permanent{fmt.Errorf("%s %w", name, err)}
	}
	st, err := updatesig.Verify(c.cfg.Keys, sig, bytes.NewReader(raw), c.cfg.Arch, c.cfg.Version)
	if err != nil {
		return permanent{err}
	}
	if st.Version != r.Version {
		return permanent{fmt.Errorf("%s is signed as %s", name, st.Version)}
	}
	// Recorded BEFORE staging: a crash between the two leaves an attempt
	// that Settle resolves, never a staged binary nobody accounts for.
	if err := c.save(keyAttempt, attempt{From: c.cfg.Version, Version: r.Version, At: c.cfg.Now()}); err != nil {
		return err
	}
	if err := c.cfg.Stage(raw, sig); err != nil {
		c.forget(keyAttempt)
		return permanent{fmt.Errorf("staging %s: %w", r.Version, err)}
	}
	c.forget(keyRetrying)
	log.Printf("self-update: staged HyperDrop Server %s; the root installer swaps it in", r.Version)
	return nil
}

// Facts answers what an admin is shown now.
func (c *Checker) Facts() Facts {
	now := c.cfg.Now()
	c.mu.Lock()
	m, checked := c.manifest, c.checkedAt
	c.mu.Unlock()
	f := Facts{AutoUpdate: c.auto(), CheckedAt: checked}
	if m != nil {
		if r, ok := m.Newest(); ok {
			f.Latest = r.Version
			f.UpdateAvailable = releasemanifest.Less(c.cfg.Version, r.Version)
		}
	}
	f.SelfUpdate = c.state(f.Latest)
	var fail Failure
	if f.SelfUpdate == updatenotice.Failed && c.load(keyFailed, &fail) {
		f.Failed = &fail
	}
	var d Done
	if c.load(keyDone, &d) && now.Sub(d.At) < DoneShown {
		f.LastAutoUpdate = &d
	}
	nf := updatenotice.Facts{Running: c.cfg.Version, Latest: f.Latest, SelfUpdate: f.SelfUpdate}
	if f.Failed != nil {
		nf.FailedVersion, nf.FailedReason = f.Failed.Version, f.Failed.Reason
	}
	f.Notices = updatenotice.Due(nf)
	return f
}

// Unsupported answers why automatic updates cannot be switched on this box
// ("" when they can): Package Center owns a NAS's binary, a box with no
// installer unit or no manifest to read cannot install on its own, and a
// build that is not official does not.
func (c *Checker) Unsupported() string {
	switch c.state("") {
	case updatenotice.NAS:
		return "this server is updated in Package Center"
	case updatenotice.Manual:
		if c.cfg.Base != "" && c.cfg.CanStage() && !c.cfg.Official {
			return "this server is not an official HyperDrop build, so it does not install updates on its own"
		}
		return "this server cannot install updates on its own"
	}
	return ""
}

func (c *Checker) state(latest string) string {
	switch {
	case c.cfg.Channel == "synology":
		return updatenotice.NAS
	case c.cfg.Base == "" || !c.cfg.CanStage() || !c.cfg.Official:
		return updatenotice.Manual
	case !c.auto():
		return updatenotice.Off
	}
	// A failure holds back the release it names, and only while that is the
	// newest the manifest offers: a newer release is tried, and a failed
	// release the manifest no longer offers holds back nothing.
	var f Failure
	if c.load(keyFailed, &f) && (latest == "" || f.Version == latest) {
		return updatenotice.Failed
	}
	return updatenotice.On
}

func (c *Checker) auto() bool {
	v, ok, err := c.cfg.Store.Setting(keyAuto)
	return err != nil || !ok || v != "off"
}

func (c *Checker) pending() bool {
	var a attempt
	return c.load(keyAttempt, &a)
}

func (c *Checker) load(key string, v any) bool {
	raw, ok, err := c.cfg.Store.Setting(key)
	if err != nil || !ok {
		return false
	}
	return json.Unmarshal([]byte(raw), v) == nil
}

func (c *Checker) save(key string, v any) error {
	raw, err := json.Marshal(v)
	if err == nil {
		err = c.cfg.Store.SetSetting(key, string(raw))
	}
	if err != nil {
		log.Printf("self-update: remember %s: %v", key, err)
	}
	return err
}

func (c *Checker) forget(key string) {
	if err := c.cfg.Store.DeleteSetting(key); err != nil {
		log.Printf("self-update: forget %s: %v", key, err)
	}
}

// get fetches at most limit bytes; a longer body is cut there, which the
// caller's own check (the manifest parse, the digest, the signature) refuses.
func (c *Checker) get(ctx context.Context, u string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "hyperdrop-server/"+c.cfg.Version)
	resp, err := c.cfg.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %s", u, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

// gunzip refuses data that is not gzip and a decompression past maxRaw: the
// manifest's checksum covers the gzip bytes only.
func gunzip(gz []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, fmt.Errorf("is not a gzip file: %w", err)
	}
	defer zr.Close()
	raw, err := io.ReadAll(io.LimitReader(zr, maxRaw+1))
	if err != nil {
		return nil, fmt.Errorf("could not decompress: %w", err)
	}
	if int64(len(raw)) > maxRaw {
		return nil, fmt.Errorf("decompresses to more than the %d byte limit", maxRaw)
	}
	return raw, nil
}
