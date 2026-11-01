package ddns

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"
)

const activityLimit = 256

type Event struct {
	At      int64  `json:"at"`
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

type HostStatus struct {
	Host        string   `json:"host"`
	DNS         string   `json:"dns"`
	Addresses   []string `json:"addresses,omitempty"`
	IPv6Present bool     `json:"ipv6Present,omitempty"`
	HTTPS       string   `json:"https"`
	ExpiresAt   int64    `json:"expiresAt,omitempty"`
	CheckedAt   int64    `json:"checkedAt"`
	// ForeignLeaf reports a pinned probe that was presented a leaf other
	// than the pin: the one proof that another server answers there. It is
	// never part of the status document.
	ForeignLeaf bool `json:"-"`
}

type Connectivity struct {
	Mode              string       `json:"mode"`
	Domain            string       `json:"domain"`
	Provider          string       `json:"provider,omitempty"`
	ProviderZone      string       `json:"providerZone,omitempty"`
	RecipeVersion     int          `json:"recipeVersion,omitempty"`
	PublicIP          string       `json:"publicIP,omitempty"`
	PreviousIP        string       `json:"previousIP,omitempty"`
	ChangedAt         int64        `json:"changedAt,omitempty"`
	LastCheck         int64        `json:"lastCheck,omitempty"`
	LastAttempt       int64        `json:"lastAttempt,omitempty"`
	LastSuccess       int64        `json:"lastSuccess,omitempty"`
	NextAttempt       int64        `json:"nextAttempt,omitempty"`
	LastError         string       `json:"lastError,omitempty"`
	Failures          int          `json:"failures"`
	IncidentAt        int64        `json:"incidentAt,omitempty"`
	Alert             bool         `json:"alert"`
	NotificationError string       `json:"notificationError,omitempty"`
	Hosts             []HostStatus `json:"hosts,omitempty"`
	Events            []Event      `json:"events,omitempty"`
}

func (s *Store) change(f func(*State)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.st
	next.Connectivity.Events = append([]Event(nil), s.st.Connectivity.Events...)
	f(&next)
	return s.commit(next)
}

func addEvent(c *Connectivity, at int64, kind, message string) {
	message = strings.ReplaceAll(message, "\n", " ")
	if len(message) > 512 {
		cut := 512
		for cut > 0 && !utf8.RuneStart(message[cut]) {
			cut--
		}
		message = message[:cut]
	}
	events := make([]Event, 0, activityLimit)
	for _, e := range c.Events {
		if e.At >= at-30*24*3600 {
			events = append(events, e)
		}
	}
	events = append(events, Event{At: at, Kind: kind, Message: message})
	if len(events) > activityLimit {
		events = events[len(events)-activityLimit:]
	}
	c.Events = events
}

func (u *Updater) Connectivity() Connectivity {
	st := u.store.Snapshot()
	c := st.Connectivity
	if u.Domain != nil {
		c.Domain = u.Domain()
	}
	c.Mode = "external"
	if st.Name != "" {
		c.Mode = "hyperdrop"
	} else if st.Custom != nil {
		c.Mode = st.Custom.Mode
		c.Provider, c.ProviderZone, c.RecipeVersion = st.Custom.Provider, st.Custom.ProviderZone, st.Custom.RecipeVersion
	}
	return c
}

// ErrPrivateRecipe refuses a recipe that asks for private destinations on a
// server whose operator has not allowed them (Updater.PrivateRecipes).
var ErrPrivateRecipe = errors.New("allowPrivate needs the server's operator to set HYPERDROP_DDNS_ALLOW_PRIVATE=1")

func (u *Updater) ConfigureHTTP(config HTTPConfig) error {
	if err := config.Validate(); err != nil {
		return err
	}
	if config.AllowPrivate && !u.PrivateRecipes {
		return ErrPrivateRecipe
	}
	u.tickMu.Lock()
	defer u.tickMu.Unlock()
	st := u.store.Snapshot()
	if st.Name != "" {
		return errors.New("disconnect the managed name after switching to a custom domain first")
	}
	if u.Domain == nil || u.Domain() != config.Domain {
		return errors.New("configure this server's custom domain before enabling DDNS")
	}
	// Configuration values become immutable once saved. Copy caller maps.
	b, _ := json.Marshal(config)
	var clone HTTPConfig
	_ = json.Unmarshal(b, &clone)
	err := u.store.change(func(s *State) {
		s.Custom = &clone
		s.AddressRefusedAt = 0
		s.Connectivity = Connectivity{Mode: config.Mode, Domain: config.Domain,
			Provider: config.Provider, ProviderZone: config.ProviderZone, RecipeVersion: config.RecipeVersion,
			Events: s.Connectivity.Events}
		addEvent(&s.Connectivity, u.Now().Unix(), "configured", "DNS management configured: "+config.Mode)
	})
	if err == nil {
		u.failStreak = 0
		u.backoffUntil = time.Time{}
	}
	return err
}

func (u *Updater) observe(ip string, now int64) error {
	return u.store.change(func(s *State) {
		c := &s.Connectivity
		c.LastCheck = now
		if ip != "" && ip != c.PublicIP {
			c.PreviousIP = c.PublicIP
			c.PublicIP = ip
			c.ChangedAt = now
			addEvent(c, now, "ip-changed", "Public IPv4 changed from "+c.PreviousIP+" to "+ip)
		}
	})
}

func (u *Updater) failure(ctx context.Context, code string, next int64, terminal bool) error {
	now := u.Now().Unix()
	wasAlert := u.store.Snapshot().Connectivity.Alert
	err := u.store.change(func(s *State) {
		c := &s.Connectivity
		c.Failures++
		c.LastError = code
		addEvent(c, now, "failure", code)
		if !watched(*s) {
			// An administrator's check of a server that is not watched:
			// no retry follows it, so it schedules none and opens no
			// incident.
			c.NextAttempt, c.IncidentAt, c.Alert = 0, 0, false
			return
		}
		c.NextAttempt = next
		if c.IncidentAt == 0 {
			c.IncidentAt = now
		}
		c.Alert = terminal || now-c.IncidentAt >= 15*60
	})
	if err == nil && !wasAlert && u.store.Snapshot().Connectivity.Alert {
		u.notify(ctx, "failure", code)
	}
	return err
}

func (u *Updater) healthy(ctx context.Context) error {
	now := u.Now().Unix()
	old := u.store.Snapshot().Connectivity
	err := u.store.change(func(s *State) {
		c := &s.Connectivity
		c.Failures = 0
		c.LastError = ""
		c.NextAttempt = now + int64(TickInterval/time.Second)
		if !watched(*s) {
			c.NextAttempt = 0
		}
		c.IncidentAt = 0
		c.Alert = false
		if old.LastError != "" {
			addEvent(c, now, "recovered", "DNS and HTTPS checks recovered")
		}
	})
	if err == nil && old.Alert {
		u.notify(ctx, "recovery", "DNS and HTTPS checks recovered")
	}
	return err
}

func (u *Updater) notify(ctx context.Context, event, message string) {
	s := u.store.Snapshot()
	if s.Custom == nil || s.Custom.Notify == nil {
		return
	}
	vars := recipeVars(s.Custom, s.Connectivity.PublicIP, s.Connectivity.PreviousIP)
	vars["event"] = event
	vars["message"] = message
	hc := recipeClient(s.Custom.AllowPrivate && u.PrivateRecipes)
	defer hc.CloseIdleConnections()
	err := executeRequest(ctx, hc, *s.Custom.Notify, vars, 1)
	_ = u.store.change(func(s *State) {
		s.Connectivity.NotificationError = ""
		var failure *RequestFailure
		switch {
		case errors.As(err, &failure) && failure.Code == "private-destination" && s.Custom != nil &&
			s.Custom.AllowPrivate && !u.PrivateRecipes:
			s.Connectivity.NotificationError = "Notification webhook failed: " + ErrPrivateRecipe.Error()
			addEvent(&s.Connectivity, u.Now().Unix(), "notification-failed", s.Connectivity.NotificationError)
		case err != nil:
			s.Connectivity.NotificationError = "Notification webhook failed"
			addEvent(&s.Connectivity, u.Now().Unix(), "notification-failed", "Notification webhook failed; see its endpoint and credentials")
		}
	})
}

// stepAccepted labels one accepted request in the activity log. A generated
// recipe names its steps, so the log reads as what happened rather than as a
// step number; a hand-written recipe need not, and keeps the number.
func stepAccepted(name string, index int) string {
	if name != "" {
		return name + ": accepted"
	}
	return fmt.Sprintf("DDNS request %d accepted", index+1)
}

func recipeVars(c *HTTPConfig, ip, previous string) map[string]string {
	vars := map[string]string{"ipv4": ip, "previous_ipv4": previous, "domain": c.Domain, "files_domain": "files." + c.Domain, "event": "", "message": ""}
	for k, v := range c.Secrets {
		vars[k] = v
	}
	return vars
}

func (u *Updater) customTick(ctx context.Context) error {
	s := u.store.Snapshot()
	now := u.Now().Unix()
	if now < s.Connectivity.NextAttempt && s.Connectivity.LastError != "" {
		return nil
	}
	ip, known := u.addr(ctx)
	if !known {
		_ = u.observe("", now)
		return u.failure(ctx, "Public IPv4 observation failed", now+300, false)
	}
	if err := u.observe(ip, now); err != nil {
		return err
	}
	c := s.Custom
	if c != nil && u.Domain != nil && c.Domain != u.Domain() {
		return u.failure(ctx, "DDNS configuration belongs to a different domain; reconfigure it", now+3600, true)
	}
	custom := c != nil && c.Mode == "custom"
	if custom {
		if c.CredentialExpiresAt > 0 && now >= c.CredentialExpiresAt {
			return u.failure(ctx, "DDNS credentials have expired", now+3600, true)
		}
		// Reconcile every twelve hours, including records edited elsewhere.
		lastProbe := s.LastProbe
		if s.Pending {
			lastProbe = s.CustomLastProbe
		}
		changed := s.Connectivity.LastSuccess != 0 && ip != lastProbe
		if changed && s.VerifiedIP != "" && ip != s.VerifiedIP {
			if refusal := u.refuseAddress(ctx, s, ip); refusal != "" {
				if err := u.store.change(func(s *State) {
					s.AddressRefusedAt = now
					addEvent(&s.Connectivity, now, "address-refused", refusal)
				}); err != nil {
					return err
				}
				// The refusal ends the tick before check, so the records
				// published last are probed here: when they point at an
				// unverified address where another certificate answers,
				// they move back to the verified one.
				if lastProbe != "" && lastProbe != s.VerifiedIP && u.addressAnswersElsewhere(ctx, lastProbe) {
					return u.rollBack(ctx, c, lastProbe, s.VerifiedIP, now)
				}
				return u.failure(ctx, refusal, now+3600, true)
			}
		}
		due := s.Connectivity.LastSuccess == 0 || changed || now-s.Connectivity.LastSuccess >= int64(Heartbeat/time.Second)
		if due {
			if err := u.store.change(func(s *State) {
				s.Connectivity.LastAttempt = now
				addEvent(&s.Connectivity, now, "update-started", "Updating custom DNS records")
			}); err != nil {
				return err
			}
			if f, err := u.runRecipe(ctx, c, ip, s.Connectivity.PreviousIP, s.Connectivity.Failures, now); f != nil {
				_ = u.failure(ctx, f.reason, f.wait, f.terminal)
				return f.err
			} else if err != nil {
				return err
			}
			if err := u.store.change(func(s *State) {
				if s.Pending {
					s.CustomLastProbe = ip
				} else {
					s.LastProbe = ip
				}
				s.Connectivity.LastSuccess = now
				s.Connectivity.NextAttempt = 0
				addEvent(&s.Connectivity, now, "update-accepted", "Provider accepted all requests; checking DNS and HTTPS")
			}); err != nil {
				return err
			}
		}
	}
	hosts, foreign, err := u.check(ctx, ip)
	if err != nil {
		return err
	}
	if custom && foreign {
		st := u.store.Snapshot()
		published := st.LastProbe
		if st.Pending {
			published = st.CustomLastProbe
		}
		if st.VerifiedIP != "" && ip != st.VerifiedIP && published == ip {
			return u.rollBack(ctx, c, ip, st.VerifiedIP, now)
		}
	}
	return u.judge(ctx, hosts)
}

// refuseAddress answers why the reported address ip must not be published,
// or "" when it may be. The names service's observation is trusted only as
// far as this server can prove it answers there: an address where another
// certificate answers is refused, and after a refusal or a rollback
// (AddressRefusedAt) so is any address that does not answer with this
// server's own certificate. Outside that state an address that does not
// answer at all publishes, because a router without hairpin NAT cannot
// reach its own public address.
func (u *Updater) refuseAddress(ctx context.Context, s State, ip string) string {
	if s.AddressRefusedAt != 0 {
		if u.addressProvesItself(ctx, ip) {
			return ""
		}
		return "The names service reported " + ip + ", where this server could not prove it answers; DNS stays on " + s.VerifiedIP
	}
	if u.addressAnswersElsewhere(ctx, ip) {
		return "The names service reported " + ip + ", where another server answers with its own certificate; DNS stays on " + s.VerifiedIP
	}
	return ""
}

// rollBack puts the records back on verified, the last address where both
// hosts answered with this server's certificate, after a check found
// another certificate at reported, where they point now. The tick ends in a
// terminal failure either way: if the provider refuses, the records still
// point at reported and the next due tick finds the mismatch again.
func (u *Updater) rollBack(ctx context.Context, c *HTTPConfig, reported, verified string, now int64) error {
	s := u.store.Snapshot()
	if f, err := u.runRecipe(ctx, c, verified, reported, s.Connectivity.Failures, now); f != nil || err != nil {
		reason := "Another server answers at " + reported + " with its own certificate, and moving DNS back to " + verified + " failed"
		if err := u.store.change(func(s *State) {
			s.AddressRefusedAt = now
			addEvent(&s.Connectivity, now, "address-rolled-back", reason)
		}); err != nil {
			return err
		}
		wait := now + 300
		if f != nil {
			wait = f.wait
			err = f.err
		}
		_ = u.failure(ctx, reason, wait, true)
		return err
	}
	reason := "Another server answers at " + reported + " with its own certificate; DNS moved back to " + verified
	if err := u.store.change(func(s *State) {
		if s.Pending {
			s.CustomLastProbe = verified
		} else {
			s.LastProbe = verified
		}
		s.AddressRefusedAt = now
		addEvent(&s.Connectivity, now, "address-rolled-back", reason)
	}); err != nil {
		return err
	}
	return u.failure(ctx, reason, now+3600, true)
}

// recipeFailure is a request of the recipe the provider refused: the reason
// to record, when to try again, and whether only a person can fix it.
type recipeFailure struct {
	reason   string
	wait     int64
	terminal bool
	err      error
}

// runRecipe sends every request of c's recipe with ipv4 = ip and
// previous_ipv4 = previous, logging each accepted one. It answers the first
// refusal, or an error writing the activity log.
func (u *Updater) runRecipe(ctx context.Context, c *HTTPConfig, ip, previous string, failures int, now int64) (*recipeFailure, error) {
	hc := recipeClient(c.AllowPrivate && u.PrivateRecipes)
	if u.RecipeHTTP != nil {
		hc = u.RecipeHTTP
	}
	defer hc.CloseIdleConnections()
	vars := recipeVars(c, ip, previous)
	for i, step := range c.Requests {
		err := executeRequest(ctx, hc, step, vars, i+1)
		if err != nil {
			f := &recipeFailure{reason: err.Error(), wait: u.Now().Add(backoffFor(failures + 1)).Unix(), err: err}
			var failure *RequestFailure
			if errors.As(err, &failure) {
				if failure.RetryAt > f.wait {
					f.wait = failure.RetryAt
				}
				f.terminal = failure.Code == "credentials-rejected" || failure.Code == "invalid-template"
				if failure.Code == "private-destination" && c.AllowPrivate && !u.PrivateRecipes {
					// A recipe stored with allowPrivate on a server
					// whose operator has not allowed it: the reason
					// names the switch, which only the operator holds.
					f.reason = fmt.Sprintf("DDNS request %d: %v", failure.Step, ErrPrivateRecipe)
					f.terminal = true
				}
			}
			return f, nil
		}
		if err := u.store.change(func(s *State) {
			addEvent(&s.Connectivity, now, "request-succeeded", stepAccepted(step.Name, i))
		}); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

func (u *Updater) verify(ctx context.Context, ip string) error {
	hosts, _, err := u.check(ctx, ip)
	if err != nil {
		return err
	}
	return u.judge(ctx, hosts)
}

func (u *Updater) hostNames() []string {
	if u.Domain == nil || u.Domain() == "" {
		return nil
	}
	domain := u.Domain()
	return []string{domain, "files." + domain}
}

// pinFor is the leaf certificate this process serves for host, DER-encoded,
// or nil when it holds none for it yet (a first boot whose certificate
// waits for the records): a nil pin probes as any trusted certificate.
func (u *Updater) pinFor(host string) []byte {
	if u.LocalLeaf == nil {
		return nil
	}
	return u.LocalLeaf(host)
}

func (u *Updater) serverID() string {
	if u.ServerID == nil {
		return ""
	}
	return u.ServerID()
}

// probe checks host at ip, pinned to the leaf this process serves for it,
// and reports whether a pin applied. withDNS selects the full probeHost;
// without it only HTTPS at the address is checked, which is what a check
// before the records move can ask. A certificate renewed while the probe
// ran is read again once, so this server's fresh leaf is never taken for
// another server's.
func (u *Updater) probe(ctx context.Context, host, ip string, withDNS bool, now int64) (HostStatus, bool) {
	run := func(pin []byte) HostStatus {
		switch {
		case u.ProbeHost != nil:
			return u.ProbeHost(ctx, host, ip, pin)
		case withDNS:
			return probeHost(ctx, host, ip, u.serverID(), pin, now)
		}
		out := HostStatus{Host: host, DNS: "unknown", CheckedAt: now}
		out.HTTPS, out.ExpiresAt, out.ForeignLeaf = probeHTTPS(ctx, host, ip, u.serverID(), pin)
		return out
	}
	pin := u.pinFor(host)
	h := run(pin)
	if pin != nil && h.ForeignLeaf {
		if fresh := u.pinFor(host); fresh != nil && !bytes.Equal(fresh, pin) {
			pin = fresh
			h = run(pin)
		}
	}
	return h, pin != nil
}

// addressAnswersElsewhere reports whether a pinned probe of either host at
// ip reaches a server presenting a certificate other than this server's.
// An address where nothing answers, where no pin applies, or where this
// server's own certificate answers without a healthy /api/health, is not
// one.
func (u *Updater) addressAnswersElsewhere(ctx context.Context, ip string) bool {
	now := u.Now().Unix()
	for _, host := range u.hostNames() {
		if h, pinned := u.probe(ctx, host, ip, false, now); pinned && h.ForeignLeaf {
			return true
		}
	}
	return false
}

// addressProvesItself reports whether both hosts answer at ip with this
// server's own certificate.
func (u *Updater) addressProvesItself(ctx context.Context, ip string) bool {
	now := u.Now().Unix()
	hosts := u.hostNames()
	for _, host := range hosts {
		if h, pinned := u.probe(ctx, host, ip, false, now); !pinned || h.HTTPS != "valid" {
			return false
		}
	}
	return len(hosts) > 0
}

// check probes both hosts at ip and records what it found. foreign reports
// a pinned probe that was presented another server's leaf; this server's
// own leaf in front of a failing /api/health is a host not healthy yet,
// which the tick retries. Both hosts valid under a pin
// record ip as the last verified address and end the strict state that a
// refusal or a rollback began.
func (u *Updater) check(ctx context.Context, ip string) (hosts []HostStatus, foreign bool, err error) {
	names := u.hostNames()
	if names == nil {
		return nil, false, nil
	}
	now := u.Now().Unix()
	proven := true
	for _, host := range names {
		h, pinned := u.probe(ctx, host, ip, true, now)
		hosts = append(hosts, h)
		if pinned && h.ForeignLeaf {
			foreign = true
		}
		if !pinned || h.HTTPS != "valid" {
			proven = false
		}
	}
	before := u.store.Snapshot().Connectivity.Hosts
	if err := u.store.change(func(s *State) {
		s.Connectivity.Hosts = hosts
		for i, h := range hosts {
			if i >= len(before) || h.DNS != before[i].DNS || h.HTTPS != before[i].HTTPS {
				addEvent(&s.Connectivity, now, "verification", h.Host+": DNS "+h.DNS+", HTTPS "+h.HTTPS)
			}
		}
		if proven && s.Custom != nil {
			s.VerifiedIP = ip
			s.AddressRefusedAt = 0
		}
	}); err != nil {
		return nil, false, err
	}
	return hosts, foreign, nil
}

// judge turns a check's hosts into the tick's outcome.
func (u *Updater) judge(ctx context.Context, hosts []HostStatus) error {
	if hosts == nil {
		return nil
	}
	now := u.Now().Unix()
	for _, h := range hosts {
		if h.IPv6Present {
			return u.failure(ctx, "AAAA records are present; IPv6 reachability is not verified", now+300, false)
		}
		if h.DNS != "current" && h.DNS != "unknown" {
			return u.failure(ctx, h.Host+": DNS has not reached the observed IPv4", now+300, false)
		}
		if h.HTTPS != "valid" {
			return u.failure(ctx, h.Host+": HTTPS "+h.HTTPS, now+300, false)
		}
		if h.ExpiresAt > 0 && h.ExpiresAt-now < 24*3600 {
			return u.failure(ctx, h.Host+": certificate expires within 24 hours", now+300, true)
		}
	}
	if c := u.store.Snapshot().Custom; c != nil && c.CredentialExpiresAt > 0 && c.CredentialExpiresAt-now < 7*24*3600 {
		return u.failure(ctx, "DDNS credentials expire within 7 days", now+300, true)
	}
	return u.healthy(ctx)
}

// hostLookups are the resolvers probeHost asks, in order, until one answers
// (an address list or a definite "no such name"): two public resolvers, so
// the verdict is what the internet sees rather than a local override, then
// the system's own, for a network that blocks DNS to public resolvers.
var hostLookups = []func(context.Context, string) ([]netip.Addr, error){
	publicLookup("1.1.1.1:53"),
	publicLookup("8.8.8.8:53"),
	func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	},
}

func publicLookup(resolverIP string) func(context.Context, string) ([]netip.Addr, error) {
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, resolverIP)
	}}
	return func(ctx context.Context, host string) ([]netip.Addr, error) {
		return resolver.LookupNetIP(ctx, "ip", host)
	}
}

// probeRoots and probeAddress are the probe's seams for tests: a nil pool
// is the system's roots, and the address dialled for ip is its port 443.
var (
	probeRoots   *x509.CertPool
	probeAddress = func(ip string) string { return net.JoinHostPort(ip, "443") }
)

// This is explicitly a check FROM THE SERVER. It does not claim to prove
// inbound internet reachability through a home router's NAT. A non-nil pin
// is the leaf certificate this server serves for host: HTTPS is "valid"
// only when the address presents that very leaf, and
// "server-identity-mismatch" when it presents another, however trusted.
func probeHost(ctx context.Context, host, ip, serverID string, pin []byte, now int64) HostStatus {
	out := HostStatus{Host: host, DNS: "unknown", HTTPS: "unchecked", CheckedAt: now}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	var addresses []netip.Addr
	answered := false
	for _, lookup := range hostLookups {
		lookupCtx, stop := context.WithTimeout(ctx, 3*time.Second)
		got, err := lookup(lookupCtx, host)
		stop()
		var dnsErr *net.DNSError
		if err == nil || errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			addresses, answered = got, true
			break
		}
	}
	// No resolver answered at all: that says nothing about the records, so
	// DNS stays "unknown" (which verify never counts as a DNS fault) and
	// HTTPS, which dials the address itself, is still checked.
	if answered {
		matched := false
		conflict := false
		for _, a := range addresses {
			out.Addresses = append(out.Addresses, a.String())
			if a.Is6() {
				out.IPv6Present = true
			} else if a.String() == ip {
				matched = true
			} else {
				conflict = true
			}
		}
		if !matched || conflict {
			out.DNS = "pending"
			return out
		}
		out.DNS = "current"
	}
	out.HTTPS, out.ExpiresAt, out.ForeignLeaf = probeHTTPS(ctx, host, ip, serverID, pin)
	return out
}

// probeHTTPS is probeHost's HTTPS half: it dials ip itself, whatever DNS
// says, and answers the HTTPS verdict, the presented leaf's expiry and
// whether a pin was given and the leaf presented is another (foreign). With
// the pinned leaf presented, a /api/health that is not a 200 or does not
// decode is "unreachable-or-untrusted": this server, not answering yet.
func probeHTTPS(ctx context.Context, host, ip, serverID string, pin []byte) (status string, expiresAt int64, foreign bool) {
	tr := &http.Transport{TLSClientConfig: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, RootCAs: probeRoots}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, probeAddress(ip))
	}}
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://"+host+"/api/health", nil)
	res, err := hc.Do(req)
	if err != nil {
		return "unreachable-or-untrusted", 0, false
	}
	defer res.Body.Close()
	if res.TLS == nil || len(res.TLS.PeerCertificates) == 0 {
		return "untrusted", 0, false
	}
	leaf := res.TLS.PeerCertificates[0]
	if pin != nil && !bytes.Equal(leaf.Raw, pin) {
		return "server-identity-mismatch", 0, true
	}
	var health struct {
		ServerID string `json:"serverID"`
	}
	healthy := res.StatusCode == 200 && json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&health) == nil
	switch {
	case !healthy && pin != nil:
		return "unreachable-or-untrusted", leaf.NotAfter.Unix(), false
	case !healthy, serverID != "" && health.ServerID != serverID:
		return "server-identity-mismatch", leaf.NotAfter.Unix(), false
	}
	return "valid", leaf.NotAfter.Unix(), false
}

func (u *Updater) CertificateEvent(event string, data map[string]any) {
	if event != "cert_obtained" && event != "cert_failed" && event != "cert_obtaining" {
		return
	}
	subject, _ := data["identifier"].(string)
	if subject == "" {
		return
	}
	_ = u.store.change(func(s *State) { addEvent(&s.Connectivity, u.Now().Unix(), event, subject+": "+event) })
}
