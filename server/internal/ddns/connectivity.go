package ddns

import (
	"context"
	"crypto/tls"
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
		c.NextAttempt = next
		if c.IncidentAt == 0 {
			c.IncidentAt = now
		}
		c.Alert = terminal || now-c.IncidentAt >= 15*60
		addEvent(c, now, "failure", code)
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
	if c != nil && c.Mode == "custom" {
		if c.CredentialExpiresAt > 0 && now >= c.CredentialExpiresAt {
			return u.failure(ctx, "DDNS credentials have expired", now+3600, true)
		}
		// Reconcile every twelve hours, including records edited elsewhere.
		lastProbe := s.LastProbe
		if s.Pending {
			lastProbe = s.CustomLastProbe
		}
		due := s.Connectivity.LastSuccess == 0 || ip != lastProbe || now-s.Connectivity.LastSuccess >= int64(Heartbeat/time.Second)
		if due {
			if err := u.store.change(func(s *State) {
				s.Connectivity.LastAttempt = now
				addEvent(&s.Connectivity, now, "update-started", "Updating custom DNS records")
			}); err != nil {
				return err
			}
			hc := recipeClient(c.AllowPrivate && u.PrivateRecipes)
			if u.RecipeHTTP != nil {
				hc = u.RecipeHTTP
			}
			defer hc.CloseIdleConnections()
			vars := recipeVars(c, ip, s.Connectivity.PreviousIP)
			for i, step := range c.Requests {
				err := executeRequest(ctx, hc, step, vars, i+1)
				if err != nil {
					wait := u.Now().Add(backoffFor(s.Connectivity.Failures + 1)).Unix()
					var failure *RequestFailure
					terminal := false
					reason := err.Error()
					if errors.As(err, &failure) {
						if failure.RetryAt > wait {
							wait = failure.RetryAt
						}
						terminal = failure.Code == "credentials-rejected" || failure.Code == "invalid-template"
						if failure.Code == "private-destination" && c.AllowPrivate && !u.PrivateRecipes {
							// A recipe stored with allowPrivate on a server
							// whose operator has not allowed it: the reason
							// names the switch, which only the operator holds.
							reason = fmt.Sprintf("DDNS request %d: %v", failure.Step, ErrPrivateRecipe)
							terminal = true
						}
					}
					_ = u.failure(ctx, reason, wait, terminal)
					return err
				}
				if err := u.store.change(func(s *State) {
					addEvent(&s.Connectivity, now, "request-succeeded", stepAccepted(step.Name, i))
				}); err != nil {
					return err
				}
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
	return u.verify(ctx, ip)
}

func (u *Updater) verify(ctx context.Context, ip string) error {
	if u.Domain == nil || u.Domain() == "" {
		return nil
	}
	domain := u.Domain()
	now := u.Now().Unix()
	hosts := []HostStatus{}
	for _, host := range []string{domain, "files." + domain} {
		if u.ProbeHost != nil {
			hosts = append(hosts, u.ProbeHost(ctx, host, ip))
			continue
		}
		identity := ""
		if u.ServerID != nil {
			identity = u.ServerID()
		}
		hosts = append(hosts, probeHost(ctx, host, ip, identity, now))
	}
	before := u.store.Snapshot().Connectivity.Hosts
	if err := u.store.change(func(s *State) {
		s.Connectivity.Hosts = hosts
		for i, h := range hosts {
			if i >= len(before) || h.DNS != before[i].DNS || h.HTTPS != before[i].HTTPS {
				addEvent(&s.Connectivity, now, "verification", h.Host+": DNS "+h.DNS+", HTTPS "+h.HTTPS)
			}
		}
	}); err != nil {
		return err
	}
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

// This is explicitly a check FROM THE SERVER. It does not claim to prove
// inbound internet reachability through a home router's NAT.
func probeHost(ctx context.Context, host, ip, serverID string, now int64) HostStatus {
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
	tr := &http.Transport{TLSClientConfig: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip, "443"))
	}}
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://"+host+"/api/health", nil)
	res, err := hc.Do(req)
	if err != nil {
		out.HTTPS = "unreachable-or-untrusted"
		return out
	}
	defer res.Body.Close()
	if res.TLS == nil || len(res.TLS.PeerCertificates) == 0 {
		out.HTTPS = "untrusted"
		return out
	}
	out.ExpiresAt = res.TLS.PeerCertificates[0].NotAfter.Unix()
	var health struct {
		ServerID string `json:"serverID"`
	}
	if res.StatusCode != 200 || json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&health) != nil || serverID != "" && health.ServerID != serverID {
		out.HTTPS = "server-identity-mismatch"
		return out
	}
	out.HTTPS = "valid"
	return out
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
