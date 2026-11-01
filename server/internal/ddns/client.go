package ddns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// DefaultBaseURL is the deployed names service. It is not part of the
// version contract and sits outside CheckCompat entirely.
const DefaultBaseURL = "https://api.gethyperdrop.com"

var (
	ErrNamePermanent = errors.New("disconnect the current domain before connecting another account-owned name")
	// ErrUnknownToken means this token names no row: the name was released
	// and taken by somebody else, or the token was rotated elsewhere.
	ErrUnknownToken = errors.New("ddns: the names service does not know this token")
	// ErrReleased means the name is mid-release and no longer ours. Retrying
	// cannot bring it back.
	ErrReleased = errors.New("ddns: the name has been released")
	// ErrNameTaken means somebody else holds it, or this install already
	// holds one. Either way the user must choose again.
	ErrNameTaken = errors.New("ddns: that name is taken")
	// ErrNameRefused means the service will not issue this name at all:
	// wrong shape, reserved, or on its refusal list.
	ErrNameRefused = errors.New("ddns: that name is not one this service issues")
	// ErrClaimRateLimited means this address has claimed too recently.
	ErrClaimRateLimited = errors.New("ddns: this address has claimed a name too recently")
)

type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// ParseBaseURL validates HYPERDROP_NAMES_URL: an absolute https URL with no
// credentials, query or fragment, answered without a trailing slash. Plain
// http is accepted to a loopback host, or anywhere on a development server
// (allowPrivate), because the free name's bearer token and a claim token
// travel on every request. Empty answers DefaultBaseURL.
func ParseBaseURL(raw string, allowPrivate bool) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return DefaultBaseURL, nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", fmt.Errorf("HYPERDROP_NAMES_URL=%q is not an absolute URL without credentials or a query", raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		host := u.Hostname()
		ip := net.ParseIP(host)
		if !allowPrivate && host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return "", fmt.Errorf("HYPERDROP_NAMES_URL=%q: plain http is accepted only to a loopback host", raw)
		}
	default:
		return "", fmt.Errorf("HYPERDROP_NAMES_URL=%q is not an https URL", raw)
	}
	return strings.TrimSuffix(u.Scheme+"://"+u.Host+u.EscapedPath(), "/"), nil
}

// base is the names service's URL: BaseURL, else DefaultBaseURL.
func (c *Client) base() string {
	if c.BaseURL == "" {
		return DefaultBaseURL
	}
	return c.BaseURL
}

// httpClient is HTTP, else a client with a 20-second timeout, and in both
// cases one that follows no redirect: a 307 would re-send a claim's body,
// the machine's token in it, to the host the answer names. A 3xx reaches
// the caller as its own status, which every call refuses.
func (c *Client) httpClient() *http.Client {
	hc := http.Client{Timeout: 20 * time.Second}
	if c.HTTP != nil {
		hc = *c.HTTP
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &hc
}

// cgnat is the carrier-grade NAT range, 100.64.0.0/10.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// IsPublicIPv4 reports whether ip is an IPv4 address a public DNS name can
// point at: not private, loopback, link-local, multicast, unspecified,
// this-network (0.0.0.0/8), class E (240.0.0.0/4, broadcast included) or
// CGNAT (100.64.0.0/10). An IPv4-mapped IPv6 address is not IPv4 here. Keep
// in agreement with core/ipaddr's IsPublicIPv4.
func IsPublicIPv4(ip netip.Addr) bool {
	if !ip.Is4() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsMulticast() || ip.IsUnspecified() || cgnat.Contains(ip) {
		return false
	}
	first := ip.As4()[0]
	return first != 0 && first < 240
}

type ServiceError struct {
	Code        string `json:"code"`
	Message     string `json:"error"`
	RetryAfter  int64  `json:"retryAfter,omitempty"`
	ApprovalURL string `json:"approvalURL,omitempty"`
	Challenge   string `json:"challenge,omitempty"`
	ExpiresAt   int64  `json:"expiresAt,omitempty"`
}

func (e *ServiceError) Error() string { return e.Message }
func registryError(res *http.Response, body []byte) error {
	e := &ServiceError{Code: "names-unavailable", Message: "The free-name service is temporarily unavailable"}
	_ = json.Unmarshal(body, e)
	e.Code, e.Message = serviceText(e.Code), serviceText(e.Message)
	if at := retryAt(res.Header.Get("Retry-After"), time.Now()); at > e.RetryAfter {
		e.RetryAfter = at
	}
	return e
}

type UpdateResult struct {
	Name      string `json:"name"`
	IP        string `json:"ip"`
	Changed   bool   `json:"changed"`
	State     string `json:"state"`
	ExpiresAt int64  `json:"expiresAt"`
}

func (u *Updater) Available(ctx context.Context, name string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", u.names.base()+"/v1/available?"+url.Values{"name": {name}}.Encode(), nil)
	if err != nil {
		return nil, err
	}
	res, err := u.names.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, errors.New("availability unavailable")
	}
	return io.ReadAll(io.LimitReader(res.Body, 64<<10))
}

// PortObservation is what answered one public port when the names service
// dialled it: answer is hyperdrop|other|none|unknown, serverID set only with
// hyperdrop.
type PortObservation struct {
	Answer   string `json:"answer"`
	ServerID string `json:"serverID"`
}

type PortsObservation struct {
	// IP is the address the names service dialled: the one this check
	// left from, which a custom domain may or may not point at.
	IP    string          `json:"ip"`
	HTTPS PortObservation `json:"https"`
	HTTP  PortObservation `json:"http"`
}

// Ports asks the names service to dial this server's public address on 443
// and 80 and say what answered. host, when set, is our domain, sent so a
// reverse proxy in front routes the check like a visitor. Advisory: any
// error, including an older registry's 404, means no information.
func (c *Client) Ports(ctx context.Context, host string) (PortsObservation, error) {
	u := c.base() + "/v1/ports"
	if host != "" {
		u += "?host=" + url.QueryEscape(host)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return PortsObservation{}, err
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return PortsObservation{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return PortsObservation{}, fmt.Errorf("ddns: the names service answered %d to a port check", resp.StatusCode)
	}
	var out PortsObservation
	if err := json.Unmarshal(body, &out); err != nil {
		return PortsObservation{}, fmt.Errorf("ddns: unreadable port check: %w", err)
	}
	return out, nil
}

// PublicIPv4 asks the HyperDrop-operated names service what address reached
// it. The value is observation only: update still sends no address and the
// service independently observes the authenticated heartbeat's connection.
func (c *Client) PublicIPv4(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base()+"/v1/ip", nil)
	if err != nil {
		return "", err
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ddns: the names service answered %d: %s", resp.StatusCode, serviceReason(body))
	}
	var out struct {
		IP string `json:"ip"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("ddns: unreadable public address: %w", err)
	}
	ip, err := netip.ParseAddr(out.IP)
	if err != nil || !IsPublicIPv4(ip) {
		return "", fmt.Errorf("ddns: names service returned an invalid public IPv4")
	}
	return ip.String(), nil
}

// Update tells the service where this server is. It sends no address: what
// gets written is the source address of this very connection, which is why
// a server cannot report a false one.
func (c *Client) Update(ctx context.Context, token string) (UpdateResult, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", c.base()+"/v1/update", nil)
	if err != nil {
		return UpdateResult{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return UpdateResult{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return UpdateResult{}, ErrUnknownToken
	case http.StatusGone:
		return UpdateResult{}, ErrReleased
	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return UpdateResult{}, registryError(resp, body)
	default:
		return UpdateResult{}, fmt.Errorf("ddns: the names service answered %d: %s",
			resp.StatusCode, serviceReason(body))
	}
	var out UpdateResult
	if err := json.Unmarshal(body, &out); err != nil {
		return UpdateResult{}, fmt.Errorf("ddns: unreadable answer: %w", err)
	}
	return out, nil
}

type ClaimResult struct {
	Name      string `json:"name"`
	FQDN      string `json:"fqdn"`
	Token     string `json:"-"`
	ExpiresAt int64  `json:"expiresAt"`
}

// Claim starts or retries account approval for this machine’s connection.
func (c *Client) Claim(ctx context.Context, name, serverID, token string) (ClaimResult, error) {
	reqBody, err := json.Marshal(struct {
		Name     string `json:"name"`
		ServerID string `json:"serverId"`
		Token    string `json:"token"`
	}{Name: name, ServerID: serverID, Token: token})
	if err != nil {
		return ClaimResult{}, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.base()+"/v1/claim", bytes.NewReader(reqBody))
	if err != nil {
		return ClaimResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return ClaimResult{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))

	switch resp.StatusCode {
	case http.StatusCreated:
	case http.StatusConflict:
		return ClaimResult{}, fmt.Errorf("%w: %s", ErrNameTaken, serviceReason(body))
	case http.StatusUnprocessableEntity:
		return ClaimResult{}, fmt.Errorf("%w: %s", ErrNameRefused, serviceReason(body))
	case http.StatusTooManyRequests:
		return ClaimResult{}, errors.Join(ErrClaimRateLimited, registryError(resp, body))
	case http.StatusServiceUnavailable, http.StatusPreconditionRequired:
		return ClaimResult{}, registryError(resp, body)
	default:
		return ClaimResult{}, fmt.Errorf("ddns: the names service answered %d: %s",
			resp.StatusCode, serviceReason(body))
	}
	var out ClaimResult
	if err := json.Unmarshal(body, &out); err != nil {
		return ClaimResult{}, fmt.Errorf("ddns: unreadable answer: %w", err)
	}
	out.Token = token
	return out, nil
}

// Release disconnects the machine, retaining the name in its owner’s account.
func (c *Client) Release(ctx context.Context, token string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.base()+"/v1/name", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized:
		return ErrUnknownToken
	case http.StatusGone:
		return ErrReleased
	default:
		return fmt.Errorf("ddns: the names service answered %d: %s", resp.StatusCode, serviceReason(data))
	}
}

// serviceReason pulls the service's own words out of an error body, falling
// back to the raw bytes so a shape we did not expect is still reported.
// Either way the text goes through serviceText, because these errors are
// logged, stored and answered.
func serviceReason(body []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		return serviceText(e.Error)
	}
	return serviceText(string(body))
}

// serviceTextLimit bounds the service's words carried in one error.
const serviceTextLimit = 500

// serviceText is text from the names service made safe to log, store and
// answer: every control character (a newline would forge a line in
// server.log) becomes a space, and the text stops at serviceTextLimit runes.
func serviceText(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == serviceTextLimit {
			b.WriteString("…")
			break
		}
		if unicode.IsControl(r) || r == utf8.RuneError {
			r = ' '
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}
