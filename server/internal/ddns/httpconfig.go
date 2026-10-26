package ddns

// The HTTP integration deliberately has no provider switch: authentication,
// record lookup and updates are an ordered, bounded request recipe.
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
	"strconv"
	"strings"
	"text/template"
	"text/template/parse"
	"time"
)

type HTTPConfig struct {
	Mode   string `json:"mode"` // custom or external
	Domain string `json:"domain"`
	// Provider, ProviderZone and RecipeVersion are PROVENANCE: which client
	// generator wrote this recipe, and against which zone. They are stored
	// and echoed, never acted on. Nothing here may branch on Provider: the
	// engine has no provider switch, and a recipe is a recipe whoever wrote
	// it.
	Provider            string            `json:"provider,omitempty"`
	ProviderZone        string            `json:"providerZone,omitempty"`
	RecipeVersion       int               `json:"recipeVersion,omitempty"`
	Secrets             map[string]string `json:"secrets,omitempty"`
	Requests            []HTTPRequest     `json:"requests,omitempty"`
	Notify              *HTTPRequest      `json:"notify,omitempty"`
	AllowPrivate        bool              `json:"allowPrivate,omitempty"`
	CredentialExpiresAt int64             `json:"credentialExpiresAt,omitempty"`
}

type HTTPRequest struct {
	Name            string            `json:"name"`
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	Headers         map[string]string `json:"headers,omitempty"`
	Body            string            `json:"body,omitempty"`
	SuccessStatuses []int             `json:"successStatuses,omitempty"`
	SuccessContains string            `json:"successContains,omitempty"`
	SuccessJSON     map[string]any    `json:"successJSON,omitempty"`
	Capture         map[string]string `json:"capture,omitempty"` // variable -> JSON path (result.0.id)
}

type RequestFailure struct {
	Code    string
	Step    int
	Status  int
	RetryAt int64
}

func (e *RequestFailure) Error() string {
	return fmt.Sprintf("DDNS request %d: %s (HTTP %d)", e.Step, e.Code, e.Status)
}

// reservedDestinations are the ranges a recipe never dials beyond what
// IsGlobalUnicast and the private, loopback and link-local checks refuse:
// this-network, CGNAT, the IETF protocol block, the documentation and
// benchmarking ranges, and class E. Stricter than IsPublicIPv4, which takes
// the documentation ranges as a test server's HYPERDROP_IP: nothing real
// answers there, so no recipe has a reason to dial one.
var reservedDestinations = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	cgnat,
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func publicAddress(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range reservedDestinations {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// Dial validates the actual resolved address and pins that address for this
// connection. A preliminary URL-only check would be vulnerable to rebinding.
// errPrivateDestination is a recipe client's refusal of a private or
// reserved address, which a request reports as private-destination.
var errPrivateDestination = errors.New("private or reserved destination refused")

func recipeClient(allowPrivate bool) *http.Client {
	tr := &http.Transport{TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second}
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errors.New("invalid destination")
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, errors.New("destination DNS lookup failed")
		}
		if len(ips) == 0 {
			return nil, errors.New("destination has no addresses")
		}
		for _, ip := range ips {
			if !allowPrivate && !publicAddress(ip) {
				return nil, errPrivateDestination
			}
		}
		var last error
		for _, ip := range ips {
			conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			last = err
		}
		return nil, last
	}
	return &http.Client{Transport: tr, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// renderLimit bounds one rendered value.
const renderLimit = 128 << 10

var errRenderTooLarge = errors.New("rendered request is too large")

// render executes one recipe value. A recipe is data, not a program: its
// templates are text and actions that print a variable, optionally through
// urlquery or json (plainTemplate), so nothing in one can loop, recurse or
// format its way to an unbounded output, and the output itself stops at
// renderLimit while it is written.
func render(value string, vars map[string]string) (string, error) {
	t, err := template.New("request").Option("missingkey=error").Funcs(template.FuncMap{
		"urlquery": url.QueryEscape,
		"json":     func(s string) string { b, _ := json.Marshal(s); return string(b) },
	}).Parse(value)
	if err != nil || !plainTemplate(t) {
		return "", errors.New("invalid request template")
	}
	out := cappedBuffer{limit: renderLimit}
	if err := t.Execute(&out, vars); err != nil {
		if errors.Is(err, errRenderTooLarge) {
			return "", errRenderTooLarge
		}
		return "", errors.New("request references an undefined variable")
	}
	return out.String(), nil
}

// plainTemplate reports whether t holds only text, comments and actions of
// the documented shapes: {{.name}}, {{urlquery .name}}, {{json .name}} and
// the same as pipelines ({{.name | urlquery}}). Control actions (range, if,
// with, template, define, block), variables and every other function are
// refused.
func plainTemplate(t *template.Template) bool {
	if t.Tree == nil || len(t.Templates()) > 1 {
		return false
	}
	for _, n := range t.Tree.Root.Nodes {
		switch n := n.(type) {
		case *parse.TextNode, *parse.CommentNode:
		case *parse.ActionNode:
			if !plainPipe(n.Pipe) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func plainPipe(p *parse.PipeNode) bool {
	if p == nil || p.IsAssign || len(p.Decl) > 0 || len(p.Cmds) == 0 {
		return false
	}
	for i, c := range p.Cmds {
		switch {
		case i == 0 && len(c.Args) == 1 && plainField(c.Args[0]):
		case i == 0 && len(c.Args) == 2 && recipeFunc(c.Args[0]) && plainField(c.Args[1]):
		case i > 0 && len(c.Args) == 1 && recipeFunc(c.Args[0]):
		default:
			return false
		}
	}
	return true
}

func plainField(n parse.Node) bool {
	f, ok := n.(*parse.FieldNode)
	return ok && len(f.Ident) == 1
}

func recipeFunc(n parse.Node) bool {
	id, ok := n.(*parse.IdentifierNode)
	return ok && (id.Ident == "urlquery" || id.Ident == "json")
}

// cappedBuffer refuses a write that would take it past limit.
type cappedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, errRenderTooLarge
	}
	return b.Buffer.Write(p)
}

func (c HTTPConfig) Validate() error {
	if c.Mode != "custom" && c.Mode != "external" {
		return errors.New("mode must be custom or external")
	}
	if !validHost(c.Domain) || strings.HasSuffix(c.Domain, "."+Zone) || c.Domain == Zone {
		return errors.New("a custom domain is required")
	}
	if !providerLabel(c.Provider) {
		return errors.New("provider must be a short lowercase label")
	}
	if c.ProviderZone != "" && !validHost(c.ProviderZone) {
		return errors.New("providerZone must be a domain")
	}
	if c.RecipeVersion < 0 || c.RecipeVersion > 1000 {
		return errors.New("recipeVersion is out of range")
	}
	if len(c.Requests) > 12 || (c.Mode == "custom" && len(c.Requests) == 0) {
		return errors.New("custom DDNS needs 1 to 12 requests")
	}
	if c.Mode == "external" && len(c.Requests) != 0 {
		return errors.New("external DNS cannot contain update requests")
	}
	if len(c.Secrets) > 32 {
		return errors.New("too many secret variables")
	}
	vars := map[string]string{"ipv4": "8.8.8.8", "previous_ipv4": "8.8.4.4", "domain": c.Domain, "files_domain": "files." + c.Domain, "event": "failure", "message": "DDNS needs attention"}
	for k, v := range c.Secrets {
		if !variableName(k) || vars[k] != "" || len(v) > 8192 {
			return errors.New("invalid or reserved secret variable")
		}
		vars[k] = v
	}
	steps := append([]HTTPRequest(nil), c.Requests...)
	baseVars := recipeVars(&c, "8.8.8.8", "8.8.4.4")
	if c.Notify != nil {
		steps = append(steps, *c.Notify)
	}
	for i, s := range steps {
		if i == len(c.Requests) {
			// Notifications run independently, including before any update succeeds.
			vars = baseVars
		}
		if len(s.Name) > 80 || len(s.Headers) > 32 || len(s.Capture) > 16 {
			return errors.New("request metadata is too large")
		}
		if s.Method != "GET" && s.Method != "PUT" && s.Method != "PATCH" && s.Method != "POST" {
			return errors.New("request method must be GET, PUT, PATCH or POST")
		}
		// Keep the destination literal: captured tokens or responses cannot
		// redirect a later step's credentials to a different host.
		literal, err := url.Parse(s.URL)
		if err != nil || literal.Scheme != "https" || literal.Hostname() == "" || literal.User != nil || strings.ContainsAny(literal.Host, "{}") || literal.Fragment != "" {
			return errors.New("request URL must use HTTPS with a literal host, no userinfo or fragment")
		}
		for _, code := range s.SuccessStatuses {
			if code < 200 || code > 299 {
				return errors.New("successStatuses must contain only 2xx statuses")
			}
		}
		values := []string{s.URL, s.Body, s.SuccessContains}
		for k, v := range s.Headers {
			if strings.ContainsAny(k+v, "\r\n") || strings.EqualFold(k, "Host") {
				return errors.New("invalid request header")
			}
			values = append(values, v)
		}
		for _, v := range values {
			if _, err := render(v, vars); err != nil {
				return err
			}
		}
		for key := range s.Capture {
			if !variableName(key) || vars[key] != "" {
				return errors.New("capture variable is invalid or already defined")
			}
			vars[key] = "captured-value"
		}
	}
	return nil
}

// providerLabel accepts the empty string (a hand-written recipe has no
// generator) and a short lowercase identifier. It is a label the server
// stores and echoes, so validation only has to keep it small and printable.
func providerLabel(s string) bool {
	if s == "" {
		return true
	}
	if len(s) > 32 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func variableName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

func validHost(s string) bool {
	if len(s) > 253 || !strings.Contains(s, ".") || net.ParseIP(s) != nil {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func jsonPath(value any, path string) (any, bool) {
	for _, part := range strings.Split(path, ".") {
		switch v := value.(type) {
		case map[string]any:
			var ok bool
			value, ok = v[part]
			if !ok {
				return nil, false
			}
		case []any:
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(v) {
				return nil, false
			}
			value = v[i]
		default:
			return nil, false
		}
	}
	return value, true
}

func retryAt(header string, now time.Time) int64 {
	if seconds, err := strconv.ParseInt(header, 10, 64); err == nil && seconds > 0 && seconds < 365*24*3600 {
		return now.Add(time.Duration(seconds) * time.Second).Unix()
	}
	if at, err := http.ParseTime(header); err == nil && at.After(now) {
		return at.Unix()
	}
	return 0
}

// No response body, rendered URL, header, captured value or transport error
// is allowed out of this function. Each can contain provider credentials.
func executeRequest(ctx context.Context, hc *http.Client, step HTTPRequest, vars map[string]string, index int) error {
	fail := func(code string, status int, at int64) error {
		return &RequestFailure{Code: code, Status: status, Step: index, RetryAt: at}
	}
	u, err := render(step.URL, vars)
	if err != nil {
		return fail("invalid-template", 0, 0)
	}
	body, err := render(step.Body, vars)
	if err != nil {
		return fail("invalid-template", 0, 0)
	}
	req, err := http.NewRequestWithContext(ctx, step.Method, u, strings.NewReader(body))
	if err != nil {
		return fail("invalid-request", 0, 0)
	}
	for k, v := range step.Headers {
		value, err := render(v, vars)
		if err != nil {
			return fail("invalid-template", 0, 0)
		}
		req.Header.Set(k, value)
	}
	res, err := hc.Do(req)
	if errors.Is(err, errPrivateDestination) {
		return fail("private-destination", 0, 0)
	}
	if err != nil {
		return fail("connection-failed", 0, 0)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return fail("invalid-response", res.StatusCode, 0)
	}
	ok := res.StatusCode >= 200 && res.StatusCode < 300
	if len(step.SuccessStatuses) > 0 {
		ok = false
		for _, v := range step.SuccessStatuses {
			if res.StatusCode == v {
				ok = true
			}
		}
	}
	if !ok {
		code := "provider-rejected"
		if res.StatusCode == 401 || res.StatusCode == 403 {
			code = "credentials-rejected"
		}
		if res.StatusCode == 429 {
			code = "rate-limited"
		}
		return fail(code, res.StatusCode, retryAt(res.Header.Get("Retry-After"), time.Now()))
	}
	contains, err := render(step.SuccessContains, vars)
	if err != nil {
		return fail("invalid-template", 0, 0)
	}
	if contains != "" && !strings.Contains(string(data), contains) {
		return fail("success-condition-failed", res.StatusCode, 0)
	}
	var decoded any
	if len(step.SuccessJSON) > 0 || len(step.Capture) > 0 {
		if json.Unmarshal(data, &decoded) != nil {
			return fail("invalid-json-response", res.StatusCode, 0)
		}
	}
	for path, want := range step.SuccessJSON {
		got, found := jsonPath(decoded, path)
		a, _ := json.Marshal(got)
		b, _ := json.Marshal(want)
		if !found || !bytes.Equal(a, b) {
			return fail("success-condition-failed", res.StatusCode, 0)
		}
	}
	for key, path := range step.Capture {
		got, found := jsonPath(decoded, path)
		if !found {
			return fail("capture-missing", res.StatusCode, 0)
		}
		switch v := got.(type) {
		case string:
			vars[key] = v
		case float64:
			vars[key] = strconv.FormatFloat(v, 'f', -1, 64)
		default:
			return fail("capture-not-scalar", res.StatusCode, 0)
		}
	}
	return nil
}
