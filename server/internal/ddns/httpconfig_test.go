package ddns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRecipeCapturesRecordIDAndChecksProviderSuccess(t *testing.T) {
	var writes int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer private-token" {
			t.Error("missing credential")
		}
		if r.Method == "GET" {
			fmt.Fprint(w, `{"success":true,"result":[{"id":"record-17"}]}`)
			return
		}
		if r.URL.Path != "/records/record-17" {
			t.Errorf("wrong record: %s", r.URL.Path)
		}
		var body map[string]string
		if json.NewDecoder(r.Body).Decode(&body) != nil || body["content"] != "8.8.4.4" {
			t.Error("wrong update body")
		}
		writes++
		fmt.Fprint(w, `{"success":false,"errors":[{"message":"private-token"}]}`)
	}))
	defer srv.Close()
	vars := map[string]string{"token": "private-token", "ipv4": "8.8.4.4"}
	lookup := HTTPRequest{Method: "GET", URL: srv.URL + "/records", Headers: map[string]string{"Authorization": "Bearer {{.token}}"}, SuccessJSON: map[string]any{"success": true}, Capture: map[string]string{"record": "result.0.id"}}
	if err := executeRequest(context.Background(), srv.Client(), lookup, vars, 1); err != nil {
		t.Fatal(err)
	}
	update := HTTPRequest{Method: "PATCH", URL: srv.URL + "/records/{{.record}}", Headers: lookup.Headers, Body: `{"content":"{{.ipv4}}"}`, SuccessJSON: map[string]any{"success": true}}
	err := executeRequest(context.Background(), srv.Client(), update, vars, 2)
	if err == nil || !strings.Contains(err.Error(), "success-condition-failed") || strings.Contains(err.Error(), "private-token") || writes != 1 {
		t.Fatalf("outcome leaked or accepted failure: %v", err)
	}
}

func TestCustomUpdateSurvivesRestartHonorsRetryAndVerifiesBothHosts(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	ip := "8.8.8.8"
	fail := true
	calls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if fail && r.URL.Path == "/files" {
			w.Header().Set("Retry-After", "3600")
			w.WriteHeader(429)
			fmt.Fprint(w, "secret-token")
			return
		}
		fmt.Fprint(w, `{"success":true}`)
	}))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "ddns")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	makeUpdater := func(s *Store) *Updater {
		u := NewUpdater(s, &Client{}, func(context.Context) (string, bool) { return ip, true })
		u.Domain = func() string { return "share.example.com" }
		u.Now = func() time.Time { return now }
		u.RecipeHTTP = srv.Client()
		u.ProbeHost = func(_ context.Context, host, ip string) HostStatus {
			return HostStatus{Host: host, DNS: "current", HTTPS: "valid", ExpiresAt: now.Add(72 * time.Hour).Unix(), CheckedAt: now.Unix()}
		}
		return u
	}
	u := makeUpdater(s)
	cfg := HTTPConfig{Mode: "custom", Domain: "share.example.com", Secrets: map[string]string{"token": "secret-token"}, Requests: []HTTPRequest{{Method: "PUT", URL: srv.URL + "/main", SuccessJSON: map[string]any{"success": true}}, {Method: "PUT", URL: srv.URL + "/files", SuccessJSON: map[string]any{"success": true}}}}
	if err := u.ConfigureHTTP(cfg); err != nil {
		t.Fatal(err)
	}
	if err := u.Tick(context.Background()); err == nil {
		t.Fatal("partial update was accepted")
	}
	if c := u.Connectivity(); c.LastSuccess != 0 || c.NextAttempt < now.Add(59*time.Minute).Unix() {
		t.Fatalf("bad partial/retry state: %+v", c)
	}
	reloaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	u = makeUpdater(reloaded)
	if err := u.Tick(context.Background()); err != nil || calls != 2 {
		t.Fatalf("restart ignored Retry-After: %v, calls %d", err, calls)
	}
	fail = false
	now = now.Add(2 * time.Hour)
	if err := u.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c := u.Connectivity(); c.LastError != "" || c.LastSuccess == 0 || len(c.Hosts) != 2 {
		t.Fatalf("no recovery: %+v", c)
	}
	encoded, _ := json.Marshal(u.Connectivity())
	if strings.Contains(string(encoded), "secret-token") {
		t.Fatal("status leaks credentials")
	}
	before := calls
	now = now.Add(10 * time.Minute)
	_ = u.Tick(context.Background())
	if calls != before {
		t.Fatal("unchanged IP rewrote records")
	}
	ip = "8.8.4.4"
	now = now.Add(10 * time.Minute)
	_ = u.Tick(context.Background())
	if calls != before+2 {
		t.Fatal("changed IP did not update both records")
	}
}

func TestRequestRedirectsCannotForwardSecrets(t *testing.T) {
	var stolen bool
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { stolen = true }))
	defer target.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	hc := srv.Client()
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	err := executeRequest(context.Background(), hc, HTTPRequest{Method: "GET", URL: srv.URL, Headers: map[string]string{"Authorization": "Bearer secret"}}, nil, 1)
	if err == nil || stolen {
		t.Fatal("redirect followed or accepted")
	}
}

func TestRecipeValidationRejectsUnsafeAndUnboundedConfiguration(t *testing.T) {
	good := HTTPConfig{Mode: "custom", Domain: "share.example.com", Requests: []HTTPRequest{{Method: "PUT", URL: "https://api.example.com/update?ip={{.ipv4}}"}}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, url := range []string{"http://api.example.com/update", "https://{{.ipv4}}/update", "https://user:password@api.example.com/update"} {
		c := good
		c.Requests = []HTTPRequest{{Method: "PUT", URL: url}}
		if c.Validate() == nil {
			t.Errorf("accepted %s", url)
		}
	}
	for _, ip := range []string{"127.0.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "::1", "::ffff:127.0.0.1",
		// NAT64 (well-known and local-use) and 6to4 carry an IPv4 address a
		// gateway reaches on the server's behalf: 127.0.0.1 and 192.168.1.1.
		"64:ff9b::7f00:1", "64:ff9b:1::c0a8:101", "2002:7f00:1::1", "2002:c0a8:101::1"} {
		if publicAddress(netip.MustParseAddr(ip)) {
			t.Errorf("accepted private destination %s", ip)
		}
	}
	for _, ip := range []string{"1.1.1.1", "2606:4700:4700::1111"} {
		if !publicAddress(netip.MustParseAddr(ip)) {
			t.Fatalf("public IP %s refused", ip)
		}
	}
	hc := recipeClient(false)
	defer hc.CloseIdleConnections()
	_, err := hc.Get("https://127.0.0.1:9/")
	if err == nil {
		t.Fatal("actual dial accepted loopback")
	}
}

func TestDisconnectAllowsAnotherAccountApprovalAfterRestart(t *testing.T) {
	s, path := tempStore(t)
	_ = s.Set("alice", "token")
	if err := s.Clear(); err != nil {
		t.Fatal(err)
	}
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPreconditionRequired)
		fmt.Fprintf(w, `{"code":"account-required","approvalURL":"https://gethyperdrop.com/account/#code=new","challenge":"nonce","expiresAt":%d}`, time.Now().Add(time.Minute).Unix())
	}))
	defer srv.Close()
	u := NewUpdater(s, &Client{BaseURL: srv.URL}, nil)
	var approval *ServiceError
	if err := u.Choose(context.Background(), "bravo", "server"); !errors.As(err, &approval) || approval.Code != "account-required" {
		t.Fatalf("new approval: %v", err)
	}
	if st := s.Snapshot(); !st.Pending || st.Name != "bravo" {
		t.Fatalf("state: %+v", st)
	}
}

func TestActivityRetentionAndAlertRecovery(t *testing.T) {
	s, _ := tempStore(t)
	now := time.Now()
	u := NewUpdater(s, &Client{}, nil)
	u.Now = func() time.Time { return now }
	_ = u.failure(context.Background(), "temporary", now.Add(time.Minute).Unix(), false)
	if u.Connectivity().Alert {
		t.Fatal("first transient failure alerted")
	}
	now = now.Add(16 * time.Minute)
	_ = u.failure(context.Background(), "temporary", now.Add(time.Minute).Unix(), false)
	if !u.Connectivity().Alert {
		t.Fatal("sustained failure did not alert")
	}
	_ = u.healthy(context.Background())
	if u.Connectivity().Alert || u.Connectivity().LastError != "" {
		t.Fatal("incident did not recover")
	}
	for i := 0; i < 300; i++ {
		_ = s.change(func(s *State) { addEvent(&s.Connectivity, now.Unix(), "check", "bounded") })
	}
	if len(u.Connectivity().Events) != activityLimit {
		t.Fatal("activity cap not enforced")
	}
	now = now.Add(31 * 24 * time.Hour)
	_ = s.change(func(s *State) { addEvent(&s.Connectivity, now.Unix(), "check", "new") })
	if len(u.Connectivity().Events) != 1 {
		t.Fatal("activity retention not enforced")
	}
}

// A recipe value is text and variables: nothing in one can loop, recurse or
// format its way to an unbounded output, and the output is capped as it is
// written.
func TestRecipeTemplatesAreDataNotPrograms(t *testing.T) {
	vars := map[string]string{"ipv4": "203.0.113.7", "token": "a b&c", "big": strings.Repeat("x", 8192)}
	for in, want := range map[string]string{
		"https://api.example.com/u?ip={{.ipv4}}": "https://api.example.com/u?ip=203.0.113.7",
		"t={{urlquery .token}}":                  "t=a+b%26c",
		"t={{.token | urlquery}}":                "t=a+b%26c",
		`{"t":{{json .token}}}`:                  `{"t":"a b\u0026c"}`,
		`{{- .ipv4 -}}`:                          "203.0.113.7",
		"{{/* a comment */}}plain":               "plain",
		"":                                       "",
		"{{json .token | urlquery}}":             "%22a+b%5Cu0026c%22",
	} {
		got, err := render(in, vars)
		if err != nil || got != want {
			t.Errorf("render(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{
		"{{range 300000000}}{{end}}",
		"{{range 20000000}}abcdefgh{{end}}",
		`{{printf "%01000000000d" 1}}`,
		`{{define "x"}}{{template "x"}}{{end}}{{template "x"}}`,
		"{{if .ipv4}}yes{{end}}",
		"{{with .ipv4}}{{.}}{{end}}",
		"{{$x := .ipv4}}{{$x}}",
		"{{len .ipv4}}",
		"{{.}}",
		`{{print .ipv4}}`,
		"{{urlquery .token .ipv4}}",
	} {
		start := time.Now()
		if got, err := render(in, vars); err == nil {
			t.Errorf("render(%q) accepted, rendering %d bytes", in, len(got))
		}
		if took := time.Since(start); took > time.Second {
			t.Errorf("render(%q) took %v before refusing", in, took)
		}
	}
	if _, err := render(strings.Repeat("{{.big}}", 20), vars); !errors.Is(err, errRenderTooLarge) {
		t.Fatalf("an output past the limit: %v", err)
	}
}

// A recipe reaches private addresses only on a server whose operator allowed
// it: the admin role that writes recipes is not the network's operator.
func TestAPrivateRecipeNeedsTheOperator(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "ddns"))
	if err != nil {
		t.Fatal(err)
	}
	u := NewUpdater(s, &Client{}, nil)
	u.Domain = func() string { return "share.example.com" }
	c := HTTPConfig{Mode: "custom", Domain: "share.example.com", AllowPrivate: true,
		Requests: []HTTPRequest{{Method: "PUT", URL: "https://router.example.com/update?ip={{.ipv4}}"}}}
	if err := u.ConfigureHTTP(c); !errors.Is(err, ErrPrivateRecipe) {
		t.Fatalf("allowPrivate without the operator: %v, want ErrPrivateRecipe", err)
	}
	if s.Snapshot().Custom != nil {
		t.Fatal("the refused recipe was stored")
	}
	u.PrivateRecipes = true
	if err := u.ConfigureHTTP(c); err != nil {
		t.Fatalf("allowPrivate with the operator: %v", err)
	}
	c.AllowPrivate = false
	u.PrivateRecipes = false
	if err := u.ConfigureHTTP(c); err != nil {
		t.Fatalf("a public recipe: %v", err)
	}
}

// A recipe stored with allowPrivate on a server whose operator has not
// allowed private destinations fails with the reason and the switch that
// fixes it, not a bare connection failure, and alerts at once.
func TestAStoredPrivateRecipeNamesTheOperatorSwitch(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "ddns"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	u := NewUpdater(s, &Client{}, func(context.Context) (string, bool) { return "203.0.113.8", true })
	u.Domain = func() string { return "share.example.com" }
	u.Now = func() time.Time { return now }
	u.PrivateRecipes = true
	c := HTTPConfig{Mode: "custom", Domain: "share.example.com", AllowPrivate: true,
		Requests: []HTTPRequest{{Method: "PUT", URL: "https://localhost/update?ip={{.ipv4}}"}}}
	if err := u.ConfigureHTTP(c); err != nil {
		t.Fatal(err)
	}
	// The operator's switch is gone on the next start.
	u.PrivateRecipes = false
	if err := u.Tick(context.Background()); err == nil {
		t.Fatal("a private destination was dialled")
	}
	got := u.Connectivity()
	if !strings.Contains(got.LastError, "HYPERDROP_DDNS_ALLOW_PRIVATE=1") || !got.Alert {
		t.Fatalf("connectivity %+v: want the operator's switch named, alerting", got)
	}
}
