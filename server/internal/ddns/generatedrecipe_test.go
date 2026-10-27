package ddns

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testdata/*-recipe.golden.json are the recipes HyperDrop's clients generate,
// one per DNS provider: the server's copy of the golden files core's
// ddnsprovider tests write, which those tests' -update rewrites too
// (TestTheGoldenRecipesAreCores, in the monorepo, fails when the two
// differ). core and server are separate modules and cannot link, so these
// files are what prove the recipe a client generates is one this engine
// accepts and can run. A generator that drifts fails here, in the module
// that would have failed in production.
const goldenRecipePath = "testdata/cloudflare-recipe.golden.json"

func loadGoldenRecipe(t *testing.T) HTTPConfig {
	t.Helper()
	data, err := os.ReadFile(goldenRecipePath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg HTTPConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// Every generator's golden recipe must be one this engine accepts, with its
// provenance intact. A provider added in core is covered by its golden file
// alone.
func TestEveryGeneratedRecipeIsValid(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join(filepath.Dir(goldenRecipePath), "*-recipe.golden.json"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no golden recipes found: %v", err)
	}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var cfg HTTPConfig
		if err := json.Unmarshal(data, &cfg); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		name := strings.TrimSuffix(filepath.Base(p), "-recipe.golden.json")
		if err := cfg.Validate(); err != nil {
			t.Fatalf("the %s recipe is not one this engine accepts: %v", name, err)
		}
		if cfg.Provider != name || cfg.ProviderZone != "example.com" || cfg.RecipeVersion == 0 {
			t.Fatalf("%s: provenance did not survive the wire: %+v", name, cfg)
		}
	}
}

// cloudflareStub answers the two calls each hostname's pair makes, and
// records what it was asked to write.
type cloudflareStub struct {
	t       *testing.T
	updates map[string]string // record id -> content
	fail    bool              // answer HTTP 200 with success false
	srv     *httptest.Server
}

func newCloudflareStub(t *testing.T) *cloudflareStub {
	s := &cloudflareStub{t: t, updates: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /client/v4/zones/{zone}/dns_records", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer TEST_TOKEN" {
			s.t.Errorf("the recipe did not send the stored secret: %q", r.Header.Get("Authorization"))
		}
		name := r.URL.Query().Get("name")
		fmt.Fprintf(w, `{"success":true,"result":[{"id":%q,"name":%q,"type":"A"}]}`, "id-for-"+name, name)
	})
	mux.HandleFunc("PATCH /client/v4/zones/{zone}/dns_records/{record}", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if s.fail {
			fmt.Fprint(w, `{"success":false,"errors":[{"code":1004,"message":"refused"}]}`)
			return
		}
		s.updates[r.PathValue("record")] = fmt.Sprint(body["content"])
		fmt.Fprint(w, `{"success":true,"result":{}}`)
	})
	s.srv = httptest.NewServer(mux)
	t.Cleanup(s.srv.Close)
	return s
}

// client sends the recipe's api.cloudflare.com requests to the stub. The
// recipe keeps its real literal host, so what runs here is the URL a real
// server would dial.
func (s *cloudflareStub) client() *http.Client {
	base, err := url.Parse(s.srv.URL)
	if err != nil {
		s.t.Fatal(err)
	}
	return &http.Client{Transport: rewriteHost{base: base}}
}

type rewriteHost struct{ base *url.URL }

func (t rewriteHost) RoundTrip(r *http.Request) (*http.Response, error) {
	out := r.Clone(r.Context())
	out.URL.Scheme, out.URL.Host, out.Host = t.base.Scheme, t.base.Host, t.base.Host
	return http.DefaultTransport.RoundTrip(out)
}

func goldenUpdater(t *testing.T, stub *cloudflareStub, now time.Time) *Updater {
	t.Helper()
	store, err := Load(filepath.Join(t.TempDir(), "ddns"))
	if err != nil {
		t.Fatal(err)
	}
	u := NewUpdater(store, &Client{}, func(context.Context) (string, bool) { return "203.0.113.9", true })
	u.Domain = func() string { return "share.example.com" }
	u.Now = func() time.Time { return now }
	u.RecipeHTTP = stub.client()
	u.ProbeHost = func(_ context.Context, host, ip string) HostStatus {
		return HostStatus{Host: host, DNS: "current", HTTPS: "valid", CheckedAt: now.Unix()}
	}
	return u
}

func TestGeneratedCloudflareRecipeRuns(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	stub := newCloudflareStub(t)
	u := goldenUpdater(t, stub, now)
	if err := u.ConfigureHTTP(loadGoldenRecipe(t)); err != nil {
		t.Fatal(err)
	}
	if err := u.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The id captured by each lookup is the one its update addresses, which
	// is what keeps a record recreated in the dashboard working.
	want := map[string]string{
		"id-for-share.example.com":       "203.0.113.9",
		"id-for-files.share.example.com": "203.0.113.9",
	}
	for id, content := range want {
		if stub.updates[id] != content {
			t.Fatalf("updates = %+v, want %+v", stub.updates, want)
		}
	}
	c := u.Connectivity()
	if c.LastError != "" || c.LastSuccess == 0 {
		t.Fatalf("the run did not succeed: %+v", c)
	}
	if c.Provider != "cloudflare" || c.ProviderZone != "example.com" {
		t.Fatalf("status does not name the provider: %+v", c)
	}
	var named int
	for _, e := range c.Events {
		if e.Kind == "request-succeeded" && strings.HasPrefix(e.Message, "Update ") {
			named++
		}
	}
	if named != 2 {
		t.Fatalf("activity does not name the update steps: %+v", c.Events)
	}
	encoded, _ := json.Marshal(c)
	if strings.Contains(string(encoded), "TEST_TOKEN") {
		t.Fatal("status leaks the provider token")
	}
}

// Cloudflare reports failure inside HTTP 200. The recipe's success condition
// is what turns that into a failure the server retries.
func TestGeneratedRecipeFailsOnSuccessFalse(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	stub := newCloudflareStub(t)
	stub.fail = true
	u := goldenUpdater(t, stub, now)
	if err := u.ConfigureHTTP(loadGoldenRecipe(t)); err != nil {
		t.Fatal(err)
	}
	if err := u.Tick(context.Background()); err == nil {
		t.Fatal("a refusal inside HTTP 200 was accepted")
	}
	if c := u.Connectivity(); c.LastSuccess != 0 || c.LastError == "" {
		t.Fatalf("the failure did not stick: %+v", c)
	}
}

// The label says which client generated a recipe. The engine must never read
// it: it has no provider switch, and growing one here is what this whole
// design exists to avoid.
func TestTheServerNeverBranchesOnTheProviderLabel(t *testing.T) {
	// Every provider a client generates recipes for has a golden file.
	goldens, err := filepath.Glob(filepath.Join(filepath.Dir(goldenRecipePath), "*-recipe.golden.json"))
	if err != nil || len(goldens) == 0 {
		t.Fatalf("no golden recipes found: %v", err)
	}
	var generatorNames []string
	for _, g := range goldens {
		generatorNames = append(generatorNames, strings.TrimSuffix(filepath.Base(g), "-recipe.golden.json"))
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.Contains(line, "Provider") || strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			for _, provider := range generatorNames {
				if strings.Contains(line, `"`+provider+`"`) {
					t.Errorf("%s branches on a provider name: %s", name, strings.TrimSpace(line))
				}
			}
		}
	}
}
