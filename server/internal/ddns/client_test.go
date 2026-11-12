package ddns

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

// The names client follows no redirect: a 307 would re-send a claim's
// body, the machine's token in it, to whatever host the answer names, so a
// 3xx is an error and the other host hears nothing.
func TestNamesClientDoesNotFollowRedirects(t *testing.T) {
	var reached bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))
	defer other.Close()
	names := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer names.Close()

	for _, c := range []*Client{{BaseURL: names.URL}, {BaseURL: names.URL, HTTP: &http.Client{}}} {
		if _, err := c.Claim(context.Background(), "alpha", "server-id", "the-secret-token"); err == nil {
			t.Fatal("a claim answered 307 succeeded")
		}
		if _, err := c.Update(context.Background(), "the-secret-token"); err == nil {
			t.Fatal("an update answered 307 succeeded")
		}
		if reached {
			t.Fatal("the redirect was followed to another host")
		}
	}
}

func TestUpdateSendsTheTokenAsABearerAndReadsTheAnswer(t *testing.T) {
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"ip":"203.0.113.7","changed":true,"state":"active","expiresAt":99}`))
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL}
	got, err := c.Update(context.Background(), "tok-123")
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if gotAuth != "Bearer tok-123" {
		t.Fatalf("Authorization %q", gotAuth)
	}
	if gotPath != "/v1/update" {
		t.Fatalf("path %q", gotPath)
	}
	if got.IP != "203.0.113.7" || !got.Changed || got.State != "active" || got.ExpiresAt != 99 {
		t.Fatalf("result %+v", got)
	}
}

func TestPublicIPv4UsesTheNamesObservation(t *testing.T) {
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_, _ = w.Write([]byte(`{"ip":"203.0.113.7"}`))
	}))
	defer srv.Close()
	got, err := (&Client{BaseURL: srv.URL}).PublicIPv4(context.Background())
	if err != nil || got != "203.0.113.7" {
		t.Fatalf("PublicIPv4 = %q, %v", got, err)
	}
	if path != "/v1/ip" {
		t.Fatalf("path = %q", path)
	}
}

func TestPublicIPv4RejectsAnInvalidServiceAnswer(t *testing.T) {
	for _, answer := range []string{"10.0.0.1", "100.64.0.1", "::1", "not-an-ip"} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = fmt.Fprintf(w, `{"ip":%q}`, answer)
		}))
		_, err := (&Client{BaseURL: srv.URL}).PublicIPv4(context.Background())
		srv.Close()
		if err == nil {
			t.Errorf("accepted %q", answer)
		}
	}
}

// The body carries no address. What the service writes is the source address
// of the connection, so sending one would be misleading at best.
func TestUpdateSendsNoAddress(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = readAllForTest(r)
		_, _ = w.Write([]byte(`{"ip":"203.0.113.7"}`))
	}))
	defer srv.Close()
	if _, err := (&Client{BaseURL: srv.URL}).Update(context.Background(), "t"); err != nil {
		t.Fatal(err)
	}
	if len(body) != 0 {
		t.Fatalf("sent a body: %q", body)
	}
}

func TestUpdateNamesTheTwoRefusalsThatMeanSomething(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   error
	}{
		{http.StatusUnauthorized, ErrUnknownToken},
		{http.StatusGone, ErrReleased},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(`{"error":"no"}`))
		}))
		_, err := (&Client{BaseURL: srv.URL}).Update(context.Background(), "t")
		if !errors.Is(err, tc.want) {
			t.Errorf("status %d gave %v, want %v", tc.status, err, tc.want)
		}
		srv.Close()
	}
}

func TestUpdateReportsAnyOtherFailureWithItsStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	_, err := (&Client{BaseURL: srv.URL}).Update(context.Background(), "t")
	if err == nil {
		t.Fatal("a 500 was not an error")
	}
	if errors.Is(err, ErrUnknownToken) || errors.Is(err, ErrReleased) {
		t.Fatalf("a 500 was classified as a token problem: %v", err)
	}
}

func readAllForTest(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	buf := make([]byte, 4096)
	n, _ := r.Body.Read(buf)
	return buf[:n], nil
}

func TestClaimSendsTheNameServerIDAndDurableToken(t *testing.T) {
	var body, path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		b := make([]byte, 512)
		n, _ := r.Body.Read(b)
		body = string(b[:n])
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"name":"alice","fqdn":"alice.hyperdrop.link","expiresAt":9}`))
	}))
	defer srv.Close()

	got, err := (&Client{BaseURL: srv.URL}).Claim(context.Background(), "alice", "srv-abc", "durable-token")
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if path != "/v1/claim" {
		t.Errorf("path %q", path)
	}
	if !strings.Contains(body, `"name":"alice"`) || !strings.Contains(body, `"serverId":"srv-abc"`) || !strings.Contains(body, `"token":"durable-token"`) {
		t.Errorf("body %q", body)
	}
	if got.Token != "durable-token" || got.FQDN != "alice.hyperdrop.link" {
		t.Errorf("result %+v", got)
	}
}

// Each refusal means something different to the user, so each is its own
// error rather than one opaque failure the app cannot explain.
func TestClaimNamesEachRefusal(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		want   error
	}{
		{http.StatusConflict, `{"error":"taken"}`, ErrNameTaken},
		{http.StatusConflict, `{"error":"this server already holds a name"}`, ErrNameTaken},
		{http.StatusUnprocessableEntity, `{"error":"reserved: admin is not available"}`, ErrNameRefused},
		{http.StatusTooManyRequests, `{"error":"one address may claim one name a day"}`, ErrClaimRateLimited},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		}))
		_, err := (&Client{BaseURL: srv.URL}).Claim(context.Background(), "alice", "srv", "durable-token")
		if !errors.Is(err, tc.want) {
			t.Errorf("status %d gave %v, want %v", tc.status, err, tc.want)
		}
		srv.Close()
	}
}

// The reason the service gave has to survive, or the app can only say that
// something went wrong.
func TestClaimCarriesTheServicesReason(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"error":"reserved: admin is not available"}`))
	}))
	defer srv.Close()
	_, err := (&Client{BaseURL: srv.URL}).Claim(context.Background(), "admin", "srv", "durable-token")
	if err == nil || !strings.Contains(err.Error(), "admin is not available") {
		t.Fatalf("error %v does not carry the reason", err)
	}
}

func TestReleaseUsesTheBearerAndClassifiesACompletedRelease(t *testing.T) {
	var gotMethod, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotAuth = r.Method, r.Header.Get("Authorization")
		w.WriteHeader(http.StatusGone)
	}))
	defer srv.Close()
	err := (&Client{BaseURL: srv.URL}).Release(context.Background(), "tok")
	if !errors.Is(err, ErrReleased) || gotMethod != http.MethodDelete || gotAuth != "Bearer tok" {
		t.Fatalf("method %q auth %q error %v", gotMethod, gotAuth, err)
	}
}

func TestPortsReadsTheNamesObservation(t *testing.T) {
	var gotHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.URL.Query().Get("host")
		w.Write([]byte(`{"ip":"203.0.113.9","https":{"answer":"hyperdrop","serverID":"s1"},"http":{"answer":"other"}}`))
	}))
	defer srv.Close()
	got, err := (&Client{BaseURL: srv.URL}).Ports(context.Background(), "share.example.com")
	if err != nil || got.HTTPS != (PortObservation{"hyperdrop", "s1"}) || got.HTTP.Answer != "other" || gotHost != "share.example.com" {
		t.Fatalf("Ports = %+v, %v, host %q", got, err, gotHost)
	}
}

func TestPortsOnOldRegistryIsSilent(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	if _, err := (&Client{BaseURL: srv.URL}).Ports(context.Background(), ""); err == nil {
		t.Fatal("a 404 must be an error the caller turns into no verdict")
	}
}

// The names service's words reach a log line, the stored state and an API
// answer, so they arrive on one line and bounded.
func TestServiceTextIsOneBoundedLine(t *testing.T) {
	forged := "name taken\n2026/10/21 00:00:00 admin password reset for admin\r\n"
	if got := serviceText(forged); strings.ContainsAny(got, "\r\n") {
		t.Fatalf("serviceText kept a line break: %q", got)
	}
	long := strings.Repeat("é", 10*serviceTextLimit)
	if got := serviceText(long); utf8.RuneCountInString(got) != serviceTextLimit+1 || !utf8.ValidString(got) {
		t.Fatalf("serviceText of %d runes = %d runes", 10*serviceTextLimit, utf8.RuneCountInString(got))
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		fmt.Fprint(w, forged+strings.Repeat("x", 60<<10))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL}
	for name, call := range map[string]func() error{
		"ip":      func() error { _, err := c.PublicIPv4(context.Background()); return err },
		"update":  func() error { _, err := c.Update(context.Background(), "t"); return err },
		"claim":   func() error { _, err := c.Claim(context.Background(), "alice", "id", "t"); return err },
		"release": func() error { return c.Release(context.Background(), "t") },
	} {
		err := call()
		if err == nil {
			t.Fatalf("%s: no error", name)
		}
		if msg := err.Error(); strings.ContainsAny(msg, "\r\n") || len(msg) > 4*serviceTextLimit {
			t.Errorf("%s: error carries %d bytes or a line break: %.80q", name, len(msg), msg)
		}
	}
}
