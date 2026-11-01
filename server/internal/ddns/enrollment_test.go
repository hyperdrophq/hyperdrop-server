package ddns

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClaimReturnsStructuredAccountApproval(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPreconditionRequired)
		_, _ = w.Write([]byte(`{"code":"account-required","error":"Sign in to approve this free domain","approvalURL":"https://gethyperdrop.com/account/#code=approval","challenge":"bootstrap-nonce","expiresAt":2000000600}`))
	}))
	defer srv.Close()
	_, err := (&Client{BaseURL: srv.URL}).Claim(context.Background(), "myserver", "1111111111111111", "machine-credential")
	var serviceErr *ServiceError
	if !errors.As(err, &serviceErr) {
		t.Fatalf("account approval was not structured: %v", err)
	}
	data, _ := json.Marshal(serviceErr)
	var fields map[string]any
	_ = json.Unmarshal(data, &fields)
	if fields["approvalURL"] != "https://gethyperdrop.com/account/#code=approval" || fields["challenge"] != "bootstrap-nonce" || fields["expiresAt"] != float64(2000000600) {
		t.Fatalf("lost approval details: %s", data)
	}
	if serviceErr.Error() != "Sign in to approve this free domain" {
		t.Fatalf("raw credentials in error text: %s", serviceErr.Error())
	}
}

func TestPendingApprovalPersistsWithoutPublishingDNS(t *testing.T) {
	var updates int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/update" {
			updates++
		}
		w.WriteHeader(http.StatusPreconditionRequired)
		_, _ = w.Write([]byte(`{"code":"account-required","error":"Sign in to approve this free domain","approvalURL":"https://gethyperdrop.com/account/#code=approval","challenge":"bootstrap-nonce","expiresAt":2000000600}`))
	}))
	defer srv.Close()
	u, store := emptyUpdaterFor(t, srv)
	u.Now = func() time.Time { return time.Unix(2000000000, 0) }
	if err := u.Choose(context.Background(), "myserver", "1111111111111111"); err == nil {
		t.Fatal("pending approval reported as connected")
	}
	reloaded, err := Load(store.path)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(reloaded.Snapshot())
	var fields map[string]any
	_ = json.Unmarshal(data, &fields)
	approval, ok := fields["enrollment"].(map[string]any)
	if !ok || approval["challenge"] != "bootstrap-nonce" || approval["approvalURL"] != "https://gethyperdrop.com/account/#code=approval" {
		t.Fatalf("approval not retained across restart: %s", data)
	}
	if updates != 0 || reloaded.Configured() {
		t.Fatal("unapproved server published or became configured")
	}
}

func TestApprovedRetryCanProbeWhileClaimLockIsHeld(t *testing.T) {
	var updater *Updater
	approved := false
	var firstToken, connected string
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/claim" {
			var req struct {
				Token string `json:"token"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			if firstToken == "" {
				firstToken = req.Token
			} else if req.Token != firstToken {
				t.Error("retry changed machine credential")
			}
			if !approved {
				w.WriteHeader(428)
				_, _ = w.Write([]byte(`{"code":"account-required","approvalURL":"https://gethyperdrop.com/account/#code=test","challenge":"nonce","expiresAt":2000000600}`))
				return
			}
			proof := httptest.NewRecorder()
			updater.ServeEnrollmentChallenge(proof, httptest.NewRequest("GET", "/.well-known/hyperdrop-names", nil))
			if proof.Code != 200 || proof.Body.String() != "{\"challenge\":\"nonce\"}\n" {
				t.Errorf("proof %d %s", proof.Code, proof.Body)
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"name":"alice"}`))
			return
		}
		_, _ = w.Write([]byte(`{"name":"alice","ip":"203.0.113.7","state":"active"}`))
	}))
	defer registry.Close()
	updater, _ = emptyUpdaterFor(t, registry)
	updater.Now = func() time.Time { return time.Unix(2000000000, 0) }
	updater.Connected = func(fqdn string) error { connected = fqdn; return nil }
	_ = updater.Choose(context.Background(), "alice", "server")
	approved = true
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := updater.Choose(ctx, "alice", "server"); err != nil {
		t.Fatal(err)
	}
	if connected != "alice.hyperdrop.link" || !updater.Store().Configured() {
		t.Fatal("approved connection not activated")
	}
	proof := httptest.NewRecorder()
	updater.ServeEnrollmentChallenge(proof, httptest.NewRequest("GET", "/.well-known/hyperdrop-names", nil))
	if proof.Code != 404 {
		t.Fatal("completed approval still exposes challenge")
	}
}

func TestExpiredApprovalDoesNotServeAChallenge(t *testing.T) {
	s, _ := tempStore(t)
	_ = s.BeginClaim("alice", "machine", "server")
	u := NewUpdater(s, &Client{}, nil)
	u.Now = func() time.Time { return time.Unix(2000000000, 0) }
	if err := u.rememberEnrollment(&ServiceError{ApprovalURL: "https://gethyperdrop.com/account/#code=test", Challenge: "nonce", ExpiresAt: 2000000001}); err != nil {
		t.Fatal(err)
	}
	u.Now = func() time.Time { return time.Unix(2000000002, 0) }
	proof := httptest.NewRecorder()
	u.ServeEnrollmentChallenge(proof, httptest.NewRequest("GET", "/.well-known/hyperdrop-names", nil))
	if proof.Code != 404 {
		t.Fatal("expired proof served")
	}
}

func TestPendingApprovalRetainsCustomDNSUntilConnected(t *testing.T) {
	s, _ := tempStore(t)
	custom := &HTTPConfig{Mode: "external", Domain: "share.example.com"}
	_ = s.change(func(st *State) { st.Custom = custom })
	if err := s.BeginClaim("alice", "machine", "server"); err != nil {
		t.Fatal(err)
	}
	if s.Snapshot().Custom == nil {
		t.Fatal("approval discarded current DNS config")
	}
	if err := s.Clear(); err != nil {
		t.Fatal(err)
	}
	if s.Snapshot().Custom == nil {
		t.Fatal("cancelling approval discarded DNS config")
	}
	_ = s.BeginClaim("alice", "machine", "server")
	if err := s.ConfirmClaim(); err != nil {
		t.Fatal(err)
	}
	if s.Snapshot().Custom != nil {
		t.Fatal("connected free name retained obsolete DNS config")
	}
}

func TestReviewApprovedBackgroundRetryFinishesDomainAdoption(t *testing.T) {
	approved, failUpdate := false, true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/claim" {
			if !approved {
				w.WriteHeader(428)
				_, _ = w.Write([]byte(`{"code":"account-required","approvalURL":"https://gethyperdrop.com/account/#code=test","challenge":"nonce","expiresAt":2000000600}`))
				return
			}
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"name":"alice"}`))
			return
		}
		if failUpdate {
			w.WriteHeader(503)
			_, _ = w.Write([]byte(`{"code":"temporary","error":"temporary"}`))
			return
		}
		_, _ = w.Write([]byte(`{"name":"alice","ip":"203.0.113.7","state":"active"}`))
	}))
	defer srv.Close()
	u, _ := emptyUpdaterFor(t, srv)
	now := time.Unix(2000000000, 0)
	u.Now = func() time.Time { return now }
	connected := ""
	u.Connected = func(name string) error { connected = name; return nil }
	_ = u.Choose(context.Background(), "alice", "server")
	approved = true
	if err := u.Tick(context.Background()); err == nil {
		t.Fatal("expected temporary update failure")
	}
	failUpdate = false
	now = now.Add(time.Hour)
	if err := u.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if connected != "alice.hyperdrop.link" {
		t.Fatalf("successful background retry lost domain adoption: connected=%q, configured=%v", connected, u.Store().Configured())
	}
}

func TestReviewPendingApprovalKeepsCustomDNSUpdating(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(428)
		_, _ = w.Write([]byte(`{"code":"account-required","approvalURL":"https://gethyperdrop.com/account/#code=test","challenge":"nonce","expiresAt":2000000600}`))
	}))
	defer srv.Close()
	writes := 0
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { writes++; w.WriteHeader(200) }))
	defer provider.Close()
	u, st := emptyUpdaterFor(t, srv)
	now := time.Unix(2000000000, 0)
	u.Now = func() time.Time { return now }
	u.Domain = func() string { return "share.example.com" }
	u.RecipeHTTP = provider.Client()
	u.ProbeHost = func(_ context.Context, host, ip string, _ []byte) HostStatus {
		return HostStatus{Host: host, DNS: "current", HTTPS: "valid"}
	}
	if err := st.change(func(s *State) {
		s.Custom = &HTTPConfig{Mode: "custom", Domain: "share.example.com", Requests: []HTTPRequest{{Method: "PUT", URL: provider.URL}}}
	}); err != nil {
		t.Fatal(err)
	}
	if err := u.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if writes != 1 {
		t.Fatalf("control failed: writes=%d", writes)
	}
	_ = u.Choose(context.Background(), "alice", "server")
	u.addr = func(context.Context) (string, bool) { return "203.0.113.8", true }
	_ = u.Tick(context.Background())
	if writes != 2 {
		t.Fatalf("pending approval stopped existing custom DNS updates after IP change: writes=%d", writes)
	}
}

func TestApprovedAdoptionFailureResumesAfterRestartKeepingCustomUntilComplete(t *testing.T) {
	claims, updates := 0, 0
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/claim" {
			claims++
			w.WriteHeader(201)
		} else {
			updates++
		}
		_, _ = w.Write([]byte(`{"name":"alice","ip":"203.0.113.7","state":"active"}`))
	}))
	defer registry.Close()
	u, store := emptyUpdaterFor(t, registry)
	_ = store.change(func(s *State) { s.Custom = &HTTPConfig{Mode: "external", Domain: "old.example.com"} })
	u.Connected = func(string) error { return errors.New("temporary certificate registration error") }
	if err := u.Choose(context.Background(), "alice", "server"); err == nil {
		t.Fatal("adoption error hidden")
	}
	if st := store.Snapshot(); !st.Pending || !st.Approved || st.Custom == nil || store.Configured() {
		t.Fatalf("unfinished adoption lost: %+v", st)
	}
	reloaded, err := Load(store.path)
	if err != nil {
		t.Fatal(err)
	}
	u = NewUpdater(reloaded, &Client{BaseURL: registry.URL}, func(context.Context) (string, bool) { return "203.0.113.7", true })
	connected := ""
	u.Connected = func(name string) error { connected = name; return nil }
	if err := u.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if connected != "alice.hyperdrop.link" || !reloaded.Configured() || reloaded.Snapshot().Custom != nil || claims != 1 || updates != 1 {
		t.Fatalf("restart did not finish exactly once: connected=%s claims=%d updates=%d state=%+v", connected, claims, updates, reloaded.Snapshot())
	}
}

func TestCustomUpdatesDoNotStarveApprovedPublicationRetry(t *testing.T) {
	fail := true
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/claim" {
			w.WriteHeader(201)
		} else if fail {
			w.WriteHeader(503)
			return
		}
		_, _ = w.Write([]byte(`{"name":"alice","ip":"203.0.113.7","state":"active"}`))
	}))
	defer registry.Close()
	u, st := emptyUpdaterFor(t, registry)
	now := time.Unix(2000000000, 0)
	u.Now = func() time.Time { return now }
	u.Domain = func() string { return "old.example.com" }
	u.ProbeHost = func(_ context.Context, host, ip string, _ []byte) HostStatus {
		return HostStatus{Host: host, DNS: "current", HTTPS: "valid"}
	}
	_ = st.change(func(s *State) { s.Custom = &HTTPConfig{Mode: "external", Domain: "old.example.com"} })
	connected := ""
	u.Connected = func(name string) error { connected = name; return nil }
	if err := u.Choose(context.Background(), "alice", "server"); err == nil {
		t.Fatal("expected failed first publication")
	}
	fail = false
	now = now.Add(time.Hour)
	if err := u.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if connected == "" || !st.Configured() {
		t.Fatal("custom health checks starved managed publication retry")
	}
}

func TestCancelledEnrollmentCannotCompleteAfterFailedDisconnectAndRestart(t *testing.T) {
	failRelease := true
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/name" {
			if failRelease {
				w.WriteHeader(503)
			}
			return
		}
		t.Error("cancelled enrollment contacted claim/update")
	}))
	defer registry.Close()
	u, store := emptyUpdaterFor(t, registry)
	_ = store.BeginClaim("alice", "token", "server")
	domain := "old.example.com"
	err := u.ChangeDomain(context.Background(), func() error { domain = "custom.example.com"; return nil })
	if err == nil {
		t.Fatal("failed disconnect hidden")
	}
	st, err := Load(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Snapshot().Cancelled || domain != "custom.example.com" {
		t.Fatal("cancellation not durable")
	}
	u = NewUpdater(st, &Client{BaseURL: registry.URL}, nil)
	u.Connected = func(string) error { t.Fatal("cancelled approval adopted a domain"); return nil }
	failRelease = false
	if err := u.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st.Snapshot().Name != "" {
		t.Fatal("disconnect was not retried")
	}
}

func TestManagedReplacementAndConditionalCandidateCancellation(t *testing.T) {
	releases, claims := 0, 0
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/name" {
			releases++
			return
		}
		if r.URL.Path != "/v1/claim" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		claims++
		w.WriteHeader(428)
		_, _ = w.Write([]byte(`{"code":"account-required","approvalURL":"https://gethyperdrop.com/account/#code=test","challenge":"nonce","expiresAt":2000000600}`))
	}))
	defer registry.Close()
	u, st := emptyUpdaterFor(t, registry)
	u.Now = func() time.Time { return time.Unix(2000000000, 0) }
	_ = st.Set("newname", "token")
	if err := u.Replace(context.Background(), "oldname", "server"); err == nil {
		t.Fatal("expected account approval")
	}
	if releases != 1 || claims != 1 || st.Snapshot().Name != "oldname" {
		t.Fatal("connected target was not replaced")
	}
	if err := u.Replace(context.Background(), "another", "server"); err == nil {
		t.Fatal("expected account approval")
	}
	if err := u.CancelCandidate(context.Background(), "oldname"); err != nil {
		t.Fatal(err)
	}
	if st.Snapshot().Name != "another" || releases != 2 {
		t.Fatal("stale cancellation removed new candidate")
	}
	if err := u.CancelCandidate(context.Background(), "another"); err != nil {
		t.Fatal(err)
	}
	if st.Snapshot().Name != "" || releases != 3 {
		t.Fatal("pending candidate not cancelled")
	}
}

func TestCustomSwitchSerializesAgainstManagedCompletion(t *testing.T) {
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"name":"alice","ip":"203.0.113.7"}`))
	}))
	defer registry.Close()
	u, st := emptyUpdaterFor(t, registry)
	_ = st.BeginClaim("alice", "token", "server")
	_ = st.change(func(s *State) { s.Approved = true })
	entered, finish := make(chan struct{}), make(chan struct{})
	domain := "old.example.com"
	u.Connected = func(name string) error { close(entered); <-finish; domain = name; return nil }
	tickDone := make(chan error, 1)
	go func() { tickDone <- u.Tick(context.Background()) }()
	<-entered
	switchDone := make(chan error, 1)
	go func() {
		switchDone <- u.ChangeDomain(context.Background(), func() error { domain = "custom.example.com"; return nil })
	}()
	close(finish)
	if err := <-tickDone; err != nil {
		t.Fatal(err)
	}
	if err := <-switchDone; err != nil {
		t.Fatal(err)
	}
	if domain != "custom.example.com" {
		t.Fatalf("background completion replaced custom choice: %s", domain)
	}
	if err := u.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if domain != "custom.example.com" {
		t.Fatal("later tick repeated adoption")
	}
}

func TestCancelledCandidateIsNotResurrectedByBootSeed(t *testing.T) {
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" || r.URL.Path != "/v1/name" {
			t.Errorf("boot resurrected cancelled enrollment: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer registry.Close()
	u, st := emptyUpdaterFor(t, registry)
	_ = st.BeginClaim("alice", "token", "server")
	if err := u.CancelCandidate(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Load(st.path)
	if err != nil {
		t.Fatal(err)
	}
	u = NewUpdater(reloaded, &Client{BaseURL: registry.URL}, nil)
	if err := u.Take(context.Background(), "alice", "server"); err != nil {
		t.Fatal(err)
	}
	if reloaded.Snapshot().Name != "" {
		t.Fatal("boot restaged a cancelled name")
	}
}

func TestCustomObservationCannotHideManagedIPChangeDuringAdoptionRetry(t *testing.T) {
	updates := 0
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/claim" {
			w.WriteHeader(201)
		}
		if r.URL.Path == "/v1/update" {
			updates++
		}
		_, _ = w.Write([]byte(`{"name":"alice","ip":"203.0.113.7"}`))
	}))
	defer registry.Close()
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer provider.Close()
	u, st := emptyUpdaterFor(t, registry)
	u.Domain = func() string { return "old.example.com" }
	u.RecipeHTTP = provider.Client()
	u.ProbeHost = func(_ context.Context, host, ip string, _ []byte) HostStatus {
		return HostStatus{Host: host, DNS: "current", HTTPS: "valid"}
	}
	_ = st.change(func(s *State) {
		s.Custom = &HTTPConfig{Mode: "custom", Domain: "old.example.com", Requests: []HTTPRequest{{Method: "PUT", URL: provider.URL}}}
	})
	u.Connected = func(string) error { return errors.New("temporary adoption failure") }
	_ = u.Choose(context.Background(), "alice", "server")
	if updates != 1 {
		t.Fatal("first publication missing")
	}
	u.addr = func(context.Context) (string, bool) { return "203.0.113.8", true }
	u.Connected = func(string) error { return nil }
	if err := u.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if updates != 2 {
		t.Fatal("custom observation hid the managed DNS IP change")
	}
}
