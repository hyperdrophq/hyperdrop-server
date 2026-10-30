package api

// The health verdict is a pure function of numbers, so it is table-tested.
// Each case is a state a real self-hosted box reaches; the assertions are on
// the LEVEL and the CODE, not the wording, since only those two are contract.

import (
	"encoding/json"
	"hyperdrop/server/internal/metadb"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/ddns"
	"hyperdrop/server/internal/domain"
)

func hasReason(v healthVerdict, code string) bool {
	for _, r := range v.Reasons {
		if r.Code == code {
			return true
		}
	}
	return false
}

func TestHealthVerdict(t *testing.T) {
	const gb = int64(1) << 30
	cases := []struct {
		name  string
		in    healthInputs
		level string
		code  string // "" = expect no reasons
	}{
		{
			name:  "a healthy server",
			in:    healthInputs{FreeBytes: 50 * gb, TotalBytes: 100 * gb, ReserveBytes: gb, MemTotal: gb, MemAvailable: gb / 2},
			level: healthOK,
		},
		{
			name:  "disk under 100 MB above the reserve",
			in:    healthInputs{FreeBytes: gb + 99_999_999, TotalBytes: 100 * gb, ReserveBytes: gb, MemTotal: gb, MemAvailable: gb / 2},
			level: healthWarn, code: reasonDiskLow,
		},
		{
			name:  "disk exactly 100 MB above the reserve",
			in:    healthInputs{FreeBytes: gb + 100_000_000, TotalBytes: 100 * gb, ReserveBytes: gb, MemTotal: gb, MemAvailable: gb / 2},
			level: healthOK,
		},
		{
			name:  "a big disk with a few gigabytes of room for shares",
			in:    healthInputs{FreeBytes: 5 * gb, TotalBytes: 4000 * gb, ReserveBytes: gb, MemTotal: gb, MemAvailable: gb / 2},
			level: healthOK,
		},
		{
			name:  "a small disk nearly full but over 100 MB of room",
			in:    healthInputs{FreeBytes: gb + 200_000_000, TotalBytes: 8 * gb, ReserveBytes: gb, MemTotal: gb, MemAvailable: gb / 2},
			level: healthOK,
		},
		{
			name:  "disk below the reserve, where uploads already fail",
			in:    healthInputs{FreeBytes: gb / 2, ReserveBytes: gb, MemTotal: gb, MemAvailable: gb / 2},
			level: healthCritical, code: reasonDiskLow,
		},
		{
			name:  "memory tight",
			in:    healthInputs{FreeBytes: 50 * gb, ReserveBytes: gb, MemTotal: 1000, MemAvailable: 120},
			level: healthWarn, code: reasonMemoryLow,
		},
		{
			name:  "memory nearly gone",
			in:    healthInputs{FreeBytes: 50 * gb, ReserveBytes: gb, MemTotal: 1000, MemAvailable: 50},
			level: healthCritical, code: reasonMemoryLow,
		},
		{
			name:  "no limits known: nothing to warn about",
			in:    healthInputs{FreeBytes: 50 * gb, MemTotal: 0},
			level: healthOK,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := evaluateHealth(tc.in)
			if got.Level != tc.level {
				t.Errorf("level = %q, want %q (reasons %+v)", got.Level, tc.level, got.Reasons)
			}
			if tc.code == "" {
				if len(got.Reasons) != 0 {
					t.Errorf("expected no reasons, got %+v", got.Reasons)
				}
				return
			}
			if !hasReason(got, tc.code) {
				t.Errorf("missing reason %q, got %+v", tc.code, got.Reasons)
			}
		})
	}
}

// roomy gives in a disk with plenty of room, so a test of another signal
// sees that signal's reason alone.
func roomy(in healthInputs) healthInputs {
	in.FreeBytes, in.TotalBytes, in.ReserveBytes = 50<<30, 100<<30, 1<<30
	return in
}

// The verdict takes the WORST of its signals, and reports each one: an owner
// with two problems has to see both, or fixing the disk leaves them
// surprised by the memory.
func TestHealthVerdictTakesTheWorstAndKeepsEveryReason(t *testing.T) {
	const gb = int64(1) << 30
	got := evaluateHealth(healthInputs{
		FreeBytes: gb + 50_000_000, TotalBytes: 100 * gb, ReserveBytes: gb, // warn
		MemTotal: 1000, MemAvailable: 50, // critical
	})
	if got.Level != healthCritical {
		t.Errorf("level = %q, want critical", got.Level)
	}
	for _, code := range []string{reasonDiskLow, reasonMemoryLow} {
		if !hasReason(got, code) {
			t.Errorf("missing reason %q from %+v", code, got.Reasons)
		}
	}
}

func TestByteText(t *testing.T) {
	for _, tc := range []struct {
		n    int64
		want string
	}{
		{999, "999 B"},
		{1000, "1.0 KB"}, // KB, as the app's ByteCountFormatter writes it
		{1_500_000, "1.5 MB"},
		{2_000_000_000, "2.0 GB"},
	} {
		if got := byteText(tc.n); got != tc.want {
			t.Errorf("byteText(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}

// The verdict rides /api/usage, which is admin-only: how close the box is to
// failing is not something a guest account gets to read.
func TestUsageCarriesTheHealthVerdict(t *testing.T) {
	h := New(newTestAPIWithDisk(t, 400), "2.0.0", testDomain(t), nil)
	createShare(t, h, "one")

	rec := doReq(t, h, "GET", "/api/usage", testToken, "")
	if rec.Code != 200 {
		t.Fatalf("usage = %d: %s", rec.Code, rec.Body)
	}
	var out struct {
		Health healthVerdict `json:"health"`
		Shares struct {
			Count int `json:"count"`
		} `json:"shares"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Health.Level == "" {
		t.Error("usage carries no health verdict")
	}
	if out.Shares.Count != 1 {
		t.Errorf("shares.count = %d, want 1", out.Shares.Count)
	}
}

// /api/health is the public compat probe and stays minimal: an
// unauthenticated caller learns the version, not how the box is doing.
func TestPublicHealthLeaksNoState(t *testing.T) {
	h := New(newTestAPIWithDisk(t, 400), "2.0.0", testDomain(t), nil)
	for i := 0; i < 3; i++ {
		createShare(t, h, "s")
	}
	rec := doReq(t, h, "GET", "/api/health", "", "")
	if rec.Code != 200 {
		t.Fatalf("health = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, leak := range []string{"health", "shares", "usedBytes", "freeBytes"} {
		if strings.Contains(body, leak) {
			t.Errorf("public health exposes %q: %s", leak, body)
		}
	}
}

// The domain rides the UNAUTHENTICATED health route, unlike GET /api/domain
// which is admin-only: a guest who joined over an IP is exactly the client that
// cannot read that route and most needs it, since links are composed
// client-side from the registry entry.
func TestHealthReportsTheDomainWhenOneIsSet(t *testing.T) {
	dom, err := domain.Load(filepath.Join(t.TempDir(), "domain"), "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	h := New(testBackend(t), "2.0.0", dom, nil)

	if got := healthField(t, h, "domain"); got != nil {
		t.Fatalf("a server with no domain must omit it, got %v", got)
	}
	if err := dom.Adopt("share.example.com"); err != nil {
		t.Fatal(err)
	}
	if got := healthField(t, h, "domain"); got != "share.example.com" {
		t.Fatalf("domain = %v, want share.example.com", got)
	}
}

// The channel names WHO owns the installed binary (Package Center on a
// Synology), so a client knows the API update path cannot apply. Absent on
// a normal VPS install: absence IS the normal case, not a missing field.
func TestHealthReportsTheInstallChannel(t *testing.T) {
	dom, err := domain.Load(filepath.Join(t.TempDir(), "domain"), "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	h := NewServer(testBackend(t), "1.19.0", dom, nil,
		Deployment{DataDir: t.TempDir(), Channel: "synology"})
	if got := healthField(t, h, "channel"); got != "synology" {
		t.Fatalf("channel = %v, want synology", got)
	}

	plain := NewServer(testBackend(t), "1.19.0", dom, nil, Deployment{DataDir: t.TempDir()})
	if got := healthField(t, plain, "channel"); got != nil {
		t.Fatalf("channel must be absent on a normal install, got %v", got)
	}
}

// The platform and architecture are the two public, non-secret coordinates
// a client needs to link to the exact DSM package rather than a release picker.
func TestHealthReportsTheDSMPlatform(t *testing.T) {
	dom, err := domain.Load(filepath.Join(t.TempDir(), "domain"), "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	for _, platform := range []string{"dsm7", "dsm6"} {
		h := NewServer(testBackend(t), "1.46.0", dom, nil,
			Deployment{DataDir: t.TempDir(), Channel: "synology", Platform: platform})
		if got := healthField(t, h, "platform"); got != platform {
			t.Fatalf("platform = %v, want %s", got, platform)
		}
	}
}

func TestHealthOmitsUnknownPlatform(t *testing.T) {
	dom, err := domain.Load(filepath.Join(t.TempDir(), "domain"), "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	h := NewServer(testBackend(t), "1.46.0", dom, nil,
		Deployment{DataDir: t.TempDir(), Channel: "synology", Platform: "something-else"})
	if got := healthField(t, h, "platform"); got != nil {
		t.Fatalf("unknown platform must be absent, got %v", got)
	}
}

func healthField(t *testing.T, h http.Handler, key string) any {
	t.Helper()
	rec := doReq(t, h, "GET", "/api/health", "", "")
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out[key]
}

func TestHealthDoesNotAdoptUnapprovedOrReleasedManagedDomain(t *testing.T) {
	dom, err := domain.Load(filepath.Join(t.TempDir(), "domain"), "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	ds, err := ddns.Load(filepath.Join(t.TempDir(), "ddns"))
	if err != nil {
		t.Fatal(err)
	}
	upd := ddns.NewUpdater(ds, &ddns.Client{}, nil)
	h := New(testBackend(t), "2.0.0", dom, upd)
	if err := dom.Adopt("alice.hyperdrop.link"); err != nil {
		t.Fatal(err)
	}
	if got := healthField(t, h, "domain"); got != nil {
		t.Fatalf("released domain advertised: %v", got)
	}
	_ = ds.BeginClaim("alice", "token", "server")
	if got := healthField(t, h, "domain"); got != nil {
		t.Fatalf("unapproved domain advertised: %v", got)
	}
	_ = dom.Adopt("custom.example.com")
	if got := healthField(t, h, "domain"); got != "custom.example.com" {
		t.Fatalf("live custom domain hidden: %v", got)
	}
	_ = dom.Adopt("alice.hyperdrop.link")
	_ = ds.ConfirmClaim()
	if got := healthField(t, h, "domain"); got != "alice.hyperdrop.link" {
		t.Fatalf("approved domain hidden: %v", got)
	}
}

func TestARecoveredDatabaseIsAWarnReason(t *testing.T) {
	v := evaluateHealth(roomy(healthInputs{Recovered: &metadb.Recovered{At: time.Date(2026, 9, 30, 8, 0, 0, 0, time.UTC),
		BackupAt: time.Date(2026, 9, 29, 3, 0, 0, 0, time.UTC), Backup: "b"}}))
	if v.Level != healthWarn || len(v.Reasons) != 1 || v.Reasons[0].Code != "db-recovered" {
		t.Fatalf("%+v", v)
	}
	if !strings.Contains(v.Reasons[0].Text, "2026-09-29") {
		t.Fatalf("text does not name the day: %q", v.Reasons[0].Text)
	}
}

func TestUsageReportsARecoveredDatabase(t *testing.T) {
	dir := t.TempDir()
	b := testBackendAt(t, dir)
	h := newHandler(b, "2.0.0", testDomain(t), nil, Deployment{DataDir: dir}).routes()
	os.WriteFile(filepath.Join(dir, metadb.RecoveredMarker), []byte(`{"at":"2026-09-29T03:00:00Z","backup":"b","corrupt":"c"}`), 0o644)
	rec := doReq(t, h, "GET", "/api/usage", testToken, "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"db-recovered"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}

func TestHealthReportsMissingFiles(t *testing.T) {
	for _, tc := range []struct {
		n    int
		text string
	}{
		{1, "1 file is missing from HyperDrop's data folder. Restore it from a backup of the folder."},
		{3, "3 files are missing from HyperDrop's data folder. Restore them from a backup of the folder."},
	} {
		v := evaluateHealth(roomy(healthInputs{MissingFiles: tc.n}))
		if v.Level != healthWarn || len(v.Reasons) != 1 || v.Reasons[0].Code != reasonFilesMissing || v.Reasons[0].Text != tc.text {
			t.Fatalf("n=%d: %+v", tc.n, v)
		}
	}
	if v := evaluateHealth(healthInputs{}); hasReason(v, reasonFilesMissing) {
		t.Fatal("zero missing files raised a reason")
	}
}

func TestHealthExplainsAProxyHeader(t *testing.T) {
	untrusted := []ProxyHeaderSource{{Addr: "10.20.30.40", Kind: ProxyKindUntrustedHeader}}
	trusted := []ProxyHeaderSource{{Addr: "192.168.1.10", Kind: ProxyKindTrustedNoHeader}}
	for _, tc := range []struct {
		name  string
		in    healthInputs
		level string
		text  string
	}{
		{"a private source on the NAS", healthInputs{ProxyPrivate: untrusted, ProxyPublic: 4, Synology: true}, healthCritical,
			"Connections from 10.20.30.40 start with a PROXY header, but 10.20.30.40 is not set as a proxy address, so every secure connection fails. Set 10.20.30.40 as the proxy address on HyperDrop's DSM page."},
		{"a private source on Linux", healthInputs{ProxyPrivate: untrusted}, healthCritical,
			"Connections from 10.20.30.40 start with a PROXY header, but 10.20.30.40 is not set as a proxy address, so every secure connection fails. Set 10.20.30.40 in HYPERDROP_TRUSTED_PROXIES."},
		{"a listed proxy without a header", healthInputs{ProxyPrivate: trusted, Synology: true}, healthCritical,
			"192.168.1.10 is set as the proxy address but sends no PROXY header, so its connections fail. Turn on send-proxy-v2 in the proxy, or clear the proxy address."},
		// Anyone on the internet can send one: a warning, not critical.
		{"public sources only", healthInputs{ProxyPublic: 3, Synology: true}, healthWarn,
			"Connections from the internet start with a PROXY header. A proxy in front of HyperDrop must be on this network."},
	} {
		v := evaluateHealth(roomy(tc.in))
		if v.Level != tc.level || len(v.Reasons) != 1 || v.Reasons[0].Code != reasonProxyHeader || v.Reasons[0].Text != tc.text {
			t.Errorf("%s: %+v", tc.name, v)
		}
	}
	if v := evaluateHealth(healthInputs{}); hasReason(v, reasonProxyHeader) {
		t.Fatal("no source raised a proxy reason")
	}
}

// The most recently seen private source, the first, is the one named.
func TestHealthNamesTheLatestProxySource(t *testing.T) {
	v := evaluateHealth(roomy(healthInputs{ProxyPrivate: []ProxyHeaderSource{
		{Addr: "10.0.0.2", Kind: ProxyKindTrustedNoHeader},
		{Addr: "10.0.0.1", Kind: ProxyKindUntrustedHeader},
	}}))
	if len(v.Reasons) != 1 || !strings.HasPrefix(v.Reasons[0].Text, "10.0.0.2 is set as the proxy address") {
		t.Fatalf("%+v", v)
	}
}

func TestUsageReportsAProxyHeader(t *testing.T) {
	for _, tc := range []struct {
		channel, want string
	}{
		{"synology", "on HyperDrop's DSM page."},
		{"", "Set 10.20.30.40 in HYPERDROP_TRUSTED_PROXIES."},
	} {
		h := newHandler(testBackend(t), "2.0.0", testDomain(t), nil, Deployment{
			DataDir: t.TempDir(), Channel: tc.channel,
			ProxyHeaders: func() ([]ProxyHeaderSource, int) {
				return []ProxyHeaderSource{{Addr: "10.20.30.40", Kind: ProxyKindUntrustedHeader}}, 2
			},
		}).routes()
		rec := doReq(t, h, "GET", "/api/usage", testToken, "")
		body := rec.Body.String()
		if rec.Code != 200 || !strings.Contains(body, `"proxy-header"`) || !strings.Contains(body, tc.want) {
			t.Fatalf("channel %q: %d %s", tc.channel, rec.Code, body)
		}
	}
}

func TestHealthReportsAPendingAddress(t *testing.T) {
	v := evaluateHealth(roomy(healthInputs{
		PendingAddress: "share.example.com",
		PendingReason:  "share.example.com does not point at this NAS yet.",
	}))
	want := "Waiting to switch to share.example.com: share.example.com does not point at this NAS yet."
	if v.Level != healthWarn || len(v.Reasons) != 1 || v.Reasons[0].Code != reasonAddressPending || v.Reasons[0].Text != want {
		t.Fatalf("%+v", v)
	}
	if v := evaluateHealth(healthInputs{}); hasReason(v, reasonAddressPending) {
		t.Fatal("no pending address raised a reason")
	}
}

func TestUsageReportsAPendingAddress(t *testing.T) {
	h := newHandler(testBackend(t), "2.0.0", testDomain(t), nil, Deployment{
		DataDir: t.TempDir(),
		AddressPending: func() (string, string) {
			return "bob.hyperdrop.link", "bob.hyperdrop.link is waiting for approval in your HyperDrop account."
		},
	}).routes()
	rec := doReq(t, h, "GET", "/api/usage", testToken, "")
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, `"address-pending"`) || !strings.Contains(body, "Waiting to switch to bob.hyperdrop.link") {
		t.Fatalf("%d %s", rec.Code, body)
	}
}

// The warning and the critical line speak of the room left for new shares,
// the number the apps show as available.
func TestTheDiskReasonsNameTheRoomForNewShares(t *testing.T) {
	const gb = int64(1) << 30
	warn := evaluateHealth(healthInputs{FreeBytes: gb + 50_000_000, TotalBytes: 4000 * gb, ReserveBytes: gb})
	if len(warn.Reasons) != 1 || warn.Reasons[0].Text != "Only "+byteText(50_000_000)+" left for new shares" {
		t.Fatalf("warn reasons %+v", warn.Reasons)
	}
	crit := evaluateHealth(healthInputs{FreeBytes: gb / 2, TotalBytes: 4000 * gb, ReserveBytes: gb})
	want := "No room left for new shares: " + byteText(gb/2) + " of disk free, below the " + byteText(gb) +
		" this server keeps free. New shares are being refused"
	if len(crit.Reasons) != 1 || crit.Reasons[0].Text != want {
		t.Fatalf("critical reasons %+v, want %q", crit.Reasons, want)
	}
}
