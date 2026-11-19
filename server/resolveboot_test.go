package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/api"
	"hyperdrop/server/internal/selfupdate"
	"hyperdrop/server/internal/sharefs"
)

// devEnv is a development server's environment plus extra, which resolves
// with no domain, so each case below varies one variable alone.
func devEnv(extra map[string]string) func(string) (string, bool) {
	m := map[string]string{"HYPERDROP_ALLOW_PRIVATE": "1"}
	for k, v := range extra {
		m[k] = v
	}
	return lookupIn(m)
}

func resolveDev(t *testing.T, extra map[string]string) bootConfig {
	t.Helper()
	bc, err := resolveBoot(devEnv(extra))
	if err != nil {
		t.Fatalf("resolveBoot(%v): %v", extra, err)
	}
	return bc
}

// The plain variables main reads after resolveBoot pass through as they are
// set, and unset is their default.
func TestResolveBootReadsThePlainVariables(t *testing.T) {
	for _, tc := range []struct {
		name, set string
		get       func(bootConfig) string
		unset     string
	}{
		{"HYPERDROP_DATA", "/srv/hyperdrop", func(bc bootConfig) string { return bc.DataDir }, "/data"},
		{"HYPERDROP_CHANNEL", "synology", func(bc bootConfig) string { return bc.Channel }, ""},
		{"HYPERDROP_STATUS_FILE", "/run/hyperdrop/status.json", func(bc bootConfig) string { return bc.StatusFile }, ""},
		{"HYPERDROP_CONF", "/var/packages/hyperdrop/etc/hyperdrop.conf", func(bc bootConfig) string { return bc.ConfFile }, ""},
		{"HYPERDROP_ADDRESS_REQUEST", "/var/packages/hyperdrop/var/address", func(bc bootConfig) string { return bc.AddressRequest }, ""},
		{"HYPERDROP_UPDATE_DIR", "/var/lib/hyperdrop/update", func(bc bootConfig) string { return bc.UpdateDir }, ""},
		{"HYPERDROP_ACME_EMAIL", "ops@example.com", func(bc bootConfig) string { return bc.ACMEEmail }, ""},
		{"HYPERDROP_ACME_CA", "https://127.0.0.1:14000/dir", func(bc bootConfig) string { return bc.ACMECA }, ""},
	} {
		if got := tc.get(resolveDev(t, nil)); got != tc.unset {
			t.Errorf("%s unset = %q, want %q", tc.name, got, tc.unset)
		}
		if got := tc.get(resolveDev(t, map[string]string{tc.name: tc.set})); got != tc.set {
			t.Errorf("%s=%q read as %q", tc.name, tc.set, got)
		}
	}
}

// DataDir and Channel are what main needs before it can log resolveBoot's
// error, so an error leaves them set.
func TestResolveBootSetsTheDataDirAndChannelOnAnError(t *testing.T) {
	bc, err := resolveBoot(lookupIn(map[string]string{
		"HYPERDROP_DATA": "/srv/hyperdrop", "HYPERDROP_CHANNEL": "synology"}))
	if err == nil {
		t.Fatal("a server with no domain and no HYPERDROP_ALLOW_PRIVATE resolved")
	}
	if bc.DataDir != "/srv/hyperdrop" || bc.Channel != "synology" {
		t.Fatalf("DataDir %q, Channel %q on an error", bc.DataDir, bc.Channel)
	}
	bc, _ = resolveBoot(lookupIn(nil))
	if bc.DataDir != "/data" {
		t.Fatalf("DataDir unset on an error = %q, want /data", bc.DataDir)
	}
}

// A process systemd started (INVOCATION_ID set) is one it restarts, so it
// is supervised; the Synology package's script runs under a unit of DSM's,
// which is not relied on to restart the server, so a server there is not.
func TestResolveBootReadsWhetherSystemdSupervises(t *testing.T) {
	if resolveDev(t, nil).Supervised {
		t.Error("INVOCATION_ID unset is supervised")
	}
	if !resolveDev(t, map[string]string{"INVOCATION_ID": "0123456789abcdef0123456789abcdef"}).Supervised {
		t.Error("INVOCATION_ID set is not supervised")
	}
	if resolveDev(t, map[string]string{"INVOCATION_ID": "0123456789abcdef0123456789abcdef", "HYPERDROP_CHANNEL": "synology"}).Supervised {
		t.Error("the Synology package is supervised")
	}
}

func TestResolveBootReadsTheDDNSPrivateSwitch(t *testing.T) {
	for v, want := range map[string]bool{"1": true, "": false, "0": false, "true": false, "yes": false} {
		if got := resolveDev(t, map[string]string{"HYPERDROP_DDNS_ALLOW_PRIVATE": v}).DDNSAllowPrivate; got != want {
			t.Errorf("HYPERDROP_DDNS_ALLOW_PRIVATE=%q = %v, want %v", v, got, want)
		}
	}
	if resolveDev(t, nil).DDNSAllowPrivate {
		t.Error("HYPERDROP_DDNS_ALLOW_PRIVATE unset allows private recipes")
	}
}

func TestResolveBootSplitsTheLinkedRoots(t *testing.T) {
	bc := resolveDev(t, nil)
	if bc.LinkedRoots != nil || bc.LinkedScan != nil {
		t.Fatalf("unset: LinkedRoots %q, LinkedScan %q, want none", bc.LinkedRoots, bc.LinkedScan)
	}
	bc = resolveDev(t, map[string]string{
		"HYPERDROP_LINKED_ROOTS": "/srv/team: /srv/photos :",
		"HYPERDROP_LINKED_SCAN":  "/volume1::/volume2"})
	if !slices.Equal(bc.LinkedRoots, []string{"/srv/team", "/srv/photos"}) {
		t.Errorf("LinkedRoots = %q", bc.LinkedRoots)
	}
	if !slices.Equal(bc.LinkedScan, []string{"/volume1", "/volume2"}) {
		t.Errorf("LinkedScan = %q", bc.LinkedScan)
	}
}

// A malformed HYPERDROP_AUTO_UPDATE is not resolveBoot's error: main refuses
// it once the volume is open, with the parse error it carries.
func TestResolveBootParsesTheAutoUpdateChoice(t *testing.T) {
	if bc := resolveDev(t, nil); bc.AutoUpdate || bc.AutoUpdateErr != nil {
		t.Fatalf("unset = %v, %v; want off", bc.AutoUpdate, bc.AutoUpdateErr)
	}
	if bc := resolveDev(t, map[string]string{"HYPERDROP_AUTO_UPDATE": "on"}); !bc.AutoUpdate || bc.AutoUpdateErr != nil {
		t.Fatalf("on = %v, %v", bc.AutoUpdate, bc.AutoUpdateErr)
	}
	bc := resolveDev(t, map[string]string{"HYPERDROP_AUTO_UPDATE": "sometimes"})
	_, want := selfupdate.ParseChoice("sometimes")
	if bc.AutoUpdateErr == nil || bc.AutoUpdateErr.Error() != want.Error() {
		t.Fatalf("malformed: %v, want %v", bc.AutoUpdateErr, want)
	}
}

// A malformed HYPERDROP_DISK_RESERVE is refused by openServingVolume once
// the admin is seeded, not by resolveBoot.
func TestResolveBootParsesTheDiskReserve(t *testing.T) {
	if bc := resolveDev(t, nil); bc.DiskReserve != sharefs.FlatReserve || bc.DiskReserveErr != nil {
		t.Fatalf("unset = %d, %v; want the flat reserve", bc.DiskReserve, bc.DiskReserveErr)
	}
	if bc := resolveDev(t, map[string]string{"HYPERDROP_DISK_RESERVE": "5"}); bc.DiskReserve != 5 || bc.DiskReserveErr != nil {
		t.Fatalf("5 = %d, %v", bc.DiskReserve, bc.DiskReserveErr)
	}
	bc := resolveDev(t, map[string]string{"HYPERDROP_DISK_RESERVE": "91"})
	if bc.DiskReserveErr == nil || bc.DiskReserveErr.Error() != `invalid value "91" (want 0-90)` {
		t.Fatalf("malformed: %v", bc.DiskReserveErr)
	}
}

func TestResolveBootParsesThePushRelay(t *testing.T) {
	for _, tc := range []struct {
		name       string
		set        bool
		raw        string
		allowPriv  bool
		want       string
		wantRefuse bool
	}{
		{"unset", false, "", true, api.DefaultPushRelay, false},
		{"set empty", true, "", true, "", false},
		{"an https origin", true, "https://relay.example.com/", true, "https://relay.example.com", false},
		{"plain http on a development server", true, "http://127.0.0.1:9000", true, "http://127.0.0.1:9000", false},
		{"plain http elsewhere", true, "http://relay.example.com", false, "", true},
		{"a path", true, "https://relay.example.com/push", true, "", true},
	} {
		m := map[string]string{"HYPERDROP_DOMAIN": "share.example.com", "HYPERDROP_IP": "203.0.113.7"}
		if tc.allowPriv {
			m["HYPERDROP_ALLOW_PRIVATE"] = "1"
		}
		if tc.set {
			m["HYPERDROP_PUSH_RELAY"] = tc.raw
		}
		bc, err := resolveBoot(lookupIn(m))
		if err != nil {
			t.Fatalf("%s: a push relay refused the boot: %v", tc.name, err)
		}
		if bc.PushRelay != tc.want || (bc.PushRelayErr != nil) != tc.wantRefuse {
			t.Errorf("%s: PushRelay %q, %v; want %q, refused %v", tc.name, bc.PushRelay, bc.PushRelayErr, tc.want, tc.wantRefuse)
		}
	}
}

func TestResolveBootParsesTheServerReleases(t *testing.T) {
	if bc := resolveDev(t, nil); bc.Releases != selfupdate.DefaultBase || bc.ReleasesErr != nil {
		t.Fatalf("unset = %q, %v; want the HyperDrop site", bc.Releases, bc.ReleasesErr)
	}
	if bc := resolveDev(t, map[string]string{"HYPERDROP_SERVER_RELEASES": ""}); bc.Releases != "" || bc.ReleasesErr != nil {
		t.Fatalf("set empty = %q, %v; want never check", bc.Releases, bc.ReleasesErr)
	}
	if bc := resolveDev(t, map[string]string{"HYPERDROP_SERVER_RELEASES": "https://mirror.example.com/server"}); bc.Releases != "https://mirror.example.com/server/" || bc.ReleasesErr != nil {
		t.Fatalf("set = %q, %v", bc.Releases, bc.ReleasesErr)
	}
	bc := resolveDev(t, map[string]string{"HYPERDROP_SERVER_RELEASES": "ftp://mirror.example.com/"})
	if bc.Releases != "" || bc.ReleasesErr == nil {
		t.Fatalf("malformed = %q, %v; want never check, with the reason", bc.Releases, bc.ReleasesErr)
	}
}

func TestResolveBootParsesTheACMECACertificate(t *testing.T) {
	if bc := resolveDev(t, nil); bc.ACMETrustedRoots != nil || bc.ACMETrustedRootsErr != nil {
		t.Fatalf("unset = %v, %v; want none", bc.ACMETrustedRoots, bc.ACMETrustedRootsErr)
	}
	bc := resolveDev(t, map[string]string{"HYPERDROP_ACME_CA_CERT": selfSignedPEM(t)})
	if bc.ACMETrustedRoots == nil || bc.ACMETrustedRootsErr != nil {
		t.Fatalf("a PEM certificate = %v, %v", bc.ACMETrustedRoots, bc.ACMETrustedRootsErr)
	}
	bc = resolveDev(t, map[string]string{"HYPERDROP_ACME_CA_CERT": "not a certificate"})
	if bc.ACMETrustedRoots != nil || bc.ACMETrustedRootsErr == nil ||
		bc.ACMETrustedRootsErr.Error() != "HYPERDROP_ACME_CA_CERT: invalid PEM" {
		t.Fatalf("malformed = %v, %v", bc.ACMETrustedRoots, bc.ACMETrustedRootsErr)
	}
}

// The web client's variables are resolveBoot's to refuse, after the domain's.
func TestResolveBootResolvesTheWebClient(t *testing.T) {
	bc := resolveDev(t, map[string]string{"HYPERDROP_WEB_RELEASES": "https://web.example.com/web/"})
	if len(bc.Web.Keys) == 0 || bc.Web.Base != "https://web.example.com/web/" {
		t.Fatalf("Web = %+v", bc.Web)
	}
	_, err := resolveBoot(lookupIn(map[string]string{
		"HYPERDROP_DOMAIN": "share.example.com", "HYPERDROP_IP": "203.0.113.7",
		"HYPERDROP_WEB_DEV_DIR": t.TempDir()}))
	if err == nil || !strings.Contains(err.Error(), "HYPERDROP_WEB_DEV_DIR") {
		t.Fatalf("a development directory without HYPERDROP_ALLOW_PRIVATE = %v", err)
	}
	_, err = resolveBoot(lookupIn(map[string]string{"HYPERDROP_WEB_DEV_DIR": t.TempDir()}))
	if err == nil || !strings.Contains(err.Error(), "HYPERDROP_DOMAIN is required") {
		t.Fatalf("no domain and a development directory = %v, want the domain's error", err)
	}
}

func selfSignedPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
