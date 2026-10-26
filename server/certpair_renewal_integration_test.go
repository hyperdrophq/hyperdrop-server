//go:build acme

package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3/acme"

	"hyperdrop/server/internal/api"
	"hyperdrop/server/internal/certpair"
)

const pebbleDirectory = "https://localhost:14000/dir"

// renewalDomain begins with a letter that sorts after the `files.` label, so
// a CA that byte-sorts the SAN set emits the file origin first. Every domain
// that does not begin with a digit or with `a` to `e` is in this position.
const renewalDomain = "zeta.example.com"

// TestMaintenanceRenewsAPairWhoseFirstNameIsTheFileOrigin drives CertMagic's
// own background maintenance over a paired certificate whose FIRST name is
// the file origin, which is the shape Let's Encrypt issues for every domain
// sorting after `files.`.
//
// Maintenance renews a cached certificate under oldCert.Names[0] and reloads
// it from storage under that same name, while the resource lives under the
// subject CertMagic manages, the app domain. The storage alias and the
// subject transformer are what bridge that gap, so this drives the real
// maintenance entry point and asserts on what the config ends up serving
// rather than on the absence of an error: an ACME renewal can succeed and
// still leave the stale leaf in the cache when the reload cannot find the
// resource.
//
// Run with, on any machine with Docker:
//
//	cd test/pebble && docker compose up -d
//	cd ../../server && go test -tags acme -run TestMaintenanceRenewsAPairWhoseFirstNameIsTheFileOrigin -v .
//	cd ../test/pebble && docker compose down
func TestMaintenanceRenewsAPairWhoseFirstNameIsTheFileOrigin(t *testing.T) {
	domain := renewalDomain
	fileOrigin := api.ShareHost(domain)

	root := fetchPebbleTrustRoot(t)
	hostIP := hostGatewayIPv4(t)
	pointChallengeDNSAt(t, domain, hostIP)
	pointChallengeDNSAt(t, fileOrigin, hostIP)
	waitForFreePort(t, ":5002")

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(root)) {
		t.Fatal("the pebble trust root is not valid PEM")
	}

	dataDir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// The wiring under test is the production wiring: the live set of managed
	// subjects, the storage alias over the same on-disk layout, the key
	// recorder as the config's key source, the subject transformer, and
	// PairIssuer in front of the ACME issuer. main.go sets these on
	// certmagic.Default because the default cache builds maintenance configs
	// out of it; a cache whose GetConfigForCert answers this config hands
	// maintenance the same values without touching package state.
	managed := certpair.NewSubjects(api.ShareHost)
	keys := certpair.NewKeyRecorder(certmagic.DefaultKeyGenerator)
	storage := certpair.NewFileOriginAlias(
		&certmagic.FileStorage{Path: filepath.Join(dataDir, "certmagic")}, managed)

	var cfg *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert:   func(certmagic.Certificate) (*certmagic.Config, error) { return cfg, nil },
		RenewCheckInterval: time.Hour,
		Logger:             certmagic.Default.Logger,
	})
	t.Cleanup(cache.Stop)

	cfg = certmagic.New(cache, certmagic.Config{
		Storage:            storage,
		KeySource:          keys,
		SubjectTransformer: managed.Subject,
		// The renewal window covers the whole lifetime, so the certificate
		// the first order produces is due for renewal as soon as it is
		// cached. This is the client-side policy knob that decides when
		// maintenance acts, and setting it here puts the certificate in the
		// state a production certificate reaches a third of the way through
		// its life without waiting for one to age.
		RenewalWindowRatio: 1,
		Logger:             certmagic.Default.Logger,
	})
	template := certmagic.ACMEIssuer{
		CA:           pebbleDirectory,
		TestCA:       pebbleDirectory,
		Agreed:       true,
		TrustedRoots: pool,
		// Pebble validates HTTP-01 against port 5002 and the issuer binds
		// that listener itself, so this test needs no server process.
		AltHTTPPort:             5002,
		DisableTLSALPNChallenge: true,
		Profile:                 certpair.DomainProfile,
		Logger:                  certmagic.Default.Logger,
	}
	acmeIssuer := certmagic.NewACMEIssuer(cfg, template)
	template.Profile = certpair.IPProfile
	ipIssuer := certmagic.NewACMEIssuer(cfg, template)
	cfg.Issuers = []certmagic.Issuer{
		certpair.NewPairIssuer(boulderOrdering{inner: acmeIssuer, keys: keys}, ipIssuer, keys, api.ShareHost),
	}

	managed.Add(domain)
	if err := cfg.ManageSync(ctx, []string{domain}); err != nil {
		t.Fatalf("obtaining the first certificate for %s: %v", domain, err)
	}

	cached := cache.AllMatchingCertificates(domain)
	if len(cached) != 1 {
		t.Fatalf("the cache holds %d certificates for %s, want exactly one", len(cached), domain)
	}
	before := cached[0]
	t.Logf("first issuance: common name %q, SANs %v, cert.Names %v",
		before.Leaf.Subject.CommonName, before.Leaf.DNSNames, before.Names)
	// Without this the test degrades into a first-issuance test: maintenance
	// would renew under the app domain, which needs neither the alias nor the
	// transformer, and the whole failure mode would go unobserved.
	if len(before.Names) == 0 || before.Names[0] != fileOrigin {
		t.Fatalf("the cached leaf's first name is %v, want the file origin %q; this test cannot observe the production condition otherwise",
			before.Names, fileOrigin)
	}
	oldSerial := before.Leaf.SerialNumber.String()

	issuerKey := cfg.Issuers[0].IssuerKey()
	storedCert := filepath.Join(dataDir, "certmagic",
		filepath.FromSlash(certmagic.StorageKeys.SiteCert(issuerKey, domain)))
	stored, err := readLeafPEM(storedCert)
	if err != nil {
		t.Fatalf("the first certificate is not stored under the app domain at %s: %v", storedCert, err)
	}
	if stored.SerialNumber.String() != oldSerial {
		t.Fatalf("the certificate stored at %s is not the one in the cache", storedCert)
	}

	if err := cache.RenewManagedCertificates(ctx); err != nil {
		t.Fatalf("maintenance renewal: %v", err)
	}

	// Maintenance submits the renewal to a job queue and returns, so the new
	// resource appears on disk some time later.
	renewed := waitForNewStoredLeaf(t, storedCert, oldSerial, 3*time.Minute)
	newSerial := renewed.SerialNumber.String()
	t.Logf("renewal: common name %q, SANs %v, serial %s", renewed.Subject.CommonName, renewed.DNSNames, newSerial)

	// 1. The renewed resource is still addressed by the app domain, and the
	// file origin still has no managed certificate of its own.
	assertNoManagedFileOriginCertificate(t, dataDir, domain)

	// 2. The renewal carries both origins. A renewal that narrowed to one
	// name would take the other origin down at the next handshake.
	renewedNames := map[string]bool{}
	for _, n := range renewed.DNSNames {
		renewedNames[n] = true
	}
	if len(renewedNames) != 2 || !renewedNames[domain] || !renewedNames[fileOrigin] {
		t.Fatalf("the renewed leaf carries %v, want exactly %s and %s", renewed.DNSNames, domain, fileOrigin)
	}

	// 3 and 4. The config serves the renewed leaf on both SNIs. This is the
	// assertion that separates a successful ACME exchange from a successful
	// renewal: when the reload cannot address the resource, the exchange
	// still succeeds and the cache keeps the leaf it already had.
	for _, sni := range []string{domain, fileOrigin} {
		served := waitForServedLeaf(t, cfg, sni, newSerial, time.Minute)
		if served.SerialNumber.String() != newSerial {
			t.Errorf("%s is served serial %s, want the renewed %s (the cache is still holding the stale leaf %s)",
				sni, served.SerialNumber, newSerial, oldSerial)
		}
	}
}

// boulderOrdering stands in for the one CA behavior Pebble does not have.
// Let's Encrypt normalizes and byte-sorts the SAN set of every certificate it
// issues, so the order a signing request asks for never reaches the leaf, and
// the profiles this server orders under emit no Common Name; together
// those make the alphabetically first name the leaf's first name. Pebble
// emits the SANs in the order the request carried them, so the sort is
// applied to the request on its way to Pebble and what comes back carries the
// names in the order Let's Encrypt would have emitted.
//
// It sits between PairIssuer and the ACME issuer, on the CA's side of the
// boundary. PairIssuer widens exactly as it does in production and nothing
// downstream of the leaf is touched, so the alias, the transformer and the
// storage layout are all the real ones.
type boulderOrdering struct {
	inner certmagic.Issuer
	keys  *certpair.KeyRecorder
}

func (b boulderOrdering) IssuerKey() string { return b.inner.IssuerKey() }

func (b boulderOrdering) Issue(ctx context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	sorted := slices.Clone(csr.DNSNames)
	slices.Sort(sorted)
	if !slices.Equal(sorted, csr.DNSNames) {
		// A signing request carries its names inside the signature, so
		// reordering them means re-signing with the same key. The key
		// recorder holds it for the same reason PairIssuer reads it.
		key, ok := b.keys.Lookup(csr.PublicKey)
		if !ok {
			return nil, fmt.Errorf("boulderOrdering: no recorded key for the request naming %v", csr.DNSNames)
		}
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: sorted}, key)
		if err != nil {
			return nil, fmt.Errorf("boulderOrdering: re-signing the sorted request: %w", err)
		}
		resigned, err := x509.ParseCertificateRequest(der)
		if err != nil {
			return nil, fmt.Errorf("boulderOrdering: parsing the sorted request: %w", err)
		}
		csr = resigned
	}
	return b.inner.Issue(ctx, csr)
}

func (b boulderOrdering) PreCheck(ctx context.Context, names []string, interactive bool) error {
	prechecker, ok := b.inner.(certmagic.PreChecker)
	if !ok {
		return nil
	}
	return prechecker.PreCheck(ctx, names, interactive)
}

func (b boulderOrdering) GetRenewalInfo(ctx context.Context, cert certmagic.Certificate) (acme.RenewalInfo, error) {
	getter, ok := b.inner.(certmagic.RenewalInfoGetter)
	if !ok {
		return acme.RenewalInfo{}, fmt.Errorf("boulderOrdering: %s does not support ACME renewal info", b.inner.IssuerKey())
	}
	return getter.GetRenewalInfo(ctx, cert)
}

// readLeafPEM parses the first certificate in a stored PEM bundle, which is
// the leaf.
func readLeafPEM(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s holds no PEM block", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

// waitForNewStoredLeaf waits for the stored resource to hold a certificate
// other than the one with oldSerial, which is how the ACME half of a renewal
// announces it finished.
func waitForNewStoredLeaf(t *testing.T, path, oldSerial string, within time.Duration) *x509.Certificate {
	t.Helper()
	deadline := time.Now().Add(within)
	var lastErr error
	for time.Now().Before(deadline) {
		leaf, err := readLeafPEM(path)
		if err != nil {
			lastErr = err
		} else if leaf.SerialNumber.String() != oldSerial {
			return leaf
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("no renewed certificate at %s within %s (serial is still %s), last read error: %v",
		path, within, oldSerial, lastErr)
	return nil
}

// waitForServedLeaf answers the leaf the config hands a handshake for sni,
// waiting up to within for it to become the one with wantSerial. It answers
// whatever it last saw when the deadline passes, so the caller reports the
// mismatch rather than a timeout.
func waitForServedLeaf(t *testing.T, cfg *certmagic.Config, sni, wantSerial string, within time.Duration) *x509.Certificate {
	t.Helper()
	deadline := time.Now().Add(within)
	var last *x509.Certificate
	for {
		served, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: sni})
		if err != nil {
			t.Fatalf("the config serves nothing for %s: %v", sni, err)
		}
		if served.Leaf == nil {
			t.Fatalf("the certificate served for %s has no parsed leaf", sni)
		}
		last = served.Leaf
		if last.SerialNumber.String() == wantSerial || !time.Now().Before(deadline) {
			return last
		}
		time.Sleep(2 * time.Second)
	}
}

// waitForFreePort blocks until addr can be bound, so a listener another test
// left behind does not make the ACME solver assume somebody else is serving
// the challenge.
func waitForFreePort(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			ln.Close()
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("%s is still bound after 30s: %v", addr, err)
		}
		time.Sleep(time.Second)
	}
}
