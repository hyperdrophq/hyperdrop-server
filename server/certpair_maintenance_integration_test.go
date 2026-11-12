//go:build acme

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"

	"hyperdrop/server/internal/api"
	"hyperdrop/server/internal/certpair"
)

// maintenanceDomain begins with a letter that sorts after the `files.` label,
// so the pair's file origin is the leaf's first name, which is the shape
// Let's Encrypt issues for every domain that does not begin with a digit or
// with `a` to `e`. It is not the domain the other ACME tests use: each test
// gets its own name so an order or an authorization one of them left behind
// cannot answer for another.
const maintenanceDomain = "zulu.example.com"

// pebbleCertLifetime is the validity period of the tlsserver profile in
// test/pebble/pebble-config.json, and this constant and that file have to
// agree. Pebble issues notAfter one second short of the period and does not
// backdate notBefore.
//
// The value is what makes an unattended maintenance renewal observable in
// minutes. CertMagic checks for renewals every DefaultRenewCheckInterval (a
// const, 10 minutes) and renews a certificate with less than five check
// intervals of life left, so a certificate that has MORE than 50 minutes
// remaining when the server adopts it is not renewed at startup, and has LESS
// than 50 minutes remaining at the first check 10 minutes later. 55 minutes
// sits between the two with about 5 minutes of slack on each side:
//
//	adoption:   55:00 - <seeding time> > 50:00, so startup renews nothing
//	first tick: 55:00 - <seeding time> - 10:00 < 50:00, so maintenance renews
const pebbleCertLifetime = 3300 * time.Second

// maintenanceRenewalTimeout bounds the wait for the renewal. Two check
// intervals plus slack, so a first attempt that fails and is retried is still
// inside the window while a renewal that never comes is reported rather than
// waited on forever.
const maintenanceRenewalTimeout = 20 * time.Minute

// startupSettleWindow is how long the served certificate is watched before the
// wait for a renewal begins. CertMagic submits a startup renewal the moment it
// adopts a stored certificate, so a serial that is still the seeded one after
// this window proves the change that follows came from the maintenance ticker
// and not from adoption.
const startupSettleWindow = 90 * time.Second

// TestTheRealServerRenewsThePairThroughBackgroundMaintenance runs the server
// binary against Pebble and waits for CertMagic's own maintenance ticker,
// inside that process, to renew a paired certificate whose first name is the
// file origin.
//
// The wiring this covers is main.go's. Maintenance does not use the
// certmagic.Config the server builds: it asks the certificate cache for one,
// and the cache builds a fresh config out of package-level certmagic.Default.
// A key source, an issuer, a storage alias or a subject transformer set only
// on the server's own config is invisible to maintenance, and every background
// renewal would then issue a certificate covering the app domain alone and
// take the file origin down. Driving the cache's renewal entry point over a
// config the test assembles cannot see that: only the real binary can.
//
// Run with, on any machine with Docker. The renewal is a real wait, so the
// timeout has to be raised well above `go test`'s 10 minute default:
//
//	cd test/pebble && docker compose up -d
//	cd ../../server && go test -tags acme -timeout 45m -run TestTheRealServerRenewsThePairThroughBackgroundMaintenance -v .
//	cd ../test/pebble && docker compose down
func TestTheRealServerRenewsThePairThroughBackgroundMaintenance(t *testing.T) {
	domain := maintenanceDomain
	fileOrigin := api.ShareHost(domain)

	// Built before anything is issued: a compile is minutes the seeded
	// certificate would otherwise spend aging before the server adopts it.
	binary := serverBinary(t)

	root := fetchPebbleTrustRoot(t)
	hostIP := hostGatewayIPv4(t)
	pointChallengeDNSAt(t, domain, hostIP)
	pointChallengeDNSAt(t, fileOrigin, hostIP)
	waitForFreePort(t, ":5002")
	waitForFreePort(t, ":5001")

	dataDir := t.TempDir()
	seeded := seedFileOriginFirstCertificate(t, dataDir, root)
	seededSerial := seeded.SerialNumber.String()
	t.Logf("seeded certificate: SANs %v, serial %s, valid %s to %s",
		seeded.DNSNames, seededSerial,
		seeded.NotBefore.Format(time.RFC3339), seeded.NotAfter.Format(time.RFC3339))

	// The server must find the seeded certificate too young to renew on
	// adoption, or the renewal this test observes would be the startup one
	// and the maintenance path would go unexercised. The margin is the
	// seeding time: Pebble stamps notBefore at issuance and the clock has
	// been running since.
	adoptionFloor := certmagic.DefaultRenewCheckInterval * 5
	remaining := time.Until(seeded.NotAfter)
	if remaining <= adoptionFloor+2*time.Minute {
		t.Fatalf("the seeded certificate has %s left, which is too close to the %s CertMagic renews within: seeding took too long for a %s lifetime, so the server would renew it on adoption instead of through maintenance",
			remaining.Round(time.Second), adoptionFloor, pebbleCertLifetime)
	}
	waitForFreePort(t, ":5002")

	logs := new(syncBuffer)
	cmd := exec.Command(binary)
	cmd.Env = append(os.Environ(),
		"HYPERDROP_PUSH_RELAY=",      // push off: a test server never posts to the real relay
		"HYPERDROP_SERVER_RELEASES=", // no update check: a test server never reads the public site
		"HYPERDROP_DOMAIN="+domain,
		"HYPERDROP_DATA="+dataDir,
		"HYPERDROP_ADMIN_PASSWORD=t",
		"HYPERDROP_BEHIND_NAT=1",
		"HYPERDROP_ACME_CA="+pebbleDirectory,
		"HYPERDROP_ACME_CA_CERT="+root,
		"HYPERDROP_HTTP_ADDR=:5002",
		"HYPERDROP_HTTPS_ADDR=:5001",
	)
	cmd.Stdout = io.MultiWriter(os.Stderr, logs)
	cmd.Stderr = cmd.Stdout
	started := time.Now()
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	// The server serves the seeded certificate, unchanged. Anything else here
	// is a renewal that adoption performed, which is not the one under test.
	adopted := waitForLeaf(t, "localhost:5001", domain)
	if adopted.SerialNumber.String() != seededSerial {
		t.Fatalf("the server is serving serial %s, want the seeded %s: it renewed the certificate on adoption, so a later change would not be maintenance's work%s",
			adopted.SerialNumber, seededSerial, logTail(logs))
	}
	t.Logf("the server adopted the seeded certificate after %s", time.Since(started).Round(time.Second))

	settleDeadline := time.Now().Add(startupSettleWindow)
	for time.Now().Before(settleDeadline) {
		time.Sleep(5 * time.Second)
		leaf := servedLeaf(t, "localhost:5001", domain)
		if leaf == nil {
			continue
		}
		if leaf.SerialNumber.String() != seededSerial {
			t.Fatalf("the served serial changed to %s within %s of startup, before any maintenance check was due: this is adoption renewing, not maintenance%s",
				leaf.SerialNumber, startupSettleWindow, logTail(logs))
		}
	}
	t.Logf("still serving the seeded certificate %s after startup; from here only the maintenance ticker can change it",
		time.Since(started).Round(time.Second))

	// Nothing below asks for a renewal. The ticker inside the server process
	// is the only thing that can change what the endpoint serves.
	renewed := waitForRenewedServedLeaf(t, "localhost:5001", domain, seededSerial, started, logs)
	renewedSerial := renewed.SerialNumber.String()
	t.Logf("maintenance renewed after %s: SANs %v, serial %s, valid from %s",
		time.Since(started).Round(time.Second), renewed.DNSNames, renewedSerial,
		renewed.NotBefore.Format(time.RFC3339))

	// 1. The renewal carries both origins. A renewal that narrowed to the app
	// domain alone would take every View, Download, zip, /site and /thumb link
	// down at the next handshake.
	names := map[string]bool{}
	for _, n := range renewed.DNSNames {
		names[n] = true
	}
	if len(names) != 2 || !names[domain] || !names[fileOrigin] {
		t.Fatalf("the renewed leaf carries %v, want exactly %s and %s", renewed.DNSNames, domain, fileOrigin)
	}

	// 2. Both origins are served the renewed certificate. An ACME exchange can
	// succeed and still leave the stale leaf in the cache when the reload
	// cannot address the resource, and the file origin is never a managed
	// subject, so it is served only because the pair is cached under its name.
	for _, sni := range []string{domain, fileOrigin} {
		served := waitForServedSerial(t, "localhost:5001", sni, renewedSerial)
		if served.SerialNumber.String() != renewedSerial {
			t.Errorf("%s is served serial %s, want the renewed %s (the cache is still holding the stale leaf)",
				sni, served.SerialNumber, renewedSerial)
		}
	}

	// 3. It is a newer certificate, not the same one re-served.
	if !renewed.NotBefore.After(seeded.NotBefore) {
		t.Errorf("the renewed leaf is valid from %s, which is not after the seeded leaf's %s",
			renewed.NotBefore.Format(time.RFC3339), seeded.NotBefore.Format(time.RFC3339))
	}

	// 4. The renewal is still addressed by the app domain, and the file origin
	// still has no managed certificate of its own to spend a second
	// certificate from the weekly budget.
	assertNoManagedFileOriginCertificate(t, dataDir, domain)
}

// seedFileOriginFirstCertificate puts a paired certificate whose FIRST name is
// the file origin into dataDir's certificate storage, and answers its leaf.
//
// The server binary cannot produce that leaf against Pebble: PairIssuer widens
// the request to the app domain and then the file origin, and Pebble emits the
// SAN set in the order the request carried it, so what a real exchange here
// returns is app-domain-first and the production condition never arises. The
// ordering is arranged the way TestMaintenanceRenewsAPairWhoseFirstNameIsTheFileOrigin
// arranges it, through boulderOrdering, which sorts the request the way
// Let's Encrypt sorts what it issues. That shim sits inside an issuer chain,
// so it is reachable only in-process: the certificate is issued here and the
// server adopts it from storage, which is the same thing a server restarting
// on a certificate Let's Encrypt issued does.
//
// Everything the certificate is written through is the production wiring: the
// live set of managed subjects, the storage alias over the same on-disk
// layout, the key recorder as the key source, the subject transformer, and
// PairIssuer in front of the ACME issuer. The ACME account it registers lands
// in the same storage, so the server reuses it.
func seedFileOriginFirstCertificate(t *testing.T, dataDir, pebbleRoot string) *x509.Certificate {
	t.Helper()
	fileOrigin := api.ShareHost(maintenanceDomain)

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(pebbleRoot)) {
		t.Fatal("the pebble trust root is not valid PEM")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	managed := certpair.NewSubjects(api.ShareHost)
	keys := certpair.NewKeyRecorder(certmagic.DefaultKeyGenerator)
	storage := certpair.NewFileOriginAlias(
		&certmagic.FileStorage{Path: filepath.Join(dataDir, "certmagic")}, managed)

	var cfg *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return cfg, nil },
		// This cache exists to issue one certificate and is stopped before
		// the server starts, so its own maintenance never runs.
		RenewCheckInterval: time.Hour,
		Logger:             certmagic.Default.Logger,
	})
	defer cache.Stop()

	cfg = certmagic.New(cache, certmagic.Config{
		Storage:            storage,
		KeySource:          keys,
		SubjectTransformer: managed.Subject,
		Logger:             certmagic.Default.Logger,
	})
	template := certmagic.ACMEIssuer{
		CA:           pebbleDirectory,
		TestCA:       pebbleDirectory,
		Agreed:       true,
		TrustedRoots: pool,
		// Pebble validates HTTP-01 against port 5002 and the issuer binds
		// that listener itself, which is the port the server binds next, so
		// the caller waits for it to be free again afterwards.
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

	managed.Add(maintenanceDomain)
	if err := cfg.ManageSync(ctx, []string{maintenanceDomain}); err != nil {
		t.Fatalf("seeding the first certificate for %s: %v", maintenanceDomain, err)
	}

	cached := cache.AllMatchingCertificates(maintenanceDomain)
	if len(cached) != 1 {
		t.Fatalf("the seed cache holds %d certificates for %s, want exactly one", len(cached), maintenanceDomain)
	}
	seeded := cached[0]
	if len(seeded.Names) == 0 || seeded.Names[0] != fileOrigin {
		t.Fatalf("the seeded leaf's first name is %v, want the file origin %q; this test cannot observe the production condition otherwise",
			seeded.Names, fileOrigin)
	}
	issuerKey := cfg.Issuers[0].IssuerKey()
	stored := filepath.Join(dataDir, "certmagic",
		filepath.FromSlash(certmagic.StorageKeys.SiteCert(issuerKey, maintenanceDomain)))
	leaf, err := readLeafPEM(stored)
	if err != nil {
		t.Fatalf("the seeded certificate is not stored under the app domain at %s: %v", stored, err)
	}
	if leaf.SerialNumber.String() != seeded.Leaf.SerialNumber.String() {
		t.Fatalf("the certificate stored at %s is not the one that was issued", stored)
	}
	return leaf
}

// waitForRenewedServedLeaf polls the TLS endpoint until it answers a
// certificate other than oldSerial, and fails with what it saw when it does
// not. A silent skip here would put back the blind spot this test exists to
// remove, so the timeout carries the last serial, the wait and the server's
// own log.
func waitForRenewedServedLeaf(t *testing.T, addr, sni, oldSerial string, started time.Time, logs *syncBuffer) *x509.Certificate {
	t.Helper()
	deadline := time.Now().Add(maintenanceRenewalTimeout)
	lastSerial := oldSerial
	for time.Now().Before(deadline) {
		time.Sleep(10 * time.Second)
		leaf := servedLeaf(t, addr, sni)
		if leaf == nil {
			continue
		}
		lastSerial = leaf.SerialNumber.String()
		if lastSerial != oldSerial {
			return leaf
		}
	}
	t.Fatalf("background maintenance did not renew within %s of the server starting (waited %s): %s is still served serial %s, the one it started with.\nThe certificate's lifetime is %s and CertMagic checks every %s, so at least one check was due.%s",
		maintenanceRenewalTimeout, time.Since(started).Round(time.Second), sni, lastSerial,
		pebbleCertLifetime, certmagic.DefaultRenewCheckInterval, logTail(logs))
	return nil
}

// waitForServedSerial polls until sni is served wantSerial, and answers
// whatever it last saw when the deadline passes, so the caller reports the
// mismatch rather than a timeout.
func waitForServedSerial(t *testing.T, addr, sni, wantSerial string) *x509.Certificate {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	var last *x509.Certificate
	for {
		if leaf := servedLeaf(t, addr, sni); leaf != nil {
			last = leaf
			if last.SerialNumber.String() == wantSerial {
				return last
			}
		}
		if !time.Now().Before(deadline) {
			if last == nil {
				t.Fatalf("%s is served no certificate at all", sni)
			}
			return last
		}
		time.Sleep(2 * time.Second)
	}
}

// servedLeaf answers the leaf addr hands a handshake for sni, or nil when the
// handshake does not produce one. A renewal is in flight for much of this
// test's life, so a momentary failure is a retry rather than a verdict.
func servedLeaf(t *testing.T, addr, sni string) *x509.Certificate {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
	if err != nil {
		return nil
	}
	state := conn.ConnectionState()
	conn.Close()
	if len(state.PeerCertificates) == 0 {
		return nil
	}
	return state.PeerCertificates[0]
}

// logTail answers the last lines of the server's output, formatted for a
// failure message.
func logTail(logs *syncBuffer) string {
	const lines = 60
	all := strings.Split(strings.TrimRight(logs.String(), "\n"), "\n")
	if len(all) > lines {
		all = all[len(all)-lines:]
	}
	return "\nLast " + strconv.Itoa(len(all)) + " lines of the server log:\n" + strings.Join(all, "\n")
}

// syncBuffer collects the server's output while it also goes to the test's
// stderr. The process writes from its own goroutines and the test reads it
// from another, so the buffer is guarded.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
