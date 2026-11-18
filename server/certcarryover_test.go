package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"

	"hyperdrop/server/internal/api"
	"hyperdrop/server/internal/certpair"
)

// testLeafPEM issues a self-signed leaf carrying names and valid over the given
// window, and answers it as the certificate and private key PEM a certificate
// directory holds.
func testLeafPEM(t *testing.T, commonName string, dnsNames []string, notBefore, notAfter time.Time) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		DNSNames:              dnsNames,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// A certificate storage already holds for the file origin is served only while
// it is an improvement on serving nothing. It has to parse, it has to carry the
// file origin, and it has to be valid now: caching a certificate that fails any
// of those hands the file origin a handshake that fails differently.
func TestAStoredFileOriginCertificateIsCarriedOverOnlyWhenItCanServe(t *testing.T) {
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	fileOrigin := "files.alice.hyperdrop.link"

	covering, _ := testLeafPEM(t, "", []string{fileOrigin}, now.Add(-24*time.Hour), now.Add(24*time.Hour))
	commonNameOnly, _ := testLeafPEM(t, fileOrigin, nil, now.Add(-24*time.Hour), now.Add(24*time.Hour))
	paired, _ := testLeafPEM(t, "", []string{"alice.hyperdrop.link", fileOrigin}, now.Add(-24*time.Hour), now.Add(24*time.Hour))
	otherName, _ := testLeafPEM(t, "", []string{"alice.hyperdrop.link"}, now.Add(-24*time.Hour), now.Add(24*time.Hour))
	anotherServer, _ := testLeafPEM(t, "", []string{"files.bob.hyperdrop.link"}, now.Add(-24*time.Hour), now.Add(24*time.Hour))
	expired, _ := testLeafPEM(t, "", []string{fileOrigin}, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	notYetValid, _ := testLeafPEM(t, "", []string{fileOrigin}, now.Add(24*time.Hour), now.Add(48*time.Hour))

	for _, tc := range []struct {
		label   string
		certPEM []byte
		want    bool
	}{
		{"covers the file origin and is valid", covering, true},
		{"carries the file origin as its common name", commonNameOnly, true},
		{"already covers both origins", paired, true},
		{"carries the app domain alone", otherName, false},
		{"carries another server's file origin", anotherServer, false},
		{"expired", expired, false},
		{"not yet valid", notYetValid, false},
		{"unparseable", []byte("-----BEGIN CERTIFICATE-----\nnot a certificate\n-----END CERTIFICATE-----\n"), false},
		{"not PEM at all", []byte("nothing here"), false},
		{"empty", nil, false},
	} {
		t.Run(tc.label, func(t *testing.T) {
			if got := carriedOverCertificateUsable(tc.certPEM, fileOrigin, now); got != tc.want {
				t.Fatalf("carriedOverCertificateUsable(%s) = %v, want %v", tc.label, got, tc.want)
			}
		})
	}
}

// The configured storage answers a read of the file origin's certificate asset
// with the app domain's asset, which is what makes one certificate cover both
// origins. Reading the pre-existing narrow certificate has to bypass it, or the
// bytes carried into the cache are the app domain's certificate, which serves
// the file origin nothing.
func TestTheCarriedOverCertificateIsReadPastTheAlias(t *testing.T) {
	ctx := context.Background()
	appDomain := "alice.hyperdrop.link"
	fileOrigin := api.ShareHost(appDomain)
	raw := &certmagic.FileStorage{Path: t.TempDir()}
	issuerKey := "acme-v02.api.letsencrypt.org-directory"

	for _, name := range []string{appDomain, fileOrigin} {
		certPEM, keyPEM := testLeafPEM(t, "", []string{name}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
		if err := raw.Store(ctx, certmagic.StorageKeys.SiteCert(issuerKey, name), certPEM); err != nil {
			t.Fatal(err)
		}
		if err := raw.Store(ctx, certmagic.StorageKeys.SitePrivateKey(issuerKey, name), keyPEM); err != nil {
			t.Fatal(err)
		}
	}

	managed := certpair.NewSubjects(api.ShareHost)
	managed.Add(appDomain)
	alias := certpair.NewFileOriginAlias(raw, managed)

	certPEM, _, found := storedCertificate(ctx, raw, fileOrigin)
	if !found {
		t.Fatal("no certificate found for the file origin through raw storage")
	}
	if !carriedOverCertificateUsable(certPEM, fileOrigin, time.Now()) {
		t.Fatal("the certificate read through raw storage does not carry the file origin")
	}

	aliased, _, found := storedCertificate(ctx, alias, fileOrigin)
	if !found {
		t.Fatal("no certificate found for the file origin through the alias")
	}
	if carriedOverCertificateUsable(aliased, fileOrigin, time.Now()) {
		t.Fatal("the alias answered the file origin's own certificate; the raw read is no longer load-bearing")
	}
}

// The file origin is not a managed subject, so a server that stored one narrow
// certificate per hostname has nothing in the cache for it until the paired
// certificate is issued. The carry-over is what keeps it answering across that
// window.
func TestTheCarriedOverCertificateServesTheFileOrigin(t *testing.T) {
	ctx := context.Background()
	appDomain := "alice.hyperdrop.link"
	fileOrigin := api.ShareHost(appDomain)
	certDir := t.TempDir()
	raw := &certmagic.FileStorage{Path: certDir}
	certPEM, keyPEM := testLeafPEM(t, "", []string{fileOrigin}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	issuerKey := "acme-v02.api.letsencrypt.org-directory"
	if err := raw.Store(ctx, certmagic.StorageKeys.SiteCert(issuerKey, fileOrigin), certPEM); err != nil {
		t.Fatal(err)
	}
	if err := raw.Store(ctx, certmagic.StorageKeys.SitePrivateKey(issuerKey, fileOrigin), keyPEM); err != nil {
		t.Fatal(err)
	}

	managed := certpair.NewSubjects(api.ShareHost)
	managed.Add(appDomain)
	var magic *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return magic, nil },
		Logger:           zap.NewNop(),
	})
	defer cache.Stop()
	magic = certmagic.New(cache, certmagic.Config{
		Storage: certpair.NewFileOriginAlias(raw, managed),
		Logger:  zap.NewNop(),
	})

	// CertMagic logs the remote address when no certificate matches, so the
	// hello needs a connection even though nothing is sent over it.
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	hello := &tls.ClientHelloInfo{
		Conn:              serverConn,
		ServerName:        fileOrigin,
		CipherSuites:      []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		SupportedCurves:   []tls.CurveID{tls.CurveP256},
		SupportedPoints:   []uint8{0},
		SupportedVersions: []uint16{tls.VersionTLS12},
	}
	if _, err := magic.GetCertificateWithContext(ctx, hello); err == nil {
		t.Fatal("the file origin already had a certificate before the carry-over")
	}

	carryOverFileOriginCertificates(ctx, magic, certDir, []string{appDomain})

	served, err := magic.GetCertificateWithContext(ctx, hello)
	if err != nil {
		t.Fatalf("the file origin has no certificate after the carry-over: %v", err)
	}
	leaf, err := leafCertificate(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if served.Leaf == nil || !served.Leaf.Equal(leaf) {
		t.Fatalf("the file origin is served a certificate other than the stored one")
	}
}

// A file origin with nothing in storage is the ordinary first boot.
func TestNoStoredCertificateIsNotAFailure(t *testing.T) {
	raw := &certmagic.FileStorage{Path: t.TempDir()}
	if _, _, found := storedCertificate(context.Background(), raw, "files.alice.hyperdrop.link"); found {
		t.Fatal("an empty certificate directory answered a certificate")
	}
}
