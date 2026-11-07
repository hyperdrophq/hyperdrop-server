package certpair

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"net"
	"testing"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3/acme"
)

// recordingIssuer stands in for the ACME issuer and keeps the CSR it was given.
type recordingIssuer struct {
	got        *x509.CertificateRequest
	preChecked []string
	err        error
}

func (r *recordingIssuer) Issue(_ context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	r.got = csr
	if r.err != nil {
		return nil, r.err
	}
	return &certmagic.IssuedCertificate{Certificate: []byte("chain")}, nil
}

func (r *recordingIssuer) IssuerKey() string { return "recording" }

func (r *recordingIssuer) PreCheck(_ context.Context, names []string, _ bool) error {
	r.preChecked = names
	return nil
}

// ariRecordingIssuer stands in for an ACME issuer that supports ACME Renewal
// Information, and records the certificate it was asked about.
type ariRecordingIssuer struct {
	recordingIssuer
	got  certmagic.Certificate
	info acme.RenewalInfo
	err  error
}

func (r *ariRecordingIssuer) GetRenewalInfo(_ context.Context, cert certmagic.Certificate) (acme.RenewalInfo, error) {
	r.got = cert
	return r.info, r.err
}

// filesOrigin stands in for api.ShareHost: the file origin is "files." plus
// the domain, empty for an empty domain.
func filesOrigin(domain string) string {
	if domain == "" {
		return ""
	}
	return "files." + domain
}

func signedCSR(t *testing.T, key crypto.Signer, dnsNames []string, ips []net.IP) *x509.CertificateRequest {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: dnsNames, IPAddresses: ips}, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}
	return csr
}

func newTestPair(t *testing.T) (*KeyRecorder, crypto.Signer) {
	t.Helper()
	rec := NewKeyRecorder(certmagic.StandardKeyGenerator{KeyType: certmagic.P256})
	key, err := rec.GenerateKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return rec, key.(crypto.Signer)
}

func TestTheAppDomainCSRIsWidenedToCarryBothNames(t *testing.T) {
	rec, key := newTestPair(t)
	inner := &recordingIssuer{}
	iss := NewPairIssuer(inner, &recordingIssuer{}, rec, filesOrigin)

	csr := signedCSR(t, key, []string{"alice.hyperdrop.link"}, nil)
	if _, err := iss.Issue(context.Background(), csr); err != nil {
		t.Fatalf("issue: %v", err)
	}
	want := []string{"alice.hyperdrop.link", "files.alice.hyperdrop.link"}
	if len(inner.got.DNSNames) != 2 || inner.got.DNSNames[0] != want[0] || inner.got.DNSNames[1] != want[1] {
		t.Fatalf("delegated CSR carries %v, want %v", inner.got.DNSNames, want)
	}
	if err := inner.got.CheckSignature(); err != nil {
		t.Fatalf("widened CSR does not verify: %v", err)
	}
	if !inner.got.PublicKey.(interface{ Equal(crypto.PublicKey) bool }).Equal(key.Public()) {
		t.Fatal("widened CSR is bound to a different key")
	}
}

// The property this design exists for: one PairIssuer instance, constructed
// once, widens every app domain it is handed a CSR for, not just the one it
// saw first.
func TestTheSameIssuerWidensTwoDifferentAppDomains(t *testing.T) {
	rec, keyAlice := newTestPair(t)
	keyBob, err := rec.GenerateKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	inner := &recordingIssuer{}
	iss := NewPairIssuer(inner, &recordingIssuer{}, rec, filesOrigin)

	csrAlice := signedCSR(t, keyAlice, []string{"alice.hyperdrop.link"}, nil)
	if _, err := iss.Issue(context.Background(), csrAlice); err != nil {
		t.Fatalf("issue alice: %v", err)
	}
	wantAlice := []string{"alice.hyperdrop.link", "files.alice.hyperdrop.link"}
	if len(inner.got.DNSNames) != 2 || inner.got.DNSNames[0] != wantAlice[0] || inner.got.DNSNames[1] != wantAlice[1] {
		t.Fatalf("alice's delegated CSR carries %v, want %v", inner.got.DNSNames, wantAlice)
	}

	csrBob := signedCSR(t, keyBob.(crypto.Signer), []string{"bob.hyperdrop.link"}, nil)
	if _, err := iss.Issue(context.Background(), csrBob); err != nil {
		t.Fatalf("issue bob: %v", err)
	}
	wantBob := []string{"bob.hyperdrop.link", "files.bob.hyperdrop.link"}
	if len(inner.got.DNSNames) != 2 || inner.got.DNSNames[0] != wantBob[0] || inner.got.DNSNames[1] != wantBob[1] {
		t.Fatalf("bob's delegated CSR carries %v, want %v", inner.got.DNSNames, wantBob)
	}
}

// Let's Encrypt issues an IP address only under the short-lived profile, so
// the IP certificate goes to the IP issuer, unchanged, and never to the
// domain issuer.
func TestTheIPCertificateIsDelegatedUnchangedToTheIPIssuer(t *testing.T) {
	rec, key := newTestPair(t)
	domains, ips := &recordingIssuer{}, &recordingIssuer{}
	iss := NewPairIssuer(domains, ips, rec, filesOrigin)

	csr := signedCSR(t, key, nil, []net.IP{net.ParseIP("203.0.113.7")})
	if _, err := iss.Issue(context.Background(), csr); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if domains.got != nil {
		t.Fatal("the IP CSR reached the domain issuer")
	}
	if ips.got == nil || len(ips.got.DNSNames) != 0 || len(ips.got.IPAddresses) != 1 {
		t.Fatalf("the IP issuer did not get the IP CSR unchanged: %+v", ips.got)
	}
}

func TestADomainCertificateNeverReachesTheIPIssuer(t *testing.T) {
	rec, key := newTestPair(t)
	domains, ips := &recordingIssuer{}, &recordingIssuer{}
	iss := NewPairIssuer(domains, ips, rec, filesOrigin)

	if _, err := iss.Issue(context.Background(), signedCSR(t, key, []string{"alice.hyperdrop.link"}, nil)); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := iss.PreCheck(context.Background(), []string{"alice.hyperdrop.link"}, false); err != nil {
		t.Fatalf("precheck: %v", err)
	}
	if ips.got != nil || ips.preChecked != nil {
		t.Fatal("a domain request reached the IP issuer")
	}
	if domains.got == nil || domains.preChecked == nil {
		t.Fatal("the domain issuer did not get the domain request")
	}
}

func TestTheIPIsPreCheckedAndItsRenewalInfoComesFromTheIPIssuer(t *testing.T) {
	rec, _ := newTestPair(t)
	domains := &ariRecordingIssuer{}
	ips := &ariRecordingIssuer{info: acme.RenewalInfo{ExplanationURL: "https://example.com/ip"}}
	iss := NewPairIssuer(domains, ips, rec, filesOrigin)

	if err := iss.PreCheck(context.Background(), []string{"203.0.113.7"}, false); err != nil {
		t.Fatalf("precheck: %v", err)
	}
	got, err := iss.GetRenewalInfo(context.Background(), certmagic.Certificate{Names: []string{"203.0.113.7"}})
	if err != nil {
		t.Fatalf("GetRenewalInfo: %v", err)
	}
	if got != ips.info {
		t.Fatalf("GetRenewalInfo returned %+v, want the IP issuer's", got)
	}
	if domains.preChecked != nil || domains.got.Names != nil {
		t.Fatal("the IP reached the domain issuer")
	}
	if len(ips.preChecked) != 1 || ips.preChecked[0] != "203.0.113.7" {
		t.Fatalf("the IP issuer prechecked %v, want the IP alone", ips.preChecked)
	}
}

// files.<domain> has no certificate of its own, so narrowing here would
// leave the file origin with nothing to serve over TLS. The failure has to be loud.
func TestAnUnrecordedKeyRefusesRatherThanNarrowing(t *testing.T) {
	rec := NewKeyRecorder(certmagic.StandardKeyGenerator{KeyType: certmagic.P256})
	stray, err := certmagic.StandardKeyGenerator{KeyType: certmagic.P256}.GenerateKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	inner := &recordingIssuer{}
	iss := NewPairIssuer(inner, &recordingIssuer{}, rec, filesOrigin)

	csr := signedCSR(t, stray.(crypto.Signer), []string{"alice.hyperdrop.link"}, nil)
	if _, err := iss.Issue(context.Background(), csr); err == nil {
		t.Fatal("an unrecorded key was allowed to produce a single-name certificate")
	}
	if inner.got != nil {
		t.Fatal("the narrow CSR reached the inner issuer")
	}
}

func TestPreCheckCoversBothNames(t *testing.T) {
	rec, _ := newTestPair(t)
	inner := &recordingIssuer{}
	iss := NewPairIssuer(inner, &recordingIssuer{}, rec, filesOrigin)

	if err := iss.PreCheck(context.Background(), []string{"alice.hyperdrop.link"}, false); err != nil {
		t.Fatalf("precheck: %v", err)
	}
	if len(inner.preChecked) != 2 || inner.preChecked[1] != "files.alice.hyperdrop.link" {
		t.Fatalf("prechecked %v, want both names", inner.preChecked)
	}
}

// keyedIssuer answers an IssuerKey of its own choosing.
type keyedIssuer struct {
	recordingIssuer
	key string
}

func (k *keyedIssuer) IssuerKey() string { return k.key }

func TestIssuersOfTwoCAsAreRefused(t *testing.T) {
	rec, _ := newTestPair(t)
	defer func() {
		if recover() == nil {
			t.Fatal("a domain and an IP issuer with different IssuerKeys were accepted")
		}
	}()
	NewPairIssuer(&keyedIssuer{key: "ca-one"}, &keyedIssuer{key: "ca-two"}, rec, filesOrigin)
}

func TestTheIssuerKeyIsTheInnerOneSoStoragePathsAreUnchanged(t *testing.T) {
	rec, _ := newTestPair(t)
	iss := NewPairIssuer(&recordingIssuer{}, &recordingIssuer{}, rec, filesOrigin)
	if got := iss.IssuerKey(); got != "recording" {
		t.Fatalf("IssuerKey is %q, want the inner issuer's", got)
	}
}

func TestAnInnerFailureIsReturned(t *testing.T) {
	rec, key := newTestPair(t)
	inner := &recordingIssuer{err: errors.New("acme said no")}
	iss := NewPairIssuer(inner, &recordingIssuer{}, rec, filesOrigin)
	if _, err := iss.Issue(context.Background(), signedCSR(t, key, []string{"alice.hyperdrop.link"}, nil)); err == nil {
		t.Fatal("the inner issuer's failure was swallowed")
	}
}

func TestGetRenewalInfoForwardsToAnARICapableInnerIssuer(t *testing.T) {
	rec, _ := newTestPair(t)
	want := acme.RenewalInfo{ExplanationURL: "https://example.com/ari"}
	inner := &ariRecordingIssuer{info: want}
	iss := NewPairIssuer(inner, &recordingIssuer{}, rec, filesOrigin)

	cert := certmagic.Certificate{Names: []string{"alice.hyperdrop.link"}}
	got, err := iss.GetRenewalInfo(context.Background(), cert)
	if err != nil {
		t.Fatalf("GetRenewalInfo: %v", err)
	}
	if got != want {
		t.Fatalf("GetRenewalInfo returned %+v, want %+v", got, want)
	}
	if len(inner.got.Names) != 1 || inner.got.Names[0] != "alice.hyperdrop.link" {
		t.Fatalf("inner issuer was asked about %+v, want the passed certificate", inner.got)
	}
}

func TestGetRenewalInfoReturnsTheInnerIssuersError(t *testing.T) {
	rec, _ := newTestPair(t)
	wantErr := errors.New("ari said no")
	inner := &ariRecordingIssuer{err: wantErr}
	iss := NewPairIssuer(inner, &recordingIssuer{}, rec, filesOrigin)

	if _, err := iss.GetRenewalInfo(context.Background(), certmagic.Certificate{}); !errors.Is(err, wantErr) {
		t.Fatalf("GetRenewalInfo error = %v, want %v", err, wantErr)
	}
}

// An inner issuer that does not support ACME Renewal Information is reported
// as an error rather than a zero-value success, so CertMagic's caller logs it
// and moves on the same way it treats any issuer with nothing to offer here.
func TestGetRenewalInfoErrorsWhenTheInnerIssuerDoesNotSupportIt(t *testing.T) {
	rec, _ := newTestPair(t)
	inner := &recordingIssuer{}
	iss := NewPairIssuer(inner, &recordingIssuer{}, rec, filesOrigin)

	if _, err := iss.GetRenewalInfo(context.Background(), certmagic.Certificate{}); err == nil {
		t.Fatal("an inner issuer with no ARI support answered without an error")
	}
}

func TestACertEventForTheAppDomainIsPairedToTheFileOrigin(t *testing.T) {
	data := map[string]any{"identifier": "alice.hyperdrop.link", "error": "boom"}
	paired, ok := PairedCertEvent(filesOrigin, data)
	if !ok {
		t.Fatal("the app domain event was not paired")
	}
	if paired["identifier"] != "files.alice.hyperdrop.link" {
		t.Fatalf("paired identifier is %v", paired["identifier"])
	}
	if paired["error"] != "boom" {
		t.Fatal("the paired event lost the rest of the data")
	}
	if data["identifier"] != "alice.hyperdrop.link" {
		t.Fatal("the original event was mutated")
	}
	if _, ok := PairedCertEvent(filesOrigin, map[string]any{"identifier": "203.0.113.7"}); ok {
		t.Fatal("the IP event was paired")
	}
}

func TestAUnicodeDomainIsMatchedInItsPunycodeForm(t *testing.T) {
	rec, key := newTestPair(t)
	inner := &recordingIssuer{}
	iss := NewPairIssuer(inner, &recordingIssuer{}, rec, filesOrigin)

	// CertMagic punycodes every name before it signs the request.
	csr := signedCSR(t, key, []string{"xn--caf-dma.example.com"}, nil)
	if _, err := iss.Issue(context.Background(), csr); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if len(inner.got.DNSNames) != 2 {
		t.Fatalf("delegated CSR carries %v, want both names", inner.got.DNSNames)
	}
	if inner.got.DNSNames[1] != "files.xn--caf-dma.example.com" {
		t.Fatalf("file origin SAN is %q", inner.got.DNSNames[1])
	}
}

// noFileOrigin and sameAsName stand for a fileOrigin function that answers no
// second name. fileOrigin is injected, so the type alone does not guarantee
// that every name has a file origin.
func noFileOrigin(string) string { return "" }

func sameAsName(domain string) string { return domain }

func TestPairAnswersWhetherThereIsASecondNameToCarry(t *testing.T) {
	cases := []struct {
		label      string
		fileOrigin func(string) string
		in         string
		wantName   string
		wantFile   string
		wantOK     bool
	}{
		{"an ordinary domain", filesOrigin, "alice.hyperdrop.link", "alice.hyperdrop.link", "files.alice.hyperdrop.link", true},
		{"a punycoded domain", filesOrigin, "xn--caf-dma.example.com", "xn--caf-dma.example.com", "files.xn--caf-dma.example.com", true},
		{"no file origin", noFileOrigin, "alice.hyperdrop.link", "", "", false},
		{"the file origin is the name itself", sameAsName, "alice.hyperdrop.link", "", "", false},
		{"an IP address", filesOrigin, "203.0.113.7", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			iss := NewPairIssuer(&recordingIssuer{}, &recordingIssuer{}, NewKeyRecorder(certmagic.StandardKeyGenerator{KeyType: certmagic.P256}), tc.fileOrigin)
			name, file, ok := iss.pair(tc.in)
			if ok != tc.wantOK || name != tc.wantName || file != tc.wantFile {
				t.Fatalf("pair(%q) = (%q, %q, %v), want (%q, %q, %v)", tc.in, name, file, ok, tc.wantName, tc.wantFile, tc.wantOK)
			}
		})
	}
}

// A name with no file origin is refused rather than issued narrow: a
// certificate covering one origin of a server that serves two is the outage
// this package exists to prevent.
func TestANameWithNoFileOriginIsRefusedRatherThanIssuedNarrow(t *testing.T) {
	for _, tc := range []struct {
		label      string
		fileOrigin func(string) string
	}{
		{"no file origin", noFileOrigin},
		{"the file origin is the name itself", sameAsName},
	} {
		t.Run(tc.label, func(t *testing.T) {
			rec, key := newTestPair(t)
			inner := &recordingIssuer{}
			iss := NewPairIssuer(inner, &recordingIssuer{}, rec, tc.fileOrigin)
			if _, err := iss.Issue(context.Background(), signedCSR(t, key, []string{"alice.hyperdrop.link"}, nil)); err == nil {
				t.Fatal("a name with no file origin produced a certificate")
			}
			if inner.got != nil {
				t.Fatal("the narrow CSR reached the inner issuer")
			}
		})
	}
}

// PreCheck only tells the solver which names to verify, so a name with no
// second name to check is passed through as it arrived. Issuance is where a
// name that cannot be paired is refused.
func TestPreCheckPassesANameWithNoFileOriginThrough(t *testing.T) {
	for _, tc := range []struct {
		label      string
		fileOrigin func(string) string
	}{
		{"no file origin", noFileOrigin},
		{"the file origin is the name itself", sameAsName},
	} {
		t.Run(tc.label, func(t *testing.T) {
			rec, _ := newTestPair(t)
			inner := &recordingIssuer{}
			iss := NewPairIssuer(inner, &recordingIssuer{}, rec, tc.fileOrigin)
			if err := iss.PreCheck(context.Background(), []string{"alice.hyperdrop.link"}, false); err != nil {
				t.Fatalf("precheck: %v", err)
			}
			if len(inner.preChecked) != 1 || inner.preChecked[0] != "alice.hyperdrop.link" {
				t.Fatalf("prechecked %v, want the one name it was given", inner.preChecked)
			}
		})
	}
}

func TestACertEventIsPairedOnlyWhenThereIsASecondNameToReport(t *testing.T) {
	for _, tc := range []struct {
		label      string
		fileOrigin func(string) string
		identifier any
		wantFile   string
		wantOK     bool
	}{
		{"an ordinary domain", filesOrigin, "alice.hyperdrop.link", "files.alice.hyperdrop.link", true},
		{"an IP identifier", filesOrigin, "203.0.113.7", "", false},
		{"a non-string identifier", filesOrigin, 7, "", false},
		{"no file origin", noFileOrigin, "alice.hyperdrop.link", "", false},
		{"the file origin is the identifier", sameAsName, "alice.hyperdrop.link", "", false},
	} {
		t.Run(tc.label, func(t *testing.T) {
			paired, ok := PairedCertEvent(tc.fileOrigin, map[string]any{"identifier": tc.identifier})
			if ok != tc.wantOK {
				t.Fatalf("paired = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				if paired != nil {
					t.Fatalf("an unpaired event answered %v", paired)
				}
				return
			}
			if paired["identifier"] != tc.wantFile {
				t.Fatalf("paired identifier is %v, want %q", paired["identifier"], tc.wantFile)
			}
		})
	}
}
