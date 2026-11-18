package certpair

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"net"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3/acme"
	"golang.org/x/net/idna"
)

// The Let's Encrypt profiles this server orders under. A domain certificate
// lives 45 days; Let's Encrypt issues an IP address only under shortlived,
// which lives 160 hours and so leaves about two days to recover a failed
// renewal. Neither profile emits a Common Name, which FileOriginAlias depends
// on: under classic the leaf would carry one and its first name would no
// longer be the alphabetically first SAN.
const (
	DomainProfile = "tlsserver"
	IPProfile     = "shortlived"
)

// PairIssuer widens the certificate signing request CertMagic hands it so one
// certificate carries an app domain and its file origin together.
//
// CertMagic manages the app domain alone and caches what comes back under
// every SAN the leaf actually carries, so the file origin is served from this
// certificate without being managed. That is also why a request that cannot be
// widened is refused: the file origin has no other certificate to fall back to.
// A CSR carrying one DNS name is therefore either widened or refused, never
// delegated narrow. The one CSR that passes through untouched is the IP
// certificate, which carries no DNS name and names no origin to pair with.
//
// It also picks the issuer: a request naming an IP address goes to ips (the
// IPProfile issuer), everything else to domains (the DomainProfile issuer).
// The two must share one CA and account, since every certificate is stored
// under domains' IssuerKey.
//
// The file origin is derived per request from fileOrigin rather than fixed at
// construction, so one PairIssuer instance covers every domain this process
// ever manages: the boot domain, a free name claimed at runtime and a domain
// set through the API.
type PairIssuer struct {
	domains    certmagic.Issuer
	ips        certmagic.Issuer
	keys       *KeyRecorder
	fileOrigin func(string) string
}

// NewPairIssuer panics when domains and ips answer different IssuerKeys: an
// IP certificate would be stored where its own issuer never looks.
func NewPairIssuer(domains, ips certmagic.Issuer, keys *KeyRecorder, fileOrigin func(string) string) *PairIssuer {
	if domains.IssuerKey() != ips.IssuerKey() {
		panic(fmt.Sprintf("certpair: the domain issuer %q and the IP issuer %q must share one CA", domains.IssuerKey(), ips.IssuerKey()))
	}
	return &PairIssuer{domains: domains, ips: ips, keys: keys, fileOrigin: fileOrigin}
}

// normalizeToASCII converts a domain to its punycode ASCII form.
// If conversion fails, the original value is returned unchanged,
// because a name that cannot be converted will not match a CSR either way
// and the loud-refusal path is the correct outcome.
func normalizeToASCII(domain string) string {
	ascii, err := idna.ToASCII(domain)
	if err != nil {
		return domain
	}
	return ascii
}

// IssuerKey is the domain issuer's, so certificates land on the storage paths
// CertMagic would have used anyway.
func (p *PairIssuer) IssuerKey() string { return p.domains.IssuerKey() }

func (p *PairIssuer) Issue(ctx context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	if len(csr.IPAddresses) != 0 {
		return p.ips.Issue(ctx, csr)
	}
	if len(csr.DNSNames) != 1 {
		return p.domains.Issue(ctx, csr)
	}
	name, file, ok := p.pair(csr.DNSNames[0])
	if !ok {
		return nil, fmt.Errorf("certpair: no file origin for %q, refusing to order a certificate that covers one origin of a server that serves two", csr.DNSNames[0])
	}
	key, ok := p.keys.Lookup(csr.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certpair: no recorded key for the %s request, refusing to order a certificate that omits %s", name, file)
	}
	wider, err := widenCSR(key, name, file)
	if err != nil {
		return nil, err
	}
	return p.domains.Issue(ctx, wider)
}

// PreCheck gives the inner issuer both names, so a solver that verifies
// reachability checks the file origin too.
func (p *PairIssuer) PreCheck(ctx context.Context, names []string, interactive bool) error {
	prechecker, ok := p.issuerFor(names).(certmagic.PreChecker)
	if !ok {
		return nil
	}
	return prechecker.PreCheck(ctx, p.expand(names), interactive)
}

// GetRenewalInfo forwards to the inner issuer's ACME Renewal Information (ARI)
// lookup. CertMagic finds ARI support by type-asserting each configured
// issuer against this interface, so a wrapper that does not implement it
// leaves the CA's renewal advice unreachable and CertMagic falls back to its
// own time-ratio estimate. When the inner issuer does not support ARI
// either, that is reported as an error so CertMagic logs and moves on the
// same way it would for any other issuer with nothing to offer here.
func (p *PairIssuer) GetRenewalInfo(ctx context.Context, cert certmagic.Certificate) (acme.RenewalInfo, error) {
	inner := p.issuerFor(cert.Names)
	ariGetter, ok := inner.(certmagic.RenewalInfoGetter)
	if !ok {
		return acme.RenewalInfo{}, fmt.Errorf("certpair: inner issuer %s does not support ACME renewal info", inner.IssuerKey())
	}
	return ariGetter.GetRenewalInfo(ctx, cert)
}

// issuerFor answers the issuer for a request naming names: ips when any of
// them is an IP address, domains otherwise.
func (p *PairIssuer) issuerFor(names []string) certmagic.Issuer {
	for _, name := range names {
		if net.ParseIP(name) != nil {
			return p.ips
		}
	}
	return p.domains
}

func (p *PairIssuer) expand(names []string) []string {
	if len(names) != 1 {
		return names
	}
	name, file, ok := p.pair(names[0])
	if !ok {
		return names
	}
	return []string{name, file}
}

// pair answers name's normalized form and its file origin, and false when
// there is nothing to pair: name is an IP address (the IP certificate has no
// file origin), or fileOrigin answers empty (no file origin, e.g. an empty
// domain) or the domain itself.
func (p *PairIssuer) pair(rawName string) (name, file string, ok bool) {
	if net.ParseIP(rawName) != nil {
		return "", "", false
	}
	name = normalizeToASCII(rawName)
	file = normalizeToASCII(p.fileOrigin(name))
	if file == "" || file == name {
		return "", "", false
	}
	return name, file, true
}

func widenCSR(key crypto.Signer, names ...string) (*x509.CertificateRequest, error) {
	template := new(x509.CertificateRequest)
	for _, name := range names {
		ascii, err := idna.ToASCII(name)
		if err != nil {
			return nil, fmt.Errorf("certpair: converting %q to ASCII: %w", name, err)
		}
		template.DNSNames = append(template.DNSNames, ascii)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, fmt.Errorf("certpair: signing the widened request: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("certpair: parsing the widened request: %w", err)
	}
	return csr, nil
}

// PairedCertEvent answers the copy of a CertMagic certificate event that names
// the file origin for an app domain event, so /api/domain reports a state for
// both names from the one certificate that covers them. The second return is
// false when there is nothing to pair: no string identifier, an IP identifier
// (the separate IP certificate never pairs with anything), or a file origin
// that is empty or the same as the identifier.
//
// The identifier is matched and emitted exactly as CertMagic gave it, never
// normalized to punycode: that is the raw form the rest of the event data,
// and every other event for the same subject, already uses.
func PairedCertEvent(fileOrigin func(string) string, data map[string]any) (map[string]any, bool) {
	subject, ok := data["identifier"].(string)
	if !ok {
		return nil, false
	}
	if net.ParseIP(subject) != nil {
		return nil, false
	}
	file := fileOrigin(subject)
	if file == "" || file == subject {
		return nil, false
	}
	paired := make(map[string]any, len(data))
	for k, v := range data {
		paired[k] = v
	}
	paired["identifier"] = file
	return paired, true
}
