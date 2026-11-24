package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"net"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"

	"hyperdrop/server/internal/api"
	"hyperdrop/server/internal/ddns"
)

// initialCertSubjects is the subject list requested at boot. A pending
// account connection must not request domain certificates before the names
// service authorizes publication and charges certificate capacity.
func initialCertSubjects(domainName, publicIP string, pending bool) []string {
	if pending && ddns.InFreeZone(domainName) {
		if publicIP != "" {
			return []string{publicIP}
		}
		return nil
	}
	return certSubjects(domainName, publicIP)
}

// certSubjects is what CertMagic manages. The file origin is deliberately
// absent: certpair widens the app domain's order to carry it, and one
// certificate covering both names costs the zone half of what two cost at
// Let's Encrypt, whose budget is per registered domain.
//
// The bare IP is kept as a SEPARATE certificate, never folded into that pair:
// a single Certificate Transparency entry binding a subdomain to the operator's
// address would publish it permanently, and the address moves under DDNS.
func certSubjects(domainName, publicIP string) []string {
	subjects := []string{domainName}
	if isPublicIPv4(publicIP) {
		subjects = append(subjects, publicIP)
	}
	return subjects
}

// ensurePairedCertificates orders a replacement for any managed domain whose
// stored certificate does not carry that domain's file origin. CertMagic
// decides whether a stored certificate is still good from its expiry alone and
// never from the names it carries, so a certificate covering the app domain by
// itself would be served until its own renewal window while the file origin
// had no certificate at all and every View, Download, zip, /site and /thumb
// link failed its TLS handshake.
//
// A subject with no certificate in storage is left alone: that is the ordinary
// first boot, and certificate management is already obtaining a paired one.
// The IP certificate is a separate subject with no file origin and is skipped.
func ensurePairedCertificates(ctx context.Context, magic *certmagic.Config, subjects []string) {
	for _, subject := range subjects {
		fileOrigin := api.ShareHost(subject)
		if fileOrigin == "" || net.ParseIP(subject) != nil {
			continue
		}
		cert, err := magic.CacheManagedCertificate(ctx, subject)
		if err != nil {
			continue
		}
		if !pairedCertificateOwed(cert.Names, fileOrigin) {
			continue
		}
		log.Printf("certmagic: the certificate for %s does not cover %s; ordering one that covers both", subject, fileOrigin)
		if err := magic.RenewCertAsync(ctx, subject, true); err != nil {
			log.Printf("certmagic: ordering a certificate covering %s and %s: %v", subject, fileOrigin, err)
			continue
		}
		if _, err := magic.CacheManagedCertificate(ctx, subject); err != nil {
			log.Printf("certmagic: caching the certificate covering %s and %s: %v", subject, fileOrigin, err)
		}
	}
}

// carryOverFileOriginCertificates caches the certificate storage already holds
// for each managed domain's file origin, so every View, Download, zip, /site
// and /thumb link keeps answering a TLS handshake while ensurePairedCertificates
// orders the certificate covering both origins. That order is an ACME round
// trip, and the file origin is not a managed subject, so nothing else puts a
// certificate for it in the cache: a server holding one narrow certificate per
// hostname would serve the file origin nothing at all until the paired
// certificate arrived, which reads as a DNS fault and is not one.
//
// The certificate is read through a raw FileStorage over the certificate
// directory rather than through the configured storage. The configured storage
// is certpair.FileOriginAlias, which answers a read of the file origin's asset
// with the app domain's asset, so reading through it would hand back a
// certificate that does not carry the file origin at all.
//
// It is cached UNMANAGED. Certificate maintenance renews managed certificates
// only, so nothing here can order a certificate for the file origin alone and
// spend a second certificate from the weekly budget. CertMagic's default
// selector serves whichever cached certificate for a name is both compatible
// with the client and currently valid, so the paired certificate takes over the
// moment it is cached, and this one is skipped once it expires.
//
// Nothing here is an error and nothing here blocks: a file origin with no
// stored certificate is the ordinary first boot, and a certificate that is only
// an improvement on an empty cache must never fail a boot.
func carryOverFileOriginCertificates(ctx context.Context, magic *certmagic.Config, certPath string, subjects []string) {
	raw := &certmagic.FileStorage{Path: certPath}
	for _, subject := range subjects {
		fileOrigin := api.ShareHost(subject)
		if fileOrigin == "" || net.ParseIP(subject) != nil {
			continue
		}
		certPEM, keyPEM, found := storedCertificate(ctx, raw, fileOrigin)
		if !found || !carriedOverCertificateUsable(certPEM, fileOrigin, time.Now()) {
			continue
		}
		if _, err := magic.CacheUnmanagedCertificatePEMBytes(ctx, certPEM, keyPEM, nil); err != nil {
			log.Printf("certmagic: serving the stored certificate for %s: %v", fileOrigin, err)
			continue
		}
		log.Printf("certmagic: serving the stored certificate for %s until one covering both origins arrives", fileOrigin)
	}
}

// storedCertificate answers the PEM certificate and private key storage holds
// for name under any issuer, and false when there is none.
//
// Issuers are enumerated from storage rather than taken from the configured
// issuer list, because the certificate being looked for was written by an
// earlier version of this server, under whatever issuer key that version was
// pointed at.
func storedCertificate(ctx context.Context, storage certmagic.Storage, name string) ([]byte, []byte, bool) {
	issuers, err := storage.List(ctx, certmagic.StorageKeys.CertsPrefix(""), false)
	if err != nil {
		return nil, nil, false
	}
	for _, issuer := range issuers {
		issuerKey := path.Base(issuer)
		certPEM, err := storage.Load(ctx, certmagic.StorageKeys.SiteCert(issuerKey, name))
		if err != nil {
			continue
		}
		keyPEM, err := storage.Load(ctx, certmagic.StorageKeys.SitePrivateKey(issuerKey, name))
		if err != nil {
			continue
		}
		return certPEM, keyPEM, true
	}
	return nil, nil, false
}

// localLeaf answers the DER leaf certificate get selects for a TLS client
// naming host, or nil when this server holds none for it (a first boot whose
// certificate waits for its records). The ClientHello is the one a Go client
// offers, so the selection matches what the custom DDNS probe is served, and
// it carries a placeholder connection because CertMagic logs the remote
// address when no certificate matches.
func localLeaf(get func(context.Context, *tls.ClientHelloInfo) (*tls.Certificate, error), host string) []byte {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	cert, err := get(context.Background(), &tls.ClientHelloInfo{
		Conn:       serverConn,
		ServerName: host,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
		SignatureSchemes: []tls.SignatureScheme{
			tls.ECDSAWithP256AndSHA256, tls.ECDSAWithP384AndSHA384, tls.Ed25519,
			tls.PSSWithSHA256, tls.PSSWithSHA384, tls.PKCS1WithSHA256, tls.PKCS1WithSHA384,
		},
		SupportedCurves:   []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
		SupportedPoints:   []uint8{0},
		SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
	})
	if err != nil || cert == nil || len(cert.Certificate) == 0 {
		return nil
	}
	return cert.Certificate[0]
}

// carriedOverCertificateUsable reports whether a certificate storage holds for
// fileOrigin is worth serving until the paired certificate arrives: it has to
// parse, it has to carry fileOrigin, and it has to be valid at now. Anything
// else is no better than the empty cache it would be filling, so it is skipped
// rather than reported.
func carriedOverCertificateUsable(certPEM []byte, fileOrigin string, now time.Time) bool {
	leaf, err := leafCertificate(certPEM)
	if err != nil {
		return false
	}
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return false
	}
	return !pairedCertificateOwed(certificateNames(leaf), fileOrigin)
}

// leafCertificate parses the first certificate in a PEM bundle, which is the
// leaf: storage holds the leaf ahead of the chain it was issued with.
func leafCertificate(certPEM []byte) (*x509.Certificate, error) {
	for rest := certPEM; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		return x509.ParseCertificate(block.Bytes)
	}
	return nil, errors.New("no certificate in PEM bundle")
}

// certificateNames lists the names a certificate carries the way CertMagic's
// cache keys one: the deprecated common name, then every DNS name on it.
func certificateNames(leaf *x509.Certificate) []string {
	if leaf.Subject.CommonName == "" {
		return leaf.DNSNames
	}
	return append([]string{leaf.Subject.CommonName}, leaf.DNSNames...)
}

// pairedCertificateOwed reports whether a certificate carrying names has to be
// replaced because it does not cover fileOrigin. A certificate that already
// carries it is answered false, so a restart never spends a certificate from
// the weekly budget.
func pairedCertificateOwed(names []string, fileOrigin string) bool {
	if fileOrigin == "" {
		return false
	}
	return !slices.ContainsFunc(names, func(name string) bool { return strings.EqualFold(name, fileOrigin) })
}
