// hyperdrop-server: minimal self-hosted file share server.
//
// A server has a domain (HYPERDROP_DOMAIN, or a free name from
// HYPERDROP_DDNS_NAME) and serves it over HTTPS on HYPERDROP_HTTPS_ADDR
// (default :443) with automatic Let's Encrypt certificates, one covering the
// domain and its files.<domain> origin. HYPERDROP_HTTP_ADDR (default :80)
// serves the ACME HTTP-01 challenge, /api/health and a redirect to https. Its
// three modes (resolveBoot):
//   - public IP: HYPERDROP_IP is this box's public IPv4, which also gets a
//     certificate of its own (160 h, the only lifetime Let's Encrypt issues
//     an IP address under; the domain's is 45 days);
//   - behind NAT: HYPERDROP_BEHIND_NAT=1 and no HYPERDROP_IP, a router
//     forwarding 443 (and 80) here, as on a NAS;
//   - development: HYPERDROP_ALLOW_PRIVATE=1 and no domain, plain HTTP on
//     HYPERDROP_HTTP_ADDR with both origins collapsed onto one.
//
// Storage: a SQLite database of rows beside the bytes on the local
// filesystem (HYPERDROP_DATA). Accounts are rows too (login-minted bearer
// tokens; the first admin bootstrapped from HYPERDROP_ADMIN_USER and
// HYPERDROP_ADMIN_PASSWORD).
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/caddyserver/certmagic"

	"hyperdrop/core/domainconn"
	"hyperdrop/server/dsmpage"
	"hyperdrop/server/internal/api"
	"hyperdrop/server/internal/certpair"
	"hyperdrop/server/internal/conffile"
	"hyperdrop/server/internal/ddns"
	"hyperdrop/server/internal/domain"
	"hyperdrop/server/internal/housekeep"
	"hyperdrop/server/internal/linked"
	"hyperdrop/server/internal/logfile"
	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/netprobe"
	"hyperdrop/server/internal/selfupdate"
	"hyperdrop/server/internal/sharefs"
	"hyperdrop/server/internal/systemfiles"
	"hyperdrop/server/internal/updatesig"
	"hyperdrop/server/internal/webapp"
)

const version = "1.4.0"

// official is "true" in the binaries HyperDrop's own build scripts make
// (-ldflags "-X main.official=true"). A build without it, such as a fork or
// a plain `go build`, still checks for newer releases and reminds its admins,
// but never replaces itself with one on its own.
var official string

// isPublicIPv4 reports whether s is an IPv4 literal the domain can be
// expected to resolve to. Certificates are issued for the DOMAIN, never for
// the address, so this is only the "does your DNS point here" reference
// point. IPv6 is deliberately not accepted; an IPv4-mapped IPv6 literal
// counts as its IPv4 address.
func isPublicIPv4(s string) bool {
	v4 := net.ParseIP(s).To4()
	if v4 == nil {
		return false
	}
	return ddns.IsPublicIPv4(netip.AddrFrom4([4]byte(v4)))
}

// bootConfig is what main derives from the environment before it can listen.
// PublicIP is empty in behind-NAT mode: the router holds the public address
// and forwards 443 (and optionally 80) to the addrs below, so there is no IP
// to certify and no "does DNS point here" reference; ACME arbitrates
// reachability instead (the boot-time twin of `domain set --behind-nat`).
// The Synology package is what sets HYPERDROP_BEHIND_NAT and the alternate
// addrs: DSM's own nginx owns :80/:443 on a NAS.
type bootConfig struct {
	HTTPAddr     string
	HTTPSAddr    string
	Domain       string
	PublicIP     string
	AllowPrivate bool
	// BehindNAT: HTTPS mode with no local public IP; the domain manager
	// needs to know, or boot-time adoption refuses its own domain.
	BehindNAT bool
	// DDNSName is the free name this server should hold. When set it is the
	// source of Domain, so nothing downstream needs to know the difference.
	DDNSName string
	// Platform is the package family (HYPERDROP_PLATFORM; the DSM package
	// sets dsm7 or dsm6), reported by /api/health.
	Platform string
	// LiveShareGrace (HYPERDROP_LIVE_SHARE_GRACE) and AbandonedWindow
	// (HYPERDROP_ABANDONED_UPLOAD_TTL) override the live-share grace and the
	// abandoned-upload window; 0 keeps each package's default.
	LiveShareGrace  time.Duration
	AbandonedWindow time.Duration
	// TrustedProxies (HYPERDROP_TRUSTED_PROXIES, comma-separated addresses
	// and CIDR prefixes) are the peers whose PROXY header the HTTPS listener
	// requires and believes; empty lists none, so every peer's header is
	// refused. Nothing is trusted implicitly, loopback included. See
	// proxyproto.go.
	TrustedProxies []netip.Prefix
	// NamesURL (HYPERDROP_NAMES_URL) is the free-name service this server
	// talks to; unset is the HyperDrop service (ddns.ParseBaseURL).
	NamesURL string
}

// positiveDuration parses a Go duration override ("45m", "12h"), answering 0
// (the default) for an empty, unparseable or non-positive value: a typo must
// not disable a sweep or a grace period, so it is ignored rather than obeyed.
func positiveDuration(v string) time.Duration {
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0
	}
	return d
}

// resolveBoot validates the whole environment in one place. A custom domain
// is REQUIRED (two structural reasons: the files.<domain> origin split, and
// links that survive a move, see the comment at the call site), and with a
// domain there must be either a public HYPERDROP_IP or HYPERDROP_BEHIND_NAT=1.
func resolveBoot(getenv func(string) string) (bootConfig, error) {
	bc := bootConfig{
		HTTPAddr:     orDefault(getenv("HYPERDROP_HTTP_ADDR"), ":80"),
		HTTPSAddr:    orDefault(getenv("HYPERDROP_HTTPS_ADDR"), ":443"),
		Domain:       getenv("HYPERDROP_DOMAIN"),
		PublicIP:     getenv("HYPERDROP_IP"),
		AllowPrivate: getenv("HYPERDROP_ALLOW_PRIVATE") == "1",
		Platform:     getenv("HYPERDROP_PLATFORM"),

		LiveShareGrace:  positiveDuration(getenv("HYPERDROP_LIVE_SHARE_GRACE")),
		AbandonedWindow: positiveDuration(getenv("HYPERDROP_ABANDONED_UPLOAD_TTL")),
	}
	behindNAT := getenv("HYPERDROP_BEHIND_NAT") == "1"
	bc.BehindNAT = behindNAT
	trusted, err := conffile.ParseTrustedProxies(getenv("HYPERDROP_TRUSTED_PROXIES"))
	if err != nil {
		return bc, err
	}
	bc.TrustedProxies = trusted
	if bc.NamesURL, err = ddns.ParseBaseURL(getenv("HYPERDROP_NAMES_URL"), bc.AllowPrivate); err != nil {
		return bc, err
	}
	// A free name IS the domain: <name>.hyperdrop.link. Deriving it here
	// means origins, certificate subjects and adoption all read one field.
	if name := getenv("HYPERDROP_DDNS_NAME"); name != "" {
		if bc.Domain != "" {
			return bc, errors.New("HYPERDROP_DDNS_NAME and HYPERDROP_DOMAIN are both set: " +
				"a free name supplies the domain, so set one or the other")
		}
		if !ddns.ValidName(name) {
			return bc, fmt.Errorf("HYPERDROP_DDNS_NAME=%q is not a name this service issues: "+
				"use 5 to 32 characters of lowercase letters, digits and hyphens", name)
		}
		bc.DDNSName = name
		bc.Domain = ddns.FQDN(name)
	}
	if bc.Domain == "" && !bc.AllowPrivate {
		return bc, errors.New("HYPERDROP_DOMAIN is required: HyperDrop serves share pages on it and " +
			"uploaded files on files.<domain>, which is what keeps an uploaded page off " +
			"the origin that holds your listings and password form. " +
			"Set HYPERDROP_ALLOW_PRIVATE=1 for a development server with neither")
	}
	if bc.Domain != "" && !domain.Valid(bc.Domain) {
		return bc, fmt.Errorf("HYPERDROP_DOMAIN=%q is not a valid domain name", bc.Domain)
	}
	if bc.Domain != "" && !isPublicIPv4(bc.PublicIP) {
		if !behindNAT {
			// A free name is the variable the operator actually set, so it
			// is named here instead of the derived HYPERDROP_DOMAIN: naming
			// the wrong one sends them looking for a variable they never
			// touched.
			domainVar, domainVal := "HYPERDROP_DOMAIN", bc.Domain
			if bc.DDNSName != "" {
				domainVar, domainVal = "HYPERDROP_DDNS_NAME", bc.DDNSName
			}
			return bc, fmt.Errorf("%s=%s needs HYPERDROP_IP set to this server's public IPv4 "+
				"(got %q): the certificate is only issued once %s resolves here. "+
				"Behind a router that forwards 443 here, set HYPERDROP_BEHIND_NAT=1 instead",
				domainVar, domainVal, bc.PublicIP, bc.Domain)
		}
		if bc.PublicIP != "" {
			return bc, fmt.Errorf("HYPERDROP_IP=%q is not a public IPv4; behind NAT leave it unset", bc.PublicIP)
		}
	}
	return bc, nil
}

func orDefault(v, def string) string {
	if v != "" {
		return v
	}
	return def
}

// initialCertSubjects is the subject list requested at boot. A pending
// account connection must not request domain certificates before the names
// service authorizes publication and charges certificate capacity.
func initialCertSubjects(domainName, publicIP string, pending bool) []string {
	if pending && strings.HasSuffix(domainName, "."+ddns.Zone) {
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

// runCheck opens the data volume as it is and runs the database's integrity
// check, for two subcommands. `checkschema` is the pre-flight the provisioner
// runs before replacing the running server, which is still serving the
// volume. `checkdb` is the same check for an operator who suspects the
// volume, and reportOK prints "ok" on success for it. cmd prefixes every
// error line. Exit codes:
//
//	0: this binary can serve the data
//	3: the data is newer than this binary knows (the client app is out of date)
//	1: the data directory could not be opened or failed the check
func runCheck(cmd, dataDir string, reportOK bool) int {
	db, err := metadb.OpenAsIs(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", cmd, err)
		if errors.Is(err, metadb.ErrSchemaTooNew) {
			return 3
		}
		return 1
	}
	defer db.Close()
	if err := db.Check(); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", cmd, err)
		return 1
	}
	if reportOK {
		fmt.Println("ok")
	}
	return 0
}

// runLogs prints the tail of the server's log file. The default and the
// cap match the admin route's, so the two readers show the same thing.
func runLogs(dataDir string, args []string) int {
	tail := logfile.DefaultTail
	for i := 0; i < len(args); i++ {
		if args[i] == "--tail" && i+1 < len(args) {
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n < 1 {
				fmt.Fprintf(os.Stderr, "logs: --tail wants a positive number, got %q\n", args[i+1])
				return 2
			}
			tail = min(n, logfile.MaxTail)
			i++
		}
	}
	out, err := logfile.Tail(filepath.Join(dataDir, "logs"), tail)
	if err != nil {
		fmt.Fprintf(os.Stderr, "logs: %v\n", err)
		return 1
	}
	os.Stdout.Write(out)
	return 0
}

// runResetAdmin puts an administrator named by HYPERDROP_ADMIN_USER (empty:
// the sole existing admin, or the default name on an empty volume) on the
// volume with the password held in the seed file HYPERDROP_ADMIN_PASSWORD_FILE
// names, byte for byte. The file is removed once read, whatever the outcome,
// so the password neither sits on disk after the command nor ever passes
// through an environment or an argv another process could read. Every device
// token of that account is revoked with it: they were minted under the
// password being replaced.
func runResetAdmin(dataDir, name, seed string) int {
	if seed == "" {
		fmt.Fprintln(os.Stderr, "resetadmin: HYPERDROP_ADMIN_PASSWORD_FILE is not set")
		return 2
	}
	b, err := os.ReadFile(seed)
	if errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "resetadmin: no password seed at %s\n", seed)
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "resetadmin:", err)
		return 1
	}
	if err := os.Remove(seed); err != nil {
		fmt.Fprintln(os.Stderr, "resetadmin: removing the password seed:", err)
		return 1
	}
	password := string(b)
	if password == "" {
		fmt.Fprintf(os.Stderr, "resetadmin: the password seed %s is empty\n", seed)
		return 2
	}
	db, err := metadb.OpenAsIs(dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "resetadmin:", err)
		return 1
	}
	defer db.Close()
	got, err := db.ResetAdmin(name, password)
	if err != nil {
		fmt.Fprintln(os.Stderr, "resetadmin:", err)
		return 1
	}
	fmt.Printf("admin password reset for %s\n", got)
	return 0
}

// runAdmins powers the `admins` subcommand the provisioner, the installer's
// preflight and the app's arch probe run to learn whether a volume already
// holds an administrator: one username per line, nothing when there is no
// database yet. It never creates a database: a probe against a directory an
// install then abandons must leave nothing behind. With --standing each
// line is the name, a tab and whether the account can sign in: "active",
// "suspended" or "expired" (the DSM page's admin rescue labels the last two).
func runAdmins(dataDir string, args []string) int {
	standing := false
	switch {
	case len(args) == 0:
	case len(args) == 1 && args[0] == "--standing":
		standing = true
	default:
		fmt.Fprintln(os.Stderr, "admins: usage: hyperdrop-server admins [--standing]")
		return 2
	}
	if _, err := os.Stat(filepath.Join(dataDir, metadb.FileName)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0
		}
		fmt.Fprintf(os.Stderr, "admins: %v\n", err)
		return 1
	}
	db, err := metadb.OpenAsIs(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "admins: %v\n", err)
		return 1
	}
	defer db.Close()
	names, err := db.AdminNames()
	if err != nil {
		fmt.Fprintf(os.Stderr, "admins: %v\n", err)
		return 1
	}
	now := time.Now()
	for _, n := range names {
		if !standing {
			fmt.Println(n)
			continue
		}
		u, err := db.User(n)
		if err != nil {
			fmt.Fprintf(os.Stderr, "admins: %v\n", err)
			return 1
		}
		state := "active"
		switch {
		case u.Disabled:
			state = "suspended"
		case !u.Active(now):
			state = "expired"
		}
		fmt.Printf("%s\t%s\n", n, state)
	}
	return 0
}

// notOfficialUpdates is why a build that is not official never installs a
// release on its own, as the API's self-update-unavailable says it.
const notOfficialUpdates = "this server is not an official HyperDrop build, so it does not install updates on its own"

// runAutoUpdate powers `auto-update [on|off]`. It never creates a database:
// a volume that does not exist yet has no switch to read or turn. A build
// that is not official prints "unavailable: <why>" after the switch and
// refuses to turn it (exit 3).
func runAutoUpdate(dataDir string, args []string) int {
	on, set := false, len(args) == 1
	switch {
	case len(args) == 0:
	case set && args[0] == "on":
		on = true
	case set && args[0] == "off":
	default:
		fmt.Fprintln(os.Stderr, "auto-update: usage: hyperdrop-server auto-update [on|off]")
		return 2
	}
	if set && official != "true" {
		fmt.Fprintln(os.Stderr, "auto-update:", notOfficialUpdates)
		return 3
	}
	if _, err := os.Stat(filepath.Join(dataDir, metadb.FileName)); err != nil {
		fmt.Fprintf(os.Stderr, "auto-update: no HyperDrop database in %s: %v\n", dataDir, err)
		return 1
	}
	db, err := metadb.OpenAsIs(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "auto-update: %v\n", err)
		return 1
	}
	defer db.Close()
	if set {
		if err := selfupdate.Switch(db, on); err != nil {
			fmt.Fprintf(os.Stderr, "auto-update: %v\n", err)
			return 1
		}
	}
	on, err = selfupdate.AutoIn(db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "auto-update: %v\n", err)
		return 1
	}
	if on {
		fmt.Println("on")
	} else {
		fmt.Println("off")
	}
	if official != "true" {
		fmt.Println("unavailable:", notOfficialUpdates)
	}
	return 0
}

// runReset2FA powers `reset2fa <account>`: it clears the account's second
// factor and recovery codes. The client runs it over SSH with the unit
// stopped, so no login is mid-flight while the factor goes away; the stdout
// markers are what the client reads. An unfinished enrolment is cleared with
// a confirmed one: only an account with no secret at all is already off.
func runReset2FA(dataDir, account string) int {
	if !metadb.ValidUsername(account) {
		fmt.Fprintln(os.Stderr, "reset2fa: usage: hyperdrop-server reset2fa <account>")
		return 2
	}
	db, err := metadb.OpenAsIs(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reset2fa: %v\n", err)
		return 1
	}
	defer db.Close()
	u, err := db.User(account)
	if errors.Is(err, metadb.ErrUserNotFound) {
		fmt.Fprintf(os.Stderr, "reset2fa: no account %s\n", account)
		return 4
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "reset2fa: %v\n", err)
		return 1
	}
	if !u.TwoFactorEnabled() && u.TOTPStored == "" {
		fmt.Println("RESET2FA-ALREADY-OFF")
		return 0
	}
	if err := db.DisableTOTP(account); err != nil {
		fmt.Fprintf(os.Stderr, "reset2fa: %v\n", err)
		return 1
	}
	fmt.Println("RESET2FA-DONE")
	return 0
}

func main() {
	dataDir := orDefault(os.Getenv("HYPERDROP_DATA"), "/data")
	// The operator subcommands each run against the data volume and exit
	// without serving; dsmpage and dsmpage-apply are the Synology package
	// page's CGI and its worker. Any other argument falls through and starts
	// a server.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "checkschema":
			// A read-only pre-flight the provisioner runs against the data
			// volume BEFORE replacing the running container, so a downgrade
			// is refused while the old server is still serving.
			os.Exit(runCheck("checkschema", dataDir, false))
		case "resetadmin":
			// Sets the admin account's password from the seed file
			// HYPERDROP_ADMIN_PASSWORD_FILE names, and removes the file.
			//
			// The recovery path for a data volume that outlived the password
			// that created it: EnsureAdmin only seeds on a FIRST boot, so
			// re-provisioning a volume that already has an admin cannot
			// change it, and the install then succeeds while the login that
			// follows bounces. Whoever runs this already has root on the box
			// over SSH, which is strictly more authority than the admin
			// account it resets, so it grants nothing new. It deliberately
			// keeps every share: only the password changes.
			os.Exit(runResetAdmin(dataDir, os.Getenv("HYPERDROP_ADMIN_USER"), os.Getenv("HYPERDROP_ADMIN_PASSWORD_FILE")))
		case "admins":
			// Prints the username of every administrator on the data volume,
			// one per line. The provisioner, the installer's preflight and
			// the app's arch probe read it to learn whether the volume
			// already holds an administrator; empty output means it does not.
			// --standing adds whether each one can sign in.
			os.Exit(runAdmins(dataDir, os.Args[2:]))
		case "reset2fa":
			// reset2fa <account>: clears one account's second factor and
			// recovery codes, for an operator who lost the authenticator that
			// holds the only way into their own server. The client runs it
			// over SSH with the unit stopped.
			account := ""
			if len(os.Args) > 2 {
				account = os.Args[2]
			}
			os.Exit(runReset2FA(dataDir, account))
		case "auto-update":
			// auto-update [on|off]: prints "on" or "off", or turns automatic
			// updates on or off on the data volume, as an admin's switch in
			// the apps does; a build that is not official says so on a second
			// line and refuses the switch, as the API does. Server Management runs it over SSH as the
			// service account, beside the running server, then sends that
			// server SIGUSR1 so a switch turned on checks at once. Whoever
			// runs it already holds the box, which is more than any admin.
			os.Exit(runAutoUpdate(dataDir, os.Args[2:]))
		case "checkdb":
			// An integrity check of the data volume's database, printed.
			os.Exit(runCheck("checkdb", dataDir, true))
		case "logs":
			// logs [--tail N]: the last N lines (default 2000) of the server's
			// own log, across its rotated files. Server Management runs it over
			// SSH, which is how a box whose service is down still shows what
			// it did last.
			os.Exit(runLogs(dataDir, os.Args[2:]))
		case "verify-update":
			// verify-update <binary> <signature>: exits 0 only when the
			// signature is a release key's, names this binary's bytes and
			// this host's arch, and is not older than this version. The root
			// installer runs it with the binary ALREADY installed before it
			// executes anything staged, which is what makes the release key,
			// not whoever can write the staging directory, decide what runs
			// as root.
			os.Exit(runVerifyUpdate(os.Args[2:]))
		case "system-files":
			// Prints the provisioner this binary embeds and exits, touching
			// nothing. The root updater runs it with the binary it has just
			// verified, as root, and renders the service unit, itself and
			// its units from what it prints, so a normal update refreshes
			// what the install wrote.
			os.Exit(systemfiles.Run(os.Stdout))
		case "dsmpage":
			// The CGI behind the package's page in DSM 7's main menu
			// (ui/index.cgi execs it once per request). It never opens the
			// data volume, so it answers while the server is stopped.
			os.Exit(dsmpage.Serve())
		case "dsmpage-apply":
			// dsmpage-apply <job>: the DSM page's Save, which the CGI starts
			// in a session of its own because stopping, starting and
			// watching the server outlasts the request.
			os.Exit(dsmpage.RunApply(os.Args[2:]))
		case "version", "--version", "-version":
			// The over-the-air update installer runs this against a STAGED
			// binary before it replaces a working one, so "does this file
			// actually execute on this host" is answered without side
			// effects and without binding a port. Any argument the binary
			// does not understand would otherwise fall through and start a
			// server.
			fmt.Println(version)
			os.Exit(0)
		}
	}

	// Everything the serving process logs, CertMagic included, lands in its
	// own rotating file beside the data, and on stderr too except on a NAS
	// (logSink). Opened after the operator subcommands above, which run while
	// another server process still owns the file.
	logs, err := logfile.Open(filepath.Join(dataDir, "logs"))
	if err != nil {
		log.Fatalf("opening the log directory: %v", err)
	}
	defer logs.Close()
	sink := logSink(os.Getenv("HYPERDROP_CHANNEL"), logs)
	log.SetFlags(log.LUTC | log.Ldate | log.Ltime)
	log.SetOutput(sink)
	certmagic.Default.Logger = certLogger(sink)
	certmagic.DefaultACME.Logger = certmagic.Default.Logger

	// SIGINT/SIGTERM (docker stop) trigger a graceful shutdown instead of
	// truncating in-flight transfers.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// A custom domain is REQUIRED. Two reasons, both structural:
	//
	//   1. Uploaded bytes are served from files.<domain>, a separate origin,
	//      so an uploaded .html cannot run as first-party script on the page
	//      origin. An IP address cannot be split that way, and a second PORT
	//      cannot either (cookies ignore ports).
	//   2. A domain is what makes links survive. Every link embeds the host;
	//      with a domain the server can move and the links keep working.
	//
	// HYPERDROP_ALLOW_PRIVATE=1 is the development escape hatch (matching the
	// client-side flag of the same name): plain HTTP, one origin, no domain.
	// An env var rather than a flag, so it stays out of --help and cannot be
	// reached by accident. The rest of the rules live in resolveBoot.
	bc, err := resolveBoot(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	wc, err := resolveWeb(os.LookupEnv, bc.AllowPrivate)
	if err != nil {
		log.Fatal(err)
	}
	publicIP := bc.PublicIP
	httpAddr := bc.HTTPAddr
	if len(bc.TrustedProxies) > 0 {
		log.Printf("HTTPS requires a PROXY header from %s and refuses one from anyone else",
			joinPrefixes(bc.TrustedProxies))
	}
	domainName := bc.Domain

	db, err := metadb.Open(dataDir)
	if err != nil {
		log.Fatalf("opening the database at %s: %v", dataDir, err)
	}
	defer db.Close()
	store, err := sharefs.Open(dataDir)
	if err != nil {
		log.Fatalf("opening the data directory at %s: %v", dataDir, err)
	}
	store.AbandonedWindow = bc.AbandonedWindow
	roots, err := linked.FromEnv(os.Getenv)
	if err != nil {
		log.Fatalf("linked roots: %v", err)
	}
	if roots.Enabled() {
		names := []string{}
		for _, r := range roots.List() {
			names = append(names, r.Name)
		}
		log.Printf("linked roots: %s", strings.Join(names, ", "))
	}
	// Accounts live on the data volume beside the shares they own. The first
	// administrator is bootstrapped from HYPERDROP_ADMIN_USER (empty: "admin")
	// and HYPERDROP_ADMIN_PASSWORD on first boot; once any admin exists both
	// env values are ignored (renames and password changes win), and so is
	// HYPERDROP_AUTO_UPDATE, the new volume's automatic-update choice.
	autoUpdate, err := selfupdate.ParseChoice(os.Getenv("HYPERDROP_AUTO_UPDATE"))
	if err != nil {
		log.Fatalf("HYPERDROP_AUTO_UPDATE: %v", err)
	}
	if err := seedAdmin(db, autoUpdate); err != nil {
		log.Fatalf("admin bootstrap: %v", err)
	}
	pct, err := diskReservePercent(os.Getenv("HYPERDROP_DISK_RESERVE"))
	if err != nil {
		log.Fatalf("HYPERDROP_DISK_RESERVE: %v", err)
	}
	store.ReservePercent = pct

	// The boot pass lists shares/ once and removes what no row names, then
	// reclaims stale staging. Rows are the truth; a directory without one is a
	// delete that crashed between its two halves.
	ids, err := db.ShareIDs()
	if err != nil {
		log.Fatalf("listing shares: %v", err)
	}
	known := make(map[string]bool, len(ids))
	for _, id := range ids {
		known[id] = true
	}
	if removed, err := store.Orphans(func(id string) bool { return known[id] }); err != nil {
		log.Printf("boot pass: %v", err)
	} else if removed > 0 {
		log.Printf("boot pass: orphan share directories removed: %d", removed)
	}
	// A publish whose commit journal remains is a commit a crash or a failed
	// rename stopped: settled here, before the listener starts, so no
	// visitor reads rows naming bytes still in stage/.
	finished, reopened, err := bootPublishes(db, store)
	if err != nil {
		log.Printf("boot pass: publishes left for the next boot: %v", err)
	}
	if finished > 0 {
		log.Printf("boot pass: interrupted publish commits finished: %d", finished)
	}
	if reopened > 0 {
		log.Printf("boot pass: publishes reopened, their commits never written: %d", reopened)
	}
	// The startup pass runs in the background rather than ahead of the
	// listener: every step is advisory cleanup that takes the same locks as a
	// scheduled pass, and blocking the listener on it costs a minute of
	// downtime per restart on a big volume. A pass that finds nothing to do
	// logs nothing, so an idle server stays silent in the journal.
	missingFiles := new(atomic.Int64)
	status := newStatusWriter(os.Getenv("HYPERDROP_STATUS_FILE"))
	status.Set(Status{Version: version, StartedAt: time.Now().Unix()})
	// The HTTPS listener's record of connections failing on the PROXY
	// header, kept in the status file and the health verdict.
	proxyHeaders := newProxyWatch(func(private []ProxySource, public int) {
		status.Update(func(s *Status) { s.ProxySources, s.PublicProxy = private, public })
	})
	go func() {
		for range time.Tick(time.Minute) {
			proxyHeaders.Tick()
		}
	}()
	pass := &housekeep.Pass{DB: db, FS: store, DataDir: dataDir, MissingFiles: missingFiles}
	// The pass starts once the API exists, because its empty sweep asks the
	// API's preparing tracker whether a sender is still making a share's
	// bytes (below, after NewServer).
	startHousekeeping := func() {
		go func() {
			for {
				res := pass.Run()
				for _, line := range res.Lines() {
					log.Print(line)
				}
				if res.MissingChecked {
					n := int(missingFiles.Load())
					status.Update(func(s *Status) { s.MissingFiles = n })
				}
				time.Sleep(housekeep.Interval)
			}
		}()
	}

	// The domain is persisted in the data volume and can be CHANGED at
	// runtime via PUT /api/domain, but it cannot be absent: see the
	// HYPERDROP_DOMAIN check above.
	dom, err := domain.Load(filepath.Join(dataDir, "domain"), publicIP)
	if err != nil {
		log.Fatalf("reading domain state: %v", err)
	}
	// The Synology package's conf names the current address, whichever path
	// changes it.
	conf := &confAddress{path: os.Getenv("HYPERDROP_CONF")}
	dom.Changed = conf.Sync
	dom.Moved = func(from, to string) {
		now := time.Now()
		if err := db.RecordDomainChange(domainconn.Change{From: from, To: to, At: now}, now); err != nil {
			log.Printf("domain change %s → %s not recorded: %v", from, to, err)
		}
	}
	// Installation environment is a seed. Runtime domain changes must
	// survive a restart, including switching a managed name to custom DDNS.
	if persisted := dom.Current(); persisted != "" {
		domainName = persisted
	}
	// The free-name address and a DDNS recipe. Both are absent on a server
	// with a domain of its own, the ordinary case: its updater's ticks then
	// send nothing anywhere, and the address and hostnames are checked only
	// when an administrator asks (POST /api/connectivity/check).
	dstore, err := ddns.Load(filepath.Join(dataDir, "ddns"))
	if err != nil {
		log.Fatalf("reading ddns state: %v", err)
	}
	namesClient := &ddns.Client{BaseURL: bc.NamesURL}
	updater := ddns.NewUpdater(dstore, namesClient, func(ctx context.Context) (string, bool) {
		ip, err := namesClient.PublicIPv4(ctx)
		return ip, err == nil
	})
	dom.BehindNAT = bc.BehindNAT
	updater.Connected = func(string) error { return errors.New("certificate management is starting") }
	updater.Domain = dom.Current
	updater.PrivateRecipes = os.Getenv("HYPERDROP_DDNS_ALLOW_PRIVATE") == "1"
	updater.ServerID = store.ServerID
	// A desired free name is claimed before the domain is adopted, so the A
	// pair exists by the time ACME goes looking for it. A refusal is logged
	// and carried in GET /api/ddns: the server still boots and serves over
	// its IP, it simply does not hold the name it was asked to.
	if bc.DDNSName != "" && (dom.Current() == "" || domainName == ddns.FQDN(bc.DDNSName)) {
		if err := bootTake(ctx, updater, bc.DDNSName, store.ServerID(), bootTakeLimit); err != nil {
			log.Printf("ddns: taking %s: %v", ddns.FQDN(bc.DDNSName), err)
		}
	}
	// HYPERDROP_DOMAIN is the boot-time source of truth. Adopt rather than
	// Set: Set verifies the domain already resolves HERE, which cannot be
	// true yet on a server that has not started serving.
	if domainName != "" && dom.Current() != domainName {
		if err := dom.Adopt(domainName); err != nil {
			// A free name that could not be claimed must not stop the
			// server from booting: it serves over its IP and GET
			// /api/ddns explains why. An explicitly configured
			// HYPERDROP_DOMAIN is an operator error and stays fatal.
			if bc.DDNSName != "" {
				log.Printf("ddns: configuring domain %s: %v", domainName, err)
			} else {
				log.Fatalf("configuring domain %s: %v", domainName, err)
			}
		}
	}

	// The persisted domain wins over the conf's seed, so the conf may name an
	// older address until now.
	conf.Sync(dom.Current())
	// An address change asked for on DSM; unset, as on every server but the
	// Synology package, nothing is asked.
	var addressReqs *addressRequests
	if path := os.Getenv("HYPERDROP_ADDRESS_REQUEST"); path != "" {
		addressReqs = &addressRequests{path: path, dom: dom, up: updater, st: status}
	}

	// Set by the systemd unit provisioning writes, beside the root-owned
	// installer unit that watches it. Without it the binary belongs to a
	// container image or a package manager, so the update route stays off and
	// /api/health says so rather than accepting a binary nothing would ever
	// install.
	updateDir := os.Getenv("HYPERDROP_UPDATE_DIR")
	// The port /api/local-addresses joins onto the server's private
	// addresses. bc.HTTPSAddr is always host:port shaped (":443" default),
	// so the split cannot fail; plain-HTTP mode reports no candidates.
	_, localPort, _ := net.SplitHostPort(bc.HTTPSAddr)
	if domainName == "" {
		localPort = ""
	}
	// Unset is the HyperDrop relay; set and empty turns push off. A malformed
	// value turns push off with a log line rather than refusing to boot: a
	// typo must not take the shares offline.
	pushRelay := api.DefaultPushRelay
	if v, set := os.LookupEnv("HYPERDROP_PUSH_RELAY"); set {
		pushRelay = v
	}
	if pushRelay, err = api.ParsePushRelay(pushRelay, bc.AllowPrivate); err != nil {
		log.Printf("push notifications are off: %v", err)
		pushRelay = ""
	}
	// The website directory the self-updater reads once a day. Unset: the
	// HyperDrop site; empty: never check (the box then gets no reminders
	// and installs nothing on its own); malformed: logged, never check.
	releases := selfupdate.DefaultBase
	if raw, set := os.LookupEnv("HYPERDROP_SERVER_RELEASES"); set {
		parsed, err := selfupdate.ParseBase(raw)
		if err != nil {
			log.Printf("HYPERDROP_SERVER_RELEASES: %v; this server will not check for updates", err)
		}
		releases = parsed
	}
	// The web client's installs under the data directory, and the fetch that
	// keeps them current from the web release manifest. A store that cannot
	// be opened leaves /app saying the web version is not installed rather
	// than keeping the shares offline, and the settings say why.
	if wc.BaseErr != nil {
		log.Printf("%v; this server will not fetch the web version", wc.BaseErr)
	}
	var webFetcher *webapp.Fetcher
	webFailed := ""
	web, err := webapp.Open(dataDir, wc.Keys, version)
	if err != nil {
		log.Printf("the web version is unavailable: %v", err)
		web, webFailed = nil, err.Error()
	} else {
		if wc.DevDir != "" {
			log.Printf("serving the web version unsigned from %s (HYPERDROP_WEB_DEV_DIR)", wc.DevDir)
			web.UseDevDir(wc.DevDir)
		}
		webFetcher = webapp.NewFetcher(web, wc.Base, nil)
	}
	mux := api.NewServer(api.Backend{DB: db, FS: store, Roots: roots}, version, dom, updater, api.Deployment{
		DataDir:      dataDir,
		MissingFiles: missingFiles,
		ProxyHeaders: func() ([]api.ProxyHeaderSource, int) {
			private, public := proxyHeaders.Snapshot()
			out := make([]api.ProxyHeaderSource, len(private))
			for i, s := range private {
				out[i] = api.ProxyHeaderSource{Addr: s.Addr, Kind: s.Kind}
			}
			return out, public
		},
		AddressPending: func() (string, string) {
			if p := status.Current().AddressPending; p != nil {
				return p.Address, p.Reason
			}
			return "", ""
		},
		AddressChange: addressReqs.AppChange,
		UpdateDir:     updateDir,
		Channel:       os.Getenv("HYPERDROP_CHANNEL"),
		LocalPort:     localPort,
		Platform:      bc.Platform,

		LiveShareGrace: bc.LiveShareGrace,
		PushRelay:      pushRelay,
		Releases:       releases,
		Official:       official == "true",
		Web:            web,
		WebFailed:      webFailed,
		WebFetcher:     webFetcher,
	})
	if webFetcher != nil {
		webFetcher.Start(ctx)
	}
	pass.Alive = mux.PreparingReportedSince
	watchSelfUpdateSwitch(ctx, mux.RereadSelfUpdate)
	startHousekeeping()
	// A readable password copy that no longer opens beside its row's hash
	// (the previous release changed or removed the hash, or the copy came
	// from another server's volume) is cleared once per boot, in the
	// background so it never delays the listener or the updater's health
	// wait: every read already treats such a copy as absent. It stops
	// between batches at shutdown.
	go func() {
		cleared, err := api.SweepSealed(ctx, db, store.Secret())
		if cleared > 0 {
			log.Printf("sealed passwords: cleared %d stale", cleared)
		}
		if err != nil && ctx.Err() == nil {
			log.Printf("sealed passwords: %v", err)
		}
	}()

	if domainName == "" {
		log.Printf("hyperdrop-server %s serving HTTP on %s (no domain, development mode)",
			version, httpAddr)
		// Not proxy-wrapped: the boot self-check dials this one listener
		// over loopback with no header, and a development server has no
		// HTTPS listener for a proxy to sit in front of.
		srv := newServer(httpAddr, mux)
		go bootSelfCheck(httpAddr)
		serveUntilShutdown(ctx, mux.Drain, serverRun{srv, srv.ListenAndServe})
		return
	}
	subject := domainName

	// managed is the live set of domains under certificate management, which
	// both the storage alias and the subject transformer below consult. It is
	// filled by the manage closure, the one way a domain enters management.
	managed := certpair.NewSubjects(api.ShareHost)
	certPath := filepath.Join(dataDir, "certmagic")
	certmagic.Default.Storage = certpair.NewFileOriginAlias(
		&certmagic.FileStorage{Path: certPath}, managed)
	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.Email = os.Getenv("HYPERDROP_ACME_EMAIL")
	certmagic.DefaultACME.Profile = certpair.DomainProfile
	// Test hook: point ACME at a private CA (e.g. Pebble) instead of Let's
	// Encrypt. Both CA and TestCA are set to the override: certmagic retries
	// a failed order against TestCA, so leaving it at its Let's Encrypt
	// staging default would send a test server's ACME traffic to a public
	// CA on the open internet on the very first retry.
	if ca := os.Getenv("HYPERDROP_ACME_CA"); ca != "" {
		certmagic.DefaultACME.CA = ca
		certmagic.DefaultACME.TestCA = ca
	}
	// Test hook: trust a private ACME CA's TLS cert (e.g. Pebble). PEM content.
	if pem := os.Getenv("HYPERDROP_ACME_CA_CERT"); pem != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(pem)) {
			log.Fatal("HYPERDROP_ACME_CA_CERT: invalid PEM")
		}
		certmagic.DefaultACME.TrustedRoots = pool
	}
	keys := certpair.NewKeyRecorder(certmagic.DefaultKeyGenerator)
	// Every field the certificate pair depends on is set on certmagic.Default
	// rather than on the config below, because background certificate
	// maintenance does not use that config: it asks the certificate cache for
	// one, and the cache builds a fresh config out of certmagic.Default. A
	// renewal that ran with the stock key generator and the bare ACME issuer
	// would replace the certificate with one covering the app domain alone
	// and take the file origin down.
	certmagic.Default.KeySource = keys
	// CertMagic renews a cached certificate under its FIRST name, which for a
	// paired certificate is whichever of the two origins sorts first (see
	// certpair.FileOriginAlias). Mapping a file origin back to its app domain
	// here is what keeps the ACME order, the storage lock and every
	// certificate event naming the domain an operator can act on.
	certmagic.Default.SubjectTransformer = managed.Subject
	// Behind NAT the router is the only thing that knows whether inbound
	// traffic can ever arrive, so classify the NAT above it and ask the
	// names service to dial our public 443 and 80 (probeNetwork). Async and
	// advisory. Assigned before CertMagic's event hook is installed and before
	// any domain enters management, so nothing that fires it (Adopt, a
	// freshly issued certificate, a manual connectivity check) can race the
	// assignment; a probe does nothing until both listeners are bound: a dial
	// back that lands first would read "closed" and raise a false alarm.
	// Probes run one at a time, so a slow one can never overwrite a newer
	// verdict.
	var netListening atomic.Bool
	if bc.BehindNAT {
		var probeMu sync.Mutex
		dom.ReprobeNAT = func() {
			if !netListening.Load() {
				return
			}
			probeMu.Lock()
			defer probeMu.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			probeNetwork(ctx, netprobe.RouterExternalIP, namesClient, store.ServerID(), dom)
			reachable := reachableFromManager(dom)
			status.Update(func(s *Status) { s.Reachable = reachable })
		}
	}

	// One certificate covers both origins, so a lifecycle event for a
	// managed domain is its file origin's event too: /api/domain reports a
	// state for each name an operator can point DNS at, for every domain
	// this process manages, not only the one it booted with.
	certmagic.Default.OnEvent = func(_ context.Context, event string, data map[string]any) error {
		dom.RecordCertEvent(event, data)
		if paired, ok := certpair.PairedCertEvent(api.ShareHost, data); ok {
			dom.RecordCertEvent(event, paired)
		}
		updater.CertificateEvent(event, data)
		return nil
	}
	// Keep the ordinary fallback stable. The selector below handles direct-IP
	// NAT connections separately, without mutating live CertMagic configuration.
	certmagic.Default.DefaultServerName = subject
	// The cache is this process's own rather than CertMagic's default, which
	// is unreachable, so a subject can be removed from maintenance: the IP
	// certificate of an address the box no longer has. Like the default
	// cache, it builds each certificate's config fresh out of
	// certmagic.Default.
	var certCache *certmagic.Cache
	certCache = certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			return certmagic.New(certCache, certmagic.Default), nil
		},
		Logger: certmagic.Default.Logger,
	})
	magic := certmagic.New(certCache, certmagic.Default)
	bootstrapTLS := &bootstrapCertificateSelector{getCertificate: magic.GetCertificate}
	// Custom DDNS pins its HTTPS checks to the leaf this process serves.
	// Set before the update loop starts and before the API serves the
	// connectivity check, the two callers that read it concurrently.
	updater.LocalLeaf = func(host string) []byte { return localLeaf(magic.GetCertificateWithContext, host) }
	bootstrapTLS.observe(publicIP)
	domainACME := certmagic.NewACMEIssuer(magic, certmagic.DefaultACME)
	ipTemplate := certmagic.DefaultACME
	ipTemplate.Profile = certpair.IPProfile
	ipACME := certmagic.NewACMEIssuer(magic, ipTemplate)
	// One PairIssuer instance serves every domain this process ever manages:
	// the boot domain, a free name claimed at runtime and a domain set through
	// the API all widen through it, and it sends the IP certificate to the one
	// issuer ordering the profile Let's Encrypt issues an IP address under.
	certmagic.Default.Issuers = []certmagic.Issuer{certpair.NewPairIssuer(domainACME, ipACME, keys, api.ShareHost)}
	magic.Issuers = certmagic.Default.Issuers

	// manage is the one way a domain enters certificate management, so it is
	// where the alias, the subject transformer and the paired-certificate
	// check all see it. Recording precedes the request: certificate work
	// begins immediately and resolves names through that set.
	manage := func(ctx context.Context, names []string) error {
		managed.Add(names...)
		if err := magic.ManageAsync(ctx, names); err != nil {
			return err
		}
		// Async for the same reason management is: a transient ACME outage
		// must not crash-loop the service. The carry-over runs first and in
		// the same goroutine, so the file origin has a certificate to serve
		// before the ACME round trip the check below can start.
		go func() {
			carryOverFileOriginCertificates(ctx, magic, certPath, names)
			ensurePairedCertificates(ctx, magic, names)
		}()
		return nil
	}

	// The app domain alone: files.<domain> is a real origin serving real
	// bytes and still needs its own DNS A record, which is why `domain set`
	// creates two, but its certificate rides the app domain's order through
	// the paired issuer above instead of being requested here.
	//
	// The bare IP is kept as an ADDITIONAL subject, never as the identity: a
	// server has to be reachable before its DNS points here at all, the
	// client logs in right after installing. It does not reopen the
	// origin split, which is enforced by the Host header (origins.go): a
	// payload request arriving on the IP is redirected to the file origin.
	//
	// Async so a transient ACME/network outage doesn't crash-loop the
	// service; issuance retries while :80 stays up.
	subjects := initialCertSubjects(subject, publicIP, !dstore.Configured())
	if err := manage(context.Background(), subjects); err != nil {
		log.Fatalf("certmagic manage %v: %v", subjects, err)
	}
	// Every domain change after boot, a free name claimed at runtime or an
	// operator-set domain, runs certificate
	// management through this closure. It manages the domain alone: the
	// PairIssuer constructed above widens whichever domain CertMagic orders
	// a certificate for, so the file origin never needs its own subject here.
	dom.Manage = func(d string) error {
		return manage(context.Background(), []string{d})
	}

	updater.Connected = dom.Adopt
	if bc.BehindNAT && bc.DDNSName != "" && publicIP == "" {
		go bootstrapIPCertificate(ctx, 30*time.Second, ddns.TickInterval, namesClient.PublicIPv4, func(ip string) error {
			if err := manage(ctx, []string{ip}); err != nil {
				return err
			}
			bootstrapTLS.observe(ip)
			return nil
		}, func(ip string) {
			certCache.RemoveManaged([]certmagic.SubjectIssuer{{Subject: ip}})
			log.Printf("tls: the public IP changed; stopped managing the certificate for %s", ip)
		})
	}

	// A server that already holds a name or a DDNS recipe resumes its
	// heartbeat on boot, the same way it resumes after any PUT /api/ddns: a
	// restart must not leave the address unpublished until the next config
	// change. On a server holding neither, the loop's ticks send nothing.
	if domainName != "" {
		updater.Start(context.Background())
	}

	// A free name outlives a domain change made before this boot: links
	// already issued under it must keep answering, so a certificate for it
	// stays managed even when it is not the server's current domain.
	// Without this a server that changed domain would lose the free name's
	// certificate at its next restart, and every link issued under that name
	// would start failing a TLS handshake instead of just going unused.
	if st := dstore.Snapshot(); !st.Pending && st.Name != "" && ddns.FQDN(st.Name) != dom.Current() {
		if err := dom.Manage(ddns.FQDN(st.Name)); err != nil {
			log.Printf("ddns: keeping a certificate for %s: %v", ddns.FQDN(st.Name), err)
		}
	}

	// :80 serves the ACME challenge, health and the redirect to https.
	httpMux := http.NewServeMux()
	httpMux.Handle("GET /api/health", mux) // the api handler's open health route
	httpMux.Handle("GET /.well-known/hyperdrop-names", mux)
	httpMux.Handle("/", redirectToHTTPS(dom, subject))
	// CertMagic keeps every pending challenge in one process-wide table read
	// through the shared config, so the domain issuer's handler answers the
	// IP issuer's challenges as well.
	httpSrv := newServer(bc.HTTPAddr, domainACME.HTTPChallengeHandler(httpMux))

	tlsConfig := httpsTLSConfig(magic.TLSConfig(), bootstrapTLS.GetCertificate)
	// The PROXY header precedes the TLS ClientHello, so the proxy listener
	// sits BELOW TLS: TCP, then PROXY, then TLS. Port 80 stays unwrapped
	// (proxyproto.go says why).
	tcpLn, err := listenRecording(status, bc.HTTPSAddr)
	if err != nil {
		log.Fatalf("listen %s: %v", bc.HTTPSAddr, err)
	}
	ln := tls.NewListener(wrapProxyListener(tcpLn, bc.TrustedProxies, proxyHeaders), tlsConfig)
	log.Printf("hyperdrop-server %s serving HTTPS for %s", version, subject)
	// Bound here rather than by ListenAndServe so both ports accept before
	// the first port check asks the names service to dial them.
	httpLn, err := listenRecording(status, bc.HTTPAddr)
	if err != nil {
		log.Fatalf("listen %s: %v", bc.HTTPAddr, err)
	}
	tlsSrv := newServer("", mux)
	go bootSelfCheck(bc.HTTPAddr)
	if dom.ReprobeNAT != nil {
		netListening.Store(true)
		go func() {
			dom.ReprobeNAT()
			// A user who fixes the router sees the warning go away without
			// a restart; a check is one small request to the registry.
			t := time.NewTicker(30 * time.Minute)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					dom.ReprobeNAT()
				}
			}
		}()
	}
	// An address change asked for on DSM waits for certificate management
	// and the updater's adoption hook above, and runs beside the listeners:
	// it may wait for DNS or approval for as long as it takes, and the old
	// address serves meanwhile.
	if addressReqs != nil {
		go addressReqs.watch(ctx, addressRetry, addressRefresh)
	}
	serveUntilShutdown(ctx, mux.Drain,
		serverRun{httpSrv, func() error { return httpSrv.Serve(httpLn) }},
		serverRun{tlsSrv, func() error { return tlsSrv.Serve(ln) }})
}

// bootTakeLimit bounds the free-name claim that runs before the listeners
// bind, well inside the 90 s health windows of the updater and the
// provisioner.
const bootTakeLimit = 30 * time.Second

// bootTake is the boot's attempt at the free name: Take under ctx (the signal
// context, so a stop during boot is not held up by the names service) and at
// most limit. A claim cut short stays pending in the store, and the update
// loop finishes it like any other pending claim.
func bootTake(ctx context.Context, updater *ddns.Updater, name, serverID string, limit time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	return updater.Take(ctx, name, serverID)
}

// seedAdmin bootstraps the first administrator from HYPERDROP_ADMIN_USER and
// the password (EnsureAdmin ignores both once any admin exists), then lets
// the password go. A volume with no administrator is a new one, so it first
// records autoUpdate, the volume's automatic-update choice, before the
// administrator exists: a boot that stops between the two records it again,
// and a volume that already has an administrator keeps the switch it has. It is read once, from the file HYPERDROP_ADMIN_PASSWORD_FILE
// names when that is set and the file exists, else from
// HYPERDROP_ADMIN_PASSWORD.
//
// A seed file is removed once EnsureAdmin succeeds, so the password never
// enters this process's environment and does not outlive the first boot on
// disk. A volume that already has an administrator never reads the seed: it
// says so in the log, because a password typed into a reinstall over kept
// data changes nothing, and removes it, so a seed it cannot read (a
// directory, a file another user owns) never stops a boot that does not
// need it. Only a volume with no administrator yet fails on a seed it cannot
// read, since that password is the one it would be created with.
// The variable is unset either way, which keeps it out of every later
// os.Getenv and of anything this process starts; the copy the kernel shows in
// /proc/<pid>/environ is the one passed at exec, and it stays.
func seedAdmin(db *metadb.DB, autoUpdate bool) error {
	defer os.Unsetenv("HYPERDROP_ADMIN_PASSWORD")
	password := os.Getenv("HYPERDROP_ADMIN_PASSWORD")
	seed := os.Getenv("HYPERDROP_ADMIN_PASSWORD_FILE")
	admins, err := db.AdminNames()
	if err != nil {
		return err
	}
	if len(admins) > 0 {
		if seed != "" {
			if _, err := os.Lstat(seed); err == nil {
				log.Printf("admin bootstrap: %s is ignored: this volume already has an administrator, whose password is unchanged", seed)
				if err := os.Remove(seed); err != nil && !errors.Is(err, fs.ErrNotExist) {
					log.Printf("admin bootstrap: removing %s: %v", seed, err)
				}
			}
		}
		return nil
	}
	fromFile := false
	if seed != "" {
		b, err := os.ReadFile(seed)
		switch {
		case err == nil:
			password, fromFile = string(b), true
		case !errors.Is(err, fs.ErrNotExist):
			return fmt.Errorf("reading the admin password seed: %w", err)
		}
	}
	if err := selfupdate.StartWith(db, autoUpdate); err != nil {
		return fmt.Errorf("recording the automatic-update choice: %w", err)
	}
	if err := db.EnsureAdmin(os.Getenv("HYPERDROP_ADMIN_USER"), password); err != nil {
		return err
	}
	if fromFile {
		if err := os.Remove(seed); err != nil && !errors.Is(err, fs.ErrNotExist) {
			log.Printf("admin bootstrap: removing %s: %v", seed, err)
		}
	}
	return nil
}

// redirectToHTTPS is port 80's answer to everything but health, the
// names-service probe and ACME. It is host-aware: a request already addressed
// to the current domain or its file origin keeps that name (so an http://
// link to a file lands on the file origin); anything else, a bare IP or a
// domain the server does not hold, goes to the current domain's page
// origin. fallback (the boot domain) stands in only while no domain is
// current. Only those names are ever a redirect target, so it is not an open
// redirect.
func redirectToHTTPS(dom *domain.Manager, fallback string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(r.Host); err == nil {
			host = h
		}
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		target := dom.Current()
		switch {
		case target == "":
			target = fallback
		case dom.IsCurrent(host) || host == api.ShareHost(target):
			target = host
		}
		http.Redirect(w, r, "https://"+target+r.URL.RequestURI(), http.StatusPermanentRedirect)
	})
}

// httpsTLSConfig is the HTTPS listener's TLS configuration: CertMagic's
// (which carries the TLS-ALPN challenge protocol), with certificates chosen
// by getCertificate, HTTP/2 offered ahead of HTTP/1.1, and TLS 1.2 the
// oldest version accepted.
func httpsTLSConfig(base *tls.Config, getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
	base.GetCertificate = getCertificate
	base.NextProtos = append([]string{"h2", "http/1.1"}, base.NextProtos...)
	base.MinVersion = tls.VersionTLS12
	return base
}

// bootSelfCheck probes this process's own plain-HTTP health route (served
// unredirected on :80 in both modes) and exits nonzero when it cannot answer
// within the window. `systemctl is-active` cannot tell serving from wedged,
// so a process that binds and then cannot serve would otherwise sit
// active-but-broken past the updater's rollback watch; exiting turns that
// state into a visible unit failure instead. The window is generous because
// a big store's startup scan is real work, not a wedge.
func bootSelfCheck(addr string) {
	urls, ok := selfCheckURLs(addr)
	if !ok {
		return
	}
	if !waitServing(time.Minute, time.Second, urls...) {
		log.Fatal("boot self-check: /api/health never answered; exiting so systemd (and the updater's rollback) can see the failure")
	}
}

// The HTTP/2 receive windows: how many body bytes a connection, and one
// stream on it, may have in flight before the handler reads them. Go's
// default of 1 MiB for both caps every upload on a connection at 1 MiB per
// round trip (about 80 Mbit/s at 100 ms), and a client carries all of a
// share's parallel chunks, and every other command, on one connection. The
// upload handlers stream to disk, so these are ceilings, not steady memory.
const (
	h2ConnWindow   = 16 << 20
	h2StreamWindow = 8 << 20
)

// serverErrorLog is every HTTP server's error log: abandoned TLS handshakes
// are counted per address and hour (handshakeLog), the rest logged as is.
var serverErrorLog = log.New(newHandshakeLog(time.Now), "", 0)

// newServer applies header timeouts and no whole-request timeout: uploads and
// downloads can legitimately run for many minutes. A request body is read
// under serverBodyDeadline instead (bodydeadline.go), which fails a body that
// stalls or trickles and never one that keeps arriving. IdleTimeout only reaps
// keep-alive connections between requests, so it is safe to set. The HTTP/2
// windows apply where HTTP/2 is negotiated (the HTTPS server).
func newServer(addr string, h http.Handler) *http.Server {
	return &http.Server{Addr: addr, Handler: serverBodyDeadline.wrap(h),
		ErrorLog:          serverErrorLog,
		ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute,
		HTTP2: &http.HTTP2Config{
			MaxReceiveBufferPerConnection: h2ConnWindow,
			MaxReceiveBufferPerStream:     h2StreamWindow,
		}}
}

// serverRun pairs a server with its (blocking) serve call.
type serverRun struct {
	srv   *http.Server
	serve func() error
}

// serveUntilShutdown runs the servers and, when ctx is canceled (SIGINT/
// SIGTERM), drains the parked long-polls and gives each server a short
// graceful Shutdown. The grace is 5 s, not the watch timeout: long-polls are
// woken by drain, resumable uploads pick up where they were cut, and holding
// the listener longer is downtime for everyone during an update. A serve
// error before that is fatal.
func serveUntilShutdown(ctx context.Context, drain func(), servers ...serverRun) {
	errc := make(chan error, len(servers))
	for _, s := range servers {
		go func() { errc <- s.serve() }()
	}
	select {
	case err := <-errc:
		log.Fatal(err)
	case <-ctx.Done():
	}
	log.Print("shutting down")
	drain()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for _, s := range servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.srv.Shutdown(shutdownCtx)
		}()
	}
	wg.Wait()
}

// runVerifyUpdate is the verify-update subcommand.
func runVerifyUpdate(args []string) int {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: hyperdrop-server verify-update <binary> <signature>")
		return 2
	}
	sig, err := readSignature(args[1])
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintln(os.Stderr, "verify-update:", err)
		return 1
	}
	bin, err := os.Open(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify-update:", err)
		return 1
	}
	defer bin.Close()
	st, err := updatesig.Verify(updatesig.TrustedKeys, sig, bin, runtime.GOARCH, version)
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify-update:", err)
		return 1
	}
	fmt.Println("verified", st.Version, st.Arch)
	return 0
}

// readSignature reads a signature file, at most one byte past
// updatesig.MaxSize: a longer file is refused by Verify, so nothing past that
// is worth reading, however large the staged file is.
func readSignature(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, updatesig.MaxSize+1))
}

// diskReservePercent reads HYPERDROP_DISK_RESERVE: unset, the flat 1 GiB
// reserve (sharefs.FlatReserve); otherwise a percentage of the disk from 0
// (no reserve, uploads still admitted against the free space) to 90.
func diskReservePercent(v string) (int, error) {
	if v == "" {
		return sharefs.FlatReserve, nil
	}
	pct, err := strconv.Atoi(v)
	if err != nil || pct < 0 || pct > 90 {
		return 0, fmt.Errorf("invalid value %q (want 0-90)", v)
	}
	return pct, nil
}

// bootPublishes settles the commit journals the boot pass found. The
// database spells paths as the volume does before the first journal is
// judged: a commit's rows and a later upload's are spelled that way, so on
// a volume that folds case only a spelled lookup finds them. api.NewServer
// sets the same answer (b.FS.SamePath) when it builds the handler.
func bootPublishes(db *metadb.DB, store *sharefs.FS) (finished, reopened int, err error) {
	if store.FoldsCase() {
		db.SetFoldCase(store.SamePath)
	}
	return housekeep.FinishPublishes(db, store)
}
