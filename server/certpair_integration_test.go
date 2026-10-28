//go:build acme

package main

import (
	"archive/tar"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/certpair"
)

// TestOneCertificateCoversBothOrigins drives a real ACME exchange against a
// local Pebble server and asserts the server ends up with a single leaf
// carrying the app domain and the file origin, which is what halves the cost
// of a name at Let's Encrypt.
//
// Run with, on any machine with Docker (no file to edit first):
//
//	cd test/pebble && docker compose up -d
//	cd ../../server && go test -tags acme -run TestOneCertificateCoversBothOrigins -v .
//	cd ../test/pebble && docker compose down
func TestOneCertificateCoversBothOrigins(t *testing.T) {
	const domain = "pair.example.com"

	root := fetchPebbleTrustRoot(t)
	hostIP := hostGatewayIPv4(t)
	pointChallengeDNSAt(t, domain, hostIP)
	pointChallengeDNSAt(t, "files."+domain, hostIP)

	dataDir := t.TempDir()
	cmd := exec.Command(serverBinary(t))
	cmd.Env = append(os.Environ(),
		"HYPERDROP_PUSH_RELAY=",      // push off: a test server never posts to the real relay
		"HYPERDROP_SERVER_RELEASES=", // no update check: a test server never reads the public site
		"HYPERDROP_DOMAIN="+domain,
		"HYPERDROP_DATA="+dataDir,
		"HYPERDROP_ADMIN_PASSWORD=t",
		"HYPERDROP_BEHIND_NAT=1",
		"HYPERDROP_ACME_CA=https://localhost:14000/dir",
		"HYPERDROP_ACME_CA_CERT="+root,
		"HYPERDROP_HTTP_ADDR=:5002",
		"HYPERDROP_HTTPS_ADDR=:5001",
	)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	leaf := waitForLeaf(t, "localhost:5001", domain)
	// The SET of names is the contract. A CA normalizes and byte-sorts the
	// SAN set when it issues, so the order the CSR asked for is the CA's to
	// choose and asserting it here would only pin this CA's habits.
	names := map[string]bool{}
	for _, n := range leaf.DNSNames {
		names[n] = true
	}
	if len(names) != 2 || !names[domain] || !names["files."+domain] {
		t.Fatalf("leaf carries %v, want exactly %s and files.%s", leaf.DNSNames, domain, domain)
	}
	// Each Pebble profile issues a different lifetime, so the leaf's lifetime
	// names the profile the order asked for: the domain one, never the IP one.
	if lifetime := leaf.NotAfter.Sub(leaf.NotBefore); lifetime > pebbleCertLifetime || lifetime < pebbleCertLifetime-time.Minute {
		t.Fatalf("the leaf lives %v, want the %s profile's %v", lifetime, certpair.DomainProfile, pebbleCertLifetime)
	}

	// The same certificate has to answer the file origin's SNI, or the split
	// origin has no certificate at all.
	fileLeaf := waitForLeaf(t, "localhost:5001", "files."+domain)
	if !fileLeaf.Equal(leaf) {
		t.Fatal("the file origin is served a different certificate")
	}

	assertNoManagedFileOriginCertificate(t, dataDir, domain)
}

// assertNoManagedFileOriginCertificate walks the certmagic storage tree and
// fails the test if a certificate was ever ordered for the file origin on
// its own: the whole point of the pairing is that files.<domain> rides the
// app domain's order and is never a managed subject in its own right.
func assertNoManagedFileOriginCertificate(t *testing.T, dataDir, domain string) {
	t.Helper()
	certRoot := filepath.Join(dataDir, "certmagic")
	fileOrigin := "files." + domain
	var found []string
	var listing []string
	var sawAppDomainCert bool
	err := filepath.WalkDir(certRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(certRoot, path)
		if relErr != nil {
			rel = path
		}
		if d.IsDir() {
			return nil
		}
		listing = append(listing, rel)
		if strings.Contains(path, fileOrigin) {
			found = append(found, rel)
		}
		if strings.HasSuffix(path, domain+".crt") {
			sawAppDomainCert = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", certRoot, err)
	}
	t.Logf("certmagic storage tree under %s:\n%s", certRoot, strings.Join(listing, "\n"))
	// A tree with nothing in it would let the "no files.<domain> files" check
	// below pass without proving anything, so the app domain's own leaf must
	// actually be on disk first.
	if !sawAppDomainCert {
		t.Fatalf("no %s.crt found under %s, the storage tree proves nothing", domain, certRoot)
	}
	if len(found) > 0 {
		t.Fatalf("the file origin has managed certificate files, it must not: %v", found)
	}
}

// fetchPebbleTrustRoot returns the PEM root that signs Pebble's OWN HTTPS
// listener (its directory and management API on :14000/:15000), which is a
// static "minica" CA baked into the pebble image at
// test/certs/pebble.minica.pem. That CA is separate from the CA Pebble
// generates at startup to sign the certificates it ISSUES (served from
// GET /roots/0): the server under test never needs to trust the latter, only
// to reach Pebble's API over TLS, so this fetches the former, straight out
// of the running container, which keeps the trust root correct even when
// pebble:latest regenerates it.
func fetchPebbleTrustRoot(t *testing.T) string {
	t.Helper()
	composeFile := filepath.Join("..", "test", "pebble", "docker-compose.yml")
	cmd := exec.Command("docker", "compose", "-f", composeFile, "cp", "pebble:/test/certs/pebble.minica.pem", "-")
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		t.Skipf("pebble is not running (start it with: cd ../test/pebble && docker compose up -d): %v: %s", err, stderr.String())
	}
	tr := tar.NewReader(&out)
	if _, err := tr.Next(); err != nil {
		t.Fatalf("read pebble.minica.pem from the container copy stream: %v", err)
	}
	pem, err := io.ReadAll(tr)
	if err != nil {
		t.Fatalf("read pebble.minica.pem contents: %v", err)
	}
	return string(pem)
}

// hostGatewayIPv4 returns the address a container reaches this Mac host at.
// "host.docker.internal" is the portable name for it on both Docker Desktop
// and OrbStack, but it only resolves from inside a container, not from the
// host's own resolver, so this asks a throwaway container to look it up.
// Nothing in this repository, or in the committed compose file, hardcodes
// the answer: it can differ between machines and between Docker runtimes.
func hostGatewayIPv4(t *testing.T) string {
	t.Helper()
	cmd := exec.Command("docker", "run", "--rm", "alpine", "getent", "hosts", "host.docker.internal")
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("resolve host.docker.internal (needs the alpine image, pulled automatically): %v: %s", err, stderr.String())
	}
	fields := strings.Fields(out.String())
	if len(fields) == 0 {
		t.Fatalf("host.docker.internal did not resolve inside a container: %q", out.String())
	}
	return fields[0]
}

// pointChallengeDNSAt registers an A record on challtestsrv's management API
// (challtestsrv is Pebble's configured DNS server) so Pebble resolves name to
// addr when it dials back for HTTP-01 or TLS-ALPN-01 validation. The trailing
// dot matches the FQDN form challtestsrv's mocks are keyed on.
func pointChallengeDNSAt(t *testing.T, name, addr string) {
	t.Helper()
	body := strings.NewReader(`{"host":"` + name + `.","addresses":["` + addr + `"]}`)
	resp, err := http.Post("http://localhost:8055/add-a", "application/json", body)
	if err != nil {
		t.Skipf("challtestsrv is not running on localhost:8055 (start it with: cd ../test/pebble && docker compose up -d): %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("challtestsrv POST /add-a for %s: %s", name, resp.Status)
	}
}

func waitForLeaf(t *testing.T, addr, serverName string) *x509.Certificate {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
		if err == nil {
			state := conn.ConnectionState()
			conn.Close()
			if len(state.PeerCertificates) > 0 {
				leaf := state.PeerCertificates[0]
				if len(leaf.DNSNames) > 0 {
					return leaf
				}
			}
		} else {
			lastErr = err
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("no certificate for %s within the deadline, last dial error: %v", serverName, lastErr)
	return nil
}

func serverBinary(t *testing.T) string {
	t.Helper()
	path := t.TempDir() + "/hyperdrop-server"
	build := exec.Command("go", "build", "-o", path, ".")
	build.Stdout, build.Stderr = os.Stderr, os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build server: %v", err)
	}
	return path
}
