//go:build acme

package main

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

// TestTheLockoutIsPerVisitorBehindAProxy boots the real server with a Pebble
// certificate and talks to it the way a pass-through proxy on loopback does:
// a PROXY v2 header, then TLS. Ten wrong logins claiming one visitor lock
// THAT visitor out, while another visitor behind the same proxy still signs
// in, which is the whole point of reading the header.
//
// Run with, on any machine with Docker (same harness as
// TestOneCertificateCoversBothOrigins):
//
//	cd test/pebble && docker compose up -d
//	cd ../../server && go test -tags acme -run TestTheLockoutIsPerVisitorBehindAProxy -v .
//	cd ../test/pebble && docker compose down
func TestTheLockoutIsPerVisitorBehindAProxy(t *testing.T) {
	const domain = "proxy.example.com"

	root := fetchPebbleTrustRoot(t)
	hostIP := hostGatewayIPv4(t)
	pointChallengeDNSAt(t, domain, hostIP)
	pointChallengeDNSAt(t, "files."+domain, hostIP)

	cmd := exec.Command(serverBinary(t))
	cmd.Env = append(os.Environ(),
		"HYPERDROP_PUSH_RELAY=",      // push off: a test server never posts to the real relay
		"HYPERDROP_SERVER_RELEASES=", // no update check: a test server never reads the public site
		"HYPERDROP_DOMAIN="+domain,
		"HYPERDROP_DATA="+t.TempDir(),
		"HYPERDROP_ADMIN_PASSWORD=right",
		"HYPERDROP_BEHIND_NAT=1",
		"HYPERDROP_ACME_CA=https://localhost:14000/dir",
		"HYPERDROP_ACME_CA_CERT="+root,
		"HYPERDROP_HTTP_ADDR=:5002",
		"HYPERDROP_HTTPS_ADDR=:5001",
		// The proxy sits on this box: listed explicitly, as nothing is
		// trusted implicitly.
		"HYPERDROP_TRUSTED_PROXIES=127.0.0.1",
	)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	// Pebble validates over the host gateway with no header: an unlisted
	// peer without a header is served as before, so a certificate arrives.
	waitForProxiedLeaf(t, domain)

	// Port 80 is not wrapped: the boot self-check and the provisioner reach
	// /api/health over loopback with no header even with 127.0.0.1 listed.
	resp, err := http.Get("http://127.0.0.1:5002/api/health")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("plain-HTTP health over loopback: %v %v", resp, err)
	}
	resp.Body.Close()

	// The listed proxy must send a header: without one HTTPS refuses.
	if c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", "127.0.0.1:5001",
		&tls.Config{ServerName: domain, InsecureSkipVerify: true}); err == nil {
		c.Close()
		t.Fatal("a listed peer completed TLS without a PROXY header")
	}

	login := func(src, password string) int {
		t.Helper()
		raw, err := net.DialTimeout("tcp", "127.0.0.1:5001", 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		raw.SetDeadline(time.Now().Add(30 * time.Second))
		if _, err := raw.Write(proxyV2(src)); err != nil {
			t.Fatal(err)
		}
		c := tls.Client(raw, &tls.Config{ServerName: domain, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
		body := `{"username":"admin","password":"` + password + `"}`
		req := "POST /api/auth/login HTTP/1.1\r\nHost: " + domain + "\r\nContent-Type: application/json\r\n" +
			"Content-Length: " + strconv.Itoa(len(body)) + "\r\nConnection: close\r\n\r\n" + body
		if _, err := io.WriteString(c, req); err != nil {
			t.Fatalf("login as %s: %v", src, err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatalf("login as %s: %v", src, err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	for i := range 10 {
		code := login("198.51.100.1:40000", "wrong")
		t.Logf("wrong login %d from 198.51.100.1: %d", i+1, code)
		if code != http.StatusUnauthorized && code != http.StatusTooManyRequests {
			t.Fatalf("wrong login %d answered %d", i+1, code)
		}
	}
	if code := login("198.51.100.1:40001", "right"); code != http.StatusTooManyRequests {
		t.Fatalf("the 11th login from the locked-out visitor answered %d, want 429", code)
	}
	if code := login("198.51.100.2:40000", "right"); code != http.StatusOK {
		t.Fatalf("another visitor behind the same proxy answered %d, want 200: the lockout is shared", code)
	}
	t.Log("198.51.100.1 is locked out; 198.51.100.2 behind the same proxy signs in")

	if cmd.ProcessState != nil {
		t.Fatalf("the server exited: %v", cmd.ProcessState)
	}
}

// waitForProxiedLeaf waits for the domain's certificate, dialling the way the
// listed proxy does (a PROXY v2 header, then TLS), since a header-less
// loopback dial is refused.
func waitForProxiedLeaf(t *testing.T, domain string) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		raw, err := net.DialTimeout("tcp", "127.0.0.1:5001", 5*time.Second)
		if err == nil {
			raw.SetDeadline(time.Now().Add(5 * time.Second))
			raw.Write(proxyV2("198.51.100.200:1"))
			c := tls.Client(raw, &tls.Config{ServerName: domain, InsecureSkipVerify: true})
			err = c.Handshake()
			if err == nil {
				certs := c.ConnectionState().PeerCertificates
				raw.Close()
				if len(certs) > 0 && len(certs[0].DNSNames) > 0 {
					return
				}
			} else {
				raw.Close()
			}
		}
		lastErr = err
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("no certificate for %s within the deadline, last error: %v", domain, lastErr)
}
