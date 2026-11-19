package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

type nasConnection struct{ net.Conn }

func (nasConnection) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.168.1.8"), Port: 5443}
}

func TestNATBootstrapSelectsTrustedIPWithoutSNI(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	var magic *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return magic, nil }, Logger: zap.NewNop()})
	defer cache.Stop()
	magic = certmagic.New(cache, certmagic.Config{DefaultServerName: "unapproved.hyperdrop.link", Storage: &certmagic.FileStorage{Path: t.TempDir()}, Logger: zap.NewNop()})
	for i, name := range []string{"8.8.4.4", "8.8.8.8", "custom.example.com"} {
		leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 2)), NotBefore: root.NotBefore, NotAfter: root.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		if ip := net.ParseIP(name); ip != nil {
			leaf.IPAddresses = []net.IP{ip}
		} else {
			leaf.DNSNames = []string{name}
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		_, err = magic.CacheUnmanagedTLSCertificate(context.Background(), tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	selector := &bootstrapCertificateSelector{getCertificate: magic.GetCertificate}
	selector.observe("8.8.4.4")
	getCertificate := selector.GetCertificate
	handshake := func(name string) {
		t.Helper()
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()
		_ = clientConn.SetDeadline(time.Now().Add(3 * time.Second))
		_ = serverConn.SetDeadline(time.Now().Add(3 * time.Second))
		receivedSNI := make(chan string, 1)
		server := tls.Server(nasConnection{serverConn}, &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			receivedSNI <- hello.ServerName
			return getCertificate(hello)
		}})
		done := make(chan error, 1)
		go func() { done <- server.Handshake() }()
		client := tls.Client(clientConn, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: name})
		if err := client.Handshake(); err != nil {
			t.Fatalf("trusted handshake for %s: %v", name, err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		want := name
		if net.ParseIP(name) != nil {
			want = ""
		}
		if got := <-receivedSNI; got != want {
			t.Fatalf("SNI=%q want %q", got, want)
		}
		if err := client.ConnectionState().PeerCertificates[0].VerifyHostname(name); err != nil {
			t.Fatal(err)
		}
	}
	handshake("8.8.4.4")
	handshake("custom.example.com")
	selector.observe("192.168.1.8") // invalid observations cannot replace the trusted public subject
	handshake("8.8.4.4")
	selector.observe("8.8.8.8")
	handshake("8.8.8.8")
	handshake("custom.example.com")
	// Observations and handshakes run concurrently in production.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			selector.observe("8.8.8.8")
		}
	}()
	for range 8 {
		handshake("8.8.8.8")
	}
	cancel()
	<-done
}
