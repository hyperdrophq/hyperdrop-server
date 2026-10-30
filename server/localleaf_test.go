package main

import (
	"bytes"
	"context"
	"encoding/pem"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

// The custom DDNS pin is the leaf CertMagic serves for the host, and a
// server holding no certificate for it yet answers no pin (rather than
// panicking on CertMagic's miss, which logs the hello's connection).
func TestLocalLeafIsTheCertificateServedForTheHost(t *testing.T) {
	ctx := context.Background()
	var magic *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return magic, nil },
		Logger:           zap.NewNop(),
	})
	defer cache.Stop()
	magic = certmagic.New(cache, certmagic.Config{Storage: &certmagic.FileStorage{Path: t.TempDir()}, Logger: zap.NewNop()})

	if pin := localLeaf(magic.GetCertificateWithContext, "share.example.com"); pin != nil {
		t.Fatalf("a server with no certificate answered a pin of %d bytes", len(pin))
	}

	now := time.Now()
	certPEM, keyPEM := testLeafPEM(t, "share.example.com", []string{"share.example.com", "files.share.example.com"}, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	if _, err := magic.CacheUnmanagedCertificatePEMBytes(ctx, certPEM, keyPEM, nil); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	for _, host := range []string{"share.example.com", "files.share.example.com"} {
		if pin := localLeaf(magic.GetCertificateWithContext, host); !bytes.Equal(pin, block.Bytes) {
			t.Fatalf("%s: the pin is not the served leaf", host)
		}
	}
	if pin := localLeaf(magic.GetCertificateWithContext, "other.example.com"); pin != nil {
		t.Fatal("a host this server holds no certificate for answered a pin")
	}
}
