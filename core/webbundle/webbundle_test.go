package webbundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestStatementShape(t *testing.T) {
	got, err := Statement("1.0.0", 1, "1.2.0", strings.Repeat("a", 64), 10)
	if err != nil {
		t.Fatal(err)
	}
	want := "hyperdrop-web\n1.0.0\n1\n1.2.0\n" + strings.Repeat("a", 64) + "\n10\n"
	if got != want {
		t.Fatalf("statement %q, want %q", got, want)
	}
}

func TestStatementRefusesMalformed(t *testing.T) {
	sum := strings.Repeat("a", 64)
	for name, f := range map[string]func() (string, error){
		"version":  func() (string, error) { return Statement("1.0", 1, "1.2.0", sum, 10) },
		"contract": func() (string, error) { return Statement("1.0.0", 1, "1.2.x", sum, 10) },
		"build":    func() (string, error) { return Statement("1.0.0", 0, "1.2.0", sum, 10) },
		"sha":      func() (string, error) { return Statement("1.0.0", 1, "1.2.0", strings.Repeat("A", 64), 10) },
		"size":     func() (string, error) { return Statement("1.0.0", 1, "1.2.0", sum, 0) },
		"newline":  func() (string, error) { return Statement("1.0.0\n", 1, "1.2.0", sum, 10) },
	} {
		if _, err := f(); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err %v, want ErrMalformed", name, err)
		}
	}
}

func newKey(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key, base64.StdEncoding.EncodeToString(pub)
}

func TestSignVerifyRoundTrip(t *testing.T) {
	key, pub := newKey(t)
	archive := []byte("bundle bytes")
	sig, err := Sign(key, "1.0.0", 3, "1.2.0", archive)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(sig), "\n") {
		t.Fatal("signature lacks a trailing newline")
	}
	if err := Verify([]string{pub}, sig, "1.0.0", 3, "1.2.0", archive); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRefuses(t *testing.T) {
	key, pub := newKey(t)
	_, other := newKey(t)
	archive := []byte("bundle bytes")
	sig, _ := Sign(key, "1.0.0", 3, "1.2.0", archive)
	cases := map[string]func() error{
		"hash":     func() error { return Verify([]string{pub}, sig, "1.0.0", 3, "1.2.0", []byte("bundle bytez")) },
		"size":     func() error { return Verify([]string{pub}, sig, "1.0.0", 3, "1.2.0", append(archive, 0)) },
		"version":  func() error { return Verify([]string{pub}, sig, "1.0.1", 3, "1.2.0", archive) },
		"build":    func() error { return Verify([]string{pub}, sig, "1.0.0", 4, "1.2.0", archive) },
		"contract": func() error { return Verify([]string{pub}, sig, "1.0.0", 3, "1.3.0", archive) },
		"key":      func() error { return Verify([]string{other}, sig, "1.0.0", 3, "1.2.0", archive) },
		"nokeys":   func() error { return Verify(nil, sig, "1.0.0", 3, "1.2.0", archive) },
	}
	for name, f := range cases {
		if err := f(); !errors.Is(err, ErrUntrusted) {
			t.Errorf("%s: err %v, want ErrUntrusted", name, err)
		}
	}
	if err := Verify([]string{pub}, []byte("not base64!"), "1.0.0", 3, "1.2.0", archive); !errors.Is(err, ErrMalformed) {
		t.Errorf("garbage signature: %v, want ErrMalformed", err)
	}
	if err := Verify([]string{pub}, sig, "1.0", 3, "1.2.0", archive); !errors.Is(err, ErrMalformed) {
		t.Errorf("bad version: %v, want ErrMalformed", err)
	}
	if err := Verify([]string{pub}, sig, "1.0.0", 3, "1.2.0", nil); !errors.Is(err, ErrMalformed) {
		t.Errorf("empty archive: %v, want ErrMalformed", err)
	}
}

// A production server must never trust the development key.
func TestTrustedKeysHoldNoDevelopmentKey(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	data, err := os.ReadFile(filepath.Join(home, ".config", "hyperdrop", "dev", "web-dev-ed25519.key"))
	if err != nil {
		t.Skip("no development web key on this machine")
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("the development key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pub := base64.StdEncoding.EncodeToString(parsed.(ed25519.PrivateKey).Public().(ed25519.PublicKey))
	if slices.Contains(TrustedKeys, pub) {
		t.Fatalf("TrustedKeys holds the development key %s", pub)
	}
}
