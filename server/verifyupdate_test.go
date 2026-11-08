package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"hyperdrop/server/internal/updatesig"
)

// verify-update is what the root installer asks before it executes a staged
// binary: exit 0 only for a release signature over exactly these bytes.
func TestVerifyUpdateGatesOnTheReleaseSignature(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, ed25519.SeedSize))
	trusted := updatesig.TrustedKeys
	updatesig.TrustedKeys = []string{base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}
	t.Cleanup(func() { updatesig.TrustedKeys = trusted })

	dir := t.TempDir()
	bin := filepath.Join(dir, "staged.bin")
	body := []byte("\x7fELF a staged server")
	os.WriteFile(bin, body, 0o755)
	sum := sha256.Sum256(body)
	st := "hyperdrop-server-signature 3\nversion " + version + "\narch " + runtime.GOARCH +
		"\nsha256 " + hex.EncodeToString(sum[:]) + "\n"
	sig := filepath.Join(dir, "staged.sig")
	os.WriteFile(sig, []byte(st+"signature "+base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(st)))+"\n"), 0o644)

	if code := runVerifyUpdate([]string{bin, sig}); code != 0 {
		t.Fatalf("a release-signed binary: exit %d", code)
	}
	if code := runVerifyUpdate([]string{bin, filepath.Join(dir, "missing.sig")}); code != 1 {
		t.Fatalf("no signature: exit %d, want 1", code)
	}
	os.WriteFile(bin, append(body, '!'), 0o755)
	if code := runVerifyUpdate([]string{bin, sig}); code != 1 {
		t.Fatalf("an edited binary: exit %d, want 1", code)
	}
	if code := runVerifyUpdate([]string{bin}); code != 2 {
		t.Fatalf("bad usage: exit %d, want 2", code)
	}
}

// A signature file is read only as far as a signature can reach: a huge
// staged signature is refused without being read whole.
func TestVerifyUpdateReadsASignatureOnlyAsFarAsItsLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "staged.sig")
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), 10*updatesig.MaxSize), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readSignature(path)
	if err != nil || len(got) != updatesig.MaxSize+1 {
		t.Fatalf("read %d bytes, %v; want %d", len(got), err, updatesig.MaxSize+1)
	}
	if code := runVerifyUpdate([]string{path, path}); code != 1 {
		t.Fatalf("an oversized signature: exit %d, want 1", code)
	}
}
