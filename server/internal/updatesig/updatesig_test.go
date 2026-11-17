package updatesig

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// The shared test vector: core/serversig's TestTheVectorIsStable signs
// vectorRaw with the key behind vectorKey and must produce vectorFile
// byte for byte.
const (
	vectorKey  = "6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw="
	vectorFile = "hyperdrop-server-signature 3\n" +
		"version 1.0.0\n" +
		"arch amd64\n" +
		"sha256 702689a4f1fefb4715e4314fc922f035ab121586a74c39cb17c85279940bfab6\n" +
		"signature /wYtAQ2eBbHRiADUZ2CfpPAbzrhQaiFHzvgnLRTKE7Zk9+xo4GN83YvaLgnN4JpWZE0Cj8s48Wm3uHq4BT+OAQ==\n"
)

var vectorRaw = []byte("hyperdrop test binary\n")

func verify(sig string, raw []byte, arch, current string) error {
	_, err := Verify([]string{vectorKey}, []byte(sig), bytes.NewReader(raw), arch, current)
	return err
}

func TestTheCoreVectorVerifies(t *testing.T) {
	st, err := Verify([]string{vectorKey}, []byte(vectorFile), bytes.NewReader(vectorRaw), "amd64", "0.9.0")
	if err != nil {
		t.Fatal(err)
	}
	if st.Version != "1.0.0" || st.Arch != "amd64" {
		t.Fatalf("statement = %+v", st)
	}
	// The same version reinstalls; a development build orders nothing.
	for _, current := range []string{"1.0.0", "dev"} {
		if err := verify(vectorFile, vectorRaw, "amd64", current); err != nil {
			t.Fatalf("current %s: %v", current, err)
		}
	}
}

func TestEveryMismatchIsRefused(t *testing.T) {
	cases := map[string]error{
		"no signature": verify("", vectorRaw, "amd64", "0.9.0"),
		"other binary": verify(vectorFile, []byte("something else"), "amd64", "0.9.0"),
		"other arch":   verify(vectorFile, vectorRaw, "arm64", "0.9.0"),
		"downgrade":    verify(vectorFile, vectorRaw, "amd64", "1.0.1"),
		"edited arch":  verify(strings.Replace(vectorFile, "arch amd64", "arch arm64", 1), vectorRaw, "arm64", "0.9.0"),
		"edited ver":   verify(strings.Replace(vectorFile, "version 1.0.0", "version 9.9.9", 1), vectorRaw, "amd64", "0.9.0"),
		"extra line":   verify(vectorFile+"x\n", vectorRaw, "amd64", "0.9.0"),
		"garbled":      verify("hyperdrop-server-signature 3\nnonsense\n", vectorRaw, "amd64", "0.9.0"),
		"wrong header": verify(strings.Replace(vectorFile, "signature 3", "signature 4", 1), vectorRaw, "amd64", "0.9.0"),
		"retired line": verify(strings.Replace(vectorFile, "signature 3", "signature 2", 1), vectorRaw, "amd64", "0.9.0"),
	}
	for name, err := range cases {
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if !errors.Is(cases["no signature"], ErrUnsigned) {
		t.Errorf("no signature: %v, want ErrUnsigned", cases["no signature"])
	}
	// A key that is not trusted verifies nothing.
	if _, err := Verify(TrustedKeys, []byte(vectorFile), bytes.NewReader(vectorRaw), "amd64", "0.9.0"); err == nil {
		t.Error("the test key's signature passed the release keys")
	}
}

func TestTheReleaseKeysAreWellFormed(t *testing.T) {
	if len(TrustedKeys) == 0 {
		t.Fatal("no release key is trusted")
	}
	for _, k := range TrustedKeys {
		if pub, err := base64.StdEncoding.DecodeString(k); err != nil || len(pub) != ed25519.PublicKeySize {
			t.Errorf("%q is not a base64 Ed25519 public key", k)
		}
	}
}
