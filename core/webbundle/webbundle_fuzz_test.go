package webbundle

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// The web manifest is fetched from the website. One that parses holds one
// JSON value of known fields, so its own encoding parses to the same
// manifest, and the bundle picked for a server is one Serves admits with a
// readable version.
func FuzzParseManifest(f *testing.F) {
	f.Add([]byte(`{"releases":[{"version":"1.2.0","build":11,"date":"2026-11-17","contract":"1.8.1","sha256":"ab","size":3,"url":"a.tar.gz","sig":"x"},{"version":"1.1.0","build":9,"contract":"1.7.0"}]}`), "1.8.1")
	f.Add([]byte(`{"releases":[{"version":"1.2.0","build":1,"contract":"1.9.0"}]}`), "1.8.0")
	f.Add([]byte(`{"releases":[],"more":1}`), "1.8.1")
	f.Add([]byte(`{"releases":[]} {}`), "1.0.0")
	f.Add([]byte(`null`), "01.8.1")
	f.Fuzz(func(t *testing.T, data []byte, contract string) {
		m, err := ParseManifest(data)
		if err != nil {
			return
		}
		again, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		second, err := ParseManifest(again)
		if err != nil || !reflect.DeepEqual(m, second) {
			t.Fatalf("a parsed manifest's encoding reads as %+v, %v", second, err)
		}
		r, ok := Pick(m, contract)
		if !ok {
			return
		}
		if _, vok := dotted(r.Version); !vok || !Serves(r.Contract, contract) {
			t.Fatalf("Pick for %q chose %+v", contract, r)
		}
		for _, other := range m.Releases {
			if _, vok := dotted(other.Version); !vok || !Serves(other.Contract, contract) {
				continue
			}
			oc, _ := dotted(other.Contract)
			rc, _ := dotted(r.Contract)
			if oc[1] > rc[1] || (oc[1] == rc[1] && newer(other, r)) {
				t.Fatalf("Pick for %q chose %+v over %+v", contract, r, other)
			}
		}
	})
}

// A bundle's signature and the facts it is checked against come with the
// download. Verify accepts only the signature the key makes over the
// statement of exactly this version, build, contract and archive, and every
// refusal is ErrMalformed or ErrUntrusted.
func FuzzVerify(f *testing.F) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	keys := []string{base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}
	archive := []byte("a web bundle")
	sig, err := Sign(key, "1.2.0", 11, "1.8.1", archive)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(sig, "1.2.0", 11, "1.8.1", archive)
	f.Add(sig, "1.2.0", 12, "1.8.1", archive)
	f.Add(sig, "1.2.0\n11", 11, "1.8.1", archive)
	f.Add(sig[:20], "1.2.0", 11, "1.8.1", archive)
	f.Add(sig, "1.2.0", 11, "1.8.1", []byte{})
	f.Fuzz(func(t *testing.T, sig []byte, version string, build int, contract string, archive []byte) {
		err := Verify(keys, sig, version, build, contract, archive)
		if err != nil {
			if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrUntrusted) {
				t.Fatalf("Verify refuses with %v", err)
			}
			return
		}
		want, err := Sign(key, version, build, contract, archive)
		if err != nil {
			t.Fatalf("verified what cannot be signed: %v", err)
		}
		got, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
		wantRaw, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(string(want)))
		if !bytes.Equal(got, wantRaw) {
			t.Fatalf("verified %q, the key signs %q", sig, want)
		}
		st, _ := statementFor(version, build, contract, archive)
		if strings.Count(st, "\n") != 6 {
			t.Fatalf("the statement is not six lines: %q", st)
		}
	})
}
