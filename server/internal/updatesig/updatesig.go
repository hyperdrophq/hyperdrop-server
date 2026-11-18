// Package updatesig verifies a server binary's release signature: five lines,
// a header, the version, the architecture, the binary's SHA-256 and an
// Ed25519 signature over the first four, the format pinned by a test vector
// shared with HyperDrop's release signer.
//
// It is the boundary between "whoever can stage a binary" and "root on this
// box". The root updater installs a staged binary only after the binary
// already installed (root-owned, these keys compiled in) passes
// `hyperdrop-server verify-update` on it, so neither the API route nor the
// service account, which can both write the staging directory, decides what
// runs as root.
package updatesig

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// TrustedKeys are the release public keys, base64. The private halves never
// leave HyperDrop's release process. A rotation adds the new key
// here and keeps the old one for at least one release, so a box running the
// release before it still verifies what the release after it signed.
var TrustedKeys = []string{
	"NMALpCxNVOpka+DRQ0EZh4x3imohB1XaUrUAnE8Nph4=",
}

// MaxSize bounds a signature file; a real one is well under 300 bytes.
const MaxSize = 4 << 10

const header = "hyperdrop-server-signature 3"

// ErrUnsigned is a staged binary that came without a signature.
var ErrUnsigned = errors.New("the server binary is not signed")

// Statement is what a valid signature vouches for.
type Statement struct {
	Version string
	Arch    string
	SHA256  string
}

// Verify checks sig against the binary read from bin, for this host's arch,
// refusing a version older than current. keys are base64 Ed25519 public keys
// (TrustedKeys in production).
func Verify(keys []string, sig []byte, bin io.Reader, arch, current string) (Statement, error) {
	if len(sig) == 0 {
		return Statement{}, ErrUnsigned
	}
	st, signed, signature, err := parse(sig)
	if err != nil {
		return Statement{}, err
	}
	if !verifiedByAny(keys, signed, signature) {
		return Statement{}, errors.New("the signature is not from a HyperDrop release key")
	}
	h := sha256.New()
	if _, err := io.Copy(h, bin); err != nil {
		return Statement{}, err
	}
	if hex.EncodeToString(h.Sum(nil)) != st.SHA256 {
		return Statement{}, errors.New("the binary is not the one the signature names")
	}
	if st.Arch != arch {
		return Statement{}, fmt.Errorf("the binary is signed for %s; this host is %s", st.Arch, arch)
	}
	if older(st.Version, current) {
		return Statement{}, fmt.Errorf("the binary is %s, older than the %s installed; downgrade over SSH", st.Version, current)
	}
	return st, nil
}

// parse splits a signature file into its statement, the exact bytes signed
// and the signature.
func parse(sig []byte) (Statement, []byte, []byte, error) {
	if len(sig) > MaxSize {
		return Statement{}, nil, nil, errors.New("the signature file is too large")
	}
	lines := strings.Split(strings.TrimSuffix(string(sig), "\n"), "\n")
	bad := errors.New("the signature file is malformed")
	if len(lines) != 5 || lines[0] != header {
		return Statement{}, nil, nil, bad
	}
	var st Statement
	for i, field := range []struct {
		name string
		dst  *string
	}{{"version", &st.Version}, {"arch", &st.Arch}, {"sha256", &st.SHA256}} {
		v, ok := strings.CutPrefix(lines[i+1], field.name+" ")
		if !ok || v == "" || strings.ContainsAny(v, " \r") {
			return Statement{}, nil, nil, bad
		}
		*field.dst = v
	}
	if parseVersion(st.Version) == nil || len(st.SHA256) != 64 {
		return Statement{}, nil, nil, bad
	}
	b64, ok := strings.CutPrefix(lines[4], "signature ")
	if !ok {
		return Statement{}, nil, nil, bad
	}
	signature, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Statement{}, nil, nil, bad
	}
	signed := strings.Join(lines[:4], "\n") + "\n"
	return st, []byte(signed), signature, nil
}

func verifiedByAny(keys []string, msg, sig []byte) bool {
	for _, k := range keys {
		pub, err := base64.StdEncoding.DecodeString(k)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
			return true
		}
	}
	return false
}

// older reports whether version a sorts before b. An unparseable b (a
// development build) orders nothing.
func older(a, b string) bool {
	pa, pb := parseVersion(a), parseVersion(b)
	if pa == nil || pb == nil {
		return false
	}
	for i := range 3 {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}

func parseVersion(v string) []int {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return nil
	}
	out := make([]int, 3)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || strconv.Itoa(n) != p {
			return nil
		}
		out[i] = n
	}
	return out
}
