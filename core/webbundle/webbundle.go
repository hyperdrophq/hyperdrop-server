// Package webbundle is the web client's bundle contract: the statement a
// bundle's signature covers, signing and verifying it, the web release
// manifest and the rule for which bundle a server of a given contract takes.
// It is pure (no file, network or process access), so the server links it to
// verify a bundle it installs and the release signer links it to sign one.
//
// A bundle's detached Ed25519 signature covers six lines, newlines included:
//
//	hyperdrop-web
//	<version: MAJOR.MINOR.PATCH>
//	<build>
//	<contract: MAJOR.MINOR.PATCH of the server API the bundle speaks>
//	<64 lowercase hex digits of the archive's SHA-256>
//	<the archive's size in bytes>
//
// The signature file holds the base64 signature and a newline.
package webbundle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Header is the first line of the statement.
const Header = "hyperdrop-web"

// DevKeysEnv names the variable that lists extra trusted development public
// keys. Nothing in this package reads it: the server consults it only when it
// runs with private addresses allowed.
const DevKeysEnv = "HYPERDROP_WEB_DEV_KEYS"

// TrustedKeys are the web release keys' public halves, base64: the
// signatures a server accepts for a bundle. The owner's release key is made
// with `hyperdrop-sign-server -web -genkey`, its private half at
// ~/.config/hyperdrop/release/web-release-ed25519.key. A rotation adds the
// new key and keeps the old one for at least a release. A development key
// never belongs here; it is trusted only through DevKeysEnv.
var TrustedKeys = []string{
	"ZhR4KDPlsTTmc8VqgFOcB13EsJOcfW9YSE1X9ptSqqg=",
}

var (
	// ErrMalformed reports an input that cannot be read one way: a bad
	// version, contract, build, digest, size or signature encoding.
	ErrMalformed = errors.New("malformed web bundle input")
	// ErrUntrusted reports a well-formed signature no trusted key made for
	// this exact bundle.
	ErrUntrusted = errors.New("the web bundle is not signed by a trusted key")
)

// dotted splits a MAJOR.MINOR.PATCH string into its numbers; ok is false for
// anything else (signs, spaces, empty parts, leading zeros).
func dotted(s string) (n [3]int, ok bool) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return n, false
	}
	for i, p := range parts {
		if p == "" || (len(p) > 1 && p[0] == '0') || len(p) > 9 {
			return n, false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return n, false
			}
		}
		v, err := strconv.Atoi(p)
		if err != nil {
			return n, false
		}
		n[i] = v
	}
	return n, true
}

func validSum(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Statement is the six lines a bundle's signature covers. Anything that could
// be read two ways is refused with ErrMalformed.
func Statement(version string, build int, contract, sha256hex string, size int64) (string, error) {
	if _, ok := dotted(version); !ok {
		return "", fmt.Errorf("%w: version %q is not MAJOR.MINOR.PATCH", ErrMalformed, version)
	}
	if _, ok := dotted(contract); !ok {
		return "", fmt.Errorf("%w: contract %q is not MAJOR.MINOR.PATCH", ErrMalformed, contract)
	}
	if build < 1 {
		return "", fmt.Errorf("%w: build %d is not a positive build number", ErrMalformed, build)
	}
	if !validSum(sha256hex) {
		return "", fmt.Errorf("%w: %q is not a lowercase SHA-256", ErrMalformed, sha256hex)
	}
	if size < 1 {
		return "", fmt.Errorf("%w: size %d is not positive", ErrMalformed, size)
	}
	return Header + "\n" + version + "\n" + strconv.Itoa(build) + "\n" + contract + "\n" + sha256hex + "\n" + strconv.FormatInt(size, 10) + "\n", nil
}

func statementFor(version string, build int, contract string, archive []byte) (string, error) {
	sum := sha256.Sum256(archive)
	return Statement(version, build, contract, hex.EncodeToString(sum[:]), int64(len(archive)))
}

// Sign returns the signature file for archive: the base64 Ed25519 signature
// over its statement and a newline.
func Sign(key ed25519.PrivateKey, version string, build int, contract string, archive []byte) ([]byte, error) {
	st, err := statementFor(version, build, contract, archive)
	if err != nil {
		return nil, err
	}
	return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(st))) + "\n"), nil
}

// Verify accepts sig (base64, surrounding whitespace allowed) when one of
// keys signed the statement for this version, build, contract and archive,
// whose digest and size it computes itself.
func Verify(keys []string, sig []byte, version string, build int, contract string, archive []byte) error {
	st, err := statementFor(version, build, contract, archive)
	if err != nil {
		return err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || len(raw) != ed25519.SignatureSize {
		return fmt.Errorf("%w: the signature is missing or not base64 Ed25519", ErrMalformed)
	}
	for _, k := range keys {
		pub, err := base64.StdEncoding.DecodeString(k)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(pub), []byte(st), raw) {
			return nil
		}
	}
	return fmt.Errorf("%w (%s build %d, contract %s)", ErrUntrusted, version, build, contract)
}
