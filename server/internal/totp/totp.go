// Package totp implements RFC 6238 time-based one-time passwords: SHA-1,
// 6 digits, a 30 s period. That combination is not a preference, it is what
// every authenticator app assumes when it is handed a bare otpauth:// URI,
// and a server that chose otherwise would be enrolled correctly and then
// rejected on every code.
//
// Pure and dependency-free (crypto/hmac, crypto/sha1, encoding/base32 are
// all stdlib), so the server gains no dependency for the whole feature.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 6238 authenticator apps compute HMAC-SHA1 codes; SHA-1 is not used as a collision-resistant hash here
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// Digits and Period are the authenticator-app defaults; see the package
	// comment for why they are not configurable.
	Digits = 6
	Period = 30 * time.Second

	// SecretBytes is 160 bits, the size RFC 4226 specifies for SHA-1 HMAC.
	SecretBytes = 20

	// Skew accepts one step either side of now, so a clock up to 30 s out
	// still works. Deliberately not wider: the window a code stays valid for
	// IS the window an overheard code stays usable for, and phones do not
	// drift further than this.
	Skew = 1
)

// b32 is unpadded uppercase base32, the encoding otpauth:// secrets use.
// Padding is not merely optional there: several authenticator apps refuse a
// secret carrying '='.
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateSecret returns a fresh base32 shared secret.
func GenerateSecret() (string, error) {
	b := make([]byte, SecretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b32.EncodeToString(b), nil
}

// StepAt is the RFC 6238 time step containing t.
func StepAt(t time.Time) int64 { return t.Unix() / int64(Period/time.Second) }

// Code computes the code for one step. An unparseable secret is an error
// rather than a wrong code, so a corrupt user file cannot read as "the user
// keeps typing it wrong".
func Code(secret string, step int64) (string, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}
	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	mac.Write(ctr[:])
	sum := mac.Sum(nil)
	// Dynamic truncation (RFC 4226 §5.3): the low nibble of the last byte
	// picks the 4-byte window, whose top bit is masked off.
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for range Digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", Digits, v%mod), nil
}

// decodeSecret accepts the spacing and casing password managers display.
func decodeSecret(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "=", "").Replace(secret))
	if s == "" {
		return nil, fmt.Errorf("empty secret")
	}
	return b32.DecodeString(s)
}

// Normalize strips what a person types around a code: spaces and dashes,
// which is how authenticator apps display them ("123 456").
func Normalize(code string) string {
	return strings.NewReplacer(" ", "", "-", "").Replace(strings.TrimSpace(code))
}

// Verify checks code against secret at `now`, accepting Skew steps either
// side, and returns the step it matched.
//
// A step at or below lastStep is REFUSED even when the code is arithmetically
// correct. That is the replay guard, and it is the difference between a code
// being usable once and being usable by everyone who overhears it for the
// rest of its window. Callers MUST persist the returned step.
func Verify(secret, code string, now time.Time, lastStep int64) (int64, bool) {
	code = Normalize(code)
	if len(code) != Digits {
		return 0, false
	}
	center := StepAt(now)
	for delta := int64(-Skew); delta <= Skew; delta++ {
		step := center + delta
		if step <= lastStep {
			continue
		}
		want, err := Code(secret, step)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// URI builds the otpauth:// URL an authenticator app scans. The label is
// "<issuer>:<account>" and issuer is repeated as a parameter, which is what
// makes apps show "HyperDrop" beside the account rather than a bare address.
func URI(secret, issuer, account string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(Digits))
	q.Set("period", fmt.Sprint(int(Period/time.Second)))
	return "otpauth://totp/" + label + "?" + q.Encode()
}
