package totp

import (
	"strings"
	"testing"
	"time"
)

// rfcSecret is the RFC 6238 appendix B SHA-1 key ("12345678901234567890")
// in base32.
const rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

// The appendix prints 8-digit codes; a 6-digit code is the same truncated
// value mod 10^6, so these are its last six digits.
func TestRFC6238Vectors(t *testing.T) {
	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	}
	for _, c := range cases {
		got, err := Code(rfcSecret, StepAt(time.Unix(c.unix, 0)))
		if err != nil {
			t.Fatalf("t=%d: %v", c.unix, err)
		}
		if got != c.want {
			t.Errorf("t=%d code = %s, want %s", c.unix, got, c.want)
		}
	}
}

// A clock up to one step out still logs in; two steps out does not. The
// window a code stays valid for is the window an overheard code stays usable
// for, so this bound is the feature, not a rounding detail.
func TestSkewIsOneStepEitherSide(t *testing.T) {
	now := time.Unix(1700000000, 0)
	center := StepAt(now)
	for _, delta := range []int64{-1, 0, 1} {
		code, err := Code(rfcSecret, center+delta)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := Verify(rfcSecret, code, now, 0); !ok {
			t.Errorf("delta %d rejected, want accepted", delta)
		}
	}
	for _, delta := range []int64{-2, 2, 10} {
		code, err := Code(rfcSecret, center+delta)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := Verify(rfcSecret, code, now, 0); ok {
			t.Errorf("delta %d accepted, want rejected", delta)
		}
	}
}

// Without this a code read aloud over the phone is good for a full minute on
// any number of devices, which is most of what TOTP exists to prevent.
func TestACodeCannotBeReplayedInsideItsOwnWindow(t *testing.T) {
	now := time.Unix(1700000000, 0)
	code, err := Code(rfcSecret, StepAt(now))
	if err != nil {
		t.Fatal(err)
	}
	step, ok := Verify(rfcSecret, code, now, 0)
	if !ok {
		t.Fatal("first use rejected")
	}
	if _, ok := Verify(rfcSecret, code, now, step); ok {
		t.Fatal("same code accepted twice within its window")
	}
	// A code from a LATER step still works: the guard bounds replay, it does
	// not lock the account out for the rest of the day.
	next, err := Code(rfcSecret, step+1)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := Verify(rfcSecret, next, now.Add(Period), step); !ok {
		t.Fatal("the next step's code was refused after a normal use")
	}
}

// Authenticator apps display "123 456" and password managers hyphenate, so
// what the user copies is not always what the RFC computes.
func TestSpacingAndCasingAreTolerated(t *testing.T) {
	now := time.Unix(1700000000, 0)
	code, err := Code(rfcSecret, StepAt(now))
	if err != nil {
		t.Fatal(err)
	}
	spaced := code[:3] + " " + code[3:]
	if _, ok := Verify(rfcSecret, spaced, now, 0); !ok {
		t.Errorf("spaced code %q rejected", spaced)
	}
	lower := strings.ToLower(rfcSecret)
	if _, ok := Verify(lower, code, now, 0); !ok {
		t.Error("lowercase secret rejected")
	}
}

func TestAWrongLengthOrGarbageCodeIsRefused(t *testing.T) {
	now := time.Unix(1700000000, 0)
	for _, code := range []string{"", "12345", "1234567", "abcdef"} {
		if _, ok := Verify(rfcSecret, code, now, 0); ok {
			t.Errorf("%q accepted", code)
		}
	}
}

// A corrupt secret must not read as "the user keeps typing it wrong".
func TestACorruptSecretIsAnErrorNotAWrongCode(t *testing.T) {
	if _, err := Code("not!base32", 1); err == nil {
		t.Fatal("bad secret produced a code")
	}
	if _, ok := Verify("not!base32", "123456", time.Unix(1700000000, 0), 0); ok {
		t.Fatal("bad secret verified")
	}
}

func TestGeneratedSecretsAreUsableAndDistinct(t *testing.T) {
	a, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two generated secrets are identical")
	}
	now := time.Now()
	code, err := Code(a, StepAt(now))
	if err != nil {
		t.Fatalf("generated secret does not decode: %v", err)
	}
	if _, ok := Verify(a, code, now, 0); !ok {
		t.Fatal("a generated secret's own code failed to verify")
	}
	if strings.Contains(a, "=") {
		t.Fatalf("secret %q carries padding, which some apps refuse", a)
	}
}

// The URI is what the QR encodes; an app that cannot read the issuer shows
// a bare account name in a list of every other service.
func TestURICarriesTheParametersAppsRead(t *testing.T) {
	got := URI("ABC234", "HyperDrop", "alice@share.example.com")
	for _, want := range []string{
		"otpauth://totp/HyperDrop:alice@share.example.com?",
		"secret=ABC234", "issuer=HyperDrop", "algorithm=SHA1",
		"digits=6", "period=30",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("URI %q missing %q", got, want)
		}
	}
}
