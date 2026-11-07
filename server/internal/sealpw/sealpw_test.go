package sealpw

import (
	"bytes"
	"errors"
	"testing"
)

var secret = bytes.Repeat([]byte{7}, 32)

const hash = "$2a$10$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuvwxyz01234"

func TestASealedPasswordOpensForItsShareOnly(t *testing.T) {
	sealed, err := Seal(secret, "abcdefghjk", hash, "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("hunter2")) {
		t.Fatal("the sealed copy carries the plaintext")
	}
	got, err := Open(secret, "abcdefghjk", hash, sealed)
	if err != nil || got != "hunter2" {
		t.Fatalf("Open = %q, %v", got, err)
	}
	if _, err := Open(secret, "zzzzzzzzzz", hash, sealed); !errors.Is(err, ErrUnreadable) {
		t.Fatalf("another share's id opened it: %v", err)
	}
}

func TestACopyOpensOnlyBesideItsOwnHash(t *testing.T) {
	sealed, err := Seal(secret, "abcdefghjk", "h1", "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Open(secret, "abcdefghjk", "h1", sealed); err != nil || got != "hunter2" {
		t.Fatalf("Open beside its own hash = %q, %v", got, err)
	}
	for _, h := range []string{"h2", ""} {
		if _, err := Open(secret, "abcdefghjk", h, sealed); !errors.Is(err, ErrUnreadable) {
			t.Fatalf("hash %q opened a copy sealed beside h1: %v", h, err)
		}
	}
}

// The id and the hash are separated in the associated data, so moving
// characters between them never yields the same associated data.
func TestTheIDAndHashCannotTradeCharacters(t *testing.T) {
	sealed, _ := Seal(secret, "abcdefghjk", "h1", "hunter2")
	if _, err := Open(secret, "abcdefghj", "kh1", sealed); !errors.Is(err, ErrUnreadable) {
		t.Fatalf("a shifted id/hash boundary opened it: %v", err)
	}
}

func TestAnotherSecretCannotOpenIt(t *testing.T) {
	sealed, _ := Seal(secret, "abcdefghjk", hash, "hunter2")
	if _, err := Open(bytes.Repeat([]byte{8}, 32), "abcdefghjk", hash, sealed); !errors.Is(err, ErrUnreadable) {
		t.Fatalf("a replaced secret opened it: %v", err)
	}
}

func TestATamperedOrTruncatedCopyIsUnreadable(t *testing.T) {
	sealed, _ := Seal(secret, "abcdefghjk", hash, "hunter2")
	flipped := append([]byte(nil), sealed...)
	flipped[len(flipped)-1] ^= 1
	nonceFlipped := append([]byte(nil), sealed...)
	nonceFlipped[1] ^= 1
	for name, b := range map[string][]byte{"flipped": flipped, "nonce flipped": nonceFlipped,
		"short": sealed[:5], "one short": sealed[:len(sealed)-1], "empty": nil,
		"unknown version": append([]byte{9}, sealed[1:]...)} {
		if _, err := Open(secret, "abcdefghjk", hash, b); !errors.Is(err, ErrUnreadable) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestEverySealIsFresh(t *testing.T) {
	a, _ := Seal(secret, "abcdefghjk", hash, "hunter2")
	b, _ := Seal(secret, "abcdefghjk", hash, "hunter2")
	if bytes.Equal(a, b) {
		t.Fatal("two seals of one password are identical: the nonce is not random")
	}
}

func TestNoPasswordSealsToNothing(t *testing.T) {
	if b, err := Seal(secret, "abcdefghjk", hash, ""); b != nil || err != nil {
		t.Fatalf("Seal(\"\") = %v, %v", b, err)
	}
}

func TestNoHashSealsToNothing(t *testing.T) {
	if b, err := Seal(secret, "abcdefghjk", "", "hunter2"); b != nil || err != nil {
		t.Fatalf("Seal with no hash = %v, %v", b, err)
	}
}

// An error never carries the password or the secret.
func TestErrorsCarryNoSecret(t *testing.T) {
	sealed, _ := Seal(secret, "abcdefghjk", hash, "hunter2")
	_, err := Open(secret, "abcdefghjk", "other", sealed)
	if err == nil || bytes.Contains([]byte(err.Error()), []byte("hunter2")) {
		t.Fatalf("error = %v", err)
	}
}
