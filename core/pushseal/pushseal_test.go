package pushseal

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"unicode/utf8"
)

func newKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestASealedMessageOpensOnlyWithItsKey(t *testing.T) {
	k := newKey(t)
	m := Message{V: 1, Kind: "inboxReceived", Title: "Client uploads", Body: "brief-v2.docx",
		Thread: "inbox-r1", Tag: "e1", Unseen: 3, Ref: "r1"}
	ct, err := Seal(k.PublicKey().Bytes(), m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := base64.StdEncoding.Strict().DecodeString(ct); err != nil {
		t.Fatalf("not standard base64: %v", err)
	}
	got, err := Open(k, ct)
	if err != nil || got != m {
		t.Fatalf("opened %+v, %v", got, err)
	}
	if _, err := Open(newKey(t), ct); err == nil {
		t.Fatal("another key opened it")
	}
	again, _ := Seal(k.PublicKey().Bytes(), m)
	if again == ct {
		t.Fatal("two seals of one message are equal: the ephemeral key is not fresh")
	}
}

func TestAnOversizedMessageIsCutToFit(t *testing.T) {
	k := newKey(t)
	m := Message{V: 1, Kind: "inboxReceived", Title: strings.Repeat("Ünïcödé ", 600),
		Body: strings.Repeat("ファイル", 2000), Thread: "inbox-r1", Tag: "e1"}
	ct, err := Seal(k.PublicKey().Bytes(), m)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) > MaxCiphertext {
		t.Fatalf("ciphertext %d characters, limit %d", len(ct), MaxCiphertext)
	}
	got, _ := Open(k, ct)
	if !utf8.ValidString(got.Title) || !utf8.ValidString(got.Body) || !strings.HasSuffix(got.Body, "…") {
		t.Fatalf("cut badly: title %q… body %q…", got.Title[:20], got.Body[:20])
	}
	if got.Thread != "inbox-r1" || got.Tag != "e1" || got.Kind != "inboxReceived" {
		t.Fatalf("a cut touched the routing fields: %+v", got)
	}
}

func TestOnlyAUsableX25519KeyIsAccepted(t *testing.T) {
	if err := ParsePublicKey(newKey(t).PublicKey().Bytes()); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{"short": make([]byte, 31), "long": make([]byte, 33),
		"all zero (low order)": make([]byte, 32)} {
		if ParsePublicKey(raw) == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// TestTheLimitsAgree pins the arithmetic between the two caps: a plaintext of
// exactly MaxPlaintext bytes seals to at most MaxCiphertext characters, which
// stays under the relay's limit (names PushCiphertextLimit, 3,976).
func TestTheLimitsAgree(t *testing.T) {
	const relayLimit = 3976
	if n := 4 * ((32 + MaxPlaintext + 16 + 2) / 3); n > MaxCiphertext || MaxCiphertext > relayLimit {
		t.Fatalf("a %d-byte plaintext seals to %d characters; caps %d and relay %d", MaxPlaintext, n, MaxCiphertext, relayLimit)
	}
}
