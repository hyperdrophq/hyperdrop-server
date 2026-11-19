package pushseal

import (
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/base64"
	"testing"
)

// sealPlain seals raw plaintext with the push suite, bypassing Message, so a
// test can hand Open what a well-formed Seal never produces.
func sealPlain(t *testing.T, pub []byte, plain string) string {
	t.Helper()
	pk, err := hpke.DHKEM(ecdh.X25519()).NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := hpke.Seal(pk, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte(Info), []byte(plain))
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sealed)
}

func TestOpenRefusesWhatIsNotAV1Message(t *testing.T) {
	priv, pub, err := NewDeviceKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, plain := range []string{`null`, `{}`, `[1]`, `{"v":2,"kind":"x"}`, `{"v":1}`} {
		if m, err := OpenRaw(priv, sealPlain(t, pub, plain)); err == nil {
			t.Errorf("%s opened as %+v", plain, m)
		}
	}
	sealed, err := Seal(pub, Message{V: 1, Kind: "domain", Title: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if m, err := OpenRaw(priv, sealed); err != nil || m.Kind != "domain" {
		t.Fatalf("a real message: %+v %v", m, err)
	}
}
